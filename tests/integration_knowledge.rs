#![allow(clippy::unwrap_used, clippy::expect_used)]
//! C13 — Knowledge Engine : neutralité OFF, apprentissage ON, OPSEC fichier.
//!
//! - OFF (défaut) : aucune lecture/écriture disque, scores/ordre identiques
//!   au sans-knowledge (`boost 1.0` neutre, `score == evi / cost`).
//! - ON : 2 runs simulés sur la technique gagnante → `boost > 1`, borné
//!   `[0.5, 1.5]` (clamp scheduler `[0.5, 2.0]` conservé, jamais de veto).
//! - Fichier : perms `0600`, aucun secret/cible persisté (grep fixtures).

use injekt::detection::scanner::scheduler::{
    EarlyStop, RequestBudget, Scheduler, clamp_knowledge_boost, ordered_techniques_by_score,
};
use injekt::reasoning::knowledge::{
    KnowledgeStore, learn_from_run, load_if_enabled, resolve_knowledge_path, save_delta_if_enabled,
};
use injekt::session::state::{Finding, TechniqueKind};

fn unique_path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "injekt-c13-{tag}-{}-{}.json",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::remove_file(&p).ok();
    p
}

fn all_candidates() -> Vec<(TechniqueKind, f64)> {
    vec![
        (TechniqueKind::Boolean, 0.2),
        (TechniqueKind::Error, 0.15),
        (TechniqueKind::Time, 0.1),
        (TechniqueKind::Union, 0.05),
        (TechniqueKind::Stacked, 0.05),
        (TechniqueKind::Json, 0.45),
        (TechniqueKind::Oob, 0.02),
    ]
}

#[test]
fn off_by_default_no_file_and_identical_order() {
    let path = unique_path("off");
    let explicit = path.to_string_lossy().into_owned();

    // OFF : aucune IO, même avec un chemin explicite.
    assert_eq!(load_if_enabled(false, Some(&explicit)), None);
    let wrote = save_delta_if_enabled(&KnowledgeStore::empty(), false, Some(&explicit)).unwrap();
    assert!(!wrote);
    assert!(!path.exists(), "OFF doit créer 0 fichier");

    // OFF : ordre/scores identiques au sans-knowledge.
    let candidates = all_candidates();
    let plain = ordered_techniques_by_score(&candidates, None, Some(42));
    let empty = KnowledgeStore::empty();
    // Store vide => boost 1.0 partout => même ordre que None.
    let mut scored_plain = Vec::new();
    let mut scored_knowledge = Vec::new();
    for (kind, posterior) in &candidates {
        scored_plain.push(injekt::detection::scanner::scheduler::score_for(
            *kind, *posterior, None,
        ));
        scored_knowledge.push(injekt::detection::scanner::scheduler::score_for(
            *kind,
            *posterior,
            Some(empty.boost_for(*kind, "mysql", "numeric")),
        ));
    }
    assert_eq!(scored_plain, scored_knowledge);
    let neutral: Vec<TechniqueKind> = {
        // `ordered_techniques_by_score` avec boost global 1.0 explicite.
        ordered_techniques_by_score(&candidates, Some(1.0), Some(42))
    };
    assert_eq!(plain, neutral);

    // Heap scheduler : `None` vs `Some(1.0)` => même ordre de pop.
    let mut a = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());
    let mut b = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());
    for (kind, posterior) in &candidates {
        a.push_for_posterior("id", *kind, "p", *posterior, None);
        b.push_for_posterior("id", *kind, "p", *posterior, Some(1.0));
    }
    let mut order_a = Vec::new();
    let mut order_b = Vec::new();
    while let Some(p) = a.pop() {
        order_a.push(p.technique);
    }
    while let Some(p) = b.pop() {
        order_b.push(p.technique);
    }
    assert_eq!(order_a, order_b);
    assert_eq!(order_a, plain);
}

#[test]
fn on_two_simulated_runs_boost_winner_bounded() {
    // 2 runs simulés : 6 succès/run sur boolean/mysql/numeric (= 12 essais).
    let mut ks = KnowledgeStore::empty();
    for _ in 0..6 {
        ks.record(TechniqueKind::Boolean, "mysql", "numeric", true, 12);
    }
    assert!((ks.boost_for(TechniqueKind::Boolean, "mysql", "numeric") - 1.0).abs() < 1e-12);
    for _ in 0..6 {
        ks.record(TechniqueKind::Boolean, "mysql", "numeric", true, 12);
    }
    let boost = ks.boost_for(TechniqueKind::Boolean, "mysql", "numeric");
    assert!(boost > 1.0, "boost={boost}");
    assert!(boost <= 1.5 + 1e-12, "boost={boost}");
    assert!((clamp_knowledge_boost(boost) - boost).abs() < 1e-12);

    // La gagnante passe devant à posterior égal.
    let cands = vec![(TechniqueKind::Boolean, 0.2), (TechniqueKind::Error, 0.2)];
    let plain = ordered_techniques_by_score(&cands, None, Some(7));
    assert_eq!(plain[0], TechniqueKind::Boolean); // evi boolean > error
    let _ = plain;

    // `learn_from_run` : 1 run => 1 essai/technique, gagnante en succès.
    let mut delta = KnowledgeStore::empty();
    let findings = vec![Finding::new(
        "http://lab.local/?id=1",
        "id@query",
        TechniqueKind::Boolean,
        0.9,
        "boolean true_sim=0.91 false_sim=0.22 trials=3/3",
    )];
    learn_from_run(
        &mut delta,
        &findings,
        &["all".to_owned()],
        Some("mysql"),
        70,
    );
    assert_eq!(delta.len(), 7);
}

#[test]
fn knowledge_file_0600_and_no_secrets_or_targets() {
    let path = unique_path("perms");
    let explicit = path.to_string_lossy().into_owned();
    assert_eq!(
        resolve_knowledge_path(Some(&explicit)),
        std::path::PathBuf::from(&explicit)
    );

    let mut ks = KnowledgeStore::empty();
    for _ in 0..12 {
        ks.record(TechniqueKind::Union, "postgres", "generic", true, 14);
    }
    ks.save_to(&path).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "perms={mode:o}");
    }
    let content = std::fs::read_to_string(&path).unwrap();
    for needle in [
        "http",
        "lab.local",
        "example.com",
        "127.0.0.1",
        "localhost",
        "id@query",
        "cookie",
        "bearer",
        "authorization",
        "seed",
        "BEGIN PRIVATE",
    ] {
        assert!(
            !content.to_ascii_lowercase().contains(needle),
            "fuite {needle}: {content}"
        );
    }
    // Scrubber redondant : no-op sur agrégats sains.
    let sc = injekt::session::scrubber::Scrubber::new(false);
    assert_eq!(sc.scrub(&content), content);

    // Rechargé : boost gagnant > 1, fusion post-run additive.
    let back = KnowledgeStore::load_from(&path).unwrap();
    assert!(back.boost_for(TechniqueKind::Union, "postgres", "generic") > 1.0);
    let back_trials = back.entries.values().next().map_or(0, |e| e.trials);
    assert_eq!(back_trials, 12);
    let mut delta = KnowledgeStore::empty();
    delta.record(TechniqueKind::Union, "postgres", "generic", true, 14);
    let wrote = save_delta_if_enabled(&delta, true, Some(&explicit)).unwrap();
    assert!(wrote);
    let merged = KnowledgeStore::load_from(&path).unwrap();
    assert_eq!(merged.entries.len(), 1);
    // Fusion additive : 12 essais + 1 essai du delta = 13.
    let merged_trials = merged.entries.values().next().map_or(0, |e| e.trials);
    assert_eq!(merged_trials, 13);
    let merged_success = merged.entries.values().next().map_or(0, |e| e.success);
    assert_eq!(merged_success, 13);

    std::fs::remove_file(&path).ok();
}

#[test]
fn resolve_default_path_and_env_override() {
    // Sans muter l'env (Rust 1.88 : `set_var` est `unsafe`, interdit par
    // `deny(unsafe_code)`) : on vérifie les deux branches selon l'état courant.
    if let Some(env) = std::env::var_os("INJEKT_KNOWLEDGE_PATH") {
        // Env positionné (ex : CI) : override du défaut.
        assert!(!env.is_empty(), "INJEKT_KNOWLEDGE_PATH vide inattendu");
        assert_eq!(
            resolve_knowledge_path(None),
            std::path::PathBuf::from(&env),
            "l'env doit overrider le défaut"
        );
    } else {
        // Cas standard : défaut `~/.cache/injekt/knowledge.json` (ou repli `$TMPDIR`).
        let def = resolve_knowledge_path(None);
        assert_eq!(
            def.file_name().and_then(|s| s.to_str()),
            Some("knowledge.json")
        );
        assert!(
            def.to_string_lossy().contains("injekt"),
            "défaut inattendu: {}",
            def.display()
        );
    }
    // Explicite (`--knowledge-path`) gagne toujours (sans toucher l'env).
    assert_eq!(
        resolve_knowledge_path(Some("/tmp/injekt-explicit-k.json")),
        std::path::PathBuf::from("/tmp/injekt-explicit-k.json")
    );
    // Vide/whitespace = ignoré (repli env puis défaut) : identique à `None`.
    assert_eq!(
        resolve_knowledge_path(Some("   ")),
        resolve_knowledge_path(None)
    );
}

#[test]
fn dry_run_env_override_and_explicit_precedence() {
    // Bout-en-bout sans `unsafe` : `Command::env` est safe et prouve la
    // précédence `--knowledge-path` > `INJEKT_KNOWLEDGE_PATH` > défaut.
    let bin = env!("CARGO_BIN_EXE_injekt");
    let env_path = unique_path("dryrun-env");
    let explicit_path = unique_path("dryrun-explicit");
    let env_s = env_path.to_string_lossy().into_owned();
    let explicit_s = explicit_path.to_string_lossy().into_owned();

    // Env seul : le dry-run affiche le chemin d'env, sans rien écrire.
    let out = std::process::Command::new(bin)
        .args([
            "--target",
            "http://example.com/?id=1",
            "--dry-run",
            "--allow-knowledge",
            "--no-banner",
            "--seed",
            "42",
        ])
        .env("INJEKT_KNOWLEDGE_PATH", &env_s)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "dry-run exit 0 attendu, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("knowledge: ON"), "{stdout}");
    assert!(stdout.contains(&env_s), "env override ignoré: {stdout}");
    assert!(
        !env_path.exists(),
        "le dry-run ne doit écrire aucun fichier knowledge"
    );

    // Explicite gagne sur l'env.
    let out2 = std::process::Command::new(bin)
        .args([
            "--target",
            "http://example.com/?id=1",
            "--dry-run",
            "--allow-knowledge",
            "--knowledge-path",
            &explicit_s,
            "--no-banner",
        ])
        .env("INJEKT_KNOWLEDGE_PATH", &env_s)
        .output()
        .unwrap();
    assert!(out2.status.success());
    let stdout2 = String::from_utf8_lossy(&out2.stdout).into_owned();
    assert!(stdout2.contains(&explicit_s), "{stdout2}");
    assert!(
        !stdout2.contains(&env_s),
        "l'explicite doit gagner sur l'env: {stdout2}"
    );
    assert!(
        !explicit_path.exists(),
        "le dry-run ne doit écrire aucun fichier knowledge"
    );
    std::fs::remove_file(&env_path).ok();
    std::fs::remove_file(&explicit_path).ok();
}

#[test]
fn corrupted_file_is_cold_start_neutral() {
    let path = unique_path("corrupt");
    std::fs::write(&path, "{ not valid json !!!").unwrap();
    // `load_from` échoue (erreur surfacing), mais la porte opt-in absorbe :
    // fichier corrompu -> `Some(vide)` neutre, jamais de panic.
    assert!(KnowledgeStore::load_from(&path).is_err());
    let explicit = path.to_string_lossy().into_owned();
    let loaded = load_if_enabled(true, Some(&explicit)).unwrap();
    assert!(loaded.is_empty());
    for kind in [
        TechniqueKind::Boolean,
        TechniqueKind::Error,
        TechniqueKind::Union,
    ] {
        assert!((loaded.boost_for(kind, "mysql", "numeric") - 1.0).abs() < 1e-12);
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn store_json_schema_version_and_closed_vocab() {
    let mut ks = KnowledgeStore::empty();
    for _ in 0..12 {
        ks.record(TechniqueKind::Boolean, "mysql", "numeric", true, 10);
    }
    let json = ks.to_file_string();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        v.get("version").and_then(serde_json::Value::as_u64),
        Some(1)
    );
    let entries = v
        .get("entries")
        .and_then(serde_json::Value::as_object)
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries.contains_key("boolean|mysql|numeric"));
    // Clés hors vocabulaire ignorées au chargement (jamais d'identifiant accepté).
    let evil = r#"{"version":1,"entries":{"boolean|mysql|numeric":{"success":12,"trials":12,"avg_req":10.0},"http://evil.local/?id=1":{"success":99,"trials":99,"avg_req":1.0}}}"#;
    let back = KnowledgeStore::parse_str(evil).unwrap();
    assert_eq!(back.len(), 1);
    assert!(back.boost_for(TechniqueKind::Boolean, "mysql", "numeric") > 1.0);
}

#[test]
fn plan_off_empty_identical_and_on_boosts_winner() {
    use injekt::{cli::plan::build_plan, engine::EngineConfig};
    fn cfg_with(knowledge: Option<KnowledgeStore>, dbms_hint: Option<String>) -> EngineConfig {
        let mut cfg = EngineConfig::default();
        cfg.budget.threads = 1;
        cfg.net.allow_private = true;
        cfg.no_redact = true;
        cfg.techniques = vec!["all".to_owned()];
        cfg.dbms_hint = dbms_hint;
        cfg.knowledge = knowledge;
        cfg
    }
    // OFF (`None`) vs ON-vide (`Some(empty)`) : plan byte-identique.
    let off = build_plan(
        "http://example.com/?id=1",
        &cfg_with(None, Some("mysql".to_owned())),
    )
    .unwrap();
    let on_empty = build_plan(
        "http://example.com/?id=1",
        &cfg_with(Some(KnowledgeStore::empty()), Some("mysql".to_owned())),
    )
    .unwrap();
    assert_eq!(off.ordered, on_empty.ordered);
    // ON rempli (12 succès boolean/mysql/numeric, contexte passif `?id=1`) :
    // boost gagnant > 1 et score boolean supérieur au OFF.
    let mut filled = KnowledgeStore::empty();
    for _ in 0..12 {
        filled.record(TechniqueKind::Boolean, "mysql", "numeric", true, 10);
    }
    assert!(filled.boost_for(TechniqueKind::Boolean, "mysql", "numeric") > 1.0);
    let on = build_plan(
        "http://example.com/?id=1",
        &cfg_with(Some(filled), Some("mysql".to_owned())),
    )
    .unwrap();
    assert_eq!(on.ordered.len(), off.ordered.len());
    let score_off = off
        .ordered
        .iter()
        .find(|p| p.technique == "boolean")
        .map(|p| p.score)
        .unwrap();
    let score_on = on
        .ordered
        .iter()
        .find(|p| p.technique == "boolean")
        .map(|p| p.score)
        .unwrap();
    assert!(score_on > score_off, "off={score_off} on={score_on}");
    assert!(
        (score_on / score_off - 1.0).abs() <= 0.5 + 1e-12,
        "alpha<=0.5"
    );
    // Bornes finales : boost scheduler toujours dans [0.5, 2.0].
    for p in &on.ordered {
        let base = off
            .ordered
            .iter()
            .find(|q| q.technique == p.technique)
            .map_or(p.score, |q| q.score);
        let ratio = p.score / base;
        assert!(
            (0.5 - 1e-12..=2.0 + 1e-12).contains(&ratio),
            "ratio={ratio} pour {}",
            p.technique
        );
    }
}
