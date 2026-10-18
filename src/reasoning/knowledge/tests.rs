use super::scoring::{boost_from_counts, clamp_knowledge_range};
use super::*;
use crate::dbms::context::InjectionContext;
use crate::dbms::context::QuoteContext;
use crate::detection::scanner::scheduler::clamp_knowledge_boost;
use crate::session::scrubber::Scrubber;
use crate::session::state::TechniqueKind;
use std::path::PathBuf;

fn ctx_numeric() -> InjectionContext {
    InjectionContext {
        quote: QuoteContext::None,
        numeric: true,
        json: false,
        order_by: false,
        comment: crate::dbms::context::CommentStyle::DashDash,
    }
}

#[test]
fn empty_store_is_neutral() {
    let ks = KnowledgeStore::empty();
    assert!(ks.is_empty());
    for kind in all_techniques() {
        assert!((ks.boost_for(kind, "mysql", "numeric") - 1.0).abs() < 1e-12);
        assert!((ks.boost_for_context(kind, "mysql", &ctx_numeric()) - 1.0).abs() < 1e-12);
    }
}

#[test]
fn cold_start_below_min_samples_stays_neutral() {
    let mut ks = KnowledgeStore::empty();
    for _ in 0..(MIN_SAMPLES - 1) {
        ks.record(TechniqueKind::Boolean, "mysql", "numeric", true, 10);
    }
    assert!((ks.boost_for(TechniqueKind::Boolean, "mysql", "numeric") - 1.0).abs() < 1e-12);
}

#[test]
fn two_simulated_runs_learn_winning_technique_bounded() {
    // 2 runs simulés : 6 succès/run sur boolean/mysql/numeric (=12 essais).
    let mut ks = KnowledgeStore::empty();
    for _ in 0..6 {
        ks.record(TechniqueKind::Boolean, "mysql", "numeric", true, 12);
    }
    // Après le run 1 seul (6 < 10) : encore neutre.
    assert!((ks.boost_for(TechniqueKind::Boolean, "mysql", "numeric") - 1.0).abs() < 1e-12);
    for _ in 0..6 {
        ks.record(TechniqueKind::Boolean, "mysql", "numeric", true, 12);
    }
    let boost = ks.boost_for(TechniqueKind::Boolean, "mysql", "numeric");
    assert!(boost > 1.0, "boost={boost}");
    assert!(boost <= KNOWLEDGE_MAX_BOOST + 1e-12, "boost={boost}");
    // Clamp scheduler conservé.
    assert!(clamp_knowledge_boost(boost) >= 0.5 - 1e-12);
    assert!(clamp_knowledge_boost(boost) <= 2.0 + 1e-12);
    // Technique perdante (tout-échec) descend sous 1.0, bornée.
    let mut bad = KnowledgeStore::empty();
    for _ in 0..12 {
        bad.record(TechniqueKind::Time, "mysql", "numeric", false, 30);
    }
    let down = bad.boost_for(TechniqueKind::Time, "mysql", "numeric");
    assert!(down < 1.0, "down={down}");
    assert!(down >= KNOWLEDGE_MIN_BOOST - 1e-12, "down={down}");
}

#[test]
fn boost_never_vetoes_scheduler_clamp() {
    assert!((clamp_knowledge_boost(10.0) - 2.0).abs() < 1e-12);
    assert!((clamp_knowledge_boost(0.01) - 0.5).abs() < 1e-12);
    for (s, t) in [(0, 100), (100, 100), (50, 100), (1, 10)] {
        let b = clamp_knowledge_range(boost_from_counts(s, t));
        assert!(
            (KNOWLEDGE_MIN_BOOST - 1e-12..=KNOWLEDGE_MAX_BOOST + 1e-12).contains(&b),
            "{b}"
        );
    }
}

#[test]
fn merge_fuses_counters_weighted_avg() {
    let mut a = KnowledgeStore::empty();
    a.record(TechniqueKind::Boolean, "mysql", "numeric", true, 10);
    let mut b = KnowledgeStore::empty();
    b.record(TechniqueKind::Boolean, "mysql", "numeric", false, 30);
    a.merge(&b);
    let key = KnowledgeKey::new(TechniqueKind::Boolean, "mysql", "numeric");
    let e = a.entries.get(&key).expect("merged");
    assert_eq!(e.trials, 2);
    assert_eq!(e.success, 1);
    assert!((e.avg_req - 20.0).abs() < 1e-9);
}

#[test]
fn file_roundtrip_and_off_creates_nothing() {
    // OFF : aucun accès disque (le caller ne doit même pas résoudre/écrire).
    assert_eq!(
        load_if_enabled(false, Some("/nonexistent-knowledge-off.json")),
        None
    );
    let delta = KnowledgeStore::empty();
    let wrote =
        save_delta_if_enabled(&delta, false, Some("/nonexistent-knowledge-off.json")).expect("off");
    assert!(!wrote);
    assert!(!std::path::Path::new("/nonexistent-knowledge-off.json").exists());
}

#[test]
fn save_sets_0600_and_loads_back() {
    let mut ks = KnowledgeStore::empty();
    for _ in 0..12 {
        ks.record(TechniqueKind::Union, "postgres", "generic", true, 14);
    }
    let dir = std::env::temp_dir().join(format!("injekt-k-{}", rand::random::<u64>()));
    let path = dir.join("knowledge.json");
    ks.save_to(&path).expect("save");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let mode = std::fs::metadata(&path).expect("meta").mode() & 0o777;
        assert_eq!(mode, 0o600, "perms={mode:o}");
    }
    let back = KnowledgeStore::load_from(&path).expect("load");
    let key = KnowledgeKey::new(TechniqueKind::Union, "postgres", "generic");
    assert_eq!(back.entries.get(&key), ks.entries.get(&key));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn file_contains_no_target_or_secret() {
    let mut ks = KnowledgeStore::empty();
    ks.record(TechniqueKind::Boolean, "mysql", "numeric", true, 11);
    let json = ks.to_file_string();
    // Vocabulaire fermé uniquement : aucune URL/host/param/seed/secret.
    for needle in [
        "http",
        "://",
        "example.com",
        "127.0.0.1",
        "localhost",
        "id@query",
        "id=",
        "cookie",
        "bearer",
        "authorization",
        "seed",
        "BEGIN PRIVATE",
    ] {
        assert!(
            !json.to_ascii_lowercase().contains(needle),
            "leak {needle}: {json}"
        );
    }
    // Scrubber redondant : no-op sur un fichier sain.
    let sc = Scrubber::new(false);
    assert_eq!(sc.scrub(&json), json);
}

#[test]
fn learn_from_run_records_only_aggregates() {
    use crate::session::state::Finding;
    let mut ks = KnowledgeStore::empty();
    let findings = vec![Finding::new(
        "http://example.com/?id=1",
        "id@query",
        TechniqueKind::Boolean,
        0.9,
        "evidence Authorization: Bearer SECRET",
    )];
    learn_from_run(&mut ks, &findings, &["all".to_owned()], Some("mysql"), 70);
    // 12 techniques => 12 clés, la gagnante en succès.
    assert_eq!(ks.len(), 12);
    let win = KnowledgeKey::new(TechniqueKind::Boolean, "mysql", "generic");
    assert_eq!(ks.entries.get(&win).map(|e| e.success), Some(1));
    let lose = KnowledgeKey::new(TechniqueKind::Time, "mysql", "generic");
    assert_eq!(lose.flattened(), "time|mysql|generic");
    assert_eq!(ks.entries.get(&lose).map(|e| e.success), Some(0));
    // Aucune trace de la cible/du secret dans le store sérialisé.
    let json = ks.to_file_string();
    assert!(!json.contains("example.com"), "{json}");
    assert!(!json.contains("Bearer"), "{json}");
    assert!(!json.contains("id@query"), "{json}");
}

#[test]
fn resolve_prefers_explicit_then_env() {
    let p = resolve_knowledge_path(Some("/tmp/custom-k.json"));
    assert_eq!(p, PathBuf::from("/tmp/custom-k.json"));
}

#[test]
fn context_class_mapping() {
    assert_eq!(context_class_for(&ctx_numeric()), "numeric");
    let mut c = InjectionContext::new();
    c.json = true;
    assert_eq!(context_class_for(&c), "json");
    let mut o = InjectionContext::new();
    o.order_by = true;
    assert_eq!(context_class_for(&o), "order_by");
    assert_eq!(context_class_for(&InjectionContext::new()), "generic");
}

#[test]
fn scheduled_boost_none_when_disabled() {
    assert_eq!(
        scheduled_boost_for(None, TechniqueKind::Boolean, "mysql", &ctx_numeric()),
        None
    );
    let ks = KnowledgeStore::empty();
    assert_eq!(
        scheduled_boost_for(Some(&ks), TechniqueKind::Boolean, "mysql", &ctx_numeric()),
        Some(1.0)
    );
}

#[test]
fn missing_file_is_cold_start_neutral() {
    // v1.0-rc: fichier absent (premier run opt-in) → `Ok(vide)` neutre,
    // jamais d'erreur surfacing vers l'orchestrateur.
    let dir = std::env::temp_dir().join(format!("injekt-k-missing-{}", rand::random::<u64>()));
    let path = dir.join("knowledge.json");
    assert!(!path.exists());
    let store = KnowledgeStore::load_from(&path).expect("missing -> empty");
    assert!(store.is_empty());
    for kind in all_techniques() {
        assert!((store.boost_for(kind, "mysql", "numeric") - 1.0).abs() < 1e-12);
    }
    // Porte opt-in ON + fichier absent → `Some(vide)` (pas de création).
    let explicit = path.to_string_lossy().into_owned();
    let loaded = load_if_enabled(true, Some(&explicit)).expect("missing -> neutral");
    assert!(loaded.is_empty());
    assert!(!path.exists(), "load must not create the file");
}

#[test]
fn normalize_dbms_covers_sqlite() {
    // P0-3: `sqlite` is a first-class DBMS label (was: `unknown`, which
    // collapsed SQLite learning into the generic bucket).
    assert_eq!(normalize_dbms("sqlite"), "sqlite");
    assert_eq!(normalize_dbms("  SQLITE "), "sqlite");
    assert_eq!(normalize_dbms("pg"), "postgres");
    assert_eq!(normalize_dbms("nope"), "unknown");
}

#[test]
fn evil_dbms_and_context_never_persisted() {
    // `record` normalise vers le vocabulaire fermé : une valeur
    // d'appel malicieuse (URL, token, cookie) devient `unknown`/`generic`
    // et n'atteint jamais le fichier.
    let mut ks = KnowledgeStore::empty();
    ks.record(
        TechniqueKind::Boolean,
        "http://evil.local/?token=fakesecret123",
        "id@query; Cookie: sess=fakesess999",
        true,
        11,
    );
    // 12 essais pour sortir du cold-start et rendre le boost observable.
    for _ in 0..11 {
        ks.record(
            TechniqueKind::Boolean,
            "http://evil.local/?token=fakesecret123",
            "id@query",
            true,
            11,
        );
    }
    let json = ks.to_file_string();
    for needle in [
        "evil.local",
        "fakesecret123",
        "fakesess999",
        "http",
        "://",
        "id@query",
        "cookie",
        "token=",
        "oastify",
        "password",
    ] {
        assert!(
            !json.to_ascii_lowercase().contains(needle),
            "leak {needle}: {json}"
        );
    }
    // La clé normalisée existe (`unknown`/`generic`), le boost est borné.
    let boost = ks.boost_for(TechniqueKind::Boolean, "unknown", "generic");
    assert!(boost > 1.0, "boost={boost}");
    assert!(boost <= KNOWLEDGE_MAX_BOOST + 1e-12, "boost={boost}");
    let sc = Scrubber::new(false);
    assert_eq!(sc.scrub(&json), json);
}
