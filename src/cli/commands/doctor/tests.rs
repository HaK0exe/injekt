#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::config::resolve_config;
use super::*;
use crate::cli::args::Cli;
use crate::cli::file_config::FileConfig;
use crate::cli::profile::Profile;
use clap::Parser as _;
use std::path::PathBuf;

// ---- check_config -------------------------------------------------------

#[test]
fn config_absent_warns_defaults() {
    let r = check_config(&ConfigResolution::Absent { explicit: None }, None, 5);
    assert_eq!(r.level, CheckLevel::Warn);
    assert!(r.line.contains("aucun fichier config"), "{}", r.line);
    assert!(r.line.contains("défauts intégrés"), "{}", r.line);
}

#[test]
fn config_explicit_absent_mentions_flag() {
    let r = check_config(
        &ConfigResolution::Absent {
            explicit: Some("/tmp/nowhere.toml".to_owned()),
        },
        None,
        5,
    );
    assert_eq!(r.level, CheckLevel::Warn);
    assert!(r.line.contains("--config /tmp/nowhere.toml"), "{}", r.line);
}

#[test]
fn config_toml_broken_fails_with_parse_error() {
    let err = FileConfig::parse("threads = \"many\"\n").expect_err("erreur de type de clé");
    let r = check_config(
        &ConfigResolution::Broken {
            path: PathBuf::from("./injekt.toml"),
            error: err,
        },
        None,
        5,
    );
    assert_eq!(r.level, CheckLevel::Fail);
    assert!(r.line.contains("./injekt.toml"), "{}", r.line);
    // Le parse toml cite la position : « TOML parse error at line 1, … ».
    assert!(r.line.contains("TOML parse error"), "{}", r.line);
}

#[test]
fn config_found_summarizes_profile_and_threads() {
    let cfg = FileConfig::parse("profile = \"stealth\"\nthreads = 2\n").unwrap();
    let r = check_config(
        &ConfigResolution::Found {
            path: PathBuf::from("./injekt.toml"),
            cfg,
        },
        Some(Profile::Stealth),
        2,
    );
    assert_eq!(r.level, CheckLevel::Ok);
    assert!(r.line.contains("./injekt.toml"), "{}", r.line);
    assert!(r.line.contains("profil stealth (fichier)"), "{}", r.line);
    assert!(r.line.contains("threads 2"), "{}", r.line);
}

#[test]
fn config_unknown_profile_name_warns_silent_ignore() {
    let cfg = FileConfig {
        profile: Some("nouveau".to_owned()),
        ..FileConfig::default()
    };
    let r = check_config(
        &ConfigResolution::Found {
            path: PathBuf::from("./injekt.toml"),
            cfg,
        },
        None,
        5,
    );
    assert_eq!(r.level, CheckLevel::Warn);
    assert!(
        r.line.contains("preset fichier \"nouveau\" inconnu"),
        "{}",
        r.line
    );
    assert!(r.line.contains("ignoré au runtime"), "{}", r.line);
}

#[test]
fn config_cli_profile_overrides_file_with_note() {
    let cfg = FileConfig::parse("profile = \"stealth\"").unwrap();
    let r = check_config(
        &ConfigResolution::Found {
            path: PathBuf::from("./injekt.toml"),
            cfg,
        },
        Some(Profile::Quick),
        5,
    );
    assert_eq!(r.level, CheckLevel::Ok);
    // Le preset effectif est celui de la CLI, avec la mention d'écrasement.
    assert!(
        r.line
            .contains("profil quick (CLI, écrase « stealth » du fichier)"),
        "{}",
        r.line
    );
    assert!(!r.line.contains("profil stealth (fichier)"), "{}", r.line);
}

#[test]
fn config_no_profile_section_shows_builtin_default() {
    let cfg = FileConfig::parse("threads = 3\n").unwrap();
    let r = check_config(
        &ConfigResolution::Found {
            path: PathBuf::from("./injekt.toml"),
            cfg,
        },
        None,
        3,
    );
    assert_eq!(r.level, CheckLevel::Ok);
    assert!(
        r.line.contains("profil: aucun (défauts intégrés)"),
        "{}",
        r.line
    );
    assert!(r.line.contains("threads 3"), "{}", r.line);
}

#[test]
fn resolve_config_explicit_broken_toml_becomes_broken() {
    let path =
        std::env::temp_dir().join(format!("injekt-doctor-broken-{}.toml", std::process::id()));
    std::fs::write(&path, "threads = \"many\"\n").unwrap();
    let explicit = path.to_string_lossy().to_string();
    let res = resolve_config(Some(&explicit));
    std::fs::remove_file(&path).unwrap();
    match res {
        ConfigResolution::Broken { path: found, error } => {
            assert_eq!(found, path);
            assert!(error.contains("TOML parse error"), "{error}");
        }
        other => panic!("attendu Broken, obtenu {other:?}"),
    }
}

#[test]
fn resolve_config_explicit_valid_toml_becomes_found() {
    let path =
        std::env::temp_dir().join(format!("injekt-doctor-found-{}.toml", std::process::id()));
    std::fs::write(&path, "threads = 2\nproxy = \"http://127.0.0.1:8118\"\n").unwrap();
    let explicit = path.to_string_lossy().to_string();
    let res = resolve_config(Some(&explicit));
    std::fs::remove_file(&path).unwrap();
    match res {
        ConfigResolution::Found { path: found, cfg } => {
            assert_eq!(found, path);
            assert_eq!(cfg.threads, Some(2));
            assert_eq!(cfg.proxy.as_deref(), Some("http://127.0.0.1:8118"));
        }
        other => panic!("attendu Found, obtenu {other:?}"),
    }
}

// ---- check_proxy --------------------------------------------------------

#[test]
fn proxy_absent_warns_optin() {
    let r = check_proxy(None);
    assert_eq!(r.level, CheckLevel::Warn);
    assert!(r.line.contains("proxy: aucun"), "{}", r.line);
}

#[test]
fn proxy_socks5_fails_with_dns_leak_message() {
    let r = check_proxy(Some("socks5://127.0.0.1:9050"));
    assert_eq!(r.level, CheckLevel::Fail);
    // Message EXACT de `ProxyError::DnsLeak` — jamais dupliqué.
    assert!(
        r.line
            .contains("socks5 without remote DNS (socks5://) leaks DNS — use socks5h://"),
        "{}",
        r.line
    );
    assert!(
        r.line.contains("[valeur: socks5://127.0.0.1:9050]"),
        "{}",
        r.line
    );
}

#[test]
fn proxy_socks5h_ok_and_userinfo_redacted() {
    let r = check_proxy(Some("socks5h://user:secret123@127.0.0.1:9050"));
    assert_eq!(r.level, CheckLevel::Ok);
    assert!(r.line.contains("SOCKS5h"), "{}", r.line);
    assert!(
        r.line.contains("socks5h://[REDACTED]@127.0.0.1:9050"),
        "{}",
        r.line
    );
    // Aucun secret en clair dans la ligne de sortie.
    assert!(!r.line.contains("secret123"), "{}", r.line);
    assert!(!r.line.contains(":user@"), "{}", r.line);
}

#[test]
fn proxy_http_ok() {
    let r = check_proxy(Some("http://127.0.0.1:8118"));
    assert_eq!(r.level, CheckLevel::Ok);
    assert!(r.line.contains("HTTP(S)"), "{}", r.line);
    assert!(r.line.contains("sans connexion"), "{}", r.line);
}

// ---- check_cadence --------------------------------------------------------

#[test]
fn cadence_incoherent_warns_with_numbers_and_fix() {
    // 10 rps → 100ms ; jitter «2000,500» → plancher 2σ = 1000ms.
    let r = check_cadence(10.0, true, "2000,500", true, None);
    assert_eq!(r.level, CheckLevel::Warn);
    assert!(r.line.contains("100ms"), "{}", r.line);
    assert!(r.line.contains("1000ms"), "{}", r.line);
    assert!(r.line.contains("pattern détectable"), "{}", r.line);
    // Correction chiffrée : rate max cohérent = 1000/1000 = 1.
    assert!(r.line.contains("--rate-limit 1"), "{}", r.line);
}

#[test]
fn cadence_coherent_ok_at_boundary() {
    // rate 1 → 1000ms ≥ plancher 2σ 1000ms (borne incluse par la règle).
    let r = check_cadence(1.0, true, "2000,500", true, None);
    assert_eq!(r.level, CheckLevel::Ok);
    assert!(r.line.contains("≥"), "{}", r.line);
    assert!(r.line.contains("cohérent"), "{}", r.line);
}

#[test]
fn cadence_neutral_when_nothing_explicit() {
    // Pas de rate explicite ET pas de profil ⇒ check neutre.
    let r = check_cadence(10.0, false, "750,250", false, None);
    assert_eq!(r.level, CheckLevel::Ok);
    assert!(r.line.contains("neutre"), "{}", r.line);
    assert!(!r.line.contains("--rate-limit"), "{}", r.line);
}

#[test]
fn cadence_jitter_garbage_warns_default_fallback() {
    let r = check_cadence(10.0, true, "vite", true, None);
    assert_eq!(r.level, CheckLevel::Warn);
    assert!(r.line.contains("jitter \"vite\" invalide"), "{}", r.line);
    assert!(r.line.contains("750,250"), "{}", r.line);
}

#[test]
fn cadence_profile_driven_incoherent_with_numbers() {
    // Profil stealth seul (valeurs effectives du preset) : 3 rps →
    // 333ms < 1200−2×400=400ms ⇒ Warn chiffré, règle figée (§3) sans
    // exception dédiée.
    let r = check_cadence(3.0, false, "1200,400", false, Some(Profile::Stealth));
    assert_eq!(r.level, CheckLevel::Warn);
    assert!(r.line.contains("333ms"), "{}", r.line);
    assert!(r.line.contains("400ms"), "{}", r.line);
    assert!(r.line.contains("pattern détectable"), "{}", r.line);
}

#[test]
fn cadence_rate_zero_warns_runtime_clamp() {
    let r = check_cadence(0.0, true, "750,250", true, None);
    assert_eq!(r.level, CheckLevel::Warn);
    assert!(r.line.contains("0.1 rps"), "{}", r.line);
}

#[test]
fn parse_jitter_pair_matches_jitter_from_str_leniency() {
    assert_eq!(parse_jitter_pair("2000,500"), Some((2000.0, 500.0)));
    assert_eq!(parse_jitter_pair("  2000 , 500 "), Some((2000.0, 500.0)));
    // Tokens non numériques filtrés comme au runtime `jitter_from_str`.
    assert_eq!(parse_jitter_pair("abc,750"), None);
    assert_eq!(parse_jitter_pair("750"), None);
    assert_eq!(parse_jitter_pair("nan,250"), None);
    assert_eq!(parse_jitter_pair("750,inf"), None);
}

// ---- check_ingestion ---------------------------------------------------------

fn item(flag: &'static str, raw: &str, dir: bool, state: SourceState) -> SourceItem {
    SourceItem {
        flag,
        raw: raw.to_owned(),
        expects_dir: dir,
        state,
    }
}

#[test]
fn ingestion_empty_ok_neutral() {
    let r = check_ingestion(&[]);
    assert_eq!(r.level, CheckLevel::Ok);
    assert!(r.line.contains("aucune source"), "{}", r.line);
}

#[test]
fn ingestion_two_paths_one_missing_fails() {
    let r = check_ingestion(&[
        item("raw-file", "/tmp/req-burp.txt", false, SourceState::File),
        item(
            "bulk-file",
            "/tmp/not/there.txt",
            false,
            SourceState::Missing,
        ),
    ]);
    assert_eq!(r.level, CheckLevel::Fail);
    assert!(r.line.contains("1/2 sources OK"), "{}", r.line);
    assert!(
        r.line
            .contains("--bulk-file=/tmp/not/there.txt : introuvable"),
        "{}",
        r.line
    );
}

#[test]
fn ingestion_type_mismatch_warns_but_does_not_fail() {
    let r = check_ingestion(&[item(
        "raw-dir",
        "/tmp/somewhere.txt",
        true,
        SourceState::File,
    )]);
    assert_eq!(r.level, CheckLevel::Warn);
    assert!(r.line.contains("fichier (dossier attendu)"), "{}", r.line);
}

#[test]
fn ingestion_stdin_alias_is_fine() {
    let r = check_ingestion(&[
        item("bulk-file", "-", false, SourceState::Stdin),
        item("raw-file", "/tmp/x.txt", false, SourceState::File),
    ]);
    assert_eq!(r.level, CheckLevel::Ok);
    assert!(r.line.contains("--bulk-file (stdin)"), "{}", r.line);
    assert!(r.line.contains("2/2 sources"), "{}", r.line);
}

#[test]
fn collect_ingestion_maps_metadata_only() {
    let stamp = format!("injekt-doctor-ingest-{}", std::process::id());
    let real = std::env::temp_dir().join(format!("{stamp}-real.txt"));
    let missing = std::env::temp_dir().join(format!("{stamp}-missing.txt"));
    std::fs::write(&real, "https://lab.example.test/?id=1\n").unwrap();
    let cli = Cli::try_parse_from([
        "injekt",
        "--raw-file",
        real.to_string_lossy().as_ref(),
        "--bulk-file",
        missing.to_string_lossy().as_ref(),
    ])
    .expect("cli parses");
    let items = collect_ingestion_sources(&cli);
    std::fs::remove_file(&real).unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].state, SourceState::Missing);
    assert_eq!(items[0].flag, "bulk-file");
    assert_eq!(items[1].state, SourceState::File);
    assert!(!items[1].expects_dir);
}

#[test]
fn collect_ingestion_stdin_alias() {
    let cli = Cli::try_parse_from(["injekt", "--bulk-file", "-"]).expect("cli parses");
    let items = collect_ingestion_sources(&cli);
    assert_eq!(items[0].state, SourceState::Stdin);
}

#[test]
fn collect_ingestion_input_maps_file_dir_and_stdin() {
    // Alias stdin de la source unifiée.
    let cli = Cli::try_parse_from(["injekt", "--input", "-"]).expect("cli parses");
    let items = collect_ingestion_sources(&cli);
    assert_eq!(items[0].flag, "input");
    assert_eq!(items[0].state, SourceState::Stdin);

    // Fichier ET dossier : tous deux valides, `expects_dir` recalé sur
    // l'état réel (aucun Warn de type inversé possible pour `--input`).
    let stamp = format!("injekt-doctor-input-{}", std::process::id());
    let file = std::env::temp_dir().join(format!("{stamp}-file.txt"));
    let dir = std::env::temp_dir().join(format!("{stamp}-dir"));
    std::fs::write(&file, "https://lab.example.test/?id=1\n").unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    let file_str = file.to_string_lossy().into_owned();
    let dir_str = dir.to_string_lossy().into_owned();
    // `--input` est single-occurrence (parité options legacy) : deux parses
    // séparés pour le cas fichier et le cas dossier.
    let cli_file =
        Cli::try_parse_from(["injekt", "--input", file_str.as_str()]).expect("cli parses");
    let cli_dir = Cli::try_parse_from(["injekt", "--input", dir_str.as_str()]).expect("cli parses");
    let items = collect_ingestion_sources(&cli_file);
    let items_dir = collect_ingestion_sources(&cli_dir);
    std::fs::remove_file(&file).unwrap();
    std::fs::remove_dir(&dir).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].state, SourceState::File);
    assert!(!items[0].expects_dir);
    assert_eq!(items_dir.len(), 1);
    assert_eq!(items_dir[0].state, SourceState::Dir);
    assert!(items_dir[0].expects_dir);
}

#[test]
fn ingestion_input_accepts_file_and_dir_alike() {
    // `--input` : fichier et dossier rendus `good` tous deux (sniff).
    let r = check_ingestion(&[
        item("input", "/tmp/somewhere.txt", false, SourceState::File),
        item("input", "/tmp/somedir", true, SourceState::Dir),
    ]);
    assert_eq!(r.level, CheckLevel::Ok);
    assert!(
        r.line.contains("--input=/tmp/somewhere.txt") && r.line.contains("--input=/tmp/somedir"),
        "{}",
        r.line
    );
}

// ---- rendu -------------------------------------------------------------

#[test]
fn symbol_plain_without_colors() {
    assert_eq!(symbol(CheckLevel::Ok, false), "✓");
    assert_eq!(symbol(CheckLevel::Warn, false), "!");
    assert_eq!(symbol(CheckLevel::Fail, false), "✗");
}
