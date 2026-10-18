#![allow(clippy::unwrap_used, clippy::expect_used)]
//! C15 — tests `injekt doctor` : état local, exit code, et surtout la règle
//! OPSEC **zéro socket** au niveau end-to-end.
//!
//! Règle OPSEC du plan (§3) : ce fichier ne démarre JAMAIS de serveur
//! wiremock. Le « tripwire » du test socket est un simple `TcpListener` OS
//! jamais accepté : si le binaire ouvrait une connexion, le kernel la
//! placerait dans le backlog (handshake complété côté OS) et l'`accept`
//! final ne retournerait pas `WouldBlock`. Toute IO réseau du doctor est
//! une régression OPSEC visible.

use clap::Parser as _;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicUsize, Ordering};

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn temp_toml(tag: &str, content: &str) -> PathBuf {
    let name = format!(
        "injekt-doctor-it-{tag}-{}-{}.toml",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst),
    );
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, content).expect("write temp config");
    path
}

/// Lance le binaire réel `injekt --config <TOML> doctor [extra]` avec
/// l'environnement vidé : aucun `INJEKT_*`, aucun `RUST_LOG` — le
/// `Cli::parse` de l'enfant est totalement déterministe.
fn doctor_command(config_toml: &str, extra: &[&str]) -> (PathBuf, Command) {
    let config = temp_toml("run", config_toml);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_injekt"));
    cmd.arg("--config")
        .arg(config.to_string_lossy().as_ref())
        .arg("doctor");
    for e in extra {
        cmd.arg(e);
    }
    // Aucune variable héritée : l'invocation est déterministe même hors
    // harnais contrôlé (le `Cli::parse` ne voit aucun INJEKT_*).
    cmd.env_clear();
    (config, cmd)
}

fn cleanup(path: &PathBuf) {
    std::fs::remove_file(path).ok();
}

// ---------------------------------------------------------------------------
// lib-level : `doctor::run` → ExitCode (config saine → 0, socks5:// → 1)
// ---------------------------------------------------------------------------

async fn lib_doctor(config_toml: &str) -> (PathBuf, ExitCode) {
    let config = temp_toml("lib", config_toml);
    let cli = injekt::cli::args::Cli::try_parse_from([
        "injekt",
        "--config",
        config.to_string_lossy().as_ref(),
        "doctor",
    ])
    .expect("cli parses");
    let code = injekt::cli::commands::doctor::run(&cli)
        .await
        .expect("doctor run never errors today");
    (config, code)
}

#[tokio::test]
async fn doctor_run_healthy_config_is_success() {
    let (config, code) = lib_doctor(
        "threads = 2\nrate_limit = 3.0\njitter = \"1200,400\"\n\
         proxy = \"socks5h://127.0.0.1:9050\"\n",
    )
    .await;
    assert_eq!(code, ExitCode::SUCCESS);
    cleanup(&config);
}

#[tokio::test]
async fn doctor_run_socks5_leak_is_failure() {
    let (config, code) = lib_doctor("proxy = \"socks5://127.0.0.1:9050\"\n").await;
    assert_eq!(code, ExitCode::FAILURE);
    cleanup(&config);
}

#[tokio::test]
async fn doctor_run_broken_toml_is_failure() {
    let (config, code) = lib_doctor("threads = \"many\"\n").await;
    assert_eq!(code, ExitCode::FAILURE);
    cleanup(&config);
}

// ---------------------------------------------------------------------------
// e2e (binaire réel) : 4 lignes, exit code, et — surtout — 0 socket
// ---------------------------------------------------------------------------

#[test]
fn doctor_binary_healthy_no_socket_and_clean_lines() {
    // Tripwire OS : listener ouvert, jamais accepté. Le proxy configuré
    // pointe dessus — schéma `socks5h://` valide, doctor = parse only :
    // TOUTE tentative de connexion du doctor aboutirait dans le backlog et
    // ferait échouer l'`accept → WouldBlock` final.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tripwire");
    let port = listener.local_addr().expect("addr").port();

    let (config, mut cmd) = doctor_command(
        &format!("threads = 2\nproxy = \"socks5h://127.0.0.1:{port}\"\n"),
        &[],
    );
    let out = cmd.output().expect("doctor binary runs");
    cleanup(&config);

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "exit attendu 0 — stdout:\n{stdout}");
    // Les 4 checks, chacun une ligne (stdout pipé → pas de couleur, les
    // symboles restent).
    for prefix in ["✓ config:", "✓ proxy:", "✓ cadence:", "✓ ingestion:"] {
        assert!(
            stdout.contains(prefix),
            "ligne `{prefix}` manquante — stdout:\n{stdout}"
        );
    }
    // Déterminisme d'ordre : config puis proxy puis cadence puis ingestion.
    let pos = |p: &str| {
        stdout
            .lines()
            .position(|l| l.contains(p))
            .unwrap_or_else(|| panic!("ligne {p} absente — stdout:\n{stdout}"))
    };
    assert!(pos("✓ config:") < pos("✓ proxy:"));
    assert!(pos("✓ proxy:") < pos("✓ cadence:"));
    assert!(pos("✓ cadence:") < pos("✓ ingestion:"));
    // Purity : tout early-branch, tracing jamais initialisé, pas de
    // banner, pas de branche d'erreurs `main` (stdout restant pur).
    assert!(!stdout.contains("[INFO]"), "stdout:\n{stdout}");
    assert!(!stdout.contains("[WARNING]"), "stdout:\n{stdout}");
    assert!(!stdout.contains("Error:"), "stdout:\n{stdout}");
    // Le proxy est relayé sans jamais exposer d'userinfo…
    assert!(!stdout.contains("user@"), "stdout:\n{stdout}");
    // …et explicitement marqué « sans connexion » (check statique only).
    assert!(stdout.contains("sans connexion"), "stdout:\n{stdout}");

    listener
        .set_nonblocking(true)
        .expect("nonblocking tripwire");
    match listener.accept() {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {} // attendu : 0 socket
        Err(e) => panic!("accept inattendu ({e}) — OPSEC : socket ouverte par le doctor"),
        Ok((_, addr)) => panic!("OPSEC : le doctor a ouvert une socket vers {addr}"),
    }
}

#[test]
fn doctor_binary_socks5_fails_exit_one_with_leak_message() {
    let (config, mut cmd) = doctor_command("proxy = \"socks5://127.0.0.1:9050\"\n", &[]);
    let out = cmd.output().expect("doctor binary runs");
    cleanup(&config);

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "exit 1 attendu — stdout:\n{stdout}"
    );
    assert!(stdout.contains("✗ proxy:"), "stdout:\n{stdout}");
    // Message `DnsLeak` existant, inchangé (aucun ré-écriture maison).
    assert!(
        stdout.contains("socks5 without remote DNS (socks5://) leaks DNS — use socks5h://"),
        "stdout:\n{stdout}"
    );
    // Purity stdout : la branche d'erreur `main` n'a jamais été frappée.
    assert!(!stdout.contains("Error:"), "stdout:\n{stdout}");
}

#[test]
fn doctor_binary_missing_ingestion_paths_fail() {
    let (config, mut cmd) = doctor_command("threads = 2\n", &[]);
    cmd.arg("--bulk-file")
        .arg("/tmp/injekt-doctor-absent-bulk.txt")
        .arg("--raw-file")
        .arg("/tmp/injekt-doctor-absent-raw.txt");
    let out = cmd.output().expect("doctor binary runs");
    cleanup(&config);

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "stdout:\n{stdout}");
    assert!(stdout.contains("✗ ingestion:"), "stdout:\n{stdout}");
    assert!(stdout.contains("introuvable"), "stdout:\n{stdout}");
    // Le reste des checks reste sain : config ✓, ingestion ✗.
    assert!(stdout.contains("✓ config:"), "stdout:\n{stdout}");
}

#[test]
fn doctor_binary_toml_broken_fails_with_position() {
    let (config, mut cmd) = doctor_command("threads = \"many\"\n", &[]);
    let out = cmd.output().expect("doctor binary runs");
    cleanup(&config);

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "stdout:\n{stdout}");
    assert!(stdout.contains("✗ config:"), "stdout:\n{stdout}");
    // Le parse toml cite la ligne/colonne — pas de message maison.
    assert!(
        stdout.contains("TOML parse error at line 1"),
        "stdout:\n{stdout}"
    );
}
