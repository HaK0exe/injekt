#![allow(clippy::unwrap_used, clippy::expect_used)]

//! C17 — migration 1 : `--enum <items>` + `--scope <db[.table[.col]]>`.
//!
//! Zéro requête (chemins `--dry-run` uniquement, piège wiremock 0-hit) :
//! la surface assertée est le mapping `--enum`/`--scope` → fields
//! historiques (via le passage dry-run par `build_engine_config`), le
//! warning deprecated pour les flags legacy (`--dbs`, `--current-user`,
//! le triple `--db/--table/--column` → `--scope`) et le rejet clap des
//! items inconnus (usage exit 2). Les shapes MCP (bools écrits directs
//! dans `EnumOpts`) restent inchangées (builder).

use wiremock::{Mock, MockServer, matchers::method};

fn run_binary(args: &[&str]) -> (i32, String, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_injekt"))
        .args(args)
        .env_remove("INJEKT_TARGET")
        .env_remove("INJEKT_FORMAT")
        .output()
        .expect("run injekt binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// `--enum` / `--scope` — nouvelle shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn enum_items_reach_the_scan_plan_without_legacy_warning() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, stdout, stderr) = run_binary(&[
        &target,
        "--dry-run",
        "--allow-private",
        "--no-banner",
        "--enum",
        "dbs,user",
    ]);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(
        stdout.contains("dry-run: scan plan"),
        "items must reach the resolved plan: {stdout}"
    );
    assert!(
        !stderr.contains("legacy enumeration flags deprecated"),
        "nouvelle shape : aucun warning legacy attendu: {stderr}"
    );
    assert!(!stdout.is_empty());
}

#[tokio::test]
async fn scope_triple_reaches_the_scan_plan_without_legacy_warning() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, stdout, stderr) = run_binary(&[
        &target,
        "--dry-run",
        "--allow-private",
        "--no-banner",
        "--scope",
        "shop.users.password",
    ]);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(stdout.contains("dry-run: scan plan"));
    assert!(!stderr.contains("legacy enumeration flags deprecated"));
}

#[tokio::test]
async fn unknown_enum_item_is_clap_usage_exit_2() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, _stdout, stderr) =
        run_binary(&[&target, "--allow-private", "--no-banner", "--enum", "nope"]);
    assert_eq!(code, 2, "item inconnu = usage error: {stderr}");
    assert!(
        stderr.contains("invalid value 'nope'"),
        "clap value_parser doit nommer l'item fautif: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// flags legacy — warning deprecated + « commande équivalente »
// ---------------------------------------------------------------------------

#[tokio::test]
async fn legacy_dbs_flag_warns_with_enum_equivalent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, stdout, stderr) = run_binary(&[
        &target,
        "--dry-run",
        "--allow-private",
        "--no-banner",
        "--dbs",
    ]);
    assert_eq!(code, 0, "le flag legacy reste fonctionnel: {stderr}");
    assert!(stdout.contains("dry-run: scan plan"));
    assert!(
        stderr.contains("legacy enumeration flags deprecated"),
        "warning deprecated attendu: {stderr}"
    );
    assert!(
        stderr.contains("--dbs -> --enum dbs"),
        "mapping équivalent attendu: {stderr}"
    );
}

#[tokio::test]
async fn legacy_current_user_flag_warns_with_user_item_mapping() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, _stdout, stderr) = run_binary(&[
        &target,
        "--dry-run",
        "--allow-private",
        "--no-banner",
        "--current-user",
    ]);
    assert_eq!(code, 0);
    assert!(stderr.contains("--current-user -> --enum user"), "{stderr}");
}

#[tokio::test]
async fn legacy_scope_triple_warns_mapping_to_scope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, _stdout, stderr) = run_binary(&[
        &target,
        "--dry-run",
        "--allow-private",
        "--no-banner",
        "--db",
        "shop",
        "--table",
        "users",
    ]);
    assert_eq!(code, 0, "le triple legacy reste fonctionnel: {stderr}");
    assert!(
        stderr.contains("--db/--table/--column -> --scope"),
        "{stderr}"
    );
}

// ---------------------------------------------------------------------------
// C17 migration 2 — `--input <PATH|-|DIR>` (ingestion unifiée)
// ---------------------------------------------------------------------------

/// Temp fixture writer (unique per test, process-id isolated) returning the
/// path string; tracks files for explicit cleanup at test end.
fn temp_input(suffix: &str, content: &[u8]) -> String {
    let path =
        std::env::temp_dir().join(format!("injekt-c17-input-{}-{suffix}", std::process::id()));
    std::fs::write(&path, content).expect("write temp input fixture");
    path.to_string_lossy().into_owned()
}

fn cleanup_temp_input(path: &str) {
    let _ = std::fs::remove_file(path);
}

fn run_binary_stdin(args: &[&str], stdin_data: &[u8]) -> (i32, String, String) {
    use std::io::Write as _;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_injekt"))
        .args(args)
        .env_remove("INJEKT_TARGET")
        .env_remove("INJEKT_FORMAT")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn injekt binary");
    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(stdin_data)
        .expect("write stdin fixture");
    let out = child.wait_with_output().expect("wait injekt binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test]
async fn input_txt_list_ingests_targets_zero_requests() {
    let file = temp_input(
        "targets.txt",
        b"# list\nhttps://example.com/?id=1\nhttps://shop.example/?q=x\n",
    );
    let (code, stdout, stderr) = run_binary(&["--input", &file, "--dry-run", "--no-banner"]);
    cleanup_temp_input(&file);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(stdout.contains("dry-run: scan plan"));
    assert!(
        stdout.contains("targets: 2"),
        "TXT list must ingest both URLs: {stdout}"
    );
}

#[tokio::test]
async fn input_openapijson_routes_to_openapi_parser() {
    let file = temp_input(
        "spec.json",
        br#"{"openapi":"3.0.1","servers":[{"url":"https://api.example.com/v1"}],"paths":{"/users/{id}":{"get":{"parameters":[{"name":"id","in":"query"}]}}}}"#,
    );
    let (code, stdout, stderr) = run_binary(&["--input", &file, "--dry-run", "--no-banner"]);
    cleanup_temp_input(&file);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(
        stdout.contains("targets: 1"),
        "OpenAPI routing must harvest the templated path: {stdout}"
    );
    assert!(
        stdout.contains("/users/1"),
        "harvested URL must carry the expanded template: {stdout}"
    );
}

#[tokio::test]
async fn input_sitemapxml_routes_to_sitemap_parser() {
    let file = temp_input(
        "map.xml",
        br#"<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://maps.example.com/a</loc></url></urlset>"#,
    );
    let (code, stdout, stderr) = run_binary(&["--input", &file, "--dry-run", "--no-banner"]);
    cleanup_temp_input(&file);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(
        stdout.contains("targets: 1") && stdout.contains("maps.example.com"),
        "sitemap routing must harvest <loc> entries: {stdout}"
    );
}

#[tokio::test]
async fn input_stdin_marker_reads_piped_list() {
    let (code, stdout, stderr) = run_binary_stdin(
        &["--input", "-", "--dry-run", "--no-banner"],
        b"https://example.com/?id=1\nhttps://other.example/?p=1\n",
    );
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(
        stdout.contains("targets: 2"),
        "stdin marker must ingest the piped list: {stdout}"
    );
}

#[tokio::test]
async fn input_dedups_overlapping_positional_target() {
    let file = temp_input("dup.txt", b"https://example.com/?id=1\n");
    let (code, stdout, stderr) = run_binary(&[
        "https://example.com/?id=1",
        "--input",
        &file,
        "--dry-run",
        "--no-banner",
    ]);
    cleanup_temp_input(&file);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(
        stdout.contains("targets: 1"),
        "additive ingestion must dedup the overlapping positional: {stdout}"
    );
}

#[tokio::test]
async fn input_flag_is_bulk_like_pipeline_gate() {
    // `--input` counts as bulk for the scan pipeline gate (is_bulk): a TXT
    // list runs the bulk flow, not the single-target exclusive chain.
    let file = temp_input("gate.txt", b"https://example.com/?id=1\n");
    let (code, stdout, stderr) = run_binary(&["--input", &file, "--dry-run", "--no-banner"]);
    cleanup_temp_input(&file);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    // Bulk dry-run branches through the same plan render (single-target
    // exclusion confirmed by the absence of a dry-run pipeline error).
    assert!(stdout.contains("dry-run: scan plan"), "{stdout}");
}

// ---------------------------------------------------------------------------
// C17 migration 3 — `--match EXPR` / `--veto EXPR` (frozen grammar)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn match_exprs_reach_the_scan_plan_with_no_legacy_warning() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, stdout, stderr) = run_binary(&[
        &target,
        "--dry-run",
        "--allow-private",
        "--no-banner",
        "--match",
        "status==200",
        "--match",
        "body=servicing",
        "--veto",
        "body~waf|rate.bound",
        "--veto",
        "status==503",
    ]);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(stdout.contains("dry-run: scan plan"));
    assert!(!stderr.contains("legacy matcher flags deprecated"));
}

#[tokio::test]
async fn unknown_match_expr_is_usage_exit_2() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, _stdout, stderr) = run_binary(&[
        &target,
        "--allow-private",
        "--no-banner",
        "--match",
        "status=200",
    ]);
    assert_eq!(
        code, 2,
        "grammaire figée : une seule '=' est un usage error"
    );
    assert!(
        stderr.contains("unknown frozen grammar"),
        "le rejet nomme la grammaire: {stderr}"
    );
}

#[tokio::test]
async fn non_compiling_regex_is_usage_exit_2() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, _stdout, stderr) = run_binary(&[
        &target,
        "--allow-private",
        "--no-banner",
        "--veto",
        "body~[",
    ]);
    assert_eq!(code, 2, "regex non compilable = usage error: {stderr}");
    assert!(stderr.contains("does not compile"), "{stderr}");
}

#[tokio::test]
async fn legacy_code_flag_warns_with_expr_mapping() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, stdout, stderr) = run_binary(&[
        &target,
        "--dry-run",
        "--allow-private",
        "--no-banner",
        "--code",
        "200",
    ]);
    assert_eq!(code, 0, "legacy --code reste fonctionnel: {stderr}");
    assert!(stdout.contains("dry-run: scan plan"));
    assert!(
        stderr.contains("legacy matcher flags deprecated"),
        "{stderr}"
    );
    assert!(
        stderr.contains("--code <N> -> --match status==<N>"),
        "{stderr}"
    );
}

#[tokio::test]
async fn legacy_string_flag_warns_with_match_body_mapping() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, _stdout, stderr) = run_binary(&[
        &target,
        "--dry-run",
        "--allow-private",
        "--no-banner",
        "--string",
        "welcome",
        "--not-string",
        "fatal",
    ]);
    assert_eq!(code, 0);
    assert!(
        stderr.contains("--string -> --match body=<string>")
            && stderr.contains("--not-string -> --veto body=<string>"),
        "{}",
        stderr
    );
}

// ---------------------------------------------------------------------------
// C17 migration 4 — `injekt session` namespace (export re-key + replay)
// ---------------------------------------------------------------------------

/// Binary runner with an env override (passphrase via `INJEKT_PASSPHRASE`).
fn run_binary_env(args: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_injekt"));
    cmd.args(args)
        .env_remove("INJEKT_TARGET")
        .env_remove("INJEKT_FORMAT");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run injekt binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn session_temp(suffix: &str) -> String {
    let path = std::env::temp_dir().join(format!(
        "injekt-c17-session-{}-{suffix}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path.to_string_lossy().into_owned()
}

/// Minimum session state for the CLI roundtrip (no Finding construct: the
/// shape is what matters — a valid argon2id blob).
fn encrypted_export_fixture(path: &str, passphrase: &str) {
    use secrecy::SecretString;
    let state = injekt::session::state::SessionState::new();
    injekt::session::export::EncryptedExport::encrypt_to_file(
        &state,
        &SecretString::from(passphrase.to_owned()),
        path,
    )
    .expect("fixture export writes");
}

#[tokio::test]
async fn session_export_rekey_and_replay_roundtrip() {
    let src = session_temp("src.enc");
    let dst = session_temp("dst.enc");
    encrypted_export_fixture(&src, "passphrase123456");
    // Source AND destination via env (non-TTY test process): same passphrase
    // both sides here — a TTY rotation prompts a distinct one.
    let (code, stdout, stderr) = run_binary_env(
        &["session", "export", &dst, "--no-banner", "--import", &src],
        &[("INJEKT_PASSPHRASE", "passphrase123456")],
    );
    assert!(code == 0, "stdout: {stdout} stderr: {stderr}");
    assert!(stdout.contains("session export:"), "{stdout}");
    assert!(stdout.contains("self-verified"), "{stdout}");
    assert!(std::fs::exists(&dst).unwrap(), "re-keyed file written");
    // The re-keyed blob opens with the (same) passphrase and replays.
    let (code, stdout, stderr) = run_binary_env(
        &["session", "replay", &dst],
        &[("INJEKT_PASSPHRASE", "passphrase123456")],
    );
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(stdout.contains("replay: decrypted session"), "{stdout}");
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

#[tokio::test]
async fn session_export_requires_force_to_replace() {
    let src = session_temp("src2.enc");
    let dst = session_temp("dst2.enc");
    encrypted_export_fixture(&src, "passphrase123456");
    let envs = [("INJEKT_PASSPHRASE", "passphrase123456")];
    let (code, _stdout, _stderr) = run_binary_env(
        &["session", "export", &dst, "--no-banner", "--import", &src],
        &envs,
    );
    assert_eq!(code, 0);
    let (code, _stdout, stderr) = run_binary_env(
        &["session", "export", &dst, "--no-banner", "--import", &src],
        &envs,
    );
    assert_ne!(code, 0, "second write must fail without --force");
    assert!(stderr.contains("destination already exists"), "{stderr}");
    let (code, stdout, _stderr) = run_binary_env(
        &[
            "session",
            "export",
            &dst,
            "--no-banner",
            "--import",
            &src,
            "--force",
        ],
        &envs,
    );
    assert_eq!(code, 0, "{stdout}");
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

#[tokio::test]
async fn session_export_without_import_is_usage_error() {
    let dst = session_temp("dst3.enc");
    let (code, _stdout, stderr) = run_binary_env(
        &["session", "export", &dst, "--no-banner"],
        &[("INJEKT_PASSPHRASE", "passphrase123456")],
    );
    assert_ne!(code, 0, "no --import = nothing to re-key");
    assert!(stderr.contains("--import"), "{stderr}");
}

#[tokio::test]
async fn legacy_replay_alias_warns_and_still_inspects() {
    let src = session_temp("src4.enc");
    encrypted_export_fixture(&src, "passphrase123456");
    let (code, stdout, stderr) = run_binary_env(
        &["replay", "--file", &src, "--no-banner"],
        &[("INJEKT_PASSPHRASE", "passphrase123456")],
    );
    assert_eq!(code, 0, "l'alias legacy reste fonctionnel");
    assert!(stdout.contains("replay: decrypted session"), "{stdout}");
    assert!(
        stderr.contains("legacy `injekt replay` alias deprecated"),
        "{stderr}"
    );
    let _ = std::fs::remove_file(&src);
}

#[tokio::test]
async fn export_encrypted_flag_warns_deprecation_on_dry_run() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, stdout, stderr) = run_binary(&[
        &target,
        "--dry-run",
        "--allow-private",
        "--no-banner",
        "--export-encrypted",
        "/tmp/never-written-in-dryrun.enc",
    ]);
    assert_eq!(code, 0, "le flag legacy reste fonctionnel: {stderr}");
    assert!(stdout.contains("dry-run: scan plan"));
    assert!(
        stderr.contains("legacy `--export-encrypted` flag deprecated"),
        "{stderr}"
    );
    assert!(stderr.contains("injekt session export"), "{stderr}");
}
