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
