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
