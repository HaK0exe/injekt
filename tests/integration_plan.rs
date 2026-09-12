#![allow(clippy::unwrap_used, clippy::expect_used)]

//! C11 Developer Experience: `--dry-run` 0 requête, MCP `plan` sans exfil,
//! plan déterministe à seed identique.
//!
//! Tous les chemins testés sont offline par construction (lexical + contexte
//! passif + scores scheduler) : les mocks `wiremock` servent de compteurs
//! (0 hit attendu), jamais d'oracle.

use serde_json::{Value, json};
use tokio::io::AsyncBufReadExt as _;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

async fn mcp_send(stdin: &mut tokio::process::ChildStdin, payload: &Value) {
    use tokio::io::AsyncWriteExt as _;
    let mut line = serde_json::to_string(payload).expect("serialize");
    line.push('\n');
    stdin.write_all(line.as_bytes()).await.expect("write");
    stdin.flush().await.expect("flush");
}

async fn mcp_recv(
    lines: &mut tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
) -> Value {
    let line = tokio::time::timeout(std::time::Duration::from_secs(30), lines.next_line())
        .await
        .expect("timeout")
        .expect("read")
        .expect("line");
    serde_json::from_str(&line).expect("json")
}

/// `--dry-run` global (scan): exit 0, plan non vide, 0 requête.
#[tokio::test]
async fn dry_run_scan_sends_zero_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("hello"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_injekt"))
        .args([
            "--target",
            &target,
            "--dry-run",
            "--allow-private",
            "--no-banner",
            "--seed",
            "42",
        ])
        .output()
        .await
        .expect("run injekt --dry-run");
    assert!(
        out.status.success(),
        "exit 0 attendu, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("dry-run"), "{stdout}");
    assert!(
        stdout.contains("ordered probes"),
        "plan non vide attendu: {stdout}"
    );
    assert!(stdout.contains("boolean"), "{stdout}");
    assert!(stdout.contains("seed=42"), "{stdout}");
    assert!(stdout.contains("0 requ"), "{stdout}");
    let received = server.received_requests().await.expect("requests log");
    assert!(
        received.is_empty(),
        "--dry-run doit envoyer 0 requête, {} hits",
        received.len()
    );
}

/// `--dry-run` recon scan: exit 0, plan affiché, 0 requête.
#[tokio::test]
async fn dry_run_recon_scan_sends_zero_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("hello"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_injekt"))
        .args([
            "recon",
            "scan",
            "--target",
            &target,
            "--depth",
            "1",
            "--max-pages",
            "2",
            "--dry-run",
            "--allow-private",
            "--no-banner",
        ])
        .output()
        .await
        .expect("run injekt recon scan --dry-run");
    assert!(
        out.status.success(),
        "exit 0 attendu, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("dry-run"), "{stdout}");
    assert!(stdout.contains("recon"), "{stdout}");
    assert!(stdout.contains("0 requ"), "{stdout}");
    let received = server.received_requests().await.expect("requests log");
    assert!(
        received.is_empty(),
        "recon --dry-run doit envoyer 0 requête, {} hits",
        received.len()
    );
}

/// Plan offline déterministe à seed identique (lib, 0 requête).
#[test]
fn plan_is_deterministic_for_same_seed() {
    use injekt::{cli::plan::build_plan, engine::EngineConfig};
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg.seed = Some(42);
    let other = cfg.clone();
    let first = build_plan("http://example.com/?id=1", &cfg).expect("plan");
    let second = build_plan("http://example.com/?id=1", &other).expect("plan");
    assert!(!first.is_empty(), "plan non vide attendu");
    assert_eq!(first.ordered, second.ordered, "même seed => même ordre");
    assert_eq!(first.budget_spent, 0);
    assert!(first.dry_run);
}

/// MCP `plan` : 0 requête, plan non vide, aucun cookie/token en sortie.
#[tokio::test]
async fn mcp_plan_has_no_exfil_and_zero_requests() {
    use std::process::Stdio;
    use tokio::io::BufReader;

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("hello"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let secret = "sess=supersecret_cookie_abc123";

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_injekt"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn injekt mcp");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut lines = BufReader::new(stdout).lines();

    mcp_send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "plan-test", "version": "0"}},
        }),
    )
    .await;
    let _ = mcp_recv(&mut lines).await;
    mcp_send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    mcp_send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "plan", "arguments": {
                "target": target, "allow_private": true,
                "cookies": secret, "seed": 42,
            }},
        }),
    )
    .await;
    let res = mcp_recv(&mut lines).await;
    assert_eq!(res["result"]["isError"], false, "{res}");
    let text = res["result"]["content"][0]["text"]
        .as_str()
        .expect("text content")
        .to_owned();
    assert!(
        !text.contains("supersecret_cookie_abc123"),
        "exfil cookie dans MCP plan: {text}"
    );
    let plan: Value = serde_json::from_str(&text).expect("plan json");
    let ordered = plan["ordered"].as_array().expect("ordered array");
    assert!(!ordered.is_empty(), "plan non vide: {plan}");
    assert_eq!(plan["requests_sent"], 0);
    assert_eq!(plan["dry_run"], true);
    let _ = child.start_kill();
    let received = server.received_requests().await.expect("requests log");
    assert!(
        received.is_empty(),
        "MCP plan doit envoyer 0 requête, {} hits",
        received.len()
    );
}

/// MCP `explain` offline : verdict une ligne, 0 requête, secret scrubbé.
#[tokio::test]
async fn mcp_explain_is_offline_and_scrubbed() {
    use std::process::Stdio;
    use tokio::io::BufReader;

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_injekt"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn injekt mcp");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut lines = BufReader::new(stdout).lines();

    mcp_send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "explain-test", "version": "0"}},
        }),
    )
    .await;
    let _ = mcp_recv(&mut lines).await;
    mcp_send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    mcp_send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "explain", "arguments": {
                "param": "id@query",
                "evidence": "boolean true_sim=0.91 false_sim=0.22 trials=3/3",
                "confidence": 0.95, "requests": 14, "seed": 42,
            }},
        }),
    )
    .await;
    let res = mcp_recv(&mut lines).await;
    assert_eq!(res["result"]["isError"], false, "{res}");
    let text = res["result"]["content"][0]["text"]
        .as_str()
        .expect("text content")
        .to_owned();
    let out: Value = serde_json::from_str(&text).expect("explain json");
    let line = out["explain"].as_str().expect("explain line");
    assert!(line.contains("TRUE"), "{line}");
    assert!(line.contains("14 req"), "{line}");
    assert!(line.contains("seed 42"), "{line}");
    assert_eq!(out["requests_sent"], 0);
    let _ = child.start_kill();
}
