#![allow(clippy::expect_used, clippy::unwrap_used)]

use serde_json::{Value, json};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// Minimal JSON-RPC-over-stdio client for `injekt mcp`.
struct McpPipe {
    child: Child,
    stdin: ChildStdin,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
}

impl McpPipe {
    fn spawn() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_injekt"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn injekt mcp");
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let lines = BufReader::new(stdout).lines();
        Self {
            child,
            stdin,
            lines,
        }
    }

    async fn send(&mut self, payload: &Value) {
        let mut line = serde_json::to_string(payload).expect("serialize request");
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write stdin");
        self.stdin.flush().await.expect("flush stdin");
    }

    async fn recv(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(30), self.lines.next_line())
            .await
            .expect("read timeout")
            .expect("read line")
            .expect("stdout not closed");
        serde_json::from_str(&line).expect("response is JSON")
    }

    async fn request(&mut self, id: u64, rpc_method: &str, params: Value) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": rpc_method,
            "params": params,
        }))
        .await;
        self.recv().await
    }

    async fn initialize(&mut self) -> Value {
        let res = self
            .request(
                1,
                "initialize",
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-stdio-test", "version": "0"},
                }),
            )
            .await;
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        res
    }
}

impl Drop for McpPipe {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

#[tokio::test]
async fn mcp_initialize_reports_injekt_server() {
    let mut pipe = McpPipe::spawn();
    let res = pipe.initialize().await;
    assert_eq!(res["id"], 1);
    assert_eq!(res["result"]["serverInfo"]["name"], "injekt");
    assert_eq!(
        res["result"]["capabilities"]["tools"],
        json!({}),
        "tools capability advertised"
    );
}

#[tokio::test]
async fn mcp_tools_list_exposes_scan_recon_info() {
    let mut pipe = McpPipe::spawn();
    pipe.initialize().await;
    let res = pipe.request(2, "tools/list", json!({})).await;
    let tools = res["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool name"))
        .collect();
    assert!(names.contains(&"scan"), "scan tool listed: {names:?}");
    assert!(
        names.contains(&"recon_crawl"),
        "recon_crawl tool listed: {names:?}"
    );
    assert!(
        names.contains(&"recon_scan"),
        "recon_scan tool listed: {names:?}"
    );
    assert!(names.contains(&"info"), "info tool listed: {names:?}");
    // `target` is the only required param for scan-like tools.
    let scan = tools.iter().find(|t| t["name"] == "scan").expect("scan");
    assert_eq!(scan["inputSchema"]["required"], json!(["target"]));
}

#[tokio::test]
async fn mcp_info_returns_structured_capabilities() {
    let mut pipe = McpPipe::spawn();
    pipe.initialize().await;
    let res = pipe
        .request(3, "tools/call", json!({"name": "info", "arguments": {}}))
        .await;
    assert_eq!(res["result"]["isError"], false);
    let text = res["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let info: Value = serde_json::from_str(text).expect("info is JSON");
    assert!(info["techniques"].as_array().expect("techniques").len() >= 6);
    assert!(info["dbms"].as_array().expect("dbms").len() >= 4);
}

#[tokio::test]
async fn mcp_scan_rejects_encrypted_export_without_tty() {
    let mut pipe = McpPipe::spawn();
    pipe.initialize().await;
    let res = pipe
        .request(
            4,
            "tools/call",
            json!({
                "name": "scan",
                "arguments": {
                    "target": "http://127.0.0.1:9/?id=1",
                    "export_encrypted": "/tmp/injekt-mcp-test.enc",
                },
            }),
        )
        .await;
    // Protocol-level invalid-params error (no TTY for passphrase prompt).
    assert_eq!(res["id"], 4);
    assert_eq!(res["error"]["code"], -32602);
}

#[tokio::test]
async fn mcp_recon_crawl_discovers_candidates_over_stdio() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/robots.txt"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string(r#"<a href="/item?id=7">item</a>"#),
        )
        .mount(&server)
        .await;

    let mut pipe = McpPipe::spawn();
    pipe.initialize().await;
    let res = pipe
        .request(
            5,
            "tools/call",
            json!({
                "name": "recon_crawl",
                "arguments": {
                    "target": server.uri(),
                    "allow_private": true,
                    "max_pages": 2,
                    "depth": 1,
                },
            }),
        )
        .await;
    assert_eq!(res["result"]["isError"], false);
    let text = res["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let report: Value = serde_json::from_str(text).expect("report is JSON");
    let candidates = report["candidates"].as_array().expect("candidates");
    assert!(
        candidates
            .iter()
            .any(|c| c["url"].as_str().unwrap_or_default().contains("id=7")),
        "discovered ?id=7 candidate: {report}"
    );
}
