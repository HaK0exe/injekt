#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
    cli::commands::bulk::run_bulk, engine::EngineConfig, http::client::HttpClient,
    http::jitter::Jitter, http::rate_limit::RateLimiter, session::scrubber::Scrubber,
    target::bulk::parse_targets_text,
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn test_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(std::sync::Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

fn bulk_cfg() -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.allow_private = true;
    cfg.no_redact = true;
    cfg
}

fn baseline_body() -> &'static str {
    "welcome normal page id=1 content baseline 42"
}

fn different_body() -> &'static str {
    "completely different content false branch unique marker 99 xyz"
}

/// Differential boolean responder (vulnerable): `1=2` branch differs.
fn vuln_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    if url.contains("1%3d2") || url.contains("1=2") {
        return ResponseTemplate::new(200).set_body_string(different_body());
    }
    ResponseTemplate::new(200).set_body_string(baseline_body())
}

/// Healthy responder: every request returns the baseline page.
fn healthy_responder(_req: &wiremock::Request) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_string(baseline_body())
}

/// A TCP port that is (almost surely) closed: bind then release, so connecting
/// fails and the engine baseline bails out with an error.
fn closed_port_target() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback for free port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    format!("http://127.0.0.1:{port}/?id=1")
}

#[test]
fn parse_targets_text_skips_comments_blanks_dedup_rejects_ftp() {
    let content = "# comment\n\n   \n// other\nhttp://127.0.0.1:8080/?id=1\nhttp://127.0.0.1:8080/?id=1\n  http://127.0.0.1:8080/?id=1  \nftp://example.com/?id=1\nhttp://127.0.0.1:8080/?id=2\n";
    let targets = parse_targets_text(content, true);
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0], "http://127.0.0.1:8080/?id=1");
    assert_eq!(targets[1], "http://127.0.0.1:8080/?id=2");
}

#[tokio::test]
async fn bulk_two_targets_vuln_and_healthy() {
    let server_a = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(vuln_responder)
        .mount(&server_a)
        .await;
    let server_b = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(healthy_responder)
        .mount(&server_b)
        .await;

    let target_a = format!("{}/?id=1", server_a.uri());
    let target_b = format!("{}/?id=1", server_b.uri());
    let cfg = bulk_cfg();
    let scrubber = Scrubber::new(true);
    let cancel = CancellationToken::new();
    let report = run_bulk(
        vec![target_a.clone(), target_b.clone()],
        &cfg,
        || Ok(test_client()),
        &cancel,
        &scrubber,
    )
    .await;

    assert_eq!(report.targets_total, 2);
    assert_eq!(report.targets_ok, 2);
    assert_eq!(report.targets_failed, 0);
    assert_eq!(report.per_target.len(), 2);
    let ra = report
        .per_target
        .iter()
        .find(|r| r.target == target_a)
        .expect("result for A");
    let rb = report
        .per_target
        .iter()
        .find(|r| r.target == target_b)
        .expect("result for B");
    assert!(ra.error.is_none());
    assert!(rb.error.is_none());
    assert!(
        !ra.findings.is_empty(),
        "vulnerable target A should yield findings"
    );
    assert!(
        rb.findings.is_empty(),
        "healthy target B should yield no findings, got {:?}",
        rb.findings
    );
    assert_eq!(
        report.request_count_total,
        ra.request_count + rb.request_count
    );
    assert!(report.request_count_total > 0);
    // JSON shape: version=1, per-target entries present.
    let v = report.to_json(&scrubber);
    assert_eq!(
        v.get("version").and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        v.get("per_target")
            .and_then(serde_json::Value::as_array)
            .map(std::vec::Vec::len),
        Some(2)
    );
}

#[tokio::test]
async fn bulk_continues_after_failing_target() {
    let server_a = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(vuln_responder)
        .mount(&server_a)
        .await;
    let server_b = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(healthy_responder)
        .mount(&server_b)
        .await;

    let target_a = format!("{}/?id=1", server_a.uri());
    let target_c = closed_port_target();
    let target_b = format!("{}/?id=1", server_b.uri());
    let cfg = bulk_cfg();
    let scrubber = Scrubber::new(true);
    let cancel = CancellationToken::new();
    // Failing target in the middle: A and B must still be scanned.
    let report = run_bulk(
        vec![target_a.clone(), target_c.clone(), target_b.clone()],
        &cfg,
        || Ok(test_client()),
        &cancel,
        &scrubber,
    )
    .await;

    assert_eq!(report.targets_total, 3);
    assert_eq!(report.targets_ok, 2);
    assert_eq!(report.targets_failed, 1);
    assert_eq!(report.per_target.len(), 3);
    let rc = report
        .per_target
        .iter()
        .find(|r| r.target == target_c)
        .expect("result for C");
    assert!(rc.error.as_deref().is_some_and(|e| !e.is_empty()));
    assert!(rc.findings.is_empty());
    let ra = report
        .per_target
        .iter()
        .find(|r| r.target == target_a)
        .expect("result for A");
    assert!(
        !ra.findings.is_empty(),
        "A must still be scanned after C failed"
    );
    let rb = report
        .per_target
        .iter()
        .find(|r| r.target == target_b)
        .expect("result for B");
    assert!(rb.error.is_none());
}

#[tokio::test]
async fn bulk_cancelled_before_start_makes_no_requests() {
    let server_a = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(vuln_responder)
        .mount(&server_a)
        .await;

    let target_a = format!("{}/?id=1", server_a.uri());
    let cfg = bulk_cfg();
    let scrubber = Scrubber::new(true);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let report = run_bulk(
        vec![target_a],
        &cfg,
        || Ok(test_client()),
        &cancel,
        &scrubber,
    )
    .await;

    assert_eq!(report.targets_total, 1);
    assert_eq!(report.targets_ok, 0);
    assert_eq!(report.targets_failed, 0);
    assert_eq!(report.request_count_total, 0);
    assert!(report.per_target.is_empty());
}

#[test]
fn bulk_flag_parses_short_and_long() {
    use clap::Parser as _;
    use injekt::cli::args::Cli;
    let cli = Cli::try_parse_from(["injekt", "scan", "-m", "targets.txt"]).expect("parse -m");
    assert_eq!(cli.bulk_file.as_deref(), Some("targets.txt"));
    let cli = Cli::try_parse_from(["injekt", "scan", "--bulk-file", "t.txt"]).expect("parse long");
    assert_eq!(cli.bulk_file.as_deref(), Some("t.txt"));
    let cli = Cli::try_parse_from(["injekt", "scan", "--target", "http://example.com/?id=1"])
        .expect("parse target");
    assert!(cli.bulk_file.is_none());
}

#[tokio::test]
async fn bulk_conflicts_with_target_and_export() {
    use clap::Parser as _;
    use injekt::cli::{args::Cli, commands};
    // --bulk-file + --target -> bail before any network.
    let cli = Cli::try_parse_from([
        "injekt",
        "scan",
        "-m",
        "targets.txt",
        "--target",
        "http://127.0.0.1/?id=1",
        "--allow-private",
    ])
    .expect("parse conflict");
    let err = commands::scan::run(cli, CancellationToken::new())
        .await
        .expect_err("bulk+target must fail");
    assert!(
        err.to_string().contains("conflicts"),
        "unexpected error: {err}"
    );
}
