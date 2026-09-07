#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
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

fn stacked_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string();
    // Extract marker from URL (URL-encoded: %27stacked_XXXX...%27 or stacked_XXXX...)
    let marker = if let Some(start) = url.find("stacked_") {
        &url[start..(start + 40).min(url.len())]
    } else if let Some(start) = url.find("stacked%5f") {
        &url[start..(start + 40).min(url.len())]
    } else if let Some(start) = url.find("%27stacked_") {
        &url[start + 3..(start + 3 + 40).min(url.len())] // skip %27
    } else if let Some(start) = url.find("%27stacked%5f") {
        &url[start + 3..(start + 3 + 40).min(url.len())]
    } else {
        "stacked_unknown"
    };
    let url_lower = url.to_ascii_lowercase();
    // Baseline: no stacked query
    if !url_lower.contains("select") && !url_lower.contains("stacked") {
        return ResponseTemplate::new(200).set_body_string("welcome page id=1 normal content");
    }
    // Stacked query with marker - echo the marker back
    let response_body = format!("welcome page id=1 normal content {marker} EXTRA DATA");
    ResponseTemplate::new(200).set_body_string(response_body)
}

fn stacked_responder_no_vuln(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    if url.contains("select") || url.contains("stacked") {
        // Always return normal page even with stacked query
        return ResponseTemplate::new(200).set_body_string("welcome page id=1 normal content");
    }
    ResponseTemplate::new(200).set_body_string("welcome page id=1 normal content")
}

#[tokio::test]
async fn stacked_finds_vulnerability() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(stacked_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["stacked".to_owned()];
    cfg.allow_private = true;
    cfg.no_redact = true;
    cfg.extract = false;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(!findings.is_empty(), "should have stacked finding, got 0");
    let stacked_finding = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Stacked)
        .expect("stacked finding present");
    assert!(
        stacked_finding.confidence > 0.5,
        "confidence should be >0.5 got {}",
        stacked_finding.confidence
    );
    assert!(
        stacked_finding.evidence.contains("stacked"),
        "evidence should mention stacked, got {}",
        stacked_finding.evidence
    );
    assert!(stacked_finding.dbms.is_some(), "dbms should be identified");
}

#[tokio::test]
async fn stacked_no_false_positive() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(stacked_responder_no_vuln)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["stacked".to_owned()];
    cfg.allow_private = true;
    cfg.no_redact = true;
    cfg.extract = false;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let stacked_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.technique == injekt::session::state::TechniqueKind::Stacked)
        .collect();
    assert!(
        stacked_findings.is_empty(),
        "should have no stacked findings when not vulnerable, got {stacked_findings:?}"
    );
}

#[tokio::test]
async fn stacked_in_all_techniques() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(stacked_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["all".to_owned()];
    cfg.allow_private = true;
    cfg.no_redact = true;
    cfg.extract = false;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let stacked_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.technique == injekt::session::state::TechniqueKind::Stacked)
        .collect();
    assert!(
        !stacked_findings.is_empty(),
        "stacked should run when techniques=all"
    );
}
