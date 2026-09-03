#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
    detection::matcher::MatcherConfig,
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    session::state::TechniqueKind,
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn test_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(std::sync::Arc::new(RateLimiter::disabled()))
        .build()
        .expect("client build")
}

fn baseline_body() -> &'static str {
    "welcome normal page content baseline 42"
}

fn different_body() -> &'static str {
    "completely different page xyz 99 unique"
}

/// Boolean differential on raw query string: FALSE probes differ, everything else is baseline.
fn query_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string();
    if url.contains("1%3D2") || url.contains("1=2") {
        ResponseTemplate::new(200).set_body_string(different_body())
    } else {
        ResponseTemplate::new(200).set_body_string(baseline_body())
    }
}

/// Same differential wrapped in HTML so `--text-only` stripping is exercised.
fn html_query_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string();
    if url.contains("1%3D2") || url.contains("1=2") {
        ResponseTemplate::new(200).set_body_string(format!(
            "<html><body><p>{}</p></body></html>",
            different_body()
        ))
    } else {
        ResponseTemplate::new(200).set_body_string(format!(
            "<html><body><p>{}</p></body></html>",
            baseline_body()
        ))
    }
}

fn boolean_cfg() -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.allow_private = true;
    cfg.no_redact = true;
    cfg
}

#[tokio::test]
async fn string_present_keeps_finding_string_absent_vetoes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(query_responder)
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());

    // `page` is present in both TRUE (baseline) and FALSE (different) bodies:
    // matcher abstains (`None`), detector finding is kept.
    let mut cfg = boolean_cfg();
    let mut matcher = MatcherConfig::default();
    matcher.string = Some("page".to_owned());
    cfg.matcher = matcher;
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let finding = findings
        .iter()
        .find(|f| f.technique == TechniqueKind::Boolean)
        .expect("boolean finding kept when --string is present in responses");
    assert!(
        finding.evidence.contains("matcher="),
        "evidence should carry matcher suffix, got {}",
        finding.evidence
    );

    // Absent needle: both branches veto (`Some(false)`), no finding.
    let mut cfg = boolean_cfg();
    let mut matcher = MatcherConfig::default();
    matcher.string = Some("absent-marker-xyz-123".to_owned());
    cfg.matcher = matcher;
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    engine.run(&target).await.expect("engine run");
    assert!(
        engine.state_handle().read().await.findings().is_empty(),
        "--string absent from bodies must veto the boolean finding"
    );
}

#[tokio::test]
async fn code_mismatch_vetoes_finding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(query_responder)
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());

    // Mock answers 200: expecting 500 vetoes every branch.
    let mut cfg = boolean_cfg();
    let mut matcher = MatcherConfig::default();
    matcher.code = Some(500);
    cfg.matcher = matcher;
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    engine.run(&target).await.expect("engine run");
    assert!(
        engine.state_handle().read().await.findings().is_empty(),
        "--code 500 must veto findings when the server answers 200"
    );

    // Control: expecting 200 keeps the baseline finding.
    let mut cfg = boolean_cfg();
    let mut matcher = MatcherConfig::default();
    matcher.code = Some(200);
    cfg.matcher = matcher;
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .any(|f| f.technique == TechniqueKind::Boolean),
        "expected boolean finding when --code matches the server status"
    );
}

#[tokio::test]
async fn text_only_keeps_baseline_finding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(html_query_responder)
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());

    // Baseline without matcher: HTML differential is still detected.
    let cfg = boolean_cfg();
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    engine.run(&target).await.expect("engine run");
    assert!(
        engine
            .state_handle()
            .read()
            .await
            .findings()
            .iter()
            .any(|f| f.technique == TechniqueKind::Boolean),
        "expected baseline boolean finding on HTML bodies without --text-only"
    );

    // With `--text-only`: tags stripped up-front, differential survives in
    // text space, finding is kept (stripping must not break detection).
    let mut cfg = boolean_cfg();
    let mut matcher = MatcherConfig::default();
    matcher.text_only = true;
    cfg.matcher = matcher;
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let finding = findings
        .iter()
        .find(|f| f.technique == TechniqueKind::Boolean)
        .expect("--text-only must not break the baseline boolean finding");
    assert!(
        finding.evidence.contains("text-only:true"),
        "evidence should mark text-only, got {}",
        finding.evidence
    );
}
