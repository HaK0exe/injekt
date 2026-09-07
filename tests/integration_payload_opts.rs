#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    session::state::TechniqueKind,
    techniques::payload_opts::PayloadOpts,
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

/// Boolean differential scoped to the `id` query param only; `q` never differs.
fn scoped_query_responder(req: &wiremock::Request) -> ResponseTemplate {
    let id_value: String = req
        .url
        .query_pairs()
        .filter(|(k, _)| k == "id")
        .map(|(_, v)| v.into_owned())
        .collect();
    if id_value.contains("1=2") || id_value.contains("1%3D2") {
        ResponseTemplate::new(200).set_body_string(different_body())
    } else {
        ResponseTemplate::new(200).set_body_string(baseline_body())
    }
}

/// Boolean differential on POST form body.
fn body_responder(req: &wiremock::Request) -> ResponseTemplate {
    let body = String::from_utf8_lossy(&req.body);
    if body.contains("1%3D2") || body.contains("1=2") {
        ResponseTemplate::new(200).set_body_string(different_body())
    } else {
        ResponseTemplate::new(200).set_body_string(baseline_body())
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
async fn suffix_passthrough_keeps_finding_and_marks_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(query_responder)
        .mount(&server)
        .await;

    let mut cfg = boolean_cfg();
    let mut popts = PayloadOpts::default();
    popts.suffix = Some(" -- -".to_owned());
    cfg.payload_opts = popts;
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let target = format!("{}/?id=1", server.uri());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let finding = findings
        .iter()
        .find(|f| f.technique == TechniqueKind::Boolean)
        .expect("boolean finding with neutral suffix");
    assert!(
        finding.evidence.contains("suffix="),
        "evidence should carry payload-opts suffix, got {}",
        finding.evidence
    );
}

#[tokio::test]
async fn data_posts_body_and_finds_body_param() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(body_responder)
        .mount(&server)
        .await;

    let mut cfg = boolean_cfg();
    cfg.post_data = Some("id=1&user=guest".to_owned());
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    engine.run(&server.uri()).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .any(|f| f.technique == TechniqueKind::Boolean && f.parameter == "id@body"),
        "expected boolean finding on id@body via --data, got {:?}",
        findings.iter().map(|f| &f.parameter).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn param_filter_selects_only_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(scoped_query_responder)
        .mount(&server)
        .await;

    // Filter on q (never injectable here) -> no findings.
    let mut cfg = boolean_cfg();
    cfg.test_params = vec!["q".to_owned()];
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let target = format!("{}/?id=1&q=1", server.uri());
    engine.run(&target).await.expect("engine run");
    assert!(
        engine.state_handle().read().await.findings().is_empty(),
        "-p q must yield no findings when only id is injectable"
    );

    // Filter on id -> finding on id@query.
    let mut cfg = boolean_cfg();
    cfg.test_params = vec!["id".to_owned()];
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .any(|f| f.technique == TechniqueKind::Boolean && f.parameter == "id@query"),
        "expected boolean finding on id@query via -p id, got {:?}",
        findings.iter().map(|f| &f.parameter).collect::<Vec<_>>()
    );
}
