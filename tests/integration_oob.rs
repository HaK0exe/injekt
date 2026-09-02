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
        .build()
        .expect("client build")
}

fn baseline_page() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content")
}

fn engine_with_oob(
    oob_domain: Option<String>,
    oob_poll_url: Option<String>,
) -> (Engine, CancellationToken) {
    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["oob".to_owned()];
    cfg.allow_private = true;
    cfg.no_redact = true;
    cfg.extract = false;
    cfg.oob_domain = oob_domain;
    cfg.oob_poll_url = oob_poll_url;
    cfg.oob_wait_secs = 0;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel.clone());
    (engine, cancel)
}

#[tokio::test]
async fn oob_confirmed_when_poll_reports_seen() {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    // Collaborator shim: always confirms (simulates DB egress observed).
    let poll = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"seen":true}"#))
        .mount(&poll)
        .await;

    let (engine, _cancel) =
        engine_with_oob(Some("collab.example.com".to_owned()), Some(poll.uri()));
    let url = format!("{}/?id=1", target.uri());
    let state = engine.run(&url).await.expect("engine run");
    assert_eq!(state, injekt::engine::EngineState::Done);

    let findings = engine.state_handle().read().await.findings().to_vec();
    let oob = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Oob)
        .expect("oob finding present on callback");
    assert!(
        (oob.confidence - 0.95).abs() < 1e-6,
        "confidence {}",
        oob.confidence
    );
    assert!(oob.evidence.contains("token="), "evidence {}", oob.evidence);
    assert!(
        oob.evidence.contains("collab.example.com"),
        "evidence {}",
        oob.evidence
    );
}

#[tokio::test]
async fn oob_no_finding_when_no_callback() {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    let poll = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"seen":false,"interactions":[]}"#),
        )
        .mount(&poll)
        .await;

    let (engine, _cancel) =
        engine_with_oob(Some("collab.example.com".to_owned()), Some(poll.uri()));
    let url = format!("{}/?id=1", target.uri());
    let _ = engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .all(|f| f.technique != injekt::session::state::TechniqueKind::Oob),
        "no OOB finding without callback, got {findings:?}"
    );
}

#[tokio::test]
async fn oob_skipped_without_domain() {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    let (engine, _cancel) = engine_with_oob(None, None);
    let url = format!("{}/?id=1", target.uri());
    let state = engine.run(&url).await.expect("engine run");
    assert_eq!(state, injekt::engine::EngineState::Done);
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "oob without domain must not emit findings"
    );
}

#[tokio::test]
async fn oob_skipped_with_invalid_domain() {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    let (engine, _cancel) = engine_with_oob(Some("http://not-a-domain/path".to_owned()), None);
    let url = format!("{}/?id=1", target.uri());
    let _ = engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(findings.is_empty(), "invalid oob domain must be skipped");
}

#[tokio::test]
async fn oob_manual_mode_sends_probes_without_finding() {
    // No poll URL: probes are sent for manual collaborator check, but the
    // engine must not invent a finding without evidence.
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    let (engine, _cancel) = engine_with_oob(Some("collab.example.com".to_owned()), None);
    let url = format!("{}/?id=1", target.uri());
    let _ = engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .all(|f| f.technique != injekt::session::state::TechniqueKind::Oob),
        "manual mode must not auto-confirm, got {findings:?}"
    );
    // Probes were still sent: baseline (3) + 3 OOB payloads.
    let count = engine.state_handle().read().await.request_count();
    assert!(count >= 6, "probes should have been sent, count={count}");
}
