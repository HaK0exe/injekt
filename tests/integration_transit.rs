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

fn baseline_body() -> &'static str {
    "welcome normal page id=1 content baseline 42"
}

fn different_body() -> &'static str {
    "completely different content — false branch unique marker 99"
}

fn transit_responder() -> impl Fn(&wiremock::Request) -> ResponseTemplate {
    move |req: &wiremock::Request| {
        let body = String::from_utf8_lossy(&req.body).to_string();
        if body.contains("select") && body.contains('0') && !body.contains('1') {
            return ResponseTemplate::new(200).set_body_string(different_body());
        }
        if body.trim_end().ends_with(',') {
            return ResponseTemplate::new(200)
                .set_body_string("clojure.lang.ExceptionInfo: HoneySQL syntax error");
        }
        ResponseTemplate::new(200).set_body_string(baseline_body())
    }
}

fn transit_engine(techniques: Vec<String>) -> (Engine, CancellationToken) {
    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = techniques;
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel.clone());
    (engine, cancel)
}

#[tokio::test]
async fn transit_boolean_channel_finds_injection() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(transit_responder())
        .mount(&server)
        .await;
    // Also allow GET baseline? Engine baseline may GET. Mount catch-all.
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(baseline_body()))
        .mount(&server)
        .await;

    let (engine, _cancel) = transit_engine(vec!["transit".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    let state = engine.run(&target).await.expect("engine run");
    assert_eq!(state, injekt::engine::EngineState::Done);

    let findings = engine.state_handle().read().await.findings().to_vec();
    let tf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Transit)
        .expect("transit finding present");
    assert!(
        tf.evidence.contains("channel=boolean"),
        "evidence {}",
        tf.evidence
    );
}

#[tokio::test]
async fn transit_error_channel_finds_injection() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(|req: &wiremock::Request| {
            let body = String::from_utf8_lossy(&req.body).to_string();
            if body.trim_end().ends_with(',') {
                return ResponseTemplate::new(200)
                    .set_body_string("clojure.lang.ExceptionInfo: HoneySQL syntax error");
            }
            ResponseTemplate::new(200).set_body_string(baseline_body())
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(baseline_body()))
        .mount(&server)
        .await;

    let (engine, _cancel) = transit_engine(vec!["transit".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");

    let findings = engine.state_handle().read().await.findings().to_vec();
    let tf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Transit)
        .expect("transit error finding present");
    assert!(
        tf.evidence.contains("channel=error"),
        "evidence {}",
        tf.evidence
    );
}

#[tokio::test]
async fn transit_does_not_fire_on_static_page() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(baseline_body()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(baseline_body()))
        .mount(&server)
        .await;

    let (engine, _cancel) = transit_engine(vec!["transit".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");

    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        !findings
            .iter()
            .any(|f| f.technique == injekt::session::state::TechniqueKind::Transit),
        "no transit finding expected"
    );
}
