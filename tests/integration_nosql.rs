#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    target::raw_request::RawRequest,
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

fn nosql_engine(techniques: Vec<String>) -> (Engine, CancellationToken) {
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

fn nosql_json_engine(techniques: Vec<String>) -> (Engine, CancellationToken) {
    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = techniques;
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg.raw_request = Some(
        RawRequest::parse(
            "POST / HTTP/1.1\nHost: lab.local\nContent-Type: application/json\n\n{\"user\":\"admin\",\"pass\":\"secret\"}",
        )
        .expect("raw request parse"),
    );
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel.clone());
    (engine, cancel)
}

/// Mock backend with a MongoDB operator injection point (query params).
///
/// - `$lt` (false branch `{"$lt": ""}`) → different content.
/// - `$invalidOpInjekt` (sonde d'erreur, `unknown operator`) → MongoDB error
///   (only when `with_errors`).
/// - Anything else (`$gt` true branch, baseline) → baseline.
fn nosql_query_responder(with_errors: bool) -> impl Fn(&wiremock::Request) -> ResponseTemplate {
    move |req: &wiremock::Request| {
        let url = req.url.to_string().to_ascii_lowercase();
        if with_errors && url.contains("invalidop") {
            return ResponseTemplate::new(200)
                .set_body_string("MongoServerError: unknown operator: $invalidOpInjekt");
        }
        if with_errors && url.contains("%24where") && url.contains("%28%28%28") {
            return ResponseTemplate::new(200)
                .set_body_string("SyntaxError in $where clause: unexpected token");
        }
        // `%24lt` = URL-encoded `$lt` (false branch). `%24gt` (true) → baseline.
        if url.contains("%24lt") || url.contains("$lt") {
            return ResponseTemplate::new(200).set_body_string(different_body());
        }
        ResponseTemplate::new(200).set_body_string(baseline_body())
    }
}

/// Same differential on POST JSON bodies (`{"user":{"$lt":""}}` → different).
fn nosql_json_body_responder(with_errors: bool) -> impl Fn(&wiremock::Request) -> ResponseTemplate {
    move |req: &wiremock::Request| {
        let body = String::from_utf8_lossy(&req.body).to_ascii_lowercase();
        if with_errors && body.contains("invalidop") {
            return ResponseTemplate::new(200)
                .set_body_string("MongoServerError: unknown operator: $invalidOpInjekt");
        }
        if body.contains("$lt") {
            return ResponseTemplate::new(200).set_body_string(different_body());
        }
        ResponseTemplate::new(200).set_body_string(baseline_body())
    }
}

#[tokio::test]
async fn nosql_boolean_channel_finds_injection() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(nosql_query_responder(false))
        .mount(&server)
        .await;

    let (engine, _cancel) = nosql_engine(vec!["nosql".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    let state = engine.run(&target).await.expect("engine run");
    assert_eq!(state, injekt::engine::EngineState::Done);

    let findings = engine.state_handle().read().await.findings().to_vec();
    let nf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Nosql)
        .expect("nosql finding present");
    assert!(
        nf.evidence.contains("channel=boolean"),
        "evidence {}",
        nf.evidence
    );
    assert!(
        nf.evidence.contains("operator-gt"),
        "evidence {}",
        nf.evidence
    );
    assert_eq!(nf.dbms, Some("mongodb".to_owned()));
}

#[tokio::test]
async fn nosql_error_channel_finds_injection() {
    let server = MockServer::start().await;
    // No boolean differential here (true/false both baseline), only errors.
    Mock::given(method("GET"))
        .respond_with(|req: &wiremock::Request| {
            let url = req.url.to_string().to_ascii_lowercase();
            if url.contains("invalidop") {
                return ResponseTemplate::new(200)
                    .set_body_string("MongoServerError: unknown operator: $invalidOpInjekt");
            }
            ResponseTemplate::new(200).set_body_string(baseline_body())
        })
        .mount(&server)
        .await;

    let (engine, _cancel) = nosql_engine(vec!["nosql".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");

    let findings = engine.state_handle().read().await.findings().to_vec();
    let nf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Nosql)
        .expect("nosql error finding present");
    assert!(
        nf.evidence.contains("channel=error"),
        "evidence {}",
        nf.evidence
    );
    assert_eq!(nf.dbms, Some("mongodb".to_owned()));
}

#[tokio::test]
async fn nosql_json_body_operator_finds_bypass() {
    // End-to-end du bypass REST `{"user": {"$gt": ""}}` : la feuille
    // `{"user":"admin"}` devient un objet opérateur via `inject_json_operator`.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(nosql_json_body_responder(false))
        .mount(&server)
        .await;

    let (engine, _cancel) = nosql_json_engine(vec!["nosql".to_owned()]);
    let target = server.uri();
    let _ = engine.run(&target).await.expect("engine run");

    let findings = engine.state_handle().read().await.findings().to_vec();
    let nf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Nosql)
        .expect("nosql json-body finding present");
    assert!(
        nf.evidence.contains("channel=boolean"),
        "evidence {}",
        nf.evidence
    );
    assert!(
        nf.parameter.ends_with("@body"),
        "operator injection must target a body param, got {}",
        nf.parameter
    );
}

#[tokio::test]
async fn nosql_in_all_techniques() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(nosql_query_responder(true))
        .mount(&server)
        .await;

    let (engine, _cancel) = nosql_engine(vec!["all".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");

    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .any(|f| f.technique == injekt::session::state::TechniqueKind::Nosql),
        "nosql should fire under --techniques all, got {findings:?}"
    );
}

#[tokio::test]
async fn nosql_no_false_positive_on_static_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(baseline_body()))
        .mount(&server)
        .await;

    let (engine, _cancel) = nosql_engine(vec!["nosql".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");

    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .all(|f| f.technique != injekt::session::state::TechniqueKind::Nosql),
        "static page must not yield nosql findings, got {findings:?}"
    );
}
