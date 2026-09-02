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

fn baseline_body() -> &'static str {
    "welcome normal page id=1 content baseline 42"
}

fn different_body() -> &'static str {
    "completely different content — false branch unique marker 99"
}

/// Mock backend with a JSON-context injection point.
///
/// - Error probes embed the `__bad__` sentinel document → per-DBMS JSON error
///   text (only when `with_json_errors`).
/// - Boolean probes compare against `1` (true → baseline-like) or `2`
///   (false → different content). The `{"k":1}` literal encodes `:` as `%3a`,
///   so `%3d1`/`%3d2` (`=1`/`=2`) only match the trailing comparison.
/// - Anything else → baseline.
fn json_responder(with_json_errors: bool) -> impl Fn(&wiremock::Request) -> ResponseTemplate {
    move |req: &wiremock::Request| {
        let url = req.url.to_string().to_ascii_lowercase();
        if with_json_errors && url.contains("__bad__") {
            if url.contains("json_extract") || url.contains("json_unquote") {
                return ResponseTemplate::new(200).set_body_string(
                    "SQL error: Invalid JSON text in argument 1 to function json_extract",
                );
            }
            if url.contains("::json") {
                return ResponseTemplate::new(200)
                    .set_body_string("ERROR: invalid input syntax for type json (SQLSTATE 22P02)");
            }
            if url.contains("json_value") || url.contains("openjson") {
                return ResponseTemplate::new(200).set_body_string(
                    "Msg 13609, Level 16, State 2: JSON text is not properly formatted.",
                );
            }
            if url.contains("$..[") {
                return ResponseTemplate::new(200)
                    .set_body_string("ORA-40442: JSON path expression syntax error");
            }
            return ResponseTemplate::new(200).set_body_string(baseline_body());
        }
        // `%3d%271` covers quoted comparisons (`='1'`); `%3d1` covers bare ones.
        let has_false = url.contains("%3d2") || url.contains("%3d%272");
        let has_true = url.contains("%3d1") || url.contains("%3d%271");
        if has_false && !has_true {
            return ResponseTemplate::new(200).set_body_string(different_body());
        }
        ResponseTemplate::new(200).set_body_string(baseline_body())
    }
}

fn json_engine(techniques: Vec<String>) -> (Engine, CancellationToken) {
    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = techniques;
    cfg.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel.clone());
    (engine, cancel)
}

#[tokio::test]
async fn json_boolean_channel_finds_injection() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(json_responder(false))
        .mount(&server)
        .await;

    let (engine, _cancel) = json_engine(vec!["json".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    let state = engine.run(&target).await.expect("engine run");
    assert_eq!(state, injekt::engine::EngineState::Done);

    let findings = engine.state_handle().read().await.findings().to_vec();
    let jf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Json)
        .expect("json finding present");
    assert!(
        jf.evidence.contains("channel=boolean"),
        "evidence {}",
        jf.evidence
    );
    // First generic payload targets MySQL → dbms attribution feeds fingerprint.
    assert_eq!(jf.dbms, Some("mysql".to_owned()));
}

#[tokio::test]
async fn json_error_channel_finds_injection() {
    let server = MockServer::start().await;
    // No boolean differential here (true/false both baseline), only JSON errors.
    Mock::given(method("GET"))
        .respond_with(|req: &wiremock::Request| {
            let url = req.url.to_string().to_ascii_lowercase();
            if url.contains("__bad__") && url.contains("json_extract") {
                return ResponseTemplate::new(200).set_body_string(
                    "SQL error: Invalid JSON text in argument 1 to function json_extract",
                );
            }
            ResponseTemplate::new(200).set_body_string(baseline_body())
        })
        .mount(&server)
        .await;

    let (engine, _cancel) = json_engine(vec!["json".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");

    let findings = engine.state_handle().read().await.findings().to_vec();
    let jf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Json)
        .expect("json error finding present");
    assert!(
        jf.evidence.contains("channel=error"),
        "evidence {}",
        jf.evidence
    );
    assert_eq!(jf.dbms, Some("mysql".to_owned()));
}

#[tokio::test]
async fn json_in_all_techniques() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(json_responder(true))
        .mount(&server)
        .await;

    let (engine, _cancel) = json_engine(vec!["all".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");

    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .any(|f| f.technique == injekt::session::state::TechniqueKind::Json),
        "json should fire under --techniques all, got {findings:?}"
    );
}

#[tokio::test]
async fn json_no_false_positive_on_static_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(baseline_body()))
        .mount(&server)
        .await;

    let (engine, _cancel) = json_engine(vec!["json".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");

    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .all(|f| f.technique != injekt::session::state::TechniqueKind::Json),
        "static page must not yield json findings, got {findings:?}"
    );
}
