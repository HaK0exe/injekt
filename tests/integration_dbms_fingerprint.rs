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

/// Minimal boolean-oracle backend: any injected condition containing `1=1`
/// (generic boolean payload or the MySQL versioned-comment probe) renders
/// like baseline, `1=0`/`1=2` renders differently. Good enough to exercise
/// the plumbing from a generic (dbms-less) boolean finding through the
/// active fingerprint probe without modelling real per-DBMS SQL semantics.
fn oracle_responder(req: &wiremock::Request) -> ResponseTemplate {
    let id = req
        .url
        .query_pairs()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    if id.contains("1=0") || id.contains("1=2") {
        return ResponseTemplate::new(200)
            .set_body_string("completely different content unique 987654");
    }
    ResponseTemplate::new(200).set_body_string(baseline_body())
}

#[tokio::test]
async fn active_probe_confirms_mysql_when_passive_signals_are_absent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(oracle_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    engine.run(&target).await.expect("engine run");

    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(!findings.is_empty(), "expected a generic boolean finding");
    // After the fingerprint phase, the active probe should have filled dbms
    // in — the boolean detector itself never tags one, so this is only
    // possible via the new active differential probe.

    let dbms = findings
        .first()
        .and_then(|f| f.dbms.clone())
        .expect("active fingerprint probe should have filled dbms=mysql");
    assert_eq!(dbms, "mysql");
}
