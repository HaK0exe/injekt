#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn test_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(10))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(std::sync::Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

fn time_config() -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["time".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg.enumeration.extract = false;
    cfg
}

/// Backend that sleeps only when a sleep primitive is injected.
fn sleep_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    let wants_sleep = url.contains("sleep")
        || url.contains("pg_sleep")
        || url.contains("waitfor")
        || url.contains("receive_message")
        || url.contains("benchmark");
    if wants_sleep {
        ResponseTemplate::new(200)
            .set_delay(Duration::from_secs(3))
            .set_body_string("welcome page id=1 normal content")
    } else {
        ResponseTemplate::new(200).set_body_string("welcome page id=1 normal content")
    }
}

#[tokio::test]
async fn time_finds_real_sleep_injection() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(sleep_responder)
        .mount(&server)
        .await;

    let engine = Engine::new(time_config(), test_client(), CancellationToken::new());
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let time_finding = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Time)
        .expect("time finding present on real sleep backend");
    assert!(
        time_finding.evidence.contains("control="),
        "evidence should carry the differential control timing, got {}",
        time_finding.evidence
    );
}

/// Backend that only sleeps for inline concat-breakout `|| pg_sleep`
/// (bounty tweet variant). Legacy stacked `'; SELECT pg_sleep` stays fast,
/// so detection requires the new `pg_time_concat` variant.
fn pg_concat_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    // `|` travels URL-encoded via reqwest: cover raw + encoded forms.
    let has_pipe = url.contains("||")
        || url.contains("%7c%7c")
        || url.contains("%257c")
        || url.contains("%7c");
    let has_pg = url.contains("pg_sleep");
    if has_pipe && has_pg {
        ResponseTemplate::new(200)
            .set_delay(Duration::from_secs(3))
            .set_body_string("welcome page id=1 normal content")
    } else {
        ResponseTemplate::new(200).set_body_string("welcome page id=1 normal content")
    }
}

#[tokio::test]
async fn postgres_concat_time_inline_requires_pipe_variant() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(pg_concat_responder)
        .mount(&server)
        .await;

    let mut cfg = time_config();
    // L1 only tries the 4 legacies (none contains `||`); L3 exhausts all 10
    // payloads including the concat variant.
    cfg.budget.level = 3;
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .any(|f| f.technique == injekt::session::state::TechniqueKind::Time),
        "inline `|| pg_sleep` backend must be detected, got {findings:?}"
    );
}

/// Backend that answers fast during warmup, then becomes uniformly slow for
/// every request (cold cache / throttle / degraded host). Both sleep shots
/// clear the timing bar for non-SQL reasons — the benign control is equally
/// slow, so no finding must be reported.
#[tokio::test]
async fn time_rejects_uniformly_slow_endpoint() {
    let server = MockServer::start().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    Mock::given(method("GET"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n < 3 {
                ResponseTemplate::new(200).set_body_string("welcome page id=1 normal content")
            } else {
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(2))
                    .set_body_string("welcome page id=1 normal content")
            }
        })
        .mount(&server)
        .await;

    let engine = Engine::new(time_config(), test_client(), CancellationToken::new());
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let time_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.technique == injekt::session::state::TechniqueKind::Time)
        .collect();
    assert!(
        time_findings.is_empty(),
        "uniformly slow endpoint must not report time findings, got {time_findings:?}"
    );
}
