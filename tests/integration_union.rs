#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

/// Helper to build a minimal HttpClient for tests (no jitter delay, high rate limit).
fn test_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(std::sync::Arc::new(RateLimiter::disabled()))
        .build()
        .expect("client build")
}

/// Wiremock responder for ORDER BY enumeration + UNION scenario:
/// - baseline (no order by / no union): normal page
/// - ORDER BY i < 4: normal page (no error)
/// - ORDER BY i >= 4: SQL error containing "Unknown column '4' in order clause" + "ORDER BY"
/// - UNION SELECT 1,2,3: page containing "1,2,3" marker + diff
/// - other UNION: normal page
fn union_responder_with_order_by(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    // ORDER BY probes
    if url.contains("order%20by") || url.contains("order+by") {
        // Check for ORDER BY 4..10 as error (infer 3 columns)
        if url.contains("order%20by%204")
            || url.contains("order%20by%205")
            || url.contains("order%20by%206")
            || url.contains("order%20by%207")
            || url.contains("order%20by%208")
            || url.contains("order%20by%209")
            || url.contains("order%20by%2010")
            || url.contains("order+by+4")
            || url.contains("order+by+5")
        {
            return ResponseTemplate::new(200)
                .set_body_string("SQL error: Unknown column '4' in 'order clause' ORDER BY 4");
        }
        // ORDER BY 1..3 => normal
        return ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content");
    }
    if url.contains("union") {
        // Decode-ish check for 1,2,3 marker (encoded or raw)
        if url.contains("1%2c2%2c3")
            || url.contains("1,2,3")
            || url.contains("1%2c+2%2c+3")
            || url.contains("1%2c2%2c3%20")
        {
            return ResponseTemplate::new(200).set_body_string(
                "welcome page injected 1,2,3 marker success different content extra",
            );
        }
        // wrong column count => normal (no marker)
        return ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content");
    }
    ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content")
}

fn union_responder_no_order_by_error(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    if url.contains("order%20by") || url.contains("order+by") {
        // Never error — enumeration undetermined
        return ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content");
    }
    if url.contains("union") {
        if url.contains("1%2c2%2c3") || url.contains("1,2,3") {
            return ResponseTemplate::new(200).set_body_string(
                "welcome page injected 1,2,3 marker success different content extra",
            );
        }
        return ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content");
    }
    ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content")
}

fn union_responder_no_vuln(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    if url.contains("union") || url.contains("order%20by") || url.contains("order+by") {
        // Always normal, never marker, never error
        return ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content");
    }
    ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content")
}

#[tokio::test]
async fn union_order_by_infers_3_and_finds_union() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(union_responder_with_order_by)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["union".to_owned()];
    cfg.allow_private = true;
    cfg.no_redact = true;
    cfg.extract = false;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let state = engine.run(&target).await.expect("engine run");
    assert_eq!(state, injekt::engine::EngineState::Done);

    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        !findings.is_empty(),
        "should have at least one union finding, got 0"
    );
    let union_finding = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Union)
        .expect("union finding present");
    assert!(
        union_finding.confidence > 0.6,
        "confidence should be >0.6 got {}",
        union_finding.confidence
    );
    // Evidence should mention order_by_inferred=Some(3) because ORDER BY 4 errored
    assert!(
        union_finding.evidence.contains("order_by_inferred"),
        "evidence should contain order_by_inferred, got {}",
        union_finding.evidence
    );
    assert!(
        union_finding.evidence.contains("Some(3)") || union_finding.evidence.contains("3"),
        "evidence should indicate inferred 3, got {}",
        union_finding.evidence
    );
    // Ensure UNION columns=3
    assert!(
        union_finding.evidence.contains("columns=Some(3)")
            || union_finding.evidence.contains("columns=3"),
        "evidence should contain columns 3, got {}",
        union_finding.evidence
    );
}

#[tokio::test]
async fn union_order_by_no_error_fallback_still_finds_union() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(union_responder_no_order_by_error)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["union".to_owned()];
    cfg.allow_private = true;
    cfg.no_redact = true;
    cfg.extract = false;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    // With no ORDER BY error, fallback heuristic [3,2,4,5] should still find UNION 1,2,3
    assert!(
        !findings.is_empty(),
        "fallback should still find union even when ORDER BY undetermined"
    );
    let uf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Union)
        .expect("union finding via fallback");
    assert!(uf.evidence.contains("order_by_inferred"));
}

#[tokio::test]
async fn union_no_marker_no_error_yields_no_finding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(union_responder_no_vuln)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 2;
    cfg.techniques = vec!["union".to_owned()];
    cfg.allow_private = true;
    cfg.no_redact = true;
    cfg.extract = false;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "should have no findings when no marker and no order by error, got {findings:?}"
    );
}

#[tokio::test]
async fn union_order_by_only_first_error_is_inconclusive() {
    // ORDER BY 1 already errors => enumeration returns None, fallback should still work
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(|req: &wiremock::Request| {
            let url = req.url.to_string().to_ascii_lowercase();
            if url.contains("order%20by") || url.contains("order+by") {
                return ResponseTemplate::new(200)
                    .set_body_string("SQL error: Unknown column '1' in 'order clause' ORDER BY 1");
            }
            if url.contains("union") && (url.contains("1%2c2%2c3") || url.contains("1,2,3")) {
                return ResponseTemplate::new(200).set_body_string(
                    "welcome page injected 1,2,3 marker success different content extra",
                );
            }
            ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content")
        })
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["union".to_owned()];
    cfg.allow_private = true;
    cfg.no_redact = true;
    cfg.extract = false;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    // Even though ORDER BY 1 errored (inconclusive), fallback should still find union
    assert!(
        !findings.is_empty(),
        "fallback should rescue when ORDER BY inconclusive"
    );
}
