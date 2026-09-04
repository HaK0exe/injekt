#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

/// Helper to build a minimal `HttpClient` for tests (no jitter delay, high rate limit).
fn test_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(std::sync::Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

/// Decode the `id` query param from a wiremock request (empty string if absent).
fn decoded_id(req: &wiremock::Request) -> String {
    req.url
        .query_pairs()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

/// The union payloads embed a unique marker as a quoted string literal (e.g. `'u1a2b3c4'`)
/// in place of one selected column. Extract it if present.
fn extract_marker(decoded: &str) -> Option<String> {
    let re = regex::Regex::new(r"'(u[0-9a-f]{8})'").unwrap();
    re.captures(decoded)
        .map(|c| c.get(1).unwrap().as_str().to_owned())
}

/// Wiremock responder for ORDER BY enumeration + UNION scenario:
/// - baseline (no order by / no union): normal page
/// - ORDER BY i < 4: normal page (no error)
/// - ORDER BY i >= 4: SQL error containing "Unknown column '4' in order clause" + "ORDER BY"
/// - UNION SELECT with 3 columns (marker present, 2 numeric siblings): reflect marker
/// - other UNION (wrong column count): normal page
fn union_responder_with_order_by(req: &wiremock::Request) -> ResponseTemplate {
    let decoded = decoded_id(req).to_ascii_lowercase();
    if decoded.contains("order by") {
        if (4..=10).any(|i| decoded.contains(&format!("order by {i}"))) {
            return ResponseTemplate::new(200)
                .set_body_string("SQL error: Unknown column '4' in 'order clause' ORDER BY 4");
        }
        return ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content");
    }
    if decoded.contains("union select") {
        // Only reflect the marker when the payload carries exactly 3 columns
        // (two numeric siblings + the marker), matching the inferred/heuristic count.
        let has_three_cols = decoded.contains("1,2,'") || decoded.contains("null,2,'");
        if has_three_cols && let Some(marker) = extract_marker(&decoded) {
            return ResponseTemplate::new(200).set_body_string(format!(
                "welcome page injected {marker} success different content extra"
            ));
        }
        return ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content");
    }
    ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content")
}

fn union_responder_no_order_by_error(req: &wiremock::Request) -> ResponseTemplate {
    let decoded = decoded_id(req).to_ascii_lowercase();
    if decoded.contains("order by") {
        // Never error — enumeration undetermined
        return ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content");
    }
    if decoded.contains("union select") {
        let has_three_cols = decoded.contains("1,2,'") || decoded.contains("null,2,'");
        if has_three_cols && let Some(marker) = extract_marker(&decoded) {
            return ResponseTemplate::new(200).set_body_string(format!(
                "welcome page injected {marker} success different content extra"
            ));
        }
        return ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content");
    }
    ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content")
}

fn union_responder_no_vuln(req: &wiremock::Request) -> ResponseTemplate {
    let decoded = decoded_id(req).to_ascii_lowercase();
    if decoded.contains("union select") || decoded.contains("order by") {
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
        union_finding.evidence.contains("Some(3)") || union_finding.evidence.contains('3'),
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
    // With no ORDER BY error, fallback heuristic [3,2,4,5] should still find UNION 1,2,'marker'
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
            let decoded = decoded_id(req).to_ascii_lowercase();
            if decoded.contains("order by") {
                return ResponseTemplate::new(200)
                    .set_body_string("SQL error: Unknown column '1' in 'order clause' ORDER BY 1");
            }
            if decoded.contains("union select") {
                let has_three_cols = decoded.contains("1,2,'") || decoded.contains("null,2,'");
                if has_three_cols && let Some(marker) = extract_marker(&decoded) {
                    return ResponseTemplate::new(200).set_body_string(format!(
                        "welcome page injected {marker} success different content extra"
                    ));
                }
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
