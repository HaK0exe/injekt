#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
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
        .allow_private(true)
        .build()
        .expect("client build")
}

fn baseline_body() -> &'static str {
    "welcome normal page id=1 content baseline 42"
}

/// Error responder WITH an extractable fragment (0.9, self-sufficient).
fn fragment_responder(req: &wiremock::Request) -> ResponseTemplate {
    let lower = req.url.to_string().to_ascii_lowercase();
    if lower.contains("extractvalue") || lower.contains("updatexml") {
        return ResponseTemplate::new(200)
            .set_body_string("XPATH syntax error: '~5.7.32~' welcome baseline");
    }
    ResponseTemplate::new(200).set_body_string(baseline_body())
}

/// Error responder WITHOUT fragment (0.75) + boolean differential
/// (TRUE→baseline, FALSE→different) so confirmation succeeds.
fn confirm_ok_responder(req: &wiremock::Request) -> ResponseTemplate {
    let lower = req.url.to_string().to_ascii_lowercase();
    if lower.contains("extractvalue") || lower.contains("updatexml") {
        return ResponseTemplate::new(200)
            .set_body_string("XPATH syntax error occurred welcome baseline");
    }
    // FALSE branch marker `='2'` (encoded `%3d%272`) must win over TRUE:
    // both contain `%20`/`%27` digits, only the `=`-context disambiguates.
    if lower.contains("%3d%272") || lower.contains("='2'") || lower.contains("1%3d2") {
        return ResponseTemplate::new(200)
            .set_body_string("completely different false branch content 99 unique");
    }
    if lower.contains("%3d%271") || lower.contains("='1'") || lower.contains("1%3d1") {
        return ResponseTemplate::new(200).set_body_string(baseline_body());
    }
    ResponseTemplate::new(200).set_body_string(baseline_body())
}

/// Error responder WITHOUT fragment (0.75) and NO boolean differential
/// (both branches return baseline) so confirmation is denied.
fn confirm_denied_responder(req: &wiremock::Request) -> ResponseTemplate {
    let lower = req.url.to_string().to_ascii_lowercase();
    if lower.contains("extractvalue") || lower.contains("updatexml") {
        return ResponseTemplate::new(200)
            .set_body_string("XPATH syntax error occurred welcome baseline");
    }
    ResponseTemplate::new(200).set_body_string(baseline_body())
}

fn error_findings(
    findings: &[injekt::session::state::Finding],
) -> Vec<&injekt::session::state::Finding> {
    findings
        .iter()
        .filter(|f| f.technique == TechniqueKind::Error)
        .collect()
}

#[tokio::test]
async fn error_with_fragment_pushes_direct_without_confirm() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(fragment_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["error".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let errors = error_findings(&findings);
    assert_eq!(
        errors.len(),
        1,
        "expected 1 error finding, got {findings:?}"
    );
    let f = errors[0];
    assert!(
        (f.confidence - 0.9).abs() < f64::EPSILON,
        "fragment hit stays 0.9, got {} {:?}",
        f.confidence,
        f.evidence
    );
    assert!(f.evidence.contains("extracted=yes"), "{}", f.evidence);
    assert!(
        f.evidence.contains("bool_confirm=skipped(fragment)"),
        "{}",
        f.evidence
    );
}

#[tokio::test]
async fn error_without_fragment_confirmed_upgrades_to_09() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(confirm_ok_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["error".to_owned(), "boolean".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let errors = error_findings(&findings);
    assert_eq!(
        errors.len(),
        1,
        "expected 1 error finding, got {findings:?}"
    );
    let f = errors[0];
    assert!(
        (f.confidence - 0.9).abs() < f64::EPSILON,
        "confirmed 0.75 upgrades to 0.9, got {} {:?}",
        f.confidence,
        f.evidence
    );
    assert!(f.evidence.contains("bool_confirm=true"), "{}", f.evidence);
    assert!(!f.evidence.contains("unconfirmed"), "{}", f.evidence);
}

#[tokio::test]
async fn error_without_fragment_denied_degrades_to_055_unconfirmed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(confirm_denied_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["error".to_owned(), "boolean".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let errors = error_findings(&findings);
    assert_eq!(
        errors.len(),
        1,
        "expected 1 error finding, got {findings:?}"
    );
    let f = errors[0];
    assert!(
        (f.confidence - 0.55).abs() < f64::EPSILON,
        "denied 0.75 degrades to 0.55, got {} {:?}",
        f.confidence,
        f.evidence
    );
    assert!(f.evidence.contains("bool_confirm=false"), "{}", f.evidence);
    assert!(f.evidence.contains("unconfirmed"), "{}", f.evidence);
}

/// Blocking Cloudflare baseline (cf-ray + managed challenge on clean
/// requests) downgrades even a fragment-backed error hit 0.9 → 0.6.
fn waf_blocking_responder(req: &wiremock::Request) -> ResponseTemplate {
    let lower = req.url.to_string().to_ascii_lowercase();
    if lower.contains("extractvalue") || lower.contains("updatexml") {
        return ResponseTemplate::new(200)
            .insert_header("cf-ray", "test-ray-IAD")
            .set_body_string("XPATH syntax error: '~5.7.32~' welcome baseline");
    }
    ResponseTemplate::new(200)
        .insert_header("cf-ray", "test-ray-IAD")
        .set_body_string(
            "<html><head><title>Just a moment...</title></head><body>managed challenge</body></html>",
        )
}

#[tokio::test]
async fn blocking_waf_baseline_downgrades_fragment_hit_to_06() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(waf_blocking_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["error".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let errors = error_findings(&findings);
    assert_eq!(
        errors.len(),
        1,
        "expected 1 error finding, got {findings:?}"
    );
    let f = errors[0];
    assert!(
        (f.confidence - 0.6).abs() < f64::EPSILON,
        "blocking WAF downgrades 0.9 to 0.6, got {} {:?}",
        f.confidence,
        f.evidence
    );
    assert!(f.evidence.contains("extracted=yes"), "{}", f.evidence);
    assert!(f.evidence.contains("waf=cloudflare"), "{}", f.evidence);
    assert!(f.evidence.contains("blocking=true"), "{}", f.evidence);
}

/// A normal response passing through Cloudflare is presence-only: it must not
/// rewrite probes or downgrade a valid finding.
fn cloudflare_presence_responder(req: &wiremock::Request) -> ResponseTemplate {
    let lower = req.url.to_string().to_ascii_lowercase();
    let body = if lower.contains("extractvalue") || lower.contains("updatexml") {
        "XPATH syntax error: '~5.7.32~' welcome baseline"
    } else {
        baseline_body()
    };
    ResponseTemplate::new(200)
        .insert_header("cf-ray", "test-ray-IAD")
        .set_body_string(body)
}

#[tokio::test]
async fn cloudflare_presence_does_not_auto_tamper_or_downgrade() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(cloudflare_presence_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["error".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let engine = Engine::new(cfg, client, CancellationToken::new());
    let target = format!("{}/?id=1", server.uri());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let errors = error_findings(&findings);
    assert_eq!(errors.len(), 1, "expected 1 error finding: {findings:?}");
    let finding = errors[0];
    assert!((finding.confidence - 0.9).abs() < f64::EPSILON);
    assert!(
        finding.evidence.contains("tamper=none"),
        "{}",
        finding.evidence
    );
    assert!(
        finding.evidence.contains("waf=cloudflare") && finding.evidence.contains("blocking=false"),
        "{}",
        finding.evidence
    );
}
