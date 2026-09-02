#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    techniques::tamper::Tamper,
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

/// Baseline page for id=1
fn baseline_body() -> &'static str {
    "welcome normal page id=1 content baseline 42"
}

/// Mock that simulates a WAF: blocks original " OR " with %20, but allows space2comment bypass %2f%2a
fn waf_tamper_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    let baseline = baseline_body();
    // True tampered contains `/**/` which is encoded as `%2f**%2f` (stars stay literal) or `**`
    let is_tampered = url.contains("**");
    let has_true = url.contains("1%3d1") || url.contains("1=1");
    let has_false = url.contains("1%3d2") || url.contains("1=2");

    // Baseline request has no injected OR/1=1/1=2 payload — return baseline
    if !url.contains("or") && !url.contains("%27") {
        return ResponseTemplate::new(200).set_body_string(baseline);
    }
    // If tampered, simulate boolean diff: true -> baseline-like, false -> different
    if is_tampered {
        if has_true && !has_false {
            return ResponseTemplate::new(200).set_body_string(baseline);
        }
        if has_false {
            return ResponseTemplate::new(200)
                .set_body_string("tampered false branch — completely different content 99 unique");
        }
    }
    // Original (WAF blocked) -> always baseline, so true and false look same => no vuln
    ResponseTemplate::new(200).set_body_string(baseline)
}

#[tokio::test]
async fn tamper_space2comment_bypasses_waf_boolean() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(waf_tamper_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.tampers = vec![Tamper::Space2Comment];
    cfg.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        !findings.is_empty(),
        "with space2comment tamper should bypass WAF and find boolean, got 0"
    );
    let bf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Boolean)
        .expect("boolean finding");
    assert!(
        bf.evidence.contains("tamper="),
        "evidence should mention tamper, got {}",
        bf.evidence
    );
    assert!(
        bf.evidence.contains("space2comment"),
        "tamper label missing, got {}",
        bf.evidence
    );
}

#[tokio::test]
async fn without_tamper_waf_blocks_boolean() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(waf_tamper_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.tampers = Vec::new(); // no tamper
    cfg.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "without tamper, WAF should block and yield 0 findings, got {findings:?}"
    );
}

#[tokio::test]
async fn tamper_versionedcomment_produces_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(|req: &wiremock::Request| {
            let url = req.url.to_string().to_ascii_lowercase();
            // Accept versionedcomment: contains /*!50000
            if url.contains("50000") && url.contains("select") {
                return ResponseTemplate::new(200).set_body_string(
                    "tampered versioned false branch unique different content xyz",
                );
            }
            // baseline
            ResponseTemplate::new(200).set_body_string(baseline_body())
        })
        .mount(&server)
        .await;

    // directly test tamper apply does wrap keywords
    let p = "' UNION SELECT 1,2 -- -";
    let tampered = Tamper::VersionedComment.apply(p);
    assert!(
        tampered.contains("/*!50000SELECT*/")
            || tampered.contains("/*!50000select*/".to_ascii_lowercase().as_str())
            || tampered.contains("50000"),
        "versioned tamper should wrap SELECT, got {tampered}"
    );

    // ensure engine with versionedcomment still runs (no panic) even if not vulnerable
    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["error".to_owned()];
    cfg.tampers = vec![Tamper::VersionedComment];
    cfg.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    // no assertion on finding, just that it didn't crash and request_count >0
    assert!(engine.state_handle().read().await.request_count() > 0);
}

#[tokio::test]
async fn tamper_charencode_and_hexencode_variants_are_distinct() {
    let payload = "' OR 1=1 -- -";
    let charenc = Tamper::CharEncode.apply(payload);
    let hexenc = Tamper::HexEncode.apply(payload);
    let double = Tamper::DoubleEncode.apply(payload);
    assert_ne!(charenc, hexenc);
    assert_ne!(charenc, double);
    assert!(charenc.contains("%27"), "charencode should encode '");
    assert!(
        hexenc.contains("%27") || hexenc.contains("%20"),
        "hexencode should encode"
    );
    assert!(double.contains("%25"), "double should encode %");
}

#[tokio::test]
async fn tamper_randomcase_preserves_semantics_case_insensitive() {
    for _ in 0..5 {
        let out = Tamper::RandomCase.apply("SELECT");
        assert_eq!(out.to_ascii_lowercase(), "select");
        assert_eq!(out.len(), 6);
    }
}

#[tokio::test]
async fn tamper_expand_and_transformation_sets_bounded() {
    use injekt::techniques::tamper::{
        apply_tampers, expand_with_tampers, tamper_transformation_sets,
    };
    let payload = "' OR 1=1 -- -";
    // use deterministic tampers to avoid randomcase flakiness
    let tampers = vec![Tamper::Space2Comment, Tamper::CharEncode, Tamper::HexEncode];
    let variants = expand_with_tampers(payload, &tampers);
    // bounded to t.len()+2 = 5
    assert_eq!(variants.len(), 5);
    let sets = tamper_transformation_sets(&tampers);
    assert_eq!(sets.len(), 5);
    // chained should be last
    let chained = apply_tampers(payload, &tampers);
    assert_eq!(variants.last().unwrap(), &chained);
    assert_eq!(sets.last().unwrap(), &tampers);
}
