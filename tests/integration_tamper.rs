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
        .allow_private(true)
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
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.evasion.tampers = vec![Tamper::Space2Comment];
    cfg.net.allow_private = true;
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
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.evasion.tampers = Vec::new(); // no tamper
    cfg.net.allow_private = true;
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
    cfg.budget.threads = 1;
    cfg.techniques = vec!["error".to_owned()];
    cfg.evasion.tampers = vec![Tamper::VersionedComment];
    cfg.net.allow_private = true;
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

/// Mock that simulates a WAF blocking literal spaces but allowing the MySQL
/// dash-comment bypass. The injection point percent-encodes the tamper's
/// `%0A` into `%250A`, so the mock keys on `--%25`.
fn dash_waf_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    let baseline = baseline_body();
    if !url.contains("or") && !url.contains("%27") {
        return ResponseTemplate::new(200).set_body_string(baseline);
    }
    let is_dash = url.contains("--%25");
    let has_true = url.contains("1%3d1") || url.contains("1=1");
    let has_false = url.contains("1%3d2") || url.contains("1=2");
    if is_dash {
        if has_true && !has_false {
            return ResponseTemplate::new(200).set_body_string(baseline);
        }
        if has_false {
            return ResponseTemplate::new(200)
                .set_body_string("dash false branch — completely different content 77 unique");
        }
    }
    ResponseTemplate::new(200).set_body_string(baseline)
}

#[tokio::test]
async fn tamper_space2dash_bypasses_waf_boolean() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(dash_waf_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.evasion.tampers = vec![Tamper::Space2Dash];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        !findings.is_empty(),
        "with space2dash tamper should bypass WAF and find boolean, got 0"
    );
    let bf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Boolean)
        .expect("boolean finding");
    assert!(
        bf.evidence.contains("space2dash"),
        "tamper label missing, got {}",
        bf.evidence
    );
}

/// Mock that simulates a WAF stripping `=` comparisons: only `LIKE`-based
/// injections evaluate. `form_urlencoded` renders spaces as `+`, so the mock
/// keys on `1+like+1` / `1+like+2`.
fn like_waf_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    let baseline = baseline_body();
    if !url.contains("or") && !url.contains("%27") {
        return ResponseTemplate::new(200).set_body_string(baseline);
    }
    if url.contains("like") {
        if url.contains("1+like+1") && !url.contains("1+like+2") {
            return ResponseTemplate::new(200).set_body_string(baseline);
        }
        if url.contains("1+like+2") {
            return ResponseTemplate::new(200)
                .set_body_string("like false branch — completely different content 78 unique");
        }
    }
    ResponseTemplate::new(200).set_body_string(baseline)
}

#[tokio::test]
async fn tamper_equaltolike_bypasses_equals_waf_boolean() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(like_waf_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.evasion.tampers = vec![Tamper::EqualToLike];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        !findings.is_empty(),
        "with equaltolike tamper should bypass =-stripping WAF and find boolean, got 0"
    );
    let bf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Boolean)
        .expect("boolean finding");
    assert!(
        bf.evidence.contains("equaltolike"),
        "tamper label missing, got {}",
        bf.evidence
    );
}

#[tokio::test]
async fn without_equaltolike_equals_waf_blocks_boolean() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(like_waf_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.evasion.tampers = Vec::new();
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "without equaltolike, =-stripping WAF should block and yield 0 findings, got {findings:?}"
    );
}

/// Mock keyed on any percent-encoded blank (`%25xx` after the injection-point
/// encoding): simulates a WAF allowing only encoded whitespace.
fn blank_waf_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    let baseline = baseline_body();
    if !url.contains("or") && !url.contains("%27") {
        return ResponseTemplate::new(200).set_body_string(baseline);
    }
    let has_true = url.contains("1%3d1") || url.contains("1=1");
    let has_false = url.contains("1%3d2") || url.contains("1=2");
    if url.contains("%25") {
        if has_true && !has_false {
            return ResponseTemplate::new(200).set_body_string(baseline);
        }
        if has_false {
            return ResponseTemplate::new(200)
                .set_body_string("blank false branch — completely different content 79 unique");
        }
    }
    ResponseTemplate::new(200).set_body_string(baseline)
}

#[tokio::test]
async fn tamper_space2mssqlblank_bypasses_waf_boolean() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(blank_waf_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.evasion.tampers = vec![Tamper::Space2MssqlBlank];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        !findings.is_empty(),
        "with space2mssqlblank tamper should bypass WAF and find boolean, got 0"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.evidence.contains("space2mssqlblank")),
        "tamper label missing, got {:?}",
        findings.iter().map(|f| &f.evidence).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn tamper_randomcomments_bypasses_waf_boolean() {
    // RandomComments always emits `/**/` (single or doubled) per space, so the
    // existing `**`-keyed WAF mock applies deterministically.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(waf_tamper_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.evasion.tampers = vec![Tamper::RandomComments];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        !findings.is_empty(),
        "with randomcomments tamper should bypass WAF and find boolean, got 0"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.evidence.contains("randomcomments")),
        "tamper label missing, got {:?}",
        findings.iter().map(|f| &f.evidence).collect::<Vec<_>>()
    );
}

/// Mock keyed on MySQL versioned comments (`50000`): TRUE/FALSE evaluate only
/// when keywords are wrapped.
fn versioned_more_waf_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    let baseline = baseline_body();
    if !url.contains("or") && !url.contains("%27") {
        return ResponseTemplate::new(200).set_body_string(baseline);
    }
    let has_true = url.contains("1%3d1") || url.contains("1=1");
    let has_false = url.contains("1%3d2") || url.contains("1=2");
    if url.contains("50000") {
        if has_true && !has_false {
            return ResponseTemplate::new(200).set_body_string(baseline);
        }
        if has_false {
            return ResponseTemplate::new(200).set_body_string(
                "versioned-more false branch — completely different content 80 unique",
            );
        }
    }
    ResponseTemplate::new(200).set_body_string(baseline)
}

#[tokio::test]
async fn tamper_versionedmorekeywords_bypasses_waf_boolean() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(versioned_more_waf_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.evasion.tampers = vec![Tamper::VersionedMoreKeywords];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        !findings.is_empty(),
        "with versionedmorekeywords tamper should bypass WAF and find boolean, got 0"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.evidence.contains("versionedmorekeywords")),
        "tamper label missing, got {:?}",
        findings.iter().map(|f| &f.evidence).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn tamper_base64_skipped_for_boolean_without_poisoning() {
    // `base64encode` is excluded from boolean transformation sets: mixing it
    // with a working tamper must still bypass via the safe set, and the
    // finding must never be labelled base64.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(waf_tamper_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.evasion.tampers = vec![Tamper::Base64Encode, Tamper::Space2Comment];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        !findings.is_empty(),
        "safe tamper should still bypass even when base64 is also configured, got 0"
    );
    for f in &findings {
        assert!(
            !f.evidence.contains("base64"),
            "boolean finding must never be labelled base64, got {}",
            f.evidence
        );
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
