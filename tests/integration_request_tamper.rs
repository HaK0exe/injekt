#![allow(clippy::unwrap_used, clippy::expect_used)]

use http::Method;
use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    recon::parameter::{CandidateMethod, ParamType, ParameterCandidate},
    target::parameters::ParameterLocation,
};
use std::{collections::BTreeMap, time::Duration};
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

/// WAF mock: inspects only the FIRST `id` value (like naive signature WAFs).
/// - first `id` looks malicious (`or` / `%27`) → block → baseline always.
/// - first `id` benign → backend evaluates the LAST `id` value:
///   `1=1` → baseline-like, `1=2` → different.
fn hpp_waf_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    let baseline = baseline_body();
    let query = req.url.query().unwrap_or_default().to_ascii_lowercase();
    let ids: Vec<&str> = query
        .split('&')
        .filter_map(|pair| {
            pair.split_once('=')
                .filter(|(k, _)| *k == "id")
                .map(|(_, v)| v)
        })
        .collect();
    if ids.is_empty() && !url.contains("%27") {
        return ResponseTemplate::new(200).set_body_string(baseline);
    }
    let Some(first) = ids.first() else {
        return ResponseTemplate::new(200).set_body_string(baseline);
    };
    if first.contains("or") || first.contains("%27") {
        // WAF block: true and false look identical.
        return ResponseTemplate::new(200).set_body_string(baseline);
    }
    let last = ids.last().unwrap_or(first);
    if last.contains("1%3d2") || last.contains("1=2") {
        return ResponseTemplate::new(200).set_body_string(different_body());
    }
    ResponseTemplate::new(200).set_body_string(baseline)
}

#[tokio::test]
async fn hpp_bypasses_first_value_waf() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(hpp_waf_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.hpp = true;
    cfg.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        !findings.is_empty(),
        "with --hpp the duplicate should bypass the first-value WAF"
    );
    let bf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Boolean)
        .expect("boolean finding");
    assert!(
        bf.evidence.contains("hpp=true"),
        "evidence should trace hpp, got {}",
        bf.evidence
    );
}

#[tokio::test]
async fn without_hpp_first_value_waf_blocks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(hpp_waf_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.hpp = false;
    cfg.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    let _ = engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "without --hpp the single malicious param is blocked, got {findings:?}"
    );
}

/// WAF mock for chunked: blocks non-chunked bodies, evaluates chunked ones.
/// Backend reads the reassembled form body: `1=1` → baseline, `1=2` → different.
fn chunked_waf_responder(req: &wiremock::Request) -> ResponseTemplate {
    let baseline = baseline_body();
    let is_chunked = req
        .headers
        .get("transfer-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("chunked");
    if !is_chunked {
        return ResponseTemplate::new(200).set_body_string(baseline);
    }
    let body = String::from_utf8_lossy(&req.body).to_ascii_lowercase();
    if body.contains("1%3d2") || body.contains("1=2") {
        return ResponseTemplate::new(200).set_body_string(different_body());
    }
    ResponseTemplate::new(200).set_body_string(baseline)
}

fn body_candidate(server_uri: &str) -> ParameterCandidate {
    let url: url::Url = format!("{server_uri}/login").parse().expect("url");
    let mut fields = BTreeMap::new();
    fields.insert("id".to_owned(), "1".to_owned());
    fields.insert("user".to_owned(), "bob".to_owned());
    ParameterCandidate {
        url,
        method: CandidateMethod::Post,
        param_name: "id".to_owned(),
        location: ParameterLocation::Body,
        param_type: ParamType::Input,
        original_value: "1".to_owned(),
        form_context: Some(injekt::recon::parameter::FormContext {
            source_url: format!("{server_uri}/login").parse().expect("url"),
            fields,
        }),
    }
}

#[tokio::test]
async fn chunked_body_bypasses_content_length_waf() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(chunked_waf_responder)
        .mount(&server)
        .await;
    // Baseline GETs hit the same mock server; answer baseline for non-POST.
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(baseline_body()))
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.chunked = true;
    cfg.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let candidate = body_candidate(&server.uri());
    let _ = engine.run_candidate(&candidate).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        !findings.is_empty(),
        "with --chunked the streamed body should bypass the content-length WAF"
    );
    let bf = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Boolean)
        .expect("boolean finding");
    assert!(
        bf.evidence.contains("chunked=true"),
        "evidence should trace chunked, got {}",
        bf.evidence
    );
}

#[tokio::test]
async fn without_chunked_content_length_waf_blocks_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(chunked_waf_responder)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(baseline_body()))
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.chunked = false;
    cfg.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let candidate = body_candidate(&server.uri());
    let _ = engine.run_candidate(&candidate).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "without --chunked the content-length body is blocked, got {findings:?}"
    );
}

#[tokio::test]
async fn chunked_client_sends_real_chunk_framing() {
    // Direct client check: chunked spec keeps an intact body server-side and
    // the transfer-encoding header is observed.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(|req: &wiremock::Request| {
            let te = req
                .headers
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let body = String::from_utf8_lossy(&req.body).into_owned();
            ResponseTemplate::new(200).set_body_string(format!("te={te} body={body}"))
        })
        .mount(&server)
        .await;

    let client = test_client();
    let cancel = CancellationToken::new();
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert(
        http::header::TRANSFER_ENCODING,
        http::HeaderValue::from_static("chunked"),
    );
    let spec = injekt::http::client::RequestSpec::new(Method::POST, server.uri())
        .with_headers(headers)
        .with_body(b"id=1&user=bob".to_vec());
    let resp = client.send_with_retry(spec, &cancel).await.expect("resp");
    let body = resp.text().await.expect("body");
    assert!(
        body.contains("chunked"),
        "server should see chunked TE, got {body}"
    );
    assert!(
        body.contains("id=1&user=bob"),
        "chunked body must reassemble intact, got {body}"
    );
}
