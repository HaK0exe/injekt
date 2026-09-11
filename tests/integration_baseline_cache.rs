#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    recon::{BaselineCache, CandidateMethod, ParamType, ParameterCandidate},
    target::{parameters::ParameterLocation, raw_request::RawRequest, url::TargetUrl},
};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn fast_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(0.0, 0.0))
        .rate_limiter(Arc::new(RateLimiter::new(1_000.0)))
        .allow_private(true)
        .build()
        .expect("client build")
}

fn fast_cfg() -> EngineConfig {
    let mut cfg = EngineConfig::test_defaults();
    // No detection payloads + no context DBMS probes: only baseline (+
    // fingerprint no-op) hits the mock, so the test stays fast and the
    // baseline saving is observable via `BaselineCache::len`.
    cfg.techniques = Vec::new();
    cfg.dbms_hint = Some("mysql".to_owned());
    cfg
}

fn candidate_for(url: &str, param_name: &str) -> ParameterCandidate {
    ParameterCandidate {
        url: url.parse().expect("candidate url"),
        method: CandidateMethod::Get,
        param_name: param_name.to_owned(),
        location: ParameterLocation::Query,
        param_type: ParamType::Input,
        original_value: "1".to_owned(),
        form_context: None,
    }
}

#[test]
fn baseline_cache_key_groups_by_origin() {
    let a = TargetUrl::parse("http://example.com/search?q=1", true).expect("url a");
    let b = TargetUrl::parse("http://example.com/search?q=2", true).expect("url b");
    // No raw: same host+port+scheme share, query is ignored.
    assert_eq!(
        BaselineCache::cache_key(&a, None),
        BaselineCache::cache_key(&b, None)
    );

    let other_port =
        TargetUrl::parse("http://example.com:8080/search?q=1", true).expect("other port");
    assert_ne!(
        BaselineCache::cache_key(&a, None),
        BaselineCache::cache_key(&other_port, None)
    );

    let other_scheme =
        TargetUrl::parse("https://example.com/search?q=1", true).expect("other scheme");
    assert_ne!(
        BaselineCache::cache_key(&a, None),
        BaselineCache::cache_key(&other_scheme, None)
    );
}

#[test]
fn baseline_cache_key_raw_hash_ignores_path_shares_get() {
    let target = TargetUrl::parse("http://example.com/", true).expect("target");
    let raw_get_a =
        RawRequest::parse("GET /search?q=1 HTTP/1.1\nHost: example.com\n\n").expect("raw a");
    let raw_get_b =
        RawRequest::parse("GET /other?q=2 HTTP/1.1\nHost: example.com\n\n").expect("raw b");
    // Same GET shape, different paths: same key (host-level sharing).
    assert_eq!(
        BaselineCache::cache_key(&target, Some(&raw_get_a)),
        BaselineCache::cache_key(&target, Some(&raw_get_b))
    );

    let raw_post = RawRequest::parse(
        "POST /search?q=1 HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\na=1",
    )
    .expect("raw post");
    assert_ne!(
        BaselineCache::cache_key(&target, Some(&raw_get_a)),
        BaselineCache::cache_key(&target, Some(&raw_post))
    );
}

#[tokio::test]
async fn recon_ten_candidates_same_host_single_baseline() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("baseline body stable"))
        .mount(&server)
        .await;

    let base = format!("{}/search?q=1", server.uri());
    let candidates: Vec<ParameterCandidate> = (0..10)
        .map(|i| candidate_for(&base, &format!("p{i}")))
        .collect();

    let cache = Arc::new(BaselineCache::new());
    let client = fast_client();
    let cancel = CancellationToken::new();

    // Sequential like `scan_candidates` with `threads=1`: the first candidate
    // collects the 3-sample baseline, the 9 others must hit the cache.
    // Without the cache: 10 candidates x 3 req = 30 baseline requests.
    // With the cache: 1 x 3 req = 3 baseline requests (-27 req).
    for candidate in &candidates {
        let cfg = fast_cfg();
        let engine = Engine::new(cfg, client.clone(), cancel.clone())
            .with_baseline_cache(Arc::clone(&cache));
        engine
            .run_candidate(candidate)
            .await
            .expect("engine run_candidate");
    }

    assert_eq!(
        cache.len().await,
        1,
        "10 candidates on the same host must share a single cached baseline"
    );
}
