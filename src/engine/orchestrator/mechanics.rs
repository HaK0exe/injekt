//! Pipeline-adjacent mechanics tests (ex `orchestrator_gating_tests`, P5
//! split): all-5xx baseline warn, scheduler TTFB scaling, concurrent
//! baseline over Wiremock, WAF auto-tamper resolution, app-filter gate and
//! header/cookie injection-spec representability rules.

use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    reasoning::Hypothesis,
    session::state::TechniqueKind,
};

#[test]
fn baseline_all_error_only_on_full_5xx() {
    // Live case: `[520, 520, 520]` (CF origin-unreachable) must warn.
    assert!(super::baseline_all_error(&[520, 520, 520]));
    assert!(super::baseline_all_error(&[500]));
    assert!(super::baseline_all_error(&[500, 503, 524]));
    // Healthy or mixed baselines must not warn.
    assert!(!super::baseline_all_error(&[200, 200, 200]));
    assert!(!super::baseline_all_error(&[200, 520, 520]));
    assert!(!super::baseline_all_error(&[403, 403, 403]));
    assert!(!super::baseline_all_error(&[]));
}

#[test]
fn scheduler_ttfb_static_by_default_and_dynamic_when_slow() {
    use crate::detection::scanner::scheduler::{cost_for, cost_for_with_ttfb};
    use crate::engine::schedule::build_scheduler_for_param;
    let cfg = super::EngineConfig::default();
    let hyps: Vec<Hypothesis> = vec![
        Hypothesis::new(
            "id@query".to_owned(),
            TechniqueKind::Boolean,
            DbmsBelief::uniform(),
            InjectionContext::new(),
        ),
        Hypothesis::new(
            "id@query".to_owned(),
            TechniqueKind::Time,
            DbmsBelief::uniform(),
            InjectionContext::new(),
        ),
    ];
    // mean 0 => static costs (L1 byte-identical).
    let sched = build_scheduler_for_param(&cfg, "id@query", &hyps, 0, 0.0);
    assert_eq!(sched.len(), 2);
    let base_time = cost_for(TechniqueKind::Time);
    assert!((cost_for_with_ttfb(base_time, 0.0) - base_time).abs() < 1e-12);
    // mean 5s => time cost doubles (3.0 -> 6.0), boolean stays 1.0.
    let scaled = cost_for_with_ttfb(base_time, 5000.0);
    assert!((scaled - 6.0).abs() < 1e-12);
    let sched_slow = build_scheduler_for_param(&cfg, "id@query", &hyps, 0, 5000.0);
    assert_eq!(sched_slow.len(), 2);
}

#[tokio::test]
async fn baseline_concurrent_returns_three_samples() {
    use crate::{
        engine::orchestrator::{Engine, EngineConfig},
        http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
        target::url::TargetUrl,
    };
    use std::{sync::Arc, time::Duration};
    use tokio_util::sync::CancellationToken;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("baseline-ok"))
        .mount(&server)
        .await;

    let client = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build");
    let cfg = EngineConfig::test_defaults();
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = TargetUrl::parse(&format!("{}/?id=1", server.uri()), true).expect("target parse");
    let collected = crate::engine::baseline::collect_baseline_uncached(
        &engine.client,
        &engine.state,
        &engine.cancel,
        &engine.config,
        &engine.scrubber,
        &target,
        None,
    )
    .await
    .expect("baseline ok")
    .expect("some baseline");
    let (baseline, _, _) = collected;
    assert_eq!(
        baseline.status_codes.len(),
        3,
        "concurrent baseline must return 3 samples"
    );
    assert!(baseline.status_codes.iter().all(|c| *c == 200));
}

#[test]
fn waf_auto_tampers_are_space2comment_plus_randomcase() {
    use crate::techniques::tamper::Tamper;
    assert_eq!(
        super::waf_auto_tampers(),
        vec![Tamper::Space2Comment, Tamper::RandomCase]
    );
    // Blocking + no user tampers => auto-pair (never HPP/chunked here).
    assert_eq!(
        super::resolve_effective_tampers(true, &[]),
        vec![Tamper::Space2Comment, Tamper::RandomCase]
    );
    // Explicit user tampers always win, even when blocking.
    let user = vec![Tamper::VersionedComment];
    assert_eq!(super::resolve_effective_tampers(true, &user), user);
    // No block => user set unchanged (including empty).
    assert_eq!(
        super::resolve_effective_tampers(false, &[]),
        [] as [Tamper; 0]
    );
}

#[test]
fn app_filter_block_needs_double_400() {
    assert!(super::is_app_filter_block(400, 400));
    assert!(!super::is_app_filter_block(400, 200));
    assert!(!super::is_app_filter_block(200, 400));
    assert!(!super::is_app_filter_block(200, 200));
    // WAF statuses never count as app filter (separate gate).
    assert!(!super::is_app_filter_block(403, 403));
    assert!(!super::is_app_filter_block(406, 406));
    assert_eq!(super::APP_FILTER_STATUS, 400);
    assert_eq!(super::FILTER_STREAK_LIMIT, 3);
}

#[test]
fn injection_spec_rejects_unrepresentable_header_cookie_values() {
    use super::{ProbeOpts, build_injection_spec_with_raw};
    use crate::{
        target::{
            markers::MarkerSet,
            parameters::{ParameterLocation, TargetParameter},
            url::TargetUrl,
        },
        techniques::payload_opts::PayloadOpts,
    };
    let target = TargetUrl::parse("http://example.com/?id=1", true).unwrap();
    let markers = MarkerSet::default();
    let popts = PayloadOpts::default();
    let opts = ProbeOpts::new(false, false);
    // Header injection with a newline-bearing payload (e.g. a
    // `space2newline` tamper) cannot travel in an HTTP header value:
    // the probe must be skipped (`None`), never sent un-injected and
    // scored as a negative trial (silent false negative).
    let header = TargetParameter::new(
        "X-Forwarded-For",
        ParameterLocation::Header("X-Forwarded-For".to_owned()),
        "1.2.3.4",
    );
    assert!(
        build_injection_spec_with_raw(
            &target,
            target.as_str(),
            &header,
            "' OR 1=1--",
            &markers,
            None,
            opts,
            &popts,
        )
        .is_some()
    );
    assert!(
        build_injection_spec_with_raw(
            &target,
            target.as_str(),
            &header,
            "' OR\n1=1--",
            &markers,
            None,
            opts,
            &popts,
        )
        .is_none()
    );
    // Same fail-closed rule for cookie injection.
    let cookie = TargetParameter::new("sess", ParameterLocation::Cookie, "abc");
    assert!(
        build_injection_spec_with_raw(
            &target,
            target.as_str(),
            &cookie,
            "' OR 1=1--",
            &markers,
            None,
            opts,
            &popts,
        )
        .is_some()
    );
    assert!(
        build_injection_spec_with_raw(
            &target,
            target.as_str(),
            &cookie,
            "x\r\nInjected: 1",
            &markers,
            None,
            opts,
            &popts,
        )
        .is_none()
    );
    // Query/body locations are unaffected (percent-encoded into URL/body,
    // always representable).
    let query = TargetParameter::new("id", ParameterLocation::Query, "1");
    assert!(
        build_injection_spec_with_raw(
            &target,
            target.as_str(),
            &query,
            "' OR\n1=1--",
            &markers,
            None,
            opts,
            &popts,
        )
        .is_some()
    );
}
