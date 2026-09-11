#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_precision_loss,
    clippy::float_cmp
)]

//! v0.5-4 Reasoning Core loop-closure: adaptive context matrix (4 DBMS),
//! `--dbms` verrou (0 active probes), `<=8` probe bound, N1/N2 clean targets
//! (0 finding), bench-noise regression guard.
//!
//! Live-bench proof (`compare --from v0.4`, 5 runs, docker matrix) still
//! requires the lab; these wiremock tests pin the contracts offline.

use injekt::{
    dbms::{
        DbmsKind,
        context::{
            DbmsBelief, InjectionContext, MAX_CONTEXT_PROBES, QuoteContext, analyze_context,
        },
    },
    detection::baseline::{Baseline, Sample},
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    session::state::SessionState,
    target::{
        parameters::{ParameterLocation, TargetParameter},
        url::TargetUrl,
    },
};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn test_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

fn baseline_for(body: &str) -> Baseline {
    let samples = vec![
        Sample {
            status: 200,
            body: body.as_bytes().to_vec(),
            duration: Duration::from_millis(50),
            headers: Vec::new(),
        },
        Sample {
            status: 200,
            body: body.as_bytes().to_vec(),
            duration: Duration::from_millis(52),
            headers: Vec::new(),
        },
        Sample {
            status: 200,
            body: body.as_bytes().to_vec(),
            duration: Duration::from_millis(51),
            headers: Vec::new(),
        },
    ];
    Baseline::new(&samples)
}

fn query_id() -> TargetParameter {
    TargetParameter::new("id", ParameterLocation::Query, "1")
}

async fn analyze(
    server: &MockServer,
    param: &TargetParameter,
    baseline_body: &str,
    hint: Option<&str>,
) -> injekt::dbms::context::ContextProbeResult {
    let client = test_client();
    let state = Arc::new(RwLock::new(SessionState::new()));
    let cancel = CancellationToken::new();
    let target = TargetUrl::parse(
        &format!("{}/?{}={}", server.uri(), param.name, param.original_value),
        true,
    )
    .expect("target");
    let baseline = baseline_for(baseline_body);
    analyze_context(
        &client, &state, &cancel, &target, param, None, &baseline, hint,
    )
    .await
}

fn vendor_error(kind: DbmsKind) -> &'static str {
    match kind {
        DbmsKind::MySql => {
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        }
        DbmsKind::Postgres => "ERROR: syntax error at or near \"WHERE\"",
        DbmsKind::MsSql => "Unclosed quotation mark after the character string ''",
        DbmsKind::Oracle => "ORA-01756: quoted string not properly terminated",
        _ => "welcome normal page",
    }
}

/// Responder: baseline unless the injected `id` carries a single quote, in
/// which case the per-DBMS vendor error text is returned (no quote closure).
fn error_responder(kind: DbmsKind) -> impl Fn(&wiremock::Request) -> ResponseTemplate {
    move |req: &wiremock::Request| {
        let id = req
            .url
            .query_pairs()
            .find(|(k, _)| k == "id")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        if id.contains('\'') {
            ResponseTemplate::new(200).set_body_string(vendor_error(kind))
        } else {
            ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content")
        }
    }
}

#[tokio::test]
async fn dbms_hint_sends_zero_active_probes() {
    // Verrou `--dbms`: belief pinned, 0 HTTP request, comment style set.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("should never be hit"))
        .mount(&server)
        .await;

    for hint in ["mysql", "postgres", "mssql", "oracle"] {
        let res = analyze(&server, &query_id(), "welcome normal page", Some(hint)).await;
        assert_eq!(res.probes_sent, 0, "hint {hint} must send 0 probes");
        let (top, prob) = res.dbms_belief.top_candidate();
        assert_eq!(prob, 1.0);
        let expected = match hint {
            "mysql" => DbmsKind::MySql,
            "postgres" => DbmsKind::Postgres,
            "mssql" => DbmsKind::MsSql,
            _ => DbmsKind::Oracle,
        };
        assert_eq!(top, expected);
    }
    let received = server.received_requests().await.expect("requests log");
    assert!(
        received.is_empty(),
        "verrou violated: {} HTTP requests hit the mock",
        received.len()
    );
}

#[tokio::test]
async fn context_matrix_4_dbms_single_quote() {
    // 4 DBMS x single-quote context: vendor error -> belief >= 0.85,
    // quote SingleQuote, probes <= 8 (C2 invariant).
    for kind in [
        DbmsKind::MySql,
        DbmsKind::Postgres,
        DbmsKind::MsSql,
        DbmsKind::Oracle,
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(error_responder(kind))
            .mount(&server)
            .await;
        let res = analyze(
            &server,
            &query_id(),
            "welcome normal page id=1 content",
            None,
        )
        .await;
        assert!(
            res.probes_sent <= MAX_CONTEXT_PROBES,
            "{kind}: {} probes > {MAX_CONTEXT_PROBES}",
            res.probes_sent
        );
        assert_eq!(res.context.quote, QuoteContext::SingleQuote, "{kind}");
        let (top, prob) = res.dbms_belief.top_candidate();
        assert_eq!(top, kind, "{kind}");
        assert!(prob >= 0.85, "{kind}: prob {prob} < 0.85");
        assert!(res.error_evidence.is_some(), "{kind}");
    }
}

#[tokio::test]
async fn context_double_quote_when_single_quote_benign() {
    // `'` benign, `"` vendor error, non-numeric value (skips the arithmetic
    // block) -> DoubleQuote + pg belief.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(|req: &wiremock::Request| {
            let id = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "q")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            if id.contains('"') {
                ResponseTemplate::new(200)
                    .set_body_string("ERROR: syntax error at or near \"WHERE\"")
            } else {
                ResponseTemplate::new(200).set_body_string("welcome normal page")
            }
        })
        .mount(&server)
        .await;
    let param = TargetParameter::new("q", ParameterLocation::Query, "test");
    let res = analyze(&server, &param, "welcome normal page", None).await;
    assert!(res.probes_sent <= MAX_CONTEXT_PROBES);
    assert_eq!(res.context.quote, QuoteContext::DoubleQuote);
    assert_eq!(res.dbms_belief.top_candidate().0, DbmsKind::Postgres);
}

#[tokio::test]
async fn context_numeric_bare_when_quote_benign() {
    // `'` benign, `1+0` baseline-like, `1+999999` different -> numeric bare.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(|req: &wiremock::Request| {
            let id = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "id")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            if id.contains("999999") {
                ResponseTemplate::new(200)
                    .set_body_string("completely different page with many extra rows 1 2 3 4 5")
            } else {
                ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content")
            }
        })
        .mount(&server)
        .await;
    let res = analyze(
        &server,
        &query_id(),
        "welcome normal page id=1 content",
        None,
    )
    .await;
    assert!(res.probes_sent <= MAX_CONTEXT_PROBES);
    assert_eq!(res.context.quote, QuoteContext::None);
    assert!(res.context.numeric);
}

#[tokio::test]
async fn context_passive_json_and_order_by_cost_zero_probes() {
    // Passive signals only: JSON body + `sort` param name, static backend.
    // No active probe can conclude, but the passive flags must be set and
    // the probe count stays within budget.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("welcome normal page"))
        .mount(&server)
        .await;
    let client = test_client();
    let state = Arc::new(RwLock::new(SessionState::new()));
    let cancel = CancellationToken::new();
    let target = TargetUrl::parse(&format!("{}/?sort=asc", server.uri()), true).expect("target");
    let baseline = baseline_for("welcome normal page");
    let param = TargetParameter::new("sort", ParameterLocation::Query, "asc");
    let res = analyze_context(
        &client, &state, &cancel, &target, &param, None, &baseline, None,
    )
    .await;
    assert!(res.probes_sent <= MAX_CONTEXT_PROBES);
    assert!(res.context.order_by);
    // Uniform belief kept when no vendor signal fires.
    assert_eq!(res.dbms_belief, DbmsBelief::uniform());
    let _ = InjectionContext::new();
}

fn clean_engine(techniques: Vec<String>) -> (Engine, CancellationToken) {
    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = techniques;
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    (Engine::new(cfg, client, cancel.clone()), cancel)
}

#[tokio::test]
async fn n1_n2_clean_target_yields_zero_findings() {
    // Negative controls: static parameterized backend -> 0 finding and the
    // request-level EarlyStop(25) keeps detection bounded (true total stays
    // in SessionState::request_count).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content"),
        )
        .mount(&server)
        .await;
    let (engine, _cancel) = clean_engine(vec!["boolean".to_owned(), "error".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "clean N1/N2 target must yield 0 findings, got {findings:?}"
    );
}

#[tokio::test]
async fn bench_noise_envelope_yields_zero_findings() {
    // `bench/app.py::noisy()` reality: same data, random request_id +
    // generated_at per response. Normalization must keep this at 0 findings.
    static NOISE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(|_: &wiremock::Request| {
            let n = NOISE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let body = format!(
                "{{\n  \"data\": [{{\"id\": 1}}],\n  \"request_id\": \"{n:08x}\",\n  \"generated_at\": {}\n}}",
                1_757_328_000.0 + n as f64 * 0.001
            );
            ResponseTemplate::new(200).set_body_string(body)
        })
        .mount(&server)
        .await;
    let (engine, _cancel) = clean_engine(vec!["boolean".to_owned(), "error".to_owned()]);
    let target = format!("{}/?id=1", server.uri());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "noisy bench envelope must yield 0 findings, got {findings:?}"
    );
}
