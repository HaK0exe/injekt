#![allow(clippy::unwrap_used, clippy::expect_used)]

//! C10-partiel (v0.6-3): isolated `time` pool, per-class timeouts, `429` +
//! `Retry-After` honoring with per-run detectability counters, seeded jitter
//! with the 200ms OPSEC floor, and graceful `CancellationToken` behaviour
//! (zero orphaned pool permits).

use http::Method;
use injekt::{
    cli::client_builder::jitter_from_str,
    engine::{Engine, EngineConfig},
    http::{
        client::{HttpClient, RequestSpec},
        jitter::Jitter,
        rate_limit::RateLimiter,
        timeouts::{ClassTimeouts, RequestClass, TIME_POOL_SLOTS},
    },
    session::state::Detectability,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

/// Fast lab client: no pacing, deterministic seed, generous base timeout
/// (default class 30s → `boolean` 10s, `time` 15s per C10).
fn fast_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(30))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(Arc::new(RateLimiter::disabled()))
        .seed(Some(42))
        .allow_private(true)
        .build()
        .expect("client build")
}

fn get(url: String) -> RequestSpec {
    RequestSpec::new(Method::GET, url)
}

/// C10 isolation: 4 slow `time`-class probes over the 2-slot pool must not
/// starve a `boolean`-class probe, and at most 2 `time` probes overlap.
#[tokio::test]
async fn time_pool_does_not_starve_boolean() {
    assert_eq!(TIME_POOL_SLOTS, 2);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(|req: &wiremock::Request| {
            if req.url.as_str().contains("/slow") {
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(2))
                    .set_body_string("slow")
            } else {
                ResponseTemplate::new(200).set_body_string("fast")
            }
        })
        .mount(&server)
        .await;

    let client = fast_client();
    let cancel = CancellationToken::new();
    let slow = format!("{}/slow", server.uri());
    let fast = format!("{}/fast", server.uri());

    let t0 = Instant::now();
    let mut time_tasks = Vec::new();
    for _ in 0..4 {
        let client = client.clone();
        let cancel = cancel.clone();
        let url = slow.clone();
        time_tasks.push(tokio::spawn(async move {
            let start = Instant::now();
            let res = client
                .send_with_retry_for_class(get(url), RequestClass::Time, &cancel)
                .await;
            (start.elapsed(), res.map(|r| r.status().as_u16()))
        }));
    }
    // The boolean probe starts while all 4 slow time probes are queued/running.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let bool_start = Instant::now();
    let bool_res = client
        .send_with_retry_for_class(get(fast), RequestClass::Boolean, &cancel)
        .await;
    let bool_elapsed = bool_start.elapsed();
    assert_eq!(bool_res.expect("boolean probe").status(), 200);
    assert!(
        bool_elapsed < Duration::from_millis(1500),
        "boolean must bypass the slow time pool, took {bool_elapsed:?}"
    );

    let mut intervals = Vec::new();
    for task in time_tasks {
        let (offset, res) = task.await.expect("time task join");
        assert_eq!(res.expect("time probe"), 200);
        intervals.push(offset);
    }
    let total = t0.elapsed();
    // 4 × 2s over 2 slots serializes to ~4s; without the pool it would be ~2s.
    assert!(
        total >= Duration::from_secs(3),
        "time pool must serialize slow probes, total={total:?}"
    );

    // Max overlap of the 2s server phases must respect the 2 slots. Each
    // task's measured span covers its server delay; the 3rd/4th task cannot
    // have started its delay before ~2s.
    let mut starts: Vec<Duration> = intervals;
    starts.sort();
    assert!(
        starts[2] >= Duration::from_millis(1500),
        "3rd time probe must wait for a pool slot, starts={starts:?}"
    );
}

/// C10 per-class timeouts: `boolean` 10s / `time` 15s / `oob`+default base.
#[tokio::test]
async fn class_timeouts_apply_per_request_class() {
    let timeouts = ClassTimeouts::from_default(Duration::from_secs(30));
    assert_eq!(
        timeouts.for_class(RequestClass::Boolean),
        Duration::from_secs(10)
    );
    assert_eq!(
        timeouts.for_class(RequestClass::Time),
        Duration::from_secs(15)
    );
    assert_eq!(
        timeouts.for_class(RequestClass::Oob),
        Duration::from_secs(30)
    );
    assert_eq!(
        timeouts.for_class(RequestClass::Default),
        Duration::from_secs(30)
    );

    // End-to-end: a 1s `boolean` override fires on a 3s endpoint while the
    // default class sails through the same delay.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(3))
                .set_body_string("slow-but-ok"),
        )
        .mount(&server)
        .await;
    let client = HttpClient::builder()
        .timeout(Duration::from_secs(30))
        .boolean_timeout(Duration::from_secs(1))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(Arc::new(RateLimiter::disabled()))
        .seed(Some(7))
        .allow_private(true)
        .build()
        .expect("client build");
    assert_eq!(
        client.timeout_for(RequestClass::Boolean),
        Duration::from_secs(1)
    );
    assert_eq!(
        client.timeout_for(RequestClass::Time),
        Duration::from_secs(15)
    );

    let cancel = CancellationToken::new();
    let url = format!("{}/", server.uri());
    let start = Instant::now();
    let err = client
        .send_with_retry_for_class(get(url.clone()), RequestClass::Boolean, &cancel)
        .await
        .expect_err("boolean 1s timeout must fire on a 3s endpoint");
    assert!(
        matches!(err, injekt::http::client::ClientError::Timeout(_)),
        "expected Timeout, got {err}"
    );
    // The 1s class timeout fires per attempt (then the standard retry budget
    // replays it: ~4 × 1s + backoffs ≈ 5.5s) — far below any 30s-default
    // behavior, and a failure where the default class succeeds below.
    assert!(start.elapsed() >= Duration::from_secs(1));
    assert!(start.elapsed() < Duration::from_secs(20));

    let resp = client
        .send_with_retry_for_class(get(url), RequestClass::Default, &cancel)
        .await
        .expect("default class waits out the 3s endpoint");
    assert_eq!(resp.status(), 200);
}

/// C10 `429 + Retry-After` honored: the server's ask floors the backoff, the
/// shared limiter is paced (no immediate re-burst), and every `429` is
/// counted for the per-run detectability metric (A3 `0×429 p95` gate).
#[tokio::test]
async fn retry_after_is_honored_and_counted() {
    let server = MockServer::start().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    Mock::given(method("GET"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "1")
                    .set_body_string("rate limited")
            } else {
                ResponseTemplate::new(200).set_body_string("ok")
            }
        })
        .mount(&server)
        .await;

    let client = HttpClient::builder()
        .timeout(Duration::from_secs(30))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(Arc::new(RateLimiter::new(50.0)))
        .seed(Some(11))
        .allow_private(true)
        .build()
        .expect("client build");
    let cancel = CancellationToken::new();
    let start = Instant::now();
    let resp = client
        .send_with_retry(get(format!("{}/", server.uri())), &cancel)
        .await
        .expect("throttled then ok");
    let elapsed = start.elapsed();
    assert_eq!(resp.status(), 200);
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    // Two `Retry-After: 1` asks honored (plus limiter pacing): well above the
    // ~500ms default backoff that used to re-hit the gate early.
    assert!(
        elapsed >= Duration::from_millis(1800),
        "Retry-After must floor the backoff, elapsed={elapsed:?}"
    );
    let (c403, c429) = client.take_detectability_counts();
    assert_eq!(c403, 0);
    assert_eq!(c429, 2, "both retried 429s must be counted");
    // Take-semantics: drained exactly once.
    assert_eq!(client.take_detectability_counts(), (0, 0));
}

/// `429` without a header still backs off (base policy) and is counted.
#[tokio::test]
async fn bare_429_retries_and_counts() {
    let server = MockServer::start().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    Mock::given(method("GET"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                ResponseTemplate::new(429).set_body_string("slow down")
            } else {
                ResponseTemplate::new(200).set_body_string("ok")
            }
        })
        .mount(&server)
        .await;

    let client = fast_client();
    let cancel = CancellationToken::new();
    let resp = client
        .send_with_retry(get(format!("{}/", server.uri())), &cancel)
        .await
        .expect("bare 429 retried");
    assert_eq!(resp.status(), 200);
    assert_eq!(client.take_detectability_counts(), (0, 1));
}

/// `403`s feed the same per-run detectability counters.
#[tokio::test]
async fn forbidden_responses_are_counted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403).set_body_string("blocked"))
        .mount(&server)
        .await;

    let client = fast_client();
    let cancel = CancellationToken::new();
    let resp = client
        .send_with_retry(get(format!("{}/", server.uri())), &cancel)
        .await
        .expect("403 is returned, not an error");
    assert_eq!(resp.status(), 403);
    assert_eq!(client.take_detectability_counts(), (1, 0));
}

/// C10 cancellation: aborting mid-scan releases the held `time` permits —
/// zero orphans — and the same client stays reusable afterwards.
#[tokio::test]
async fn cancellation_releases_time_pool_permits() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(|req: &wiremock::Request| {
            if req.url.as_str().contains("/slow") {
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(10))
                    .set_body_string("slow")
            } else {
                ResponseTemplate::new(200).set_body_string("fast")
            }
        })
        .mount(&server)
        .await;

    let client = fast_client();
    let cancel = CancellationToken::new();
    let slow = format!("{}/slow", server.uri());

    // Occupy both pool slots with slow time probes.
    let mut tasks = Vec::new();
    for _ in 0..TIME_POOL_SLOTS {
        let client = client.clone();
        let cancel = cancel.clone();
        let url = slow.clone();
        tasks.push(tokio::spawn(async move {
            client
                .send_with_retry_for_class(get(url), RequestClass::Time, &cancel)
                .await
        }));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    cancel.cancel();

    for task in tasks {
        let res = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("cancelled probe must settle promptly")
            .expect("task join");
        assert!(
            matches!(res, Err(injekt::http::client::ClientError::Cancelled)),
            "expected Cancelled, got {res:?}"
        );
    }

    // Pool reusable with a fresh token: a new slow probe must acquire a slot
    // immediately (an orphaned permit would wedge this until timeout).
    let fresh = CancellationToken::new();
    let fast = format!("{}/fast", server.uri());
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        client.send_with_retry_for_class(get(fast), RequestClass::Time, &fresh),
    )
    .await
    .expect("pool must be reusable after cancel")
    .expect("fast time probe");
    assert_eq!(resp.status(), 200);
}

/// Engine-level: `Ctrl+C` mid-scan (slow backend) returns gracefully instead
/// of hanging on `time` probes or the pool.
#[tokio::test]
async fn engine_mid_scan_cancel_is_graceful() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(2))
                .set_body_string("welcome page id=1 normal content"),
        )
        .mount(&server)
        .await;

    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 2;
    cfg.techniques = vec!["boolean".to_owned(), "time".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg.seed = Some(9);

    let client = HttpClient::builder()
        .timeout(Duration::from_secs(30))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(Arc::new(RateLimiter::disabled()))
        .seed(Some(9))
        .allow_private(true)
        .build()
        .expect("client build");

    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel.clone());
    let target = format!("{}/?id=1", server.uri());
    let canceller = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        canceller.cancel();
    });
    let start = Instant::now();
    let state = tokio::time::timeout(Duration::from_secs(20), engine.run(&target))
        .await
        .expect("cancelled scan must settle promptly")
        .expect("engine run");
    assert_eq!(state, injekt::engine::EngineState::Done);
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "graceful cancel must beat the class timeouts, took {:?}",
        start.elapsed()
    );
}

/// C10 jitter contract: the shared builder helper floors every explicit
/// `--jitter` at 200ms (OPSEC) without ever speeding `stealth` up.
#[test]
fn jitter_helper_enforces_floor_without_speedup() {
    let low = jitter_from_str("50,10");
    let mut rng = injekt::seeded_rng::make_rng(Some(1));
    for _ in 0..50 {
        assert!(
            low.next_delay_with_rng(&mut rng).as_millis() >= 200,
            "floor 200ms must hold for low explicit jitter"
        );
    }
    // Stealth cadence untouched (mean preserved, never auto-mounted down).
    let stealth = jitter_from_str("1200,400");
    let mut rng = injekt::seeded_rng::make_rng(Some(2));
    let mean: u128 = (0..20)
        .map(|_| stealth.next_delay_with_rng(&mut rng).as_millis())
        .sum();
    assert!(
        mean / 20 >= 600,
        "stealth cadence must not be sped up, mean={}",
        mean / 20
    );
    // Garbage falls back to the floored default.
    let fallback = jitter_from_str("nope");
    let mut rng = injekt::seeded_rng::make_rng(Some(3));
    assert!(fallback.next_delay_with_rng(&mut rng).as_millis() >= 200);
}

/// `Detectability` counters saturate instead of wrapping on hostile runs.
#[test]
fn detectability_counters_saturate() {
    let mut state = injekt::session::state::SessionState::new();
    state.record_status(200);
    state.record_status(403);
    state.record_status(429);
    state.record_status(500);
    assert_eq!(state.detectability(), Detectability::new(1, 1));
    state.add_detectability(u64::MAX, u64::MAX);
    assert_eq!(state.detectability().total(), u64::MAX);
}
