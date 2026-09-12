#![allow(clippy::unwrap_used, clippy::expect_used)]
//! CODE calibration: `--request-budget N` OPT-IN global plafond.
//!
//! - `None` (default) = unlimited, historical behaviour byte-identical:
//!   two `None` runs on the same clean mock cost exactly the same.
//! - `Some(small)` on a clean mock = cooperative stop: clean
//!   [`EngineState::Done`] (never an error), 0 findings, total capped at
//!   `budget + one in-flight technique` (threads = 1 via `test_defaults`,
//!   so no concurrency overshoot beyond a single technique).
//!
//! The `BudgetConfig::request_budget` field is set directly here; the CLI
//! `--request-budget N` flag flows into it via `engine_config`
//! (`scan.rs` / `recon.rs`, covered by `args.rs` parse unit tests).
//! No live bench needed: the mock is a static clean target (N1-like veto).

use injekt::engine::{BudgetConfig, Engine, EngineConfig, EngineState};
use injekt::http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter};
use std::sync::Arc;
use std::time::Duration;
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

async fn run_clean_mock(budget: Option<usize>) -> (EngineState, u64, usize) {
    // Static clean target: every response identical, no differential, so no
    // technique can confirm (N1-like veto: 0 findings expected).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("clean-ok-static-body"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let mut cfg = EngineConfig::test_defaults();
    cfg.budget.request_budget = budget;
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let state = engine.run(&target).await.expect("run returns Done");
    let handle = engine.state_handle();
    let snap = handle.read().await;
    (state, snap.request_count(), snap.findings().len())
}

#[tokio::test]
async fn request_budget_none_is_unlimited_and_deterministic() {
    // Guard-rail: the default path must not change (A1 evasion needs ~1032
    // req live — a default cap would silently break detection).
    assert_eq!(BudgetConfig::default().request_budget, None);
    let (s1, r1, f1) = run_clean_mock(None).await;
    let (s2, r2, f2) = run_clean_mock(None).await;
    assert_eq!(s1, EngineState::Done);
    assert_eq!(s2, EngineState::Done);
    assert_eq!(f1, 0, "clean mock must yield 0 findings");
    assert_eq!(f2, 0, "clean mock must yield 0 findings");
    assert_eq!(
        r1, r2,
        "None path must stay deterministic (byte-identical, 0 behaviour change)"
    );
    println!("unlimited clean run cost: {r1} req");
}

#[tokio::test]
async fn request_budget_small_stops_cleanly_with_zero_findings() {
    let (_, r_unlimited, _) = run_clean_mock(None).await;
    println!("unlimited clean run cost: {r_unlimited} req");
    // Budget above baseline (3) + context (<=8) so detection starts, then
    // stops cooperatively mid-pass on this clean target.
    let cap = 15usize;
    let (state, r_budget, findings) = run_clean_mock(Some(cap)).await;
    println!("budgeted({cap}) clean run cost: {r_budget} req");
    assert_eq!(
        state,
        EngineState::Done,
        "budget exhaustion must end clean (Done, never an error)"
    );
    assert_eq!(findings, 0, "clean mock must yield 0 findings");
    assert!(
        r_budget < r_unlimited,
        "budget must cap the run (budgeted={r_budget} unlimited={r_unlimited})"
    );
    // Cooperative stop: the running technique finishes before the break, so
    // allow one in-flight technique of overshoot (threads = 1: a single
    // technique envelope; calibrated 15 -> 18 on the static mock, so +8
    // keeps 5 req of margin while staying strictly below the 34 req an
    // uncapped run costs — the bound is meaningful, not vacuous).
    let cap_u64 = u64::try_from(cap).unwrap_or(u64::MAX);
    assert!(
        r_budget <= cap_u64.saturating_add(8),
        "budgeted run must stay near the cap (got {r_budget}, cap {cap})"
    );
}
