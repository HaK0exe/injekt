#![allow(clippy::unwrap_used, clippy::expect_used)]
//! C5-tardif integration: mini-mutation strictly scoped to the `--confirm`
//! second-pass on already-confirmed findings.
//!
//! - never in first-pass detection (no `--confirm` → 0 `mutation:*` trace).
//! - never without a confirmed finding (clean target + `--confirm` → 0
//!   `mutation:*` trace, 0 extra request vs `--no-mutation`).
//! - bounded (≤4 variants / ≤8 req per finding), seeded (same seed → same
//!   `mutation_plan` + request hashes), traced (`mutation:<famille>`).
//! - `--no-mutation` escape hatch (0 `mutation:*` trace, findings kept).
//! - WAF-penalty gate is covered at unit level
//!   (`mutation::should_attempt_mutation` with `baseline_blocking=true` →
//!   false, no spray); here we assert the sibling no-spray property on
//!   clean targets (gate on `confirmed`).

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn fast_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

fn boolean_cfg(confirm: bool, no_mutation: bool, seed: Option<u64>) -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg.confirm = confirm;
    cfg.no_mutation = no_mutation;
    cfg.seed = seed;
    cfg
}

const CLEAN_BODY: &str = "welcome normal page id=1 content baseline 42 no sqli here";
const BASELINE_BODY: &str = "welcome normal page id=1 content baseline 42";
const DIFFERENT_BODY: &str = "completely different content false branch unique marker 99 xyz";

fn clean_responder(_req: &wiremock::Request) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_string(CLEAN_BODY)
}

/// Differential boolean responder (vulnerable): the `1=2` branch differs,
/// everything else (baseline, `1=1`, mutated `TRUE` variants) is stable.
fn vuln_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string().to_ascii_lowercase();
    if url.contains("1%3d2") || url.contains("1=2") {
        return ResponseTemplate::new(200).set_body_string(DIFFERENT_BODY);
    }
    ResponseTemplate::new(200).set_body_string(BASELINE_BODY)
}

fn mutation_plans(state: &injekt::session::state::SessionState) -> Vec<String> {
    state
        .trace()
        .records()
        .iter()
        .filter(|r| r.mutation_plan.starts_with("mutation:"))
        .map(|r| r.mutation_plan.clone())
        .collect()
}

fn mutation_hashes(state: &injekt::session::state::SessionState) -> Vec<String> {
    state
        .trace()
        .records()
        .iter()
        .filter(|r| r.mutation_plan.starts_with("mutation:"))
        .map(|r| r.request_hash.clone())
        .collect()
}

/// First-pass detection never mutates: vuln target without `--confirm`
/// yields findings but zero `mutation:*` trace records.
#[tokio::test]
async fn mutation_never_runs_in_first_pass_detection() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(vuln_responder)
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());

    let engine = Engine::new(
        boolean_cfg(false, false, Some(42)),
        fast_client(),
        CancellationToken::new(),
    );
    engine.run(&target).await.expect("run");
    let handle = engine.state_handle();
    let state = handle.read().await;
    assert!(
        !state.findings().is_empty(),
        "vuln mock must yield ≥1 boolean finding in first pass"
    );
    assert!(
        mutation_plans(&state).is_empty(),
        "first-pass detection must emit 0 mutation trace records"
    );
}

/// Clean target + `--confirm` (mutation ON by default): no confirmed
/// finding → the mutation gate stays closed (0 trace, 0 extra request).
#[tokio::test]
async fn mutation_never_runs_without_confirmed_finding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(clean_responder)
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());

    let run = async |no_mutation: bool| -> (usize, u64, usize) {
        let engine = Engine::new(
            boolean_cfg(true, no_mutation, Some(42)),
            fast_client(),
            CancellationToken::new(),
        );
        engine.run(&target).await.expect("run");
        let handle = engine.state_handle();
        let state = handle.read().await;
        (
            state.findings().len(),
            state.request_count(),
            mutation_plans(&state).len(),
        )
    };

    let (findings_on, req_on, mut_on) = run(false).await;
    let (findings_off, req_off, mut_off) = run(true).await;
    assert_eq!(findings_on, 0, "clean target must yield 0 findings");
    assert_eq!(findings_off, 0, "clean target must yield 0 findings");
    assert_eq!(mut_on, 0, "no confirmed finding → 0 mutation probes");
    assert_eq!(mut_off, 0, "no confirmed finding → 0 mutation probes");
    assert_eq!(
        req_on, req_off,
        "mutation on a clean target must cost 0 extra requests"
    );
}

/// `--confirm` on a vulnerable target: the finding is kept (silent failure
/// can never drop it here — the mock answers every TRUE stably) and the
/// mutation second-pass emits a bounded, traced `mutation:*` plan.
#[tokio::test]
async fn mutation_bounded_and_traced_on_confirmed_finding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(vuln_responder)
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());

    let engine = Engine::new(
        boolean_cfg(true, false, Some(42)),
        fast_client(),
        CancellationToken::new(),
    );
    engine.run(&target).await.expect("run");
    let handle = engine.state_handle();
    let state = handle.read().await;
    let findings = state.findings().len();
    assert!(
        findings >= 1,
        "vuln mock must keep ≥1 finding after --confirm"
    );
    let plans = mutation_plans(&state);
    assert!(
        !plans.is_empty(),
        "confirmed finding must emit ≥1 mutation trace record"
    );
    for plan in &plans {
        assert!(
            plan.starts_with("mutation:"),
            "trace must carry mutation_plan, got {plan}"
        );
    }
    // DoD bounds: ≤4 variants/finding (1 req each) and ≤8 req/finding.
    assert!(
        plans.len() <= 4 * findings,
        "≤4 variants/finding: {} plans for {findings} finding(s)",
        plans.len()
    );
    assert!(
        plans.len() <= 8 * findings,
        "≤8 req/finding: {} mutation req for {findings} finding(s)",
        plans.len()
    );
    // Scope: only the 4 known families.
    for plan in &plans {
        assert!(
            [
                "mutation:quote_fence",
                "mutation:paren_wrap",
                "mutation:comment_swap",
                "mutation:case_mix"
            ]
            .contains(&plan.as_str()),
            "unknown mutation family traced: {plan}"
        );
    }
}

/// `--no-mutation` escape hatch: same findings, zero `mutation:*` trace.
#[tokio::test]
async fn no_mutation_flag_disables_all_mutation_probes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(vuln_responder)
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());

    let engine = Engine::new(
        boolean_cfg(true, true, Some(42)),
        fast_client(),
        CancellationToken::new(),
    );
    engine.run(&target).await.expect("run");
    let handle = engine.state_handle();
    let state = handle.read().await;
    assert!(
        !state.findings().is_empty(),
        "--no-mutation must keep the confirmed finding(s)"
    );
    assert!(
        mutation_plans(&state).is_empty(),
        "--no-mutation must emit 0 mutation trace records"
    );
}

/// Same seed → same mutation sequence (plan labels + request hashes).
#[tokio::test]
async fn mutation_deterministic_for_same_seed() {
    async fn run_once() -> (Vec<String>, Vec<String>) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(vuln_responder)
            .mount(&server)
            .await;
        let target = format!("{}/?id=1", server.uri());
        let engine = Engine::new(
            boolean_cfg(true, false, Some(7)),
            fast_client(),
            CancellationToken::new(),
        );
        engine.run(&target).await.expect("run");
        let handle = engine.state_handle();
        let state = handle.read().await;
        (mutation_plans(&state), mutation_hashes(&state))
    }

    let (plans_a, hash_a) = run_once().await;
    let (plans_b, hash_b) = run_once().await;
    assert!(!plans_a.is_empty(), "seeded run must emit mutation plans");
    assert_eq!(plans_a, plans_b, "same seed → same mutation_plan sequence");
    assert_eq!(hash_a, hash_b, "same seed → same mutated payloads");
}
