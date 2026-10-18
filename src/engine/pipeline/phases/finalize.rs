//! Finalize phase of `run_internal` (P2): detectability absorb,
//! verdict shaping and run summary. Moved verbatim; returns the
//! terminal engine state.

use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::engine::pipeline::helpers::absorb_detectability;
use crate::{
    engine::{
        EngineState,
        config::{BudgetConfig, EngineConfig},
    },
    http::client::HttpClient,
    session::{scrubber::Scrubber, state::SessionState},
};

/// Finalize (moved verbatim): absorb throttled hops, verdict shaping
/// (never CLEAN on a truncated run) and the one-line run summary.
/// Returns the terminal engine state.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn finalize_run(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    scrubber: &Scrubber,
    shared_client: bool,
    target_str: &str,
    detection_started: Instant,
    run_started: Instant,
    baseline_unreachable: bool,
) -> EngineState {
    let mut current = EngineState::Done;
    // C10: absorb every throttled hop (403/429, incl. retried 429s) into
    // the run's detectability counters before reporting.
    absorb_detectability(client, state, shared_client).await;
    let requests = state.read().await.request_count();
    let detectability = state.read().await.detectability();
    let findings_snapshot = state.read().await.findings().to_vec();
    // Incomplete runs must never look CLEAN: budget/duration stops,
    // cancel, or an unusable (all-5xx) baseline degrade Done to
    // Inconclusive/Cancelled when no finding was produced. Findings still
    // surface as FINDINGS upstream (a hit is a hit, even on a truncated
    // run); only the 0-finding case changes verdict.
    if findings_snapshot.is_empty() {
        if cancel.is_cancelled() {
            current = EngineState::Cancelled;
        } else if baseline_unreachable
            || BudgetConfig::is_over_request_budget(requests, config.budget.request_budget)
            || BudgetConfig::is_over_max_duration(
                detection_started,
                config.budget.max_duration_secs,
            )
        {
            current = EngineState::Inconclusive;
        }
    } else if cancel.is_cancelled() {
        current = EngineState::Cancelled;
    }
    let total_elapsed = run_started.elapsed().as_secs_f64();
    // Findings per technique for the one-line summary (e.g. `boolean×1,
    // error×1`). Sorted for deterministic output.
    let mut by_technique: HashMap<String, usize> = HashMap::new();
    for finding in &findings_snapshot {
        *by_technique
            .entry(finding.technique.to_string())
            .or_insert(0) += 1;
    }
    let mut technique_parts: Vec<String> = by_technique
        .iter()
        .map(|(tech, count)| format!("{tech}×{count}"))
        .collect();
    technique_parts.sort();
    let findings_detail = if technique_parts.is_empty() {
        "no findings".to_owned()
    } else {
        format!(
            "{} finding(s) ({})",
            findings_snapshot.len(),
            technique_parts.join(", ")
        )
    };
    if findings_snapshot.is_empty() {
        info!(
            target=%scrubber.scrub(target_str),
            state=?current,
            requests,
            findings = 0,
            elapsed_s = total_elapsed,
            count_403 = detectability.count_403,
            count_429 = detectability.count_429,
            "scan done: {findings_detail}, {requests} req in {total_elapsed:.1}s (403×{} 429×{})",
            detectability.count_403,
            detectability.count_429,
        );
    } else {
        info!(
            target=%scrubber.scrub(target_str),
            state=?current,
            requests,
            findings = findings_snapshot.len(),
            elapsed_s = total_elapsed,
            count_403 = detectability.count_403,
            count_429 = detectability.count_429,
            "scan done: {findings_detail}, {requests} req in {total_elapsed:.1}s (403×{} 429×{}) — try --explain <param> for reasoning",
            detectability.count_403,
            detectability.count_429,
        );
    }
    current
}
