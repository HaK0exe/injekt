#![deny(unsafe_code)]

use crate::{
    engine::orchestrator::{Engine, EngineConfig},
    http::client::HttpClient,
    recon::parameter::ParameterCandidate,
    session::state::Finding,
};
use futures::StreamExt as _;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use std::{io::IsTerminal as _, sync::Arc};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryReport {
    pub candidates_tested: usize,
    pub findings: Vec<Finding>,
    pub request_count: u64,
    pub errors: Vec<String>,
}

impl DiscoveryReport {
    /// Scrubbed clone for CLI / MCP output.
    #[must_use]
    pub fn scrubbed(&self, scrubber: &crate::session::scrubber::Scrubber) -> Self {
        Self {
            candidates_tested: self.candidates_tested,
            findings: self.findings.iter().map(|f| f.scrubbed(scrubber)).collect(),
            request_count: self.request_count,
            errors: self.errors.iter().map(|e| scrubber.scrub(e)).collect(),
        }
    }
}

pub async fn scan_candidates(
    candidates: Vec<ParameterCandidate>,
    config: EngineConfig,
    client: HttpClient,
    cancel: CancellationToken,
) -> DiscoveryReport {
    let concurrency = config.budget.threads.clamp(1, 8);
    let total = candidates.len();
    let findings = Arc::new(Mutex::new(Vec::new()));
    let errors = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::new(Mutex::new(0u64));
    let baseline_cache = Arc::new(crate::recon::BaselineCache::new());
    // Global progress across all candidates: per-engine bars are suppressed
    // for single-param runs, so without this a bulk scan looks hung for its
    // whole duration. Hidden when stderr is not a TTY (MCP stdio, pipes, CI).
    let bar = Arc::new(progress_bar(total as u64));
    futures::stream::iter(candidates)
        .for_each_concurrent(concurrency, |candidate| {
            let config = config.clone();
            let client = client.clone();
            let cancel = cancel.clone();
            let findings = Arc::clone(&findings);
            let errors = Arc::clone(&errors);
            let requests = Arc::clone(&requests);
            let baseline_cache = Arc::clone(&baseline_cache);
            let bar = Arc::clone(&bar);
            async move {
                if cancel.is_cancelled() {
                    return;
                }
                let engine =
                    Engine::new(config, client, cancel.clone()).with_baseline_cache(baseline_cache);
                if let Err(error) = engine.run_candidate(&candidate).await {
                    errors.lock().await.push(format!(
                        "{} {} {}: {error}",
                        candidate.method, candidate.url, candidate.param_name
                    ));
                } else {
                    let state = engine.state_handle();
                    let state = state.read().await;
                    findings.lock().await.extend_from_slice(state.findings());
                    let mut count = requests.lock().await;
                    *count = count.saturating_add(state.request_count());
                }
                bar.inc(1);
            }
        })
        .await;
    bar.finish_with_message("recon scan done");
    let mut findings = findings.lock().await.clone();
    findings.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.parameter.cmp(&right.parameter))
    });
    let report = DiscoveryReport {
        candidates_tested: total,
        findings,
        request_count: *requests.lock().await,
        errors: errors.lock().await.clone(),
    };
    tracing::info!(
        tested = report.candidates_tested,
        findings = report.findings.len(),
        errors = report.errors.len(),
        requests = report.request_count,
        "recon scan done"
    );
    report
}

/// Bulk progress bar, hidden when stderr is not a TTY (same contract as the
/// engine-level bars so agent/CI output stays clean).
fn progress_bar(len: u64) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{bar:40} {pos}/{len} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );
    pb
}
