#![deny(unsafe_code)]

use crate::{
    engine::orchestrator::{Engine, EngineConfig},
    http::client::HttpClient,
    recon::parameter::ParameterCandidate,
    session::state::Finding,
};
use futures::StreamExt as _;
use serde::Serialize;
use std::sync::Arc;
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
    let concurrency = config.threads.clamp(1, 8);
    let total = candidates.len();
    let findings = Arc::new(Mutex::new(Vec::new()));
    let errors = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::new(Mutex::new(0u64));
    futures::stream::iter(candidates)
        .for_each_concurrent(concurrency, |candidate| {
            let config = config.clone();
            let client = client.clone();
            let cancel = cancel.clone();
            let findings = Arc::clone(&findings);
            let errors = Arc::clone(&errors);
            let requests = Arc::clone(&requests);
            async move {
                if cancel.is_cancelled() {
                    return;
                }
                let engine = Engine::new(config, client, cancel.clone());
                if let Err(error) = engine.run_candidate(&candidate).await {
                    errors.lock().await.push(format!(
                        "{} {} {}: {error}",
                        candidate.method, candidate.url, candidate.param_name
                    ));
                    return;
                }
                let state = engine.state_handle();
                let state = state.read().await;
                findings.lock().await.extend_from_slice(state.findings());
                let mut count = requests.lock().await;
                *count = count.saturating_add(state.request_count());
            }
        })
        .await;
    let mut findings = findings.lock().await.clone();
    findings.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.parameter.cmp(&right.parameter))
    });
    DiscoveryReport {
        candidates_tested: total,
        findings,
        request_count: *requests.lock().await,
        errors: errors.lock().await.clone(),
    }
}
