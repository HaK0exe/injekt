#![deny(unsafe_code)]

pub use crate::target::injection::{
    APP_FILTER_STATUS, FILTER_STREAK_LIMIT, ProbeOpts, baseline_all_error,
    build_injection_spec_with_raw, filter_params, headers_preserving_raw,
    headers_preserving_raw_keep_ct, inject_body_param, inject_multipart_field, inject_param,
    inject_param_or_marker, inject_with_marker, is_app_filter_block, is_ignored, payload_budget,
    request_spec_from_raw, resolve_effective_tampers, synthetic_raw_from_data, waf_auto_tampers,
};
use crate::{
    http::client::HttpClient,
    session::{scrubber::Scrubber, state::SessionState},
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

// `check_deadline` moved to `super::schedule` (P1). Baseline collection moved
// to `super::baseline` (P1-fin); the orchestrator re-export was dropped once
// `run_internal` (its only caller) moved to `super::pipeline`.

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineState {
    Parse,
    Baseline,
    Context,
    Detection,
    Fingerprint,
    Extraction,
    Enumeration,
    Done,
    /// Run stopped before completion (Ctrl+C, empty baseline after cancel).
    /// Never map to `CLEAN`: the target was not fully tested.
    Cancelled,
    /// Run finished without findings but the oracle was unusable or the
    /// budget was exhausted (unstable baseline, all-5xx baseline,
    /// `--request-budget` / `--max-duration` stop). Never map to `CLEAN`.
    Inconclusive,
}

/// Engine configuration structs live in `super::config` (P1).
/// Re-exported here (and via `crate::engine`) for backward compatibility.
pub use super::config::{
    BudgetConfig, EngineConfig, EnumConfig, EvasionConfig, MAX_DETECTION_DURATION_SECS_CAP,
    NetConfig, OobConfig, SecondOrderConfig,
};

// `--dbms` hint normalization moved to `super::config` (P1);
// the orchestrator re-export was dropped after the P1-fin moves.

#[derive(Debug)]
#[non_exhaustive]
pub struct Engine {
    config: EngineConfig,
    client: HttpClient,
    state: Arc<RwLock<SessionState>>,
    cancel: CancellationToken,
    scrubber: Scrubber,
    baseline_cache: Option<Arc<crate::recon::BaselineCache>>,
    /// `true` when `client` is shared across concurrent engines (recon
    /// scan): per-engine drains would race (`swap(0)` attributed to the
    /// first finisher), so absorbs are skipped and the owner drains once
    /// at the end of the whole run.
    shared_client: bool,
}

impl Engine {
    #[must_use]
    pub fn new(config: EngineConfig, client: HttpClient, cancel: CancellationToken) -> Self {
        let scrubber = Scrubber::new(config.no_redact);
        let mut initial = SessionState::new();
        initial.set_seed(config.seed);
        Self {
            config,
            client,
            state: Arc::new(RwLock::new(initial)),
            cancel,
            scrubber,
            baseline_cache: None,
            shared_client: false,
        }
    }

    /// Share ownership of `client` across concurrent engines (recon scan):
    /// per-engine detectability drains are skipped (they would race) and
    /// the caller drains once at the end via
    /// [`HttpClient::take_detectability_counts`].
    #[must_use]
    pub fn with_shared_client(mut self) -> Self {
        self.shared_client = true;
        self
    }

    #[must_use]
    pub fn with_baseline_cache(mut self, cache: Arc<crate::recon::BaselineCache>) -> Self {
        self.baseline_cache = Some(cache);
        self
    }

    #[must_use]
    pub fn state_handle(&self) -> Arc<RwLock<SessionState>> {
        Arc::clone(&self.state)
    }

    /// # Errors
    /// Returns an error if the target URL fails to parse, or a network/detection
    /// phase fails unrecoverably.
    pub async fn run(&self, target_str: &str) -> crate::error::Result<EngineState> {
        run_internal(
            &PipelineCtx {
                client: &self.client,
                state: &self.state,
                cancel: &self.cancel,
                config: &self.config,
                scrubber: &self.scrubber,
                baseline_cache: self.baseline_cache.as_ref(),
                shared_client: self.shared_client,
            },
            target_str,
            None,
        )
        .await
    }

    /// # Errors
    /// Returns an error if the candidate URL fails to parse, or a network/detection
    /// phase fails unrecoverably.
    pub async fn run_candidate(
        &self,
        candidate: &crate::recon::ParameterCandidate,
    ) -> crate::error::Result<EngineState> {
        run_internal(
            &PipelineCtx {
                client: &self.client,
                state: &self.state,
                cancel: &self.cancel,
                config: &self.config,
                scrubber: &self.scrubber,
                baseline_cache: self.baseline_cache.as_ref(),
                shared_client: self.shared_client,
            },
            candidate.url.as_str(),
            Some(candidate),
        )
        .await
    }
}

/// Pipeline glue (`run_internal` + helpers) moved to `super::pipeline` (P1-fin).
pub(crate) use super::pipeline::{PipelineCtx, run_internal};
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod gating;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod budgets;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod mechanics;
