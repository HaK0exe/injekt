use std::{io::IsTerminal as _, sync::Arc, time::Instant};

use futures::StreamExt as _;
use indicatif::ProgressBar;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use super::{param::run_detection_for_param, shared::DetectionShared};
use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    detection::baseline,
    engine::config::EngineConfig,
    http::client::HttpClient,
    session::state::SessionState,
    target::{
        markers::MarkerSet, parameters::TargetParameter, raw_request::RawRequest, url::TargetUrl,
    },
    techniques::tamper::Tamper,
};

// (le builder partagé stylé vit dans `crate::cli::output::progress::bar` —
// même contrat TTY, template enrichi + greffe MultiProgress)

/// Runs boolean/error/time/union/stacked/json/nosql/oob detection for every
/// candidate parameter with bounded concurrency (respects `--threads`).
/// Minimal C3 loop: one [`crate::reasoning::Hypothesis`] per (param, technique) seeded by
/// `compute_calibrated_prior(context, dbms_belief)`; each
/// `test_*_bounded` outcome maps to `record_probe/record_trial/
/// record_waf_penalty`; prune at `posterior <= 0.04`, confirm at
/// `>= 0.85 + trials_passed > 0`. `Finding` emission is unchanged.
/// `context_probes` (the `<=8` adaptive probes) seeds every per-parameter
/// scheduler budget so the global cost stays visible in `budget_spent`
/// from the first `pop` (the true cross-param total is
/// `SessionState::request_count`).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_detection(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    target: &TargetUrl,
    target_str: &str,
    marker_set: &MarkerSet,
    raw_request: &Arc<Option<RawRequest>>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
    context_probes: usize,
    to_test: Vec<TargetParameter>,
    progress: &crate::cli::output::progress::PipelineView,
) {
    let pb2 = if to_test.len() > 1 {
        Arc::new(progress.attach(crate::cli::output::progress::bar(
            to_test.len() as u64,
            "detection",
        )))
    } else {
        Arc::new(indicatif::ProgressBar::hidden())
    };
    let concurrency = config.budget.threads.clamp(1, 32);
    let detection_started = Instant::now();
    let shared = Arc::new(DetectionShared {
        target: target.clone(),
        target_str: target_str.to_owned(),
        marker_set: marker_set.clone(),
        baseline: baseline.clone(),
        tampers: effective_tampers.to_vec(),
        context: context.clone(),
        dbms_belief: dbms_belief.clone(),
        context_probes,
        started: detection_started,
    });
    let stream = futures::stream::iter(to_test)
        .map(|param| {
            let shared = Arc::clone(&shared);
            let client = client.clone();
            let state = Arc::clone(state);
            let cancel = cancel.clone();
            let config = config.clone();
            let pb2 = Arc::clone(&pb2);
            let raw_request = Arc::clone(raw_request);
            async move {
                run_detection_for_param(
                    &client,
                    &state,
                    &cancel,
                    &config,
                    &shared,
                    &raw_request,
                    &param,
                )
                .await;
                pb2.inc(1);
            }
        })
        .buffer_unordered(concurrency);

    stream.collect::<Vec<()>>().await;
    // Clear the bar so the `detection done in …` summary logged by the
    // caller stays on a clean line (no `████ 1/1 …` glued to logs).
    // Single global bar (X/Y over blind spinner); hidden when stderr
    // is not a TTY (MCP/CI), where it would only spam + burn CPU.
    pb2.finish_and_clear();
}
