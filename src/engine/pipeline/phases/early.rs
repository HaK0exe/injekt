//! Pre-flight, baseline and context phases of `run_internal` (P2).
//! Bodies moved verbatim from the inline pipeline; baseline early
//! exits drain `absorb_detectability` where the inline code did.

use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::engine::pipeline::helpers::absorb_detectability;
use crate::{
    detection::baseline,
    engine::{
        EngineState,
        baseline::collect_baseline,
        config::{BudgetConfig, EngineConfig},
    },
    http::client::HttpClient,
    session::{scrubber::Scrubber, state::SessionState},
    target::{
        injection::{ProbeOpts, baseline_all_error},
        parameters::TargetParameter,
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::tamper::Tamper,
};

/// Lexical parse + DNS-time SSRF pre-flight (moved verbatim from
/// `run_internal`); error propagation unchanged via `?` at the call site.
pub(crate) async fn preflight_target(
    config: &EngineConfig,
    target_str: &str,
) -> crate::error::Result<TargetUrl> {
    // Parse (lexical) + DNS-time SSRF check (anti DNS-rebinding).
    // Skipped when the proxy does remote DNS (`socks5h://`): a local
    // `lookup_host` would leak the hostname and fail `.onion` names the
    // proxy could resolve. Lexical + IP-literal checks in `parse` still apply.
    let target = TargetUrl::parse(target_str, config.net.allow_private)
        .map_err(|e| crate::error::InjektError::Other(Box::new(e)))?;
    if !config.net.allow_private
        && !config.net.remote_dns
        && let Some(host) = target.inner().host_str()
    {
        TargetUrl::resolve_and_check(host, false)
            .await
            .map_err(|e| crate::error::InjektError::Other(Box::new(e)))?;
    }
    Ok(target)
}

/// Baseline phase (moved verbatim): cancel/budget guards, 3-sample
/// collection, stability + all-5xx guards. Every early exit already
/// drained `absorb_detectability` inside this phase, mirroring the
/// original inline `absorb(...) + return` pairs.
///
/// P2 note: `candidate_param` / `build_raw_request` (pure) are hoisted in
/// the caller before this phase, right after the parse block.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_baseline_phase(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    scrubber: &Scrubber,
    baseline_cache: Option<&Arc<crate::recon::BaselineCache>>,
    shared_client: bool,
    target: &TargetUrl,
    target_str: &str,
    raw_request: Option<&RawRequest>,
) -> crate::error::Result<BaselinePhase> {
    if cancel.is_cancelled() {
        absorb_detectability(client, state, shared_client).await;
        return Ok(BaselinePhase::Stop(EngineState::Cancelled));
    }
    // Budget spent before baseline: skip the 3-sample sequence entirely
    // (cooperative plafond, same as fingerprint/extraction guards below).
    // Mid-baseline overshoot (≤3 concurrent samples) stays within the
    // documented one-technique tolerance.
    if BudgetConfig::is_over_request_budget(
        state.read().await.request_count(),
        config.budget.request_budget,
    ) {
        warn!("request-budget spent, skipping baseline");
        absorb_detectability(client, state, shared_client).await;
        return Ok(BaselinePhase::Stop(EngineState::Inconclusive));
    }

    let Some((baseline, effective_tampers, effective_opts)) = collect_baseline(
        client,
        state,
        cancel,
        config,
        scrubber,
        baseline_cache,
        target,
        raw_request,
    )
    .await?
    else {
        absorb_detectability(client, state, shared_client).await;
        return Ok(BaselinePhase::Stop(EngineState::Cancelled));
    };

    // A changing baseline is not a usable oracle: any later TRUE/FALSE
    // differential could simply be application noise.  Stop before
    // context and detection probes so an unstable endpoint is reported as
    // inconclusive instead of producing misleading findings.
    if !baseline.is_stable() {
        warn!(
            target=%scrubber.scrub(target_str),
            statuses=?baseline.status_codes,
            "baseline unstable — skipping injection detection"
        );
        absorb_detectability(client, state, shared_client).await;
        return Ok(BaselinePhase::Stop(EngineState::Inconclusive));
    }
    // All-5xx baseline: every differential below compares static error
    // pages, so the run is void by construction. Remember it for the
    // final verdict (INCONCLUSIVE, never CLEAN) while still letting
    // detection run for transient-blip tolerance.
    let baseline_unreachable = baseline_all_error(&baseline.status_codes);
    if baseline_unreachable {
        warn!(
            target=%scrubber.scrub(target_str),
            statuses=?baseline.status_codes,
            "baseline: all samples server-error (5xx) — origin unreachable, detection differentials will be meaningless"
        );
    }
    Ok(BaselinePhase::Proceed {
        baseline,
        effective_tampers,
        opts: effective_opts,
        baseline_unreachable,
    })
}

/// Baseline phase outcome: proceed with the collected data, or stop the
/// run with the exact `EngineState` the inline pipeline returned.
#[allow(clippy::large_enum_variant)]
pub(crate) enum BaselinePhase {
    Proceed {
        baseline: baseline::Baseline,
        effective_tampers: Vec<Tamper>,
        opts: ProbeOpts,
        baseline_unreachable: bool,
    },
    Stop(EngineState),
}

/// Context phase (moved verbatim): adaptive context analysis, request
/// metrics, and the early high-confidence DBMS fill. `raw` is the
/// Arc-wrapped raw request body passed through as `Option<&RawRequest>`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_context_phase(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    target: &TargetUrl,
    target_str: &str,
    scrubber: &Scrubber,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    primary_param: Option<&TargetParameter>,
) -> crate::dbms::context::ContextProbeResult {
    // Run adaptive context analysis (<=8 requests bound, 0 DBMS probes if --dbms)
    let context_started = Instant::now();
    let context_req_before = state.read().await.request_count();
    let context_result = if let Some(param) = primary_param {
        crate::dbms::context::analyze_context(
            client,
            state,
            cancel,
            target,
            param,
            raw,
            baseline,
            config.dbms_hint.as_deref(),
        )
        .await
    } else {
        crate::dbms::context::ContextProbeResult {
            context: crate::dbms::context::InjectionContext::new(),
            dbms_belief: config.dbms_hint.as_deref().map_or_else(
                crate::dbms::context::DbmsBelief::uniform,
                crate::dbms::context::DbmsBelief::from_hint,
            ),
            probes_sent: 0,
            error_evidence: None,
        }
    };

    let context_elapsed = context_started.elapsed().as_secs_f64();
    let context_req_delta = state
        .read()
        .await
        .request_count()
        .saturating_sub(context_req_before);
    info!(
        target=%scrubber.scrub(target_str),
        context=%context_result.context.summary(),
        probes=context_result.probes_sent,
        elapsed_s=context_elapsed,
        requests=context_req_delta,
        "context done in {context_elapsed:.1}s ({context_req_delta} req) — {}",
        context_result.context.summary(),
    );

    let (top_dbms, prob) = context_result.dbms_belief.top_candidate();
    if prob >= 0.85 && top_dbms != crate::dbms::common::DbmsKind::Unknown {
        state.write().await.fill_missing_dbms(top_dbms);
        info!(%top_dbms, confidence=%prob, "DBMS identified early during context analysis");
    }
    context_result
}
