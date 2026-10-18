//! Detection, fingerprint, extraction and enumeration phases of
//! `run_internal` (P2). Bodies moved verbatim; the phase transitions
//! use `*current` (P2 adaptation of the former local assignment).

use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    detection::baseline,
    engine::{
        EngineState, config::EngineConfig, confirm::is_extraction_eligible,
        detection::run_detection, enumerate::run_enumeration, extraction::run_extraction,
        fingerprint::run_fingerprint,
    },
    http::client::HttpClient,
    session::{scrubber::Scrubber, state::SessionState},
    target::{
        injection::ProbeOpts, markers::MarkerSet, parameters::TargetParameter,
        raw_request::RawRequest, url::TargetUrl,
    },
    techniques::tamper::Tamper,
};

/// Detection phase (moved verbatim): `run_detection` + request metrics.
/// Returns `detection_started`: the confirm second pass and the final
/// max-duration verdict both consume it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_detection_phase(
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
    context_result: &crate::dbms::context::ContextProbeResult,
    to_test: Vec<TargetParameter>,
) -> (Instant, Vec<TargetParameter>) {
    let detection_started = Instant::now();
    let detection_req_before = state.read().await.request_count();
    // Clone borné pour Option B second-order (Body/Query, ≤max_stores) :
    // `run_detection` consomme `to_test`, le clone préserve la liste
    // filtrée `-p` pour `run_second_order` sans refaire `select_params`.
    let to_test_for_second_order = to_test.clone();
    run_detection(
        client,
        state,
        cancel,
        config,
        target,
        target_str,
        marker_set,
        raw_request,
        baseline,
        effective_tampers,
        &context_result.context,
        &context_result.dbms_belief,
        context_result.probes_sent,
        to_test,
    )
    .await;
    {
        let detection_elapsed = detection_started.elapsed().as_secs_f64();
        let detection_req_delta = state
            .read()
            .await
            .request_count()
            .saturating_sub(detection_req_before);
        let detection_findings = state.read().await.findings().len();
        info!(
            elapsed_s = detection_elapsed,
            requests = detection_req_delta,
            findings = detection_findings,
            "detection done in {detection_elapsed:.1}s ({detection_req_delta} req, {detection_findings} findings)"
        );
    }

    // C6 strict second-pass (anti-FP P2.4): `--confirm` re-probes every
    // confirmed non-OOB finding with fresh payloads + derived seed
    // (historical behaviour, ~2x req documented); without the flag, the
    // same pass re-validates confirmed non-High findings on every
    // non-OOB technique (bounded auto anti-FP with first-pass window
    // parity — see `needs_auto_second_pass`). Never creates new
    // findings — only drops those that fail re-validation (0 new FP on
    // N1/N2 by construction).
    (detection_started, to_test_for_second_order)
}

/// Fingerprint phase (moved verbatim): `run_fingerprint` + req metrics.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_fingerprint_phase(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    target: &TargetUrl,
    target_str: &str,
    scrubber: &Scrubber,
    marker_set: &MarkerSet,
    raw_request: &Arc<Option<RawRequest>>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    effective_opts: ProbeOpts,
) {
    let fingerprint_started = Instant::now();
    let fingerprint_req_before = state.read().await.request_count();
    run_fingerprint(
        client,
        state,
        cancel,
        config,
        scrubber,
        target,
        target_str,
        marker_set,
        raw_request,
        baseline,
        effective_tampers,
        effective_opts,
        &config.matcher,
    )
    .await;
    {
        let fingerprint_elapsed = fingerprint_started.elapsed().as_secs_f64();
        let fingerprint_req_delta = state
            .read()
            .await
            .request_count()
            .saturating_sub(fingerprint_req_before);
        if fingerprint_req_delta == 0 {
            info!("fingerprint skipped (no confirmed findings, 0 req)");
        } else {
            info!(
                elapsed_s = fingerprint_elapsed,
                requests = fingerprint_req_delta,
                "fingerprint done in {fingerprint_elapsed:.1}s ({fingerprint_req_delta} req)"
            );
        }
    }
}

/// Extraction phase (moved verbatim, opt-in `--extract`): finding gate +
/// eligibility + inference run. Uses `*current` for the transition
/// (P2 adaptation of the former local assignment).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_extraction_phase(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    scrubber: &Scrubber,
    target: &TargetUrl,
    target_str: &str,
    marker_set: &MarkerSet,
    raw_request: &Arc<Option<RawRequest>>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    effective_opts: ProbeOpts,
    current: &mut EngineState,
) -> crate::error::Result<()> {
    if config.enumeration.extract {
        // Gate early (same rule as enumeration): no finding => no oracle.
        // Prevents hundreds of blind requests on a clean target, in
        // particular with `--auto-enumerate`.
        let snap = state.read().await.findings().to_vec();
        if snap.is_empty() {
            warn!(
                target=%scrubber.scrub(target_str),
                "--extract requested but no confirmed vulnerability was found — skipping"
            );
        } else if !is_extraction_eligible(&snap) {
            warn!(
                target=%scrubber.scrub(target_str),
                "likely FP, extraction skipped (no boolean-confirmed or error-with-fragment finding)"
            );
        } else {
            *current = EngineState::Extraction;
            info!(
                target=%scrubber.scrub(target_str),
                state=?current,
                "phase extraction — inference (opt-in)"
            );
            run_extraction(
                client,
                state,
                cancel,
                config,
                target,
                target_str,
                marker_set,
                raw_request,
                baseline,
                effective_tampers,
                effective_opts,
            )
            .await?;
        }
    }
    Ok(())
}

/// Enumeration phase (moved verbatim, opt-in): `needs_enum` fan-out,
/// boolean-capable gate + `run_enumeration`. Uses `*current` for the
/// transition (P2 adaptation of the former local assignment).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_enumeration_phase(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    scrubber: &Scrubber,
    target: &TargetUrl,
    target_str: &str,
    marker_set: &MarkerSet,
    raw_request: &Arc<Option<RawRequest>>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    effective_opts: ProbeOpts,
    current: &mut EngineState,
) -> crate::error::Result<()> {
    // Enumeration phase (--dbs, --tables, --columns, --dump, --count,
    // --banner, --current-user, --current-db, --hostname). Requires a
    // *boolean-capable* finding (same bar as extraction): the enumerator
    // runs a boolean-differential oracle, so stacked/time/union-only
    // snapshots would chase noise into `inference inconsistency` errors
    // after burning a full oracle pass per candidate.
    let needs_enum = config.enumeration.dbs
        || config.enumeration.tables
        || config.enumeration.columns
        || config.enumeration.dump
        || config.enumeration.count
        || config.enumeration.banner
        || config.enumeration.current_user
        || config.enumeration.current_db
        || config.enumeration.hostname;
    let snap_for_enum = state.read().await.findings().to_vec();
    let enum_eligible = is_extraction_eligible(&snap_for_enum);
    if needs_enum && enum_eligible {
        *current = EngineState::Enumeration;
        info!(
            target=%scrubber.scrub(target_str),
            state=?current,
            "phase enumeration — dbs/tables/columns/dump"
        );
        run_enumeration(
            client,
            state,
            cancel,
            config,
            target,
            target_str,
            marker_set,
            raw_request,
            baseline,
            effective_tampers,
            effective_opts,
        )
        .await?;
    } else if needs_enum && snap_for_enum.is_empty() {
        warn!(
            target=%scrubber.scrub(target_str),
            "enumeration requested but no confirmed vulnerability was found"
        );
    } else if needs_enum {
        warn!(
            target=%scrubber.scrub(target_str),
            "likely FP, enumeration skipped (no boolean-capable finding: stacked/time-only cannot feed the oracle)"
        );
    }
    Ok(())
}
