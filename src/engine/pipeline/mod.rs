//! Pipeline glue moved out of `orchestrator.rs` (P1-fin): the
//! `run_internal` phase machine (parse -> baseline -> context -> detection ->
//! confirm -> second-order -> fingerprint -> extraction -> enumeration) plus
//! its private helpers (`absorb_detectability`, `build_raw_request`,
//! `effective_marker_set`, `select_params`).
//!
//! Behavior-neutral move: bodies are verbatim `Engine::run_internal` and
//! friends; `self.*` became explicit params.

use std::{sync::Arc, time::Instant};
use tracing::{info, warn};

use super::{
    EngineState,
    confirm::{ConfirmScope, run_confirm_second_pass},
    second_order::run_second_order,
};

pub(crate) use self::helpers::PipelineCtx;
use self::helpers::{build_raw_request, select_params};

mod helpers;
mod phases;

use self::phases::BaselinePhase;

#[allow(clippy::too_many_lines)]
pub(crate) async fn run_internal(
    ctx: &PipelineCtx<'_>,
    target_str: &str,
    candidate: Option<&crate::recon::ParameterCandidate>,
) -> crate::error::Result<EngineState> {
    let client = ctx.client;
    let state = ctx.state;
    let cancel = ctx.cancel;
    let config = ctx.config;
    let scrubber = ctx.scrubber;
    let baseline_cache = ctx.baseline_cache;
    let shared_client = ctx.shared_client;
    let mut current = EngineState::Parse;
    let run_started = Instant::now();
    info!(target=%scrubber.scrub(target_str), state=?current, "engine start");
    // Vue pipeline (stderr, cargo-style) : lignes `✓ phase · résumé`
    // persistantes + barre de détection greffée. Muet si `--quiet` ou hors TTY.
    let progress = crate::cli::output::progress::PipelineView::new(config.quiet);

    // `--confirm` strict second-pass (C6): re-sonde every confirmed finding
    // with fresh payloads + derived seed after detection (OOB excluded).
    // In-detection 3-trial confirmation still applies regardless.
    if config.confirm {
        info!("--confirm second-pass enabled (fresh payloads, derived seed, OOB excluded)");
    }
    let target = phases::preflight_target(config, target_str).await?;
    current = EngineState::Baseline;
    info!(
        target=%scrubber.scrub(target_str),
        state=?current,
        "phase baseline"
    );

    let candidate_param = candidate.map(crate::recon::ParameterCandidate::target_parameter);
    let raw_request = build_raw_request(config, candidate);

    let baseline_started = Instant::now();
    let baseline_req_before = state.read().await.request_count();
    let (baseline, effective_tampers, effective_opts, baseline_unreachable) =
        match phases::run_baseline_phase(
            client,
            state,
            cancel,
            config,
            scrubber,
            baseline_cache,
            shared_client,
            &target,
            target_str,
            raw_request.as_ref(),
        )
        .await?
        {
            BaselinePhase::Proceed {
                baseline,
                effective_tampers,
                opts,
                baseline_unreachable,
            } => (baseline, effective_tampers, opts, baseline_unreachable),
            BaselinePhase::Stop(stop) => return Ok(stop),
        };
    progress.done_phase(
        "baseline",
        &format!(
            "{:.1}s · {} req",
            baseline_started.elapsed().as_secs_f64(),
            state.read().await.request_count() - baseline_req_before,
        ),
    );

    current = EngineState::Context;
    info!(
        target=%scrubber.scrub(target_str),
        state=?current,
        "phase context"
    );

    let (marker_set, to_test) = select_params(
        config,
        target_str,
        &target,
        raw_request.as_ref(),
        candidate_param.as_ref(),
    );
    let raw_request = Arc::new(raw_request);
    let primary_param = to_test.first();
    let context_started = Instant::now();
    let context_result = phases::run_context_phase(
        client,
        state,
        cancel,
        config,
        &target,
        target_str,
        scrubber,
        raw_request.as_ref().as_ref(),
        &baseline,
        primary_param,
    )
    .await;
    progress.done_phase(
        "context",
        &format!(
            "{:.1}s · {} param(s) à tester",
            context_started.elapsed().as_secs_f64(),
            to_test.len(),
        ),
    );

    current = EngineState::Detection;
    info!(
        target=%scrubber.scrub(target_str),
        state=?current,
        "phase detection"
    );

    let detection_req_before = state.read().await.request_count();
    let (detection_started, to_test_for_second_order) = phases::run_detection_phase(
        client,
        state,
        cancel,
        config,
        &target,
        target_str,
        &marker_set,
        &raw_request,
        &baseline,
        &effective_tampers,
        &context_result,
        to_test,
        &progress,
    )
    .await;
    // Compteur DELTA (phase seule), même sémantique que la ligne baseline.
    progress.done_phase(
        "detection",
        &format!(
            "{:.1}s · {} req",
            detection_started.elapsed().as_secs_f64(),
            state.read().await.request_count() - detection_req_before,
        ),
    );

    let confirm_scope = if config.confirm {
        ConfirmScope::All
    } else {
        ConfirmScope::MediumRisk
    };
    run_confirm_second_pass(
        client,
        state,
        cancel,
        config,
        &target,
        target_str,
        &marker_set,
        &raw_request,
        &baseline,
        &effective_tampers,
        effective_opts,
        &context_result.context,
        &context_result.dbms_belief,
        detection_started,
        confirm_scope,
    )
    .await;

    // Option B second-order actif borné (lab only, même-origine) :
    // APRÈS `run_confirm_second_pass`, AVANT `run_fingerprint`.
    // OFF par défaut = 0 requête extra (chemin byte-identique).
    if config.second_order.enabled {
        run_second_order(
            client,
            state,
            cancel,
            config,
            scrubber,
            &target,
            target_str,
            &to_test_for_second_order,
            &marker_set,
            &raw_request,
            &baseline,
        )
        .await?;
    }

    // `--explain <param>`: one-line reasoning verdict after the run.
    if let Some(wanted) = config.explain.clone() {
        let st = state.read().await;
        if let Some(line) = st.explain(&wanted) {
            info!(param=%wanted, explain=%line, "--explain");
        } else {
            warn!(param=%wanted, "no finding matches --explain");
        }
    }

    current = EngineState::Fingerprint;
    info!(
        target=%scrubber.scrub(target_str),
        state=?current,
        "phase fingerprint"
    );
    let fingerprint_started = Instant::now();
    phases::run_fingerprint_phase(
        client,
        state,
        cancel,
        config,
        &target,
        target_str,
        scrubber,
        &marker_set,
        &raw_request,
        &baseline,
        &effective_tampers,
        effective_opts,
    )
    .await;
    progress.done_phase(
        "fingerprint",
        &format!("{:.1}s", fingerprint_started.elapsed().as_secs_f64()),
    );

    phases::run_extraction_phase(
        client,
        state,
        cancel,
        config,
        scrubber,
        &target,
        target_str,
        &marker_set,
        &raw_request,
        &baseline,
        &effective_tampers,
        effective_opts,
        &mut current,
    )
    .await?;

    phases::run_enumeration_phase(
        client,
        state,
        cancel,
        config,
        scrubber,
        &target,
        target_str,
        &marker_set,
        &raw_request,
        &baseline,
        &effective_tampers,
        effective_opts,
        &mut current,
    )
    .await?;

    Ok(phases::finalize_run(
        client,
        state,
        cancel,
        config,
        scrubber,
        shared_client,
        target_str,
        detection_started,
        run_started,
        baseline_unreachable,
    )
    .await)
}
