//! Pipeline glue moved out of `orchestrator.rs` (P1-fin): the
//! `run_internal` phase machine (parse -> baseline -> context -> detection ->
//! confirm -> second-order -> fingerprint -> extraction -> enumeration) plus
//! its private helpers (`absorb_detectability`, `build_raw_request`,
//! `effective_marker_set`, `select_params`).
//!
//! Behavior-neutral move: bodies are verbatim `Engine::run_internal` and
//! friends; `self.*` became explicit params.

use crate::target::{injection::baseline_all_error, url::TargetUrl};
use std::{collections::HashMap, sync::Arc, time::Instant};
use tracing::{info, warn};

use super::{
    EngineState,
    baseline::collect_baseline,
    config::BudgetConfig,
    confirm::{ConfirmScope, is_extraction_eligible, run_confirm_second_pass},
    detection::run_detection,
    enumerate::run_enumeration,
    extraction::run_extraction,
    fingerprint::run_fingerprint,
    second_order::run_second_order,
};

pub(crate) use self::helpers::PipelineCtx;
use self::helpers::{absorb_detectability, build_raw_request, select_params};

mod helpers;

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

    // `--confirm` strict second-pass (C6): re-sonde every confirmed finding
    // with fresh payloads + derived seed after detection (OOB excluded).
    // In-detection 3-trial confirmation still applies regardless.
    if config.confirm {
        info!("--confirm second-pass enabled (fresh payloads, derived seed, OOB excluded)");
    }

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
    current = EngineState::Baseline;
    info!(
        target=%scrubber.scrub(target_str),
        state=?current,
        "phase baseline"
    );

    if cancel.is_cancelled() {
        absorb_detectability(client, state, shared_client).await;
        return Ok(EngineState::Cancelled);
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
        return Ok(EngineState::Inconclusive);
    }

    let candidate_param = candidate.map(crate::recon::ParameterCandidate::target_parameter);
    let raw_request = build_raw_request(config, candidate);

    let Some((baseline, effective_tampers, effective_opts)) = collect_baseline(
        client,
        state,
        cancel,
        config,
        scrubber,
        baseline_cache,
        &target,
        raw_request.as_ref(),
    )
    .await?
    else {
        absorb_detectability(client, state, shared_client).await;
        return Ok(EngineState::Cancelled);
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
        return Ok(EngineState::Inconclusive);
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

    // Run adaptive context analysis (<=8 requests bound, 0 DBMS probes if --dbms)
    let context_started = Instant::now();
    let context_req_before = state.read().await.request_count();
    let primary_param = to_test.first();
    let context_result = if let Some(param) = primary_param {
        crate::dbms::context::analyze_context(
            client,
            state,
            cancel,
            &target,
            param,
            raw_request.as_ref().as_ref(),
            &baseline,
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

    current = EngineState::Detection;
    info!(
        target=%scrubber.scrub(target_str),
        state=?current,
        "phase detection"
    );

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
        &target,
        target_str,
        &marker_set,
        &raw_request,
        &baseline,
        &effective_tampers,
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
    let fingerprint_req_before = state.read().await.request_count();
    run_fingerprint(
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
            current = EngineState::Extraction;
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
                &target,
                target_str,
                &marker_set,
                &raw_request,
                &baseline,
                &effective_tampers,
                effective_opts,
            )
            .await?;
        }
    }

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
        current = EngineState::Enumeration;
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
            &target,
            target_str,
            &marker_set,
            &raw_request,
            &baseline,
            &effective_tampers,
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

    current = EngineState::Done;
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
    Ok(current)
}
