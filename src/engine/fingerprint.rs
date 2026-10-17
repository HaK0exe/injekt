//! Fingerprint phase moved out of `orchestrator.rs` (P1-fin): passive DBMS
//! guess (findings + banners) then active true/false probe pair per candidate.
//!
//! Behavior-neutral move: bodies are verbatim `Engine::run_fingerprint` /
//! `Engine::active_fingerprint_probe`; `self.*` became explicit params.

use crate::{
    detection::{baseline, matcher::MatcherConfig},
    http::client::HttpClient,
    session::{
        scrubber::Scrubber,
        state::{Finding, SessionState},
    },
    target::{
        injection::{ProbeOpts, build_injection_spec_with_raw},
        markers::MarkerSet,
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::{
        boolean::detector::BooleanDetector, payload_opts::build_final_payload_with_rng,
        tamper::Tamper,
    },
};
use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::{
    config::{BudgetConfig, EngineConfig, dbms_hint_kind},
    confirm::{first_finding_param, has_confirmed_finding, is_confirmed_finding},
};

/// Passive DBMS guess from error findings + banner regex; if both are
/// inconclusive, falls back to one active differential probe per
/// candidate DBMS (see [`crate::dbms::common::DbmsDetector::fingerprint_probe`]),
/// stopping at the first confirmation. Only runs at all when there is
/// already a confirmed finding — no extra requests on a clean target.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_fingerprint(
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
    matcher: &MatcherConfig,
) {
    if BudgetConfig::is_over_request_budget(
        state.read().await.request_count(),
        config.budget.request_budget,
    ) {
        warn!("request-budget spent, skipping fingerprint");
        return;
    }
    let findings_snapshot = state.read().await.findings().to_vec();
    if findings_snapshot.is_empty() {
        return;
    }
    // Unconfirmed-only snapshots (error `0.55 unconfirmed`) must not feed
    // DBMS guessing: `guess_from_findings` would fill `postgres` from a
    // weak pattern and trigger a doomed enumeration pass.
    if !has_confirmed_finding(&findings_snapshot) {
        return;
    }
    // Guess only from confirmed findings so a leading unconfirmed error
    // (dbms=`postgres` at 0.55) cannot shadow a confirmed boolean.
    let confirmed: Vec<Finding> = findings_snapshot
        .iter()
        .filter(|f| is_confirmed_finding(f))
        .cloned()
        .collect();
    // Explicit `--dbms` hint wins over guessing: fill immediately and skip
    // active probing (saves requests, honours operator knowledge).
    if let Some(hint) = dbms_hint_kind(config) {
        let mut st = state.write().await;
        st.fill_missing_dbms(hint);
        info!(
            target=%scrubber.scrub(target_str),
            dbms=%hint,
            "fingerprint from --dbms hint"
        );
        return;
    }
    if let Some(kind) = crate::dbms::fingerprint::guess_from_findings(&confirmed) {
        let mut st = state.write().await;
        st.fill_missing_dbms(kind);
        info!(
            target=%scrubber.scrub(target_str),
            dbms=%kind,
            "fingerprint guessed from findings"
        );
        return;
    }
    // Try banner extraction from evidences
    for f in &confirmed {
        if let Some((kind, ver)) = crate::dbms::fingerprint::extract_banner_version(&f.evidence) {
            let mut st = state.write().await;
            st.fill_missing_dbms(kind);
            info!(
                target=%scrubber.scrub(target_str),
                dbms=%kind,
                version=%ver,
                "fingerprint banner detected"
            );
            return;
        }
    }
    active_fingerprint_probe(
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
        matcher,
    )
    .await;
}

/// Sends one true/false probe pair per [`crate::dbms::DbmsKind`] against
/// the confirmed injection point until one confirms via the standard
/// boolean true/false-vs-baseline heuristic
/// ([`BooleanDetector::evaluate_with_match_ratio`]).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn active_fingerprint_probe(
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
    matcher: &MatcherConfig,
) {
    let (param, probe_target) = first_finding_param(state, target).await;
    // P1.1 — purge des zones dynamiques marquées avant comparaison.
    let baseline_body =
        matcher.pre_process(&baseline.strip_dynamic_content(&baseline.representative_body_str()));
    let detector = BooleanDetector::new();
    // Seeded tamper RNG: one sequence per probe phase so `--seed` runs
    // build identical payloads; `None` preserves OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(config.seed);
    for kind in [
        crate::dbms::DbmsKind::MySql,
        crate::dbms::DbmsKind::Postgres,
        crate::dbms::DbmsKind::MsSql,
        crate::dbms::DbmsKind::Oracle,
    ] {
        if cancel.is_cancelled() {
            return;
        }
        let candidate = crate::dbms::fingerprint::get_detector(kind);
        let (true_base, false_base) = candidate.fingerprint_probe();
        let true_payload = build_final_payload_with_rng(
            &true_base,
            effective_tampers,
            &config.evasion.payload_opts,
            &mut rng,
        );
        let false_payload = build_final_payload_with_rng(
            &false_base,
            effective_tampers,
            &config.evasion.payload_opts,
            &mut rng,
        );

        let Some(true_spec) = build_injection_spec_with_raw(
            &probe_target,
            target_str,
            &param,
            &true_payload,
            marker_set,
            raw_request.as_ref().as_ref(),
            effective_opts,
            &config.evasion.payload_opts,
        ) else {
            warn!(dbms=%kind, "fingerprint true spec build failed, skipping");
            continue;
        };
        let start = Instant::now();
        let true_resp = client.send_with_retry(true_spec, cancel).await;
        let true_ms = start.elapsed().as_secs_f64() * 1000.0;
        state.write().await.increment_requests();
        // Never score a transport/body error as `""` (similarity ~0 =>
        // false positive). Skip this DBMS candidate instead.
        let (true_body, true_status) = match true_resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match client.read_body_string_with_timeout(r).await {
                    Ok(b) => (b, status),
                    Err(e) => {
                        warn!(error=%e, dbms=%kind, "fingerprint true body read failed, skipping");
                        continue;
                    }
                }
            }
            Err(e) => {
                warn!(error=%e, dbms=%kind, "fingerprint true probe failed, skipping");
                continue;
            }
        };

        if cancel.is_cancelled() {
            return;
        }
        let Some(false_spec) = build_injection_spec_with_raw(
            &probe_target,
            target_str,
            &param,
            &false_payload,
            marker_set,
            raw_request.as_ref().as_ref(),
            effective_opts,
            &config.evasion.payload_opts,
        ) else {
            warn!(dbms=%kind, "fingerprint false spec build failed, skipping");
            continue;
        };
        let start = Instant::now();
        let false_resp = client.send_with_retry(false_spec, cancel).await;
        let false_ms = start.elapsed().as_secs_f64() * 1000.0;
        state.write().await.increment_requests();
        let (false_body, false_status) = match false_resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match client.read_body_string_with_timeout(r).await {
                    Ok(b) => (b, status),
                    Err(e) => {
                        warn!(error=%e, dbms=%kind, "fingerprint false body read failed, skipping");
                        continue;
                    }
                }
            }
            Err(e) => {
                warn!(error=%e, dbms=%kind, "fingerprint false probe failed, skipping");
                continue;
            }
        };

        // Same differential standard as primary detection: `--text-only`
        // pre-processing plus the boolean matcher gate (veto only when
        // BOTH branches violate, so a `--string` oracle signal survives).
        let true_body = matcher.pre_process(&baseline.strip_dynamic_content(&true_body));
        let false_body = matcher.pre_process(&baseline.strip_dynamic_content(&false_body));
        if matcher.gate_boolean(&true_body, &false_body, true_status, false_status) == Some(false) {
            continue;
        }
        let res = detector.evaluate_with_match_ratio(
            &baseline_body,
            &true_body,
            &false_body,
            baseline.mean_ms,
            true_ms,
            false_ms,
            baseline.match_ratio(),
        );
        if res.is_vulnerable && res.confidence > 0.6 {
            state.write().await.fill_missing_dbms(kind);
            info!(
                target=%scrubber.scrub(target_str),
                dbms=%kind,
                "active fingerprint confirmed"
            );
            return;
        }
    }
}
