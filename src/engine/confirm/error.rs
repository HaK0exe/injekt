//! Error second-pass (`confirm_error_second_pass`).
//! Moved verbatim from `confirm.rs` (P1-fin); no behaviour change.

use crate::{
    dbms::context::InjectionContext,
    detection::baseline,
    engine::fetch::fetch_for_payload,
    http::client::HttpClient,
    session::state::{Finding, SessionState},
    target::{
        injection::{ProbeOpts, is_ignored, payload_budget},
        markers::MarkerSet,
        parameters::TargetParameter,
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::{
        payload_opts::{PayloadOpts, build_final_payload_with_rng},
        tamper::Tamper,
    },
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use super::{boolean::confirm_boolean_second_pass, dbms_label_from_finding, push_confirm_trace};

/// Error second-pass: re-send DBMS-aware error payloads (bounded retry);
/// the DB error pattern must still appear (baseline-vetoed). Fragment findings
/// (`extracted=yes`) keep the bar; `bool_confirm=true` findings additionally
/// require the boolean pair to still hold (via [`confirm_boolean_second_pass`]).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn confirm_error_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let payloads =
        crate::techniques::error::payloads::error_payloads_for(dbms_label_from_finding(finding));
    let take = payload_budget(level, 2, payloads.len()).clamp(1, 2);
    if payloads.is_empty() {
        return true;
    }
    // P1.1 — purge des zones dynamiques marquées avant comparaison.
    let baseline_body =
        matcher.pre_process(&baseline.strip_dynamic_content(&baseline.representative_body_str()));
    for p in payloads.iter().take(take) {
        if cancel.is_cancelled() {
            return true;
        }
        // Single chain (not expanded): ~2x bound, coherent with detection tamper.
        let tampered = build_final_payload_with_rng(&p.payload, effective_tampers, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload(
            client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
            popts,
        )
        .await;
        if cancel.is_cancelled() || status == 0 || is_ignored(status, ignore_codes) {
            return true;
        }
        let body = matcher.pre_process(&baseline.strip_dynamic_content(&raw_body));
        let r = crate::techniques::error::detector::ErrorDetector::new().evaluate_with_context(
            &baseline_body,
            &body,
            &tampered,
        );
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &tampered,
            &body,
            if r.is_vulnerable { 0.9 } else { 0.1 },
            ms,
        )
        .await;
        if matcher.matches(&body, status) == Some(false) {
            continue;
        }
        if !r.is_vulnerable {
            continue;
        }
        // `bool_confirm=true` findings must still hold the boolean differential.
        if finding.evidence.contains("bool_confirm=true") {
            let ok = confirm_boolean_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                context,
                level,
            )
            .await;
            if !ok {
                continue;
            }
        }
        return true;
    }
    false
}
