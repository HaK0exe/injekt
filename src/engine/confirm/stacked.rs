//! Stacked second-pass (`confirm_stacked_second_pass`).
//! Moved verbatim from `confirm.rs` (P1-fin); no behaviour change.

use crate::{
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

use super::{dbms_label_from_finding, push_confirm_trace};

/// Stacked second-pass: re-send fresh stacked cores (bounded retry); the
/// marker must still execute for ANY candidate.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn confirm_stacked_second_pass(
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
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let payloads = crate::techniques::stacked::payloads::stacked_payloads_for(
        dbms_label_from_finding(finding),
    );
    let take = payload_budget(level, 2, payloads.len()).clamp(1, 2);
    if payloads.is_empty() {
        return true;
    }
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let detector = crate::techniques::stacked::detector::StackedDetector::new();
    for p in payloads.iter().take(take) {
        if cancel.is_cancelled() {
            return true;
        }
        let tampered = build_final_payload_with_rng(&p.payload, effective_tampers, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload(
            client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
            popts,
        )
        .await;
        if cancel.is_cancelled() || status == 0 || is_ignored(status, ignore_codes) {
            return true;
        }
        let body = matcher.pre_process(&raw_body);
        let r = detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, p, &tampered);
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &tampered,
            &body,
            if r.is_vulnerable { 0.8 } else { 0.1 },
            ms,
        )
        .await;
        if matcher.matches(&body, status) == Some(false) {
            continue;
        }
        if r.is_vulnerable {
            return true;
        }
    }
    false
}
