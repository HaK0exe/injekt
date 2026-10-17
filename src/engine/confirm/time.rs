//! Time second-pass (`confirm_time_second_pass`).
//! Moved verbatim from `confirm.rs` (P1-fin); no behaviour change.

use crate::{
    detection::baseline,
    engine::fetch::fetch_for_payload_with_class,
    http::{client::HttpClient, timeouts::RequestClass},
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

/// Time second-pass: fresh sleep probes + benign control (bounded retry).
/// Keep iff ANY sleep candidate still shows the delay while the control stays
/// fast. Inconclusive (transport/`--ignore-code`/cancel/jitter-dominated
/// baseline) keeps immediately.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn confirm_time_second_pass(
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
    let label = dbms_label_from_finding(finding);
    // Parité de fenêtre avec `test_time_bounded` : blind sweep complet quand le
    // finding n'a pas d'attribution DBMS, sinon famille DBMS ; budget
    // `payload_budget(level, 4, ..)` identique à la première passe (l'ancien
    // `clamp(1, 2)` ne re-sondait que la tête de liste et perdait les variants
    // concat/heavy).
    let candidates = label.map_or_else(
        || crate::techniques::time::payloads::all_time_payloads(3),
        |label| crate::techniques::time::payloads::time_payloads_for(Some(label), 3),
    );
    let take = payload_budget(level, 4, candidates.len());
    if candidates.is_empty() {
        return true;
    }
    let detector = crate::techniques::time::detector::TimeDetector::from_baseline(baseline);
    for base in candidates.iter().take(take) {
        if cancel.is_cancelled() {
            return true;
        }
        #[allow(clippy::cast_precision_loss)]
        let sleep_ms = base.sleep_secs as f64 * 1000.0;
        if baseline.stddev_ms > sleep_ms * 0.5 {
            return true;
        }
        let payload_str =
            build_final_payload_with_rng(&base.payload, effective_tampers, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload_with_class(
            client,
            state,
            cancel,
            target,
            target_str,
            param,
            &payload_str,
            marker_set,
            raw,
            opts,
            popts,
            RequestClass::Time,
        )
        .await;
        if cancel.is_cancelled() || status == 0 || is_ignored(status, ignore_codes) {
            return true;
        }
        let body = matcher.pre_process(&raw_body);
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &payload_str,
            &body,
            if ms > detector.threshold() { 0.9 } else { 0.1 },
            ms,
        )
        .await;
        if matcher.matches(&body, status) == Some(false) {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let first = detector.evaluate(ms, base.sleep_secs as f64);
        if !first.is_vulnerable {
            continue;
        }
        // Double-shot confirmation (same bar as the primary pass): a single
        // slow response may be jitter/throttle, not SQL. Re-send the sleep
        // payload with an anti-cache comment prefix (`/*8-hex*/`, SQL
        // whitespace on every targeted DBMS, same SQL semantics): identical
        // bytes could be replayed by a reverse-proxy cache — including its
        // timing — and a cache hit must not pass for a second round-trip.
        // Both shots must clear the bar via `evaluate_confirmed` before the
        // benign control runs.
        if cancel.is_cancelled() {
            return true;
        }
        let payload2 = crate::techniques::time::detector::cache_variant(&payload_str, &mut rng);
        let (raw_body2, ms2, status2) = fetch_for_payload_with_class(
            client,
            state,
            cancel,
            target,
            target_str,
            param,
            &payload2,
            marker_set,
            raw,
            opts,
            popts,
            RequestClass::Time,
        )
        .await;
        if cancel.is_cancelled() || status2 == 0 {
            return true;
        }
        if is_ignored(status2, ignore_codes) {
            continue;
        }
        let body2 = matcher.pre_process(&raw_body2);
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &payload2,
            &body2,
            if ms2 > detector.threshold() { 0.9 } else { 0.1 },
            ms2,
        )
        .await;
        if matcher.matches(&body2, status2) == Some(false) {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let confirmed = detector.evaluate_confirmed(ms, ms2, base.sleep_secs as f64);
        if !confirmed.is_vulnerable {
            continue;
        }
        let control_payload = param.original_value.clone();
        let (_control_body, control_ms, control_status) = fetch_for_payload_with_class(
            client,
            state,
            cancel,
            target,
            target_str,
            param,
            &control_payload,
            marker_set,
            raw,
            opts,
            popts,
            RequestClass::Time,
        )
        .await;
        if control_status == 0 || cancel.is_cancelled() {
            return true;
        }
        if control_ms > detector.threshold() {
            return true;
        }
        return true;
    }
    false
}
