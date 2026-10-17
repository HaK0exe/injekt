//! Union second-pass (`parse_union_columns`, `union_marker_for_finding`,
//! `confirm_union_second_pass`). Moved verbatim from `confirm.rs` (P1-fin);
//! no behaviour change.

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

/// Parse the confirmed UNION column width from evidence (`columns=N`,
/// `columns=Some(N)` or `columns=[N, ..]`). Returns `None` when absent or
/// unparsable — the caller falls back to the historical default width 3.
/// Pure, never panics (operator-controlled evidence).
pub(crate) fn parse_union_columns(evidence: &str) -> Option<usize> {
    let key = "columns=";
    let start = evidence.find(key)? + key.len();
    let rest = evidence[start..].trim_start();
    // Shapes: `3`, `Some(3)`, `[3, 4]`, `Ok(3)`. Scan the first ASCII digit run.
    let mut digits = String::new();
    let mut in_digits = false;
    for c in rest.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            in_digits = true;
        } else if in_digits {
            break;
        }
    }
    if digits.is_empty() {
        return None;
    }
    let parsed: usize = digits.parse().ok()?;
    if parsed == 0 || parsed > 32 {
        return None;
    }
    Some(parsed)
}

/// Marqueur UNION pour le signal muté : réutilise le premier core DBMS-aware
/// quand il existe, sinon le marqueur générique `injekt`.
pub(crate) fn union_marker_for_finding(finding: &Finding) -> String {
    let label = dbms_label_from_finding(finding);
    crate::techniques::union::payloads::union_payloads_for(label, 3)
        .first()
        .map_or_else(|| "injekt".to_owned(), |p| p.marker.clone())
}

/// Union second-pass: re-send fresh UNION cores for the finding's DBMS
/// (bounded retry across the finding's column width and its neighbour);
/// the marker differential must still hold for ANY candidate.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn confirm_union_second_pass(
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
    // Column widths to retry: the finding's own width first (parsed from
    // evidence `columns=N`), then the historical default 3. Bounded to 2
    // widths × 1 payload each (mirrors the per-cols `payload_budget`).
    let mut widths: Vec<usize> = Vec::with_capacity(2);
    if let Some(w) = parse_union_columns(&finding.evidence) {
        widths.push(w);
    }
    if !widths.contains(&3) {
        widths.push(3);
    }
    let take_widths = payload_budget(level, 1, widths.len()).clamp(1, 2);
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let detector = crate::techniques::union::detector::UnionDetector::new();
    for cols in widths.into_iter().take(take_widths) {
        if cancel.is_cancelled() {
            return true;
        }
        let payloads = crate::techniques::union::payloads::union_payloads_for(label, cols);
        let Some(p) = payloads.first() else {
            continue;
        };
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
        let r = detector.evaluate(
            &baseline_body,
            &body,
            baseline.mean_ms,
            ms,
            cols,
            &p.marker,
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
            if r.is_vulnerable { 0.85 } else { 0.1 },
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
