//! Time detection probe (`test_time_bounded`).
//! Moved verbatim from `engine/probes.rs` (P1); no behaviour change.

use crate::engine::{fetch::fetch_for_payload_with_class, schedule::dbms_payload_label};
use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    detection::baseline,
    http::{client::HttpClient, timeouts::RequestClass},
    session::state::{Finding, SessionState, TechniqueKind},
    target::{
        injection::{ProbeOpts, is_ignored, payload_budget},
        markers::MarkerSet,
        parameters::TargetParameter,
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::{
        payload_opts::{PayloadOpts, build_final_payload_with_rng},
        tamper::{Tamper, tamper_transformation_sets},
        time::{detector::TimeDetector, payloads::all_time_payloads},
    },
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::debug;

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn test_time_bounded(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    baseline: &baseline::Baseline,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    level: u8,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
) {
    let (top_dbms, top_prob) = dbms_belief.top_candidate();
    debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "time: context-aware detection");
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    // Blind sweep: L1 tries the first 4 legacy payloads, L2 doubles to 8,
    // L3+ exhausts all 16 (5 legacies + conditional/alternate/heavy variants).
    // Threshold reuses the baseline calibration (`from_baseline`); a
    // positive first shot is confirmed by an immediate second shot
    // (`evaluate_confirmed`) so a single jitter spike never reports.
    // OPSEC: the extra request fires only on a positive first shot —
    // clean targets cost the same as before. Jitter/rate-limiting are
    // preserved via `fetch_for_payload`; outer `buffer_unordered`
    // concurrency is untouched.
    let detector = TimeDetector::from_baseline(baseline);
    // DBMS-aware blind sweep: a confident belief (>= 0.85) tries only that
    // engine's sleep family; otherwise the 5-legacies-first blind sweep.
    let candidates = dbms_payload_label(dbms_belief).map_or_else(
        || all_time_payloads(3),
        |label| crate::techniques::time::payloads::time_payloads_for(Some(label), 3),
    );
    let budget = payload_budget(level, 4, candidates.len());
    let sets = tamper_transformation_sets(tampers);
    for base in candidates.iter().take(budget) {
        if cancel.is_cancelled() {
            break;
        }
        // Jitter guard: when the baseline spread already dominates the sleep
        // signal, any delay measurement is noise — skip instead of reporting
        // network chaos as Oracle time-based SQLi.
        #[allow(clippy::cast_precision_loss)]
        let sleep_ms = base.sleep_secs as f64 * 1000.0;
        if baseline.stddev_ms > sleep_ms * 0.5 {
            tracing::debug!(
                param = param.key(),
                stddev_ms = baseline.stddev_ms,
                sleep_ms,
                "time probe skipped: baseline jitter dominates the sleep signal"
            );
            continue;
        }
        let mut confirmed = false;
        for trans in &sets {
            if cancel.is_cancelled() {
                break;
            }
            let payload_str = build_final_payload_with_rng(&base.payload, trans, popts, &mut rng);
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
            // `--ignore-code`: an ignored status is skipped, never a finding.
            if is_ignored(status, ignore_codes) {
                continue;
            }
            let body = matcher.pre_process(&raw_body);
            // sleep_secs is a small time-based delay (seconds); cast is always lossless.
            #[allow(clippy::cast_precision_loss)]
            let first = detector.evaluate(ms, base.sleep_secs as f64);
            if !first.is_vulnerable {
                continue;
            }
            // Matcher veto before spending the confirmation shot.
            if matcher.matches(&body, status) == Some(false) {
                continue;
            }
            if cancel.is_cancelled() {
                break;
            }
            // Anti-cache second shot (Invicti 2024): byte-identical probes can
            // be served from a reverse-proxy/CDN cache, replaying the first
            // response *and its timing* — the double-shot would then confirm a
            // cache hit. `/*8-hex*/` is SQL whitespace on MySQL/PG/MSSQL/
            // Oracle/SQLite, so the payload stays semantically identical; only
            // the confirmation shot (never the first shot nor the control)
            // varies its bytes. Seeded RNG keeps `--seed` reproducible.
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
            if is_ignored(status2, ignore_codes) {
                continue;
            }
            let body2 = matcher.pre_process(&raw_body2);
            if matcher.matches(&body2, status2) == Some(false) {
                continue;
            }
            #[allow(clippy::cast_precision_loss)]
            let r = detector.evaluate_confirmed(ms, ms2, base.sleep_secs as f64);
            if r.is_vulnerable {
                // Differential control: re-send the benign (original) value.
                // A slow backend (cold cache, throttle, degraded host) is slow
                // for ANY input — both sleep shots clear the bar for non-SQL
                // reasons. The control must stay fast, otherwise reject.
                // OPSEC: fires only after a double-positive, never on clean
                // targets.
                if cancel.is_cancelled() {
                    break;
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
                if control_status == 0 {
                    // Transport error on the control: timing untrustworthy.
                    continue;
                }
                if control_ms > detector.threshold() {
                    tracing::debug!(
                        param = param.key(),
                        control_ms,
                        threshold_ms = detector.threshold(),
                        "time finding rejected: benign control equally slow (degraded endpoint?)"
                    );
                    continue;
                }
                let tamper_label = if trans.is_empty() {
                    "none".to_owned()
                } else {
                    trans
                        .iter()
                        .map(crate::techniques::tamper::Tamper::name)
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Time,
                    r.confidence,
                    format!(
                        "time delay {:.0}ms > threshold {:.0}ms tamper={} control={:.0}ms{}{}{}",
                        r.measured_ms,
                        detector.threshold(),
                        tamper_label,
                        control_ms,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix()
                    ),
                );
                finding.dbms = base.dbms.clone();
                state.write().await.push_finding(finding);
                confirmed = true;
                break;
            }
        }
        if confirmed {
            break;
        }
    }
}
