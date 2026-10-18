//! Time detection probe (`test_time_bounded`).
//! Moved verbatim from `engine/probes.rs` (P1); no behaviour change.

use crate::engine::schedule::dbms_payload_label;
use crate::{
    http::timeouts::RequestClass,
    session::state::{Finding, TechniqueKind},
    target::injection::{is_ignored, payload_budget},
    techniques::{
        payload_opts::build_final_payload_with_rng,
        tamper::tamper_transformation_sets,
        time::{detector::TimeDetector, payloads::all_time_payloads},
    },
};
use tracing::debug;

use crate::techniques::technique::{Technique, TechniqueCtx};
use futures::future::BoxFuture;

pub(crate) struct TimeTechnique;

impl Technique for TimeTechnique {
    fn kind(&self) -> TechniqueKind {
        TechniqueKind::Time
    }

    #[allow(clippy::too_many_lines)]
    fn probe<'a>(&'a self, ctx: &'a TechniqueCtx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = ctx.state;
            let cancel = ctx.cancel;
            let target = ctx.target;
            let param = ctx.param;
            let baseline = ctx.baseline;
            let tampers = ctx.tampers;
            let opts = ctx.opts;
            let popts = ctx.popts;
            let matcher = ctx.matcher;
            let level = ctx.level;
            let ignore_codes = ctx.ignore_codes;
            let seed = ctx.seed;
            let context = ctx.context;
            let dbms_belief = ctx.dbms_belief;
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
                    let payload_str =
                        build_final_payload_with_rng(&base.payload, trans, popts, &mut rng);
                    let (raw_body, ms, status) =
                        ctx.fetch_with_class(&payload_str, RequestClass::Time).await;
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
                    let payload2 =
                        crate::techniques::time::detector::cache_variant(&payload_str, &mut rng);
                    let (raw_body2, ms2, status2) =
                        ctx.fetch_with_class(&payload2, RequestClass::Time).await;
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
                        let (_control_body, control_ms, control_status) = ctx
                            .fetch_with_class(&control_payload, RequestClass::Time)
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
                        let tamper_label = crate::techniques::tamper::tamper_label(trans);
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
        })
    }
}
