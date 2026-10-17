//! UNION detection probe (`test_union_bounded` + `enumerate_columns_via_order_by`).
//! Moved verbatim from `engine/probes.rs` (P1); no behaviour change.

use crate::engine::{
    fetch::fetch_for_payload,
    schedule::{check_deadline, dbms_payload_label, order_by_prefix_for_context},
};
use crate::{
    dbms::context::InjectionContext,
    http::client::HttpClient,
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
        union::{detector::UnionDetector, payloads::union_payloads_for},
    },
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::techniques::technique::{Technique, TechniqueCtx};
use futures::future::BoxFuture;

/// Enumerate column count via ORDER BY probing before UNION.
/// Sequential probing `ORDER BY 1 .. MAX`, stops at first error detected by
/// `UnionDetector::evaluate_order_by`. Returns `Some(n)` where `n = failed_index - 1`.
/// Rate limiting and jitter are preserved via `fetch_for_payload`; cancellation is honoured.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn enumerate_columns_via_order_by(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    marker_set: &MarkerSet,
    detector: &UnionDetector,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    level: u8,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    deadline: Option<std::time::Instant>,
) -> Option<usize> {
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    // `--level` widens ORDER BY enumeration: L1=10 (historical), L2=15, L3+=20.
    let max_order_by_cols: usize = match level {
        1 => 10,
        2 => 15,
        _ => 20,
    };
    let sets = tamper_transformation_sets(tampers);
    // Quote-aware prefix: the inferred context leads so `order_by` sinks
    // confirm within the historical 10-probe budget (see
    // `order_by_prefix_for_context`). One probe per index, as before.
    let prefix = order_by_prefix_for_context(context);
    for i in 1..=max_order_by_cols {
        if cancel.is_cancelled() {
            return None;
        }
        // Shared `--max-duration` deadline: stop enumeration early so one
        // technique cannot silently overshoot an explicit user budget.
        if check_deadline(deadline, &param.key(), "union-order-by") {
            return None;
        }
        let base = crate::techniques::union::payloads::order_by_payload_for(prefix, i);
        let mut triggered = false;
        for trans in &sets {
            if cancel.is_cancelled() {
                return None;
            }
            let payload = build_final_payload_with_rng(&base, trans, popts, &mut rng);
            let (raw_body, _ms, status) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &payload, marker_set, raw, opts,
                popts,
            )
            .await;
            // `--ignore-code`: an ignored response never triggers an ORDER BY error.
            if is_ignored(status, ignore_codes) {
                continue;
            }
            let body = matcher.pre_process(&raw_body);
            if detector.evaluate_order_by(&body) {
                triggered = true;
                break;
            }
        }
        if triggered {
            if i == 1 {
                warn!("ORDER BY 1 already errored — ORDER BY enumeration inconclusive");
                return None;
            }
            let inferred = i - 1;
            info!(inferred, "ORDER BY enumeration inferred column count");
            return Some(inferred);
        }
    }
    // Undetermined is actionable (yellow warn, not a drowned `info!`): the
    // operator can widen the enumeration instead of assuming "not
    // injectable". The hint is level-aware so L2 runs are not told to
    // "try --level 2" again.
    let level_hint = match level {
        0 | 1 => "try --level 2 (15 cols)",
        2 => "try --level 3 (20 cols)",
        _ => "already at max enumeration (20 cols)",
    };
    warn!(
        "ORDER BY enumeration inconclusive: no error up to {max_order_by_cols} columns — {level_hint}"
    );
    None
}

pub(crate) struct UnionTechnique;

impl Technique for UnionTechnique {
    fn kind(&self) -> TechniqueKind {
        TechniqueKind::Union
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn probe<'a>(&'a self, ctx: &'a TechniqueCtx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let client = ctx.client;
            let state = ctx.state;
            let cancel = ctx.cancel;
            let target = ctx.target;
            let target_str = ctx.target_str;
            let param = ctx.param;
            let baseline = ctx.baseline;
            let marker_set = ctx.marker_set;
            let raw = ctx.raw;
            let tampers = ctx.tampers;
            let opts = ctx.opts;
            let popts = ctx.popts;
            let matcher = ctx.matcher;
            let level = ctx.level;
            let ignore_codes = ctx.ignore_codes;
            let seed = ctx.seed;
            let context = ctx.context;
            let dbms_belief = ctx.dbms_belief;
            let deadline = ctx.deadline;
            if context.order_by {
                debug!(
                    param = param.key(),
                    "union: order_by context, ORDER BY enumeration prioritized"
                );
            }
            let (top_dbms, top_prob) = dbms_belief.top_candidate();
            debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "union: context-aware detection");
            // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
            // `None` preserves the historical OS-random behaviour.
            let mut rng = crate::seeded_rng::make_rng(seed);
            let detector = UnionDetector::new();
            let baseline_body = matcher.pre_process(&baseline.representative_body_str());
            let tamper_sets = tamper_transformation_sets(tampers);

            // Phase 0 — ORDER BY enumeration to reduce false positives.
            // Prioritized when `context.order_by` (the prefix cycle leads with the
            // inferred quote); always runs otherwise too, since the inferred count
            // gates the UNION column trials. If we successfully infer `n`, we test
            // only `n` first. If that fails, we still fall back to the heuristic
            // list (excluding the already-tried `n`) to keep coverage for edge
            // cases where ORDER BY is WAF-filtered but UNION still works.
            let inferred = enumerate_columns_via_order_by(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                marker_set,
                &detector,
                raw,
                tampers,
                opts,
                popts,
                matcher,
                level,
                ignore_codes,
                seed,
                context,
                deadline,
            )
            .await;
            // DBMS-aware UNION cores once the belief is actionable (>= 0.85);
            // otherwise the generic polyglot head (unchanged default).
            let dbms_label = dbms_payload_label(dbms_belief);

            let mut cols_to_try: Vec<usize> = Vec::new();
            let mut fallback = vec![3usize, 2, 4, 5];
            if let Some(n) = inferred {
                cols_to_try.push(n);
                // Keep fallback for resilience but avoid duplicate probe
                fallback.retain(|c| *c != n);
            } else {
                cols_to_try = fallback.clone();
                fallback.clear();
            }

            // Primary pass: inferred or heuristic
            for cols in &cols_to_try {
                if cancel.is_cancelled() {
                    return;
                }
                // Shared `--max-duration` deadline: stop the matrix early so one
                // technique cannot silently overshoot an explicit user budget.
                if check_deadline(deadline, &param.key(), "union") {
                    return;
                }
                let cols = *cols;
                let payloads = union_payloads_for(dbms_label, cols);
                for p in payloads
                    .iter()
                    .take(payload_budget(level, 1, payloads.len()))
                {
                    if cancel.is_cancelled() {
                        return;
                    }
                    // Shared `--max-duration` deadline: stop the matrix early (see
                    // per-cols check above).
                    if check_deadline(deadline, &param.key(), "union") {
                        return;
                    }
                    for trans in &tamper_sets {
                        if cancel.is_cancelled() {
                            return;
                        }
                        let tampered =
                            build_final_payload_with_rng(&p.payload, trans, popts, &mut rng);
                        let (raw_body, ms, status) = fetch_for_payload(
                            client, state, cancel, target, target_str, param, &tampered,
                            marker_set, raw, opts, popts,
                        )
                        .await;
                        // `--ignore-code`: an ignored status is skipped, never a finding.
                        if is_ignored(status, ignore_codes) {
                            continue;
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
                        if r.is_vulnerable {
                            // Matcher veto gate: `Some(false)` rejects the candidate.
                            if matcher.matches(&body, status) == Some(false) {
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
                                TechniqueKind::Union,
                                r.confidence,
                                format!(
                                    "union columns={:?} payload={} order_by_inferred={:?} tamper={}{}{}{}",
                                    r.columns,
                                    tampered,
                                    inferred,
                                    tamper_label,
                                    opts.evidence_suffix(),
                                    popts.evidence_suffix(),
                                    matcher.evidence_suffix()
                                ),
                            );
                            finding.dbms = Some(p.dbms.clone());
                            state.write().await.push_finding(finding);
                            return;
                        }
                    }
                }
            }

            // Secondary pass: fallback heuristic if primary (inferred) yielded nothing
            for cols in fallback {
                if cancel.is_cancelled() {
                    break;
                }
                // Shared `--max-duration` deadline (see primary pass above).
                if check_deadline(deadline, &param.key(), "union") {
                    break;
                }
                let payloads = union_payloads_for(dbms_label, cols);
                for p in payloads
                    .iter()
                    .take(payload_budget(level, 1, payloads.len()))
                {
                    if cancel.is_cancelled() {
                        break;
                    }
                    for trans in &tamper_sets {
                        if cancel.is_cancelled() {
                            break;
                        }
                        let tampered =
                            build_final_payload_with_rng(&p.payload, trans, popts, &mut rng);
                        let (raw_body, ms, status) = fetch_for_payload(
                            client, state, cancel, target, target_str, param, &tampered,
                            marker_set, raw, opts, popts,
                        )
                        .await;
                        // `--ignore-code`: an ignored status is skipped, never a finding.
                        if is_ignored(status, ignore_codes) {
                            continue;
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
                        if r.is_vulnerable {
                            // Matcher veto gate: `Some(false)` rejects the candidate.
                            if matcher.matches(&body, status) == Some(false) {
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
                                TechniqueKind::Union,
                                r.confidence,
                                format!(
                                    "union columns={:?} payload={} order_by_inferred={:?} (fallback) tamper={}{}{}{}",
                                    r.columns,
                                    tampered,
                                    inferred,
                                    tamper_label,
                                    opts.evidence_suffix(),
                                    popts.evidence_suffix(),
                                    matcher.evidence_suffix()
                                ),
                            );
                            finding.dbms = Some(p.dbms.clone());
                            state.write().await.push_finding(finding);
                            return;
                        }
                    }
                }
            }
        })
    }
}
