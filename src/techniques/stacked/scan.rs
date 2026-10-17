//! Stacked detection probe (`test_stacked_bounded`).
//! Moved verbatim from `engine/probes.rs` (P1); no behaviour change.

use crate::engine::{fetch::fetch_for_payload, schedule::dbms_payload_label};
use crate::{
    session::state::{Finding, TechniqueKind},
    target::injection::{is_ignored, payload_budget},
    techniques::{
        payload_opts::build_final_payload_with_rng,
        stacked::{detector::StackedDetector, payloads::stacked_payloads_for},
        tamper::tamper_transformation_sets,
    },
};
use tracing::debug;

use crate::techniques::technique::{Technique, TechniqueCtx};
use futures::future::BoxFuture;

pub(crate) struct StackedTechnique;

impl Technique for StackedTechnique {
    fn kind(&self) -> TechniqueKind {
        TechniqueKind::Stacked
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
            let (top_dbms, top_prob) = dbms_belief.top_candidate();
            debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "stacked: context-aware detection");
            // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
            // `None` preserves the historical OS-random behaviour.
            let mut rng = crate::seeded_rng::make_rng(seed);
            let detector = StackedDetector::new();
            let baseline_body = matcher.pre_process(&baseline.representative_body_str());
            // DBMS-aware stacked cores once actionable (>= 0.85), else generics.
            let payloads = stacked_payloads_for(dbms_payload_label(dbms_belief));
            let tamper_sets = tamper_transformation_sets(tampers);
            for p in payloads
                .iter()
                .take(payload_budget(level, 2, payloads.len()))
            {
                if cancel.is_cancelled() {
                    break;
                }
                let mut found = false;
                for trans in &tamper_sets {
                    if cancel.is_cancelled() {
                        break;
                    }
                    let tampered = build_final_payload_with_rng(&p.payload, trans, popts, &mut rng);
                    let (raw_body, ms, status) = fetch_for_payload(
                        client, state, cancel, target, target_str, param, &tampered, marker_set,
                        raw, opts, popts,
                    )
                    .await;
                    let body = matcher.pre_process(&raw_body);
                    // `--ignore-code`: an ignored status is skipped, never a finding.
                    if is_ignored(status, ignore_codes) {
                        continue;
                    }
                    let r = detector.evaluate(
                        &baseline_body,
                        &body,
                        baseline.mean_ms,
                        ms,
                        p,
                        &tampered,
                    );
                    if r.is_vulnerable {
                        // Matcher veto gate: `Some(false)` rejects the candidate.
                        if matcher.matches(&body, status) == Some(false) {
                            continue;
                        }
                        // Second-shot confirmation with a FRESH marker: the same sink
                        // must execute a different stacked statement before reporting.
                        // A single marker echo (reflected input, dynamic page) never
                        // reports. OPSEC: the extra request fires only on a positive
                        // first shot — clean targets cost the same as before.
                        // Same DBMS family as the first shot (coherent confirmation).
                        let confirm_payloads =
                            stacked_payloads_for(dbms_payload_label(dbms_belief));
                        let Some(confirm) = confirm_payloads.first() else {
                            continue;
                        };
                        let confirm_tampered =
                            build_final_payload_with_rng(&confirm.payload, trans, popts, &mut rng);
                        if cancel.is_cancelled() {
                            break;
                        }
                        let (raw_body2, ms2, status2) = fetch_for_payload(
                            client,
                            state,
                            cancel,
                            target,
                            target_str,
                            param,
                            &confirm_tampered,
                            marker_set,
                            raw,
                            opts,
                            popts,
                        )
                        .await;
                        // `--ignore-code`: an ignored status is skipped, never a finding.
                        if is_ignored(status2, ignore_codes) {
                            continue;
                        }
                        let body2 = matcher.pre_process(&raw_body2);
                        if matcher.matches(&body2, status2) == Some(false) {
                            continue;
                        }
                        let r2 = detector.evaluate(
                            &baseline_body,
                            &body2,
                            baseline.mean_ms,
                            ms2,
                            confirm,
                            &confirm_tampered,
                        );
                        if !r2.is_vulnerable {
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
                            TechniqueKind::Stacked,
                            r2.confidence.min(r.confidence),
                            format!(
                                "stacked dbms={} marker={} tamper={} confirmed=true{}{}{}",
                                r2.dbms.as_deref().unwrap_or("?"),
                                p.marker,
                                tamper_label,
                                opts.evidence_suffix(),
                                popts.evidence_suffix(),
                                matcher.evidence_suffix()
                            ),
                        );
                        finding.dbms = r.dbms.clone();
                        state.write().await.push_finding(finding);
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
            }
        })
    }
}
