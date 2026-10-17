//! JSON-function detection probe (`test_json_bounded`).
//! Moved verbatim from `engine/probes.rs` (P1); no behaviour change.

use crate::engine::{
    fetch::{fetch_for_payload, fetch_for_payload_with_class},
    schedule::{dbms_payload_label, json_scan_payloads},
};
use crate::{
    http::timeouts::RequestClass,
    session::state::{Finding, TechniqueKind},
    target::injection::{is_ignored, payload_budget},
    techniques::{
        json::detector::JsonDetector, payload_opts::build_final_payload_with_rng,
        tamper::boolean_safe_transformation_sets,
    },
};
use tracing::debug;

use crate::techniques::technique::{Technique, TechniqueCtx};
use futures::future::BoxFuture;

/// JSON-function injection: boolean differential over `JSON_EXTRACT` / `->>` /
/// `JSON_VALUE` pairs (3-trial confirmation) plus a single-shot error probe
/// (`__bad__` sentinel document → per-DBMS JSON error text).
pub(crate) struct JsonTechnique;

impl Technique for JsonTechnique {
    fn kind(&self) -> TechniqueKind {
        TechniqueKind::Json
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::similar_names,
        clippy::too_many_lines
    )]
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
            if context.json {
                debug!(
                    param = param.key(),
                    "json: json context, json priors boosted"
                );
            }
            let (top_dbms, top_prob) = dbms_belief.top_candidate();
            debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "json: context-aware detection");
            // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
            // `None` preserves the historical OS-random behaviour.
            let mut rng = crate::seeded_rng::make_rng(seed);
            let detector = JsonDetector::new();
            // JSON boost: `context.json` already lifts the hypothesis prior to 0.45
            // (see `compute_calibrated_prior`) so the scheduler tries JSON early;
            // a confident DBMS belief additionally narrows to that engine's
            // JSON family instead of the generic 3-DBMS sweep.
            let payloads = json_scan_payloads(dbms_payload_label(dbms_belief));
            let baseline_body = matcher.pre_process(&baseline.representative_body_str());
            // Same boolean-differential constraint as `test_boolean_bounded`: opaque
            // tampers (e.g. base64encode) would make TRUE/FALSE indistinguishable.
            let tamper_sets = boolean_safe_transformation_sets(tampers);
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
                    let true_payload =
                        build_final_payload_with_rng(&p.true_payload, trans, popts, &mut rng);
                    let false_payload =
                        build_final_payload_with_rng(&p.false_payload, trans, popts, &mut rng);
                    let error_probe =
                        build_final_payload_with_rng(&p.error_payload, trans, popts, &mut rng);
                    let tamper_label = if trans.is_empty() {
                        "none".to_owned()
                    } else {
                        trans
                            .iter()
                            .map(crate::techniques::tamper::Tamper::name)
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    // Channel 1 — boolean differential with confirmation (3 trials)
                    let mut trials: Vec<crate::detection::confirmation::Trial> =
                        Vec::with_capacity(3);
                    let mut last_true = String::new();
                    let mut last_false = String::new();
                    let mut last_t_status: u16 = 0;
                    #[allow(clippy::similar_names)]
                    let mut last_f_status: u16 = 0;
                    for _ in 0..3 {
                        if cancel.is_cancelled() {
                            break;
                        }
                        let (true_raw, true_ms, true_status) = fetch_for_payload_with_class(
                            client,
                            state,
                            cancel,
                            target,
                            target_str,
                            param,
                            &true_payload,
                            marker_set,
                            raw,
                            opts,
                            popts,
                            RequestClass::Boolean,
                        )
                        .await;
                        let true_body = matcher.pre_process(&true_raw);
                        let (false_raw, false_ms, false_status) = fetch_for_payload_with_class(
                            client,
                            state,
                            cancel,
                            target,
                            target_str,
                            param,
                            &false_payload,
                            marker_set,
                            raw,
                            opts,
                            popts,
                            RequestClass::Boolean,
                        )
                        .await;
                        let false_body = matcher.pre_process(&false_raw);
                        // Transport failure (`status == 0`) is never scored — neutral
                        // trial, consistent with `test_boolean_bounded`.
                        if true_status == 0 || false_status == 0 {
                            trials.push(crate::detection::confirmation::Trial {
                                true_conf: 0.5,
                                false_conf: 0.5,
                            });
                            last_true = true_body;
                            last_false = false_body;
                            last_t_status = true_status;
                            last_f_status = false_status;
                            continue;
                        }
                        // `--ignore-code`: an ignored status counts as a negative trial, never a finding.
                        if is_ignored(true_status, ignore_codes)
                            || is_ignored(false_status, ignore_codes)
                        {
                            trials.push(crate::detection::confirmation::Trial {
                                true_conf: 0.0,
                                false_conf: 1.0,
                            });
                            last_true = true_body;
                            last_false = false_body;
                            last_t_status = true_status;
                            last_f_status = false_status;
                            continue;
                        }
                        let res = detector.evaluate_boolean_with_match_ratio(
                            &baseline_body,
                            &true_body,
                            &false_body,
                            baseline.mean_ms,
                            true_ms,
                            false_ms,
                            baseline.match_ratio(),
                        );
                        // P1.2 : plancher de bruit appris et DEUX branches dans la
                        // bande (`noise_vetoed`) → trial neutre (0.5/0.5), comme le
                        // chemin booléen pur : il ne peut jamais confirmer.
                        let (t_conf, f_conf) = if res.noise_vetoed {
                            (0.5, 0.5)
                        } else {
                            (res.true_similarity, res.false_similarity)
                        };
                        trials.push(crate::detection::confirmation::Trial {
                            true_conf: t_conf,
                            false_conf: f_conf,
                        });
                        last_true = true_body;
                        last_false = false_body;
                        last_t_status = true_status;
                        last_f_status = false_status;
                    }
                    let (conf, inverted) = crate::detection::confirmation::confirm_either(&trials);
                    if conf.confirmed {
                        // Matcher veto gate: `Some(false)` rejects the candidate,
                        // `None` abstains and lets the detector decide.
                        if matcher.gate_boolean(
                            &last_true,
                            &last_false,
                            last_t_status,
                            last_f_status,
                        ) == Some(false)
                        {
                            continue;
                        }
                        // Evidence shows the measured majority across trials, not
                        // whichever trial ran last (a trailing neutral/glitch trial
                        // must not rewrite the confirmed differential).
                        let (agg_true, agg_false) =
                            crate::detection::confirmation::aggregate_sims(&trials);
                        let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Json,
                    conf.score,
                    format!(
                        "json channel=boolean dbms={} true_sim={:.2} false_sim={:.2} trials={}/3 fp={:.2} tamper={}{}{}{}{}",
                        p.dbms,
                        agg_true,
                        agg_false,
                        conf.trials,
                        conf.false_positive_prob,
                        tamper_label,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix(),
                        if inverted { " inverted" } else { "" }
                    ),
                )
                .with_false_positive_prob(conf.false_positive_prob)
                .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                        finding.dbms = Some(p.dbms.clone());
                        state.write().await.push_finding(finding);
                        found = true;
                        break;
                    }
                    // Channel 2 — single-shot JSON error probe
                    let (raw_body, _ms, status) = fetch_for_payload(
                        client,
                        state,
                        cancel,
                        target,
                        target_str,
                        param,
                        &error_probe,
                        marker_set,
                        raw,
                        opts,
                        popts,
                    )
                    .await;
                    let body = matcher.pre_process(&raw_body);
                    // `--ignore-code`: an ignored status is skipped, never a finding.
                    if is_ignored(status, ignore_codes) {
                        continue;
                    }
                    let r = detector.evaluate_error(&body);
                    if r.is_vulnerable {
                        // Matcher veto gate: `Some(false)` rejects the candidate.
                        if matcher.matches(&body, status) == Some(false) {
                            continue;
                        }
                        let mut finding = Finding::new(
                            target.as_str(),
                            param.key(),
                            TechniqueKind::Json,
                            r.confidence,
                            format!(
                                "json channel=error pattern={:?} tamper={}{}{}{}",
                                r.matched_pattern,
                                tamper_label,
                                opts.evidence_suffix(),
                                popts.evidence_suffix(),
                                matcher.evidence_suffix()
                            ),
                        );
                        finding.dbms = r.dbms.clone().or_else(|| Some(p.dbms.clone()));
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
