//! Error detection probe (`test_error_bounded`).
//! Moved verbatim from `engine/probes.rs` (P1); no behaviour change.

use crate::engine::{
    confirm::{ErrorBoolConfirm, confirm_error_with_boolean},
    schedule::dbms_payload_label,
};
use crate::{
    session::state::{Finding, TechniqueKind},
    target::injection::{is_ignored, payload_budget},
    techniques::{
        error::detector::ErrorDetector, payload_opts::build_final_payload_with_rng,
        tamper::tamper_transformation_sets,
    },
};
use tracing::debug;

use crate::techniques::{
    error::detector::is_payload_reflected,
    technique::{Technique, TechniqueCtx},
};
use futures::future::BoxFuture;

pub(crate) struct ErrorTechnique;

impl Technique for ErrorTechnique {
    fn kind(&self) -> TechniqueKind {
        TechniqueKind::Error
    }

    #[allow(clippy::too_many_lines)]
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
            let boolean_enabled = ctx.boolean_enabled;
            let seed = ctx.seed;
            let context = ctx.context;
            let dbms_belief = ctx.dbms_belief;

            let (top_dbms, top_prob) = dbms_belief.top_candidate();
            debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "error: context-aware detection");
            // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
            // `None` preserves the historical OS-random behaviour.
            let mut rng = crate::seeded_rng::make_rng(seed);
            let detector = ErrorDetector::new();
            // DBMS-aware error payloads once the belief is actionable (>= 0.85);
            // otherwise generic polyglots (unchanged default).
            let payloads = crate::techniques::error::payloads::error_payloads_for(
                dbms_payload_label(dbms_belief),
            );
            let tamper_sets = tamper_transformation_sets(tampers);
            // Baseline evaluated once per parameter: vetoes footer/banner FPs
            // (e.g. verbose `MySQL 5.7` footer already present without injection).
            // P1.1 — purge des zones dynamiques marquées avant comparaison.
            let baseline_body = matcher
                .pre_process(&baseline.strip_dynamic_content(&baseline.representative_body_str()));
            let baseline_len = baseline_body.len();
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
                    let (raw_body, _ms, status) = ctx.fetch(&tampered).await;
                    // Transport/body errors surface as status 0 + `""`: never scored
                    // (empty body would otherwise be a dissimilar-body FP elsewhere,
                    // and an error pattern can never match it anyway — skip fast).
                    if status == 0 {
                        continue;
                    }
                    let body = matcher.pre_process(&baseline.strip_dynamic_content(&raw_body));
                    // `--ignore-code`: an ignored status is skipped, never a finding.
                    if is_ignored(status, ignore_codes) {
                        continue;
                    }
                    // Context-aware gate: baseline veto + reflected-payload masking.
                    // Kills the noxtools FP shape where `EXTRACTVALUE` is merely
                    // echoed in `value="...payload..."` with no DB error.
                    let r = detector.evaluate_with_context(&baseline_body, &body, &tampered);
                    if r.is_vulnerable {
                        // Matcher veto gate: `Some(false)` rejects the candidate.
                        if matcher.matches(&body, status) == Some(false) {
                            continue;
                        }
                        // P1.3 cast-error negative control (anti-FP "application
                        // casting"): a numeric parameter (`id=1`) whose app/ORM
                        // rejects any non-strictly-numeric value makes OUR payloads
                        // fail *type parsing* (`invalid input syntax for type
                        // integer`, `Msg 245`, `NumberFormatException`, …) — which
                        // the error detector reads as SQLi. Placed before the boolean
                        // confirmation (+2 req) so a veto saves those requests too;
                        // the HIT is only evaluated once (same `body` as the finding).
                        // Bounded: +1 request, and only when the parameter is numeric
                        // AND the candidate body carries a conversion/type signature.
                        // Control verdict: cast error again on a SQL-syntax-free
                        // non-numeric value → the error belongs to the parameter's
                        // type parsing, not to injection → veto (`continue`). An SQL
                        // *syntax* error (not cast) is additional injection evidence
                        // and never vetoes; transport failure (status 0) or ignored
                        // code is neutral. No CLI knob, no evidence/confidence
                        // rewrite: the veto only drops the candidate.
                        if context.numeric
                            && param.original_value.parse::<i64>().is_ok()
                            && crate::techniques::error::detector::classify_cast_error(&body)
                        {
                            // `z` + 8 seeded hex: no quote/space/dash, so the value
                            // carries no SQL syntax — only its type-parsing verdict is
                            // read back. Fresh RNG: the tamper stream stays untouched
                            // (seeded determinism of the payload matrix preserved).
                            let mut control_rng = crate::seeded_rng::make_rng(seed);
                            let token = {
                                use rand::RngExt as _;
                                control_rng.random::<u32>()
                            };
                            let control_payload = format!("z{token:08x}");
                            let (control_raw, _control_ms, control_status) =
                                ctx.fetch(&control_payload).await;
                            if control_status != 0 && !is_ignored(control_status, ignore_codes) {
                                let control_body = matcher.pre_process(&control_raw);
                                if crate::techniques::error::detector::classify_cast_error(
                                    &control_body,
                                ) {
                                    debug!(
                                        param = param.key(),
                                        "error: cast-error negative control reproduced on a non-numeric value — parameter type parsing, not SQLi (candidate vetoed)"
                                    );
                                    continue;
                                }
                            }
                        }
                        let tamper_label = crate::techniques::tamper::tamper_label(trans);
                        let reflected = is_payload_reflected(&body, &tampered);
                        let extracted_flag = if r.extracted.is_some() { "yes" } else { "no" };
                        // Confirmation policy: a hit WITH an extracted fragment (0.9)
                        // is self-sufficient — push direct with no extra requests.
                        // A hit WITHOUT fragment (0.75) gets one boolean TRUE/FALSE
                        // pair (+2 req): confirmed upgrades to 0.9, otherwise the
                        // finding is kept degraded at 0.55 `unconfirmed` and barred
                        // from the heavy extraction oracle (see
                        // `is_extraction_eligible`).
                        let (confidence, bool_confirm, true_sim, false_sim, unconfirmed) =
                            if r.extracted.is_some() {
                                (
                                    r.confidence,
                                    "skipped(fragment)".to_owned(),
                                    0.0,
                                    0.0,
                                    false,
                                )
                            } else {
                                let outcome = confirm_error_with_boolean(
                                    client,
                                    state,
                                    cancel,
                                    target,
                                    target_str,
                                    param,
                                    baseline,
                                    &baseline_body,
                                    marker_set,
                                    raw,
                                    trans,
                                    opts,
                                    popts,
                                    matcher,
                                    ignore_codes,
                                    boolean_enabled,
                                    seed,
                                )
                                .await;
                                match outcome.verdict {
                                    ErrorBoolConfirm::Confirmed => (
                                        0.9,
                                        ErrorBoolConfirm::Confirmed.as_str().to_owned(),
                                        outcome.true_sim,
                                        outcome.false_sim,
                                        false,
                                    ),
                                    ErrorBoolConfirm::Denied
                                    | ErrorBoolConfirm::Inconclusive
                                    | ErrorBoolConfirm::Skipped => (
                                        0.55,
                                        format!("{} unconfirmed", outcome.verdict.as_str()),
                                        outcome.true_sim,
                                        outcome.false_sim,
                                        true,
                                    ),
                                }
                            };
                        let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Error,
                    if baseline.is_waf_blocking() {
                        // A blocking WAF (challenge/deny/rate-limit) silently
                        // filters long payloads: doubt the pattern (0.9→0.6)
                        // instead of trusting it blindly (noxtools lesson).
                        crate::detection::waf::downgrade_for_waf(confidence)
                    } else {
                        confidence
                    },
                    format!(
                        "error pattern {:?} tamper={} baseline_len={} injected_len={} reflected={} extracted={} bool_confirm={} true_sim={:.2} false_sim={:.2}{}{}{}{}{}",
                        r.matched_pattern,
                        tamper_label,
                        baseline_len,
                        body.len(),
                        reflected,
                        extracted_flag,
                        bool_confirm,
                        true_sim,
                        false_sim,
                        if unconfirmed { " unconfirmed" } else { "" },
                        baseline.waf_evidence_suffix(),
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix()
                    ),
                )
                .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                        finding.dbms = Some(p.dbms.clone());
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
