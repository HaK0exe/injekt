#![deny(unsafe_code)]

use crate::{
    session::state::{Finding, TechniqueKind},
    target::injection::{is_ignored, payload_budget},
    techniques::{
        orm::{detector::OrmDetector, payloads::orm_payloads},
        payload_opts::build_final_payload_with_rng,
        tamper::boolean_safe_transformation_sets,
    },
};
use tracing::debug;

use crate::techniques::technique::{Technique, TechniqueCtx};
use futures::future::BoxFuture;

pub(crate) struct OrmTechnique;

impl Technique for OrmTechnique {
    fn kind(&self) -> TechniqueKind {
        TechniqueKind::Orm
    }

    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn probe<'a>(&'a self, ctx: &'a TechniqueCtx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = ctx.state;
            let cancel = ctx.cancel;
            let target = ctx.target;
            let param = ctx.param;
            let baseline = ctx.baseline;
            let tampers = ctx.tampers;

            let popts = ctx.popts;
            let matcher = ctx.matcher;
            let level = ctx.level;
            let ignore_codes = ctx.ignore_codes;
            let seed = ctx.seed;

            let mut rng = crate::seeded_rng::make_rng(seed);
            let detector = OrmDetector::new();
            let payloads = orm_payloads(None);
            let baseline_body = matcher.pre_process(&baseline.representative_body_str());
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
                    let tamper_label = crate::techniques::tamper::tamper_label(trans);

                    // Boolean differential (3 trials)
                    let mut trials: Vec<crate::detection::confirmation::Trial> =
                        Vec::with_capacity(3);
                    let mut last_true = String::new();
                    let mut last_false = String::new();
                    let mut last_t_status: u16 = 0;
                    let mut last_f_status: u16 = 0;
                    for _ in 0..3 {
                        if cancel.is_cancelled() {
                            break;
                        }
                        let (true_raw, true_ms, true_status) = ctx
                            .fetch_with_class(
                                &true_payload,
                                crate::http::timeouts::RequestClass::Boolean,
                            )
                            .await;
                        let true_body = matcher.pre_process(&true_raw);
                        let (false_raw, false_ms, false_status) = ctx
                            .fetch_with_class(
                                &false_payload,
                                crate::http::timeouts::RequestClass::Boolean,
                            )
                            .await;
                        let false_body = matcher.pre_process(&false_raw);

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
                    let (conf, _inverted) = crate::detection::confirmation::confirm_either(&trials);
                    if conf.confirmed {
                        if matcher.gate_boolean(
                            &last_true,
                            &last_false,
                            last_t_status,
                            last_f_status,
                        ) == Some(false)
                        {
                            continue;
                        }
                        let (agg_true, agg_false) =
                            crate::detection::confirmation::aggregate_sims(&trials);
                        let finding = Finding::new(
                            target.as_str(),
                            param.key(),
                            TechniqueKind::Orm,
                            conf.score,
                            format!(
                                "orm channel=boolean true_sim={:.2} false_sim={:.2} trials={}/3 tamper={}",
                                agg_true, agg_false, conf.trials, tamper_label
                            ),
                        )
                        .with_false_positive_prob(conf.false_positive_prob)
                        .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                        state.write().await.push_finding(finding);
                        found = true;
                        break;
                    }

                    // Error channel
                    let (raw_body, _ms, status) = ctx.fetch(&error_probe).await;
                    let body = matcher.pre_process(&raw_body);
                    if is_ignored(status, ignore_codes) {
                        continue;
                    }
                    let r = detector.evaluate_error(&body);
                    if r.is_vulnerable {
                        if matcher.matches(&body, status) == Some(false) {
                            continue;
                        }
                        let finding = Finding::new(
                            target.as_str(),
                            param.key(),
                            TechniqueKind::Orm,
                            r.confidence,
                            format!(
                                "orm channel=error pattern={:?} tamper={}",
                                r.matched_pattern, tamper_label
                            ),
                        )
                        .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                        state.write().await.push_finding(finding);
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
            }
            debug!(param = param.key(), "orm probe done");
        })
    }
}
