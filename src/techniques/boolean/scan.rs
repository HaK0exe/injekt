//! Boolean detection probe (`test_boolean_bounded`).
//! Moved verbatim from `engine/probes.rs` (P1); no behaviour change.

use crate::engine::{
    fetch::fetch_for_payload_with_class,
    schedule::{check_deadline, dbms_payload_label, order_boolean_by_context},
};
use crate::{
    http::timeouts::RequestClass,
    session::state::{Finding, TechniqueKind},
    target::injection::{FILTER_STREAK_LIMIT, is_app_filter_block, is_ignored, payload_budget},
    techniques::{
        boolean::{detector::BooleanDetector, payloads::boolean_payloads_for},
        payload_opts::build_final_payload_with_rng,
        tamper::boolean_safe_transformation_sets,
    },
};
use tracing::debug;

use crate::techniques::technique::{Technique, TechniqueCtx};
use futures::future::BoxFuture;

pub(crate) struct BooleanTechnique;

impl Technique for BooleanTechnique {
    fn kind(&self) -> TechniqueKind {
        TechniqueKind::Boolean
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
            let deadline = ctx.deadline;
            let generative_mode = ctx.generative_mode;
            let max_generated = ctx.max_generated;
            let (top_dbms, top_prob) = dbms_belief.top_candidate();
            debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "boolean: context-aware detection");
            // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
            // `None` preserves the historical OS-random behaviour.
            let mut rng = crate::seeded_rng::make_rng(seed);
            // Quote-correct + DBMS-aware: a confident belief (>= 0.85, same bar as
            // `fill_missing_dbms`) selects engine comment styles, and the inferred
            // quote context leads so L1 (`take(2)`) probes the right family first.
            let mut payloads = boolean_payloads_for(dbms_payload_label(dbms_belief));
            order_boolean_by_context(&mut payloads, context);
            // Génération opt-in (`--generative`) : paires historiques d'abord (ordre
            // et budgets inchangés), puis synthétisées jusqu'à `max_generated`.
            // `Off` = byte-identical (0 générée). Les générées sont dédupliquées
            // contre l'historique (zéro requête redondante) et portent leur label
            // `gen:<fence>+<logic>+<pred>` en évidence.
            let (hist_take, generated): (usize, Vec<crate::generation::GeneratedCandidate>) =
                match generative_mode {
                    crate::generation::GenerativeMode::Off => {
                        (payload_budget(level, 2, payloads.len()), Vec::new())
                    }
                    crate::generation::GenerativeMode::Conservative
                    | crate::generation::GenerativeMode::Aggressive => {
                        let comment = crate::generation::comment_for(top_dbms, &context.comment);
                        let historical_true: std::collections::HashSet<String> =
                            payloads.iter().map(|p| p.true_payload.clone()).collect();
                        let pool = crate::generation::enumerate_candidates(
                            context,
                            top_dbms,
                            comment,
                            generative_mode,
                            crate::generation::MAX_GENERATED,
                            seed,
                        );
                        let mut gen_pool =
                            crate::generation::dedupe_against(pool, &historical_true);
                        gen_pool.truncate(usize::from(max_generated));
                        (
                            if generative_mode == crate::generation::GenerativeMode::Aggressive {
                                payloads.len()
                            } else {
                                payload_budget(level, 2, payloads.len())
                            },
                            gen_pool,
                        )
                    }
                };
            let mut combined: Vec<(
                crate::techniques::boolean::payloads::BooleanPayload,
                Option<String>,
            )> = Vec::with_capacity(hist_take.saturating_add(generated.len()));
            for p in payloads.iter().take(hist_take) {
                combined.push((p.clone(), None));
            }
            for g in generated {
                combined.push((g.payload, Some(g.label)));
            }
            let detector = BooleanDetector::new();
            // P1.1 — purge des zones dynamiques marquées AVANT le pre_process (les
            // marquages sont calculés sur le texte normalisé) : baseline et probes
            // restent comparés dans le même référentiel.
            let baseline_body = matcher
                .pre_process(&baseline.strip_dynamic_content(&baseline.representative_body_str()));
            // Boolean TRUE/FALSE pairs require coherent transforms: opaque tampers
            // (e.g. base64encode) are excluded via the boolean-safe sets.
            let tamper_sets = boolean_safe_transformation_sets(tampers);
            // App-filter pruning (A1-style `400` signature filter): every spaced
            // payload returns `400`/`400` while the baseline is `200`, so the full
            // L3 matrix would burn hundreds of requests for a certain 0-finding.
            // After 3 consecutive fully-filtered probes, stop the technique early.
            // Bypass payloads (`/**/`) return `200` and reset the streak, so evasion
            // still detects; N1/N2 (`200`) never trip it.
            let mut filter_streak: usize = 0;
            'payload: for (p, gen_label) in &combined {
                if cancel.is_cancelled() {
                    break;
                }
                // Shared `--max-duration` deadline: stop the technique early so one
                // payload family cannot silently overshoot an explicit user budget.
                // `None` deadline = no-op. Outcome folds normally below.
                if check_deadline(deadline, &param.key(), "boolean") {
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
                    // Skip duplicate variants already tried for this base payload
                    // (dedupe via string equality already handled by transformation sets, but
                    // randomcase produces different strings per call — we still try each set once)
                    let tamper_label = if trans.is_empty() {
                        "none".to_owned()
                    } else {
                        trans
                            .iter()
                            .map(crate::techniques::tamper::Tamper::name)
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    // 3 trials confirmation
                    let mut trials: Vec<crate::detection::confirmation::Trial> =
                        Vec::with_capacity(3);
                    let mut last_true = String::new();
                    let mut last_false = String::new();
                    let mut last_t_status: u16 = 0;
                    #[allow(clippy::similar_names)]
                    let mut last_f_status: u16 = 0;
                    let mut all_filter_blocked = true;
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
                        let true_body =
                            matcher.pre_process(&baseline.strip_dynamic_content(&true_raw));
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
                        let false_body =
                            matcher.pre_process(&baseline.strip_dynamic_content(&false_raw));
                        // Transport/body failure (`status == 0`, body `""`) must never
                        // be scored: TRUE=baseline vs FALSE="" yields a 1.0 gap and a
                        // 0.9-confidence false positive on network hiccups. Record a
                        // neutral trial (never confirms) like `confirm_error_with_boolean`.
                        if true_status == 0 || false_status == 0 {
                            trials.push(crate::detection::confirmation::Trial {
                                true_conf: 0.5,
                                false_conf: 0.5,
                            });
                            last_true = true_body;
                            last_false = false_body;
                            last_t_status = true_status;
                            last_f_status = false_status;
                            all_filter_blocked = false;
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
                            all_filter_blocked = false;
                            continue;
                        }
                        if !is_app_filter_block(true_status, false_status) {
                            all_filter_blocked = false;
                        }
                        let res = detector.evaluate_with_match_ratio(
                            &baseline_body,
                            &true_body,
                            &false_body,
                            baseline.mean_ms,
                            true_ms,
                            false_ms,
                            baseline.match_ratio(),
                        );
                        // P1.2 : plancher de bruit appris et DEUX branches dans la
                        // bande (`noise_vetoed`) → le couple ne porte aucun signal
                        // d'oracle ; trial neutre (0.5/0.5), comme un transport
                        // manqué : il ne peut jamais passer la règle par-trial, donc
                        // ne contribue ni au gap-clause ni à la majorité.
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
                    // App-filter pruning: a full `(payload, tamper-set)` probe that
                    // never left the `400` filter on either branch carries no
                    // differential signal. Three in a row means the sink filters this
                    // payload family (A1 spaces) — stop boolean early with 0 finding
                    // instead of burning the rest of the L3 matrix. Requires 3
                    // completed trials so cancel/ignore never prunes.
                    if all_filter_blocked && trials.len() == 3 {
                        filter_streak = filter_streak.saturating_add(1);
                    } else {
                        filter_streak = 0;
                    }
                    if filter_streak >= FILTER_STREAK_LIMIT {
                        debug!(
                            param = param.key(),
                            streak = filter_streak,
                            "app signature filter (repeated 400) — pruning boolean early"
                        );
                        // `--ai-suggest` trigger (post-échec) : mémorise le prune par
                        // param pour le second-pass, sans requête supplémentaire.
                        state.write().await.note_app_filter_hit(&param.key());
                        break 'payload;
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
                        // P0.2 — contrôle à arithmétique aléatoire (`checkFalsePositives`) :
                        // avant d'enregistrer, re-tester le même point avec `r=r` (doit
                        // rester baseline-like) et `r1=r2` (doit s'en écarter). Une page
                        // qui ne suit pas ce sens (filtre de motif, reflet, instabilité)
                        // est un faux positif. Budget borné : +2 requêtes, uniquement
                        // pour une paire déjà confirmée ; `None`/transport = neutre.
                        let control_label =
                            match crate::detection::control_pair::derive_control_pair(
                                &true_payload,
                                &false_payload,
                                seed,
                            ) {
                                None => "skip",
                                Some(ctrl) => {
                                    let (ctl_true_raw, ctl_true_ms, ctl_true_status) =
                                        fetch_for_payload_with_class(
                                            client,
                                            state,
                                            cancel,
                                            target,
                                            target_str,
                                            param,
                                            &ctrl.must_true,
                                            marker_set,
                                            raw,
                                            opts,
                                            popts,
                                            RequestClass::Boolean,
                                        )
                                        .await;
                                    let (ctl_false_raw, ctl_false_ms, ctl_false_status) =
                                        fetch_for_payload_with_class(
                                            client,
                                            state,
                                            cancel,
                                            target,
                                            target_str,
                                            param,
                                            &ctrl.must_false,
                                            marker_set,
                                            raw,
                                            opts,
                                            popts,
                                            RequestClass::Boolean,
                                        )
                                        .await;
                                    if cancel.is_cancelled() {
                                        break;
                                    }
                                    let verdict = if ctl_true_status == 0 || ctl_false_status == 0 {
                                        crate::detection::control_pair::ControlVerdict::Neutral
                                    } else {
                                        crate::detection::control_pair::control_verdict_with_match_ratio(
                                &baseline_body,
                                &matcher
                                    .pre_process(&baseline.strip_dynamic_content(&ctl_true_raw)),
                                &matcher
                                    .pre_process(&baseline.strip_dynamic_content(&ctl_false_raw)),
                                baseline.mean_ms,
                                ctl_true_ms,
                                ctl_false_ms,
                                inverted,
                                baseline.match_ratio(),
                            )
                                    };
                                    match verdict {
                                        crate::detection::control_pair::ControlVerdict::Veto => {
                                            continue;
                                        }
                                        crate::detection::control_pair::ControlVerdict::Keep => {
                                            "ok"
                                        }
                                        crate::detection::control_pair::ControlVerdict::Neutral => {
                                            "skip"
                                        }
                                    }
                                }
                            };
                        // Evidence shows the measured majority across trials, not
                        // whichever trial ran last (a trailing neutral/glitch trial
                        // must not rewrite the confirmed differential).
                        let (agg_true, agg_false) =
                            crate::detection::confirmation::aggregate_sims(&trials);
                        let evidence = format!(
                            "boolean true_sim={:.2} false_sim={:.2} trials={}/3 fp={:.2} tamper={}{}{}{}{}{} control={control_label}",
                            agg_true,
                            agg_false,
                            conf.trials,
                            conf.false_positive_prob,
                            tamper_label,
                            opts.evidence_suffix(),
                            popts.evidence_suffix(),
                            matcher.evidence_suffix(),
                            if inverted { " inverted" } else { "" },
                            gen_label
                                .as_deref()
                                .map_or(String::new(), |l| format!(" gen={l}")),
                        );
                        let mut finding = Finding::new(
                            target.as_str(),
                            param.key(),
                            TechniqueKind::Boolean,
                            conf.score,
                            evidence,
                        )
                        // C7: measured FP from the 3-trial confirmation + WAF context
                        // from the baseline feed the calibrated severity bucket.
                        .with_false_positive_prob(conf.false_positive_prob)
                        .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                        finding.dbms = None;
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
