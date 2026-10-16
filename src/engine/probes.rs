#![deny(unsafe_code)]

//! Detection probes (P1): the 8 `test_*_bounded` technique loops + helpers.
//! Extracted verbatim from `orchestrator.rs`; no behaviour change.

use super::{
    confirm::{ErrorBoolConfirm, confirm_error_with_boolean},
    fetch::{fetch_for_payload, fetch_for_payload_with_class},
    schedule::{
        check_deadline, dbms_payload_label, json_scan_payloads, order_boolean_by_context,
        order_by_prefix_for_context,
    },
};
use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    detection::baseline,
    http::{
        client::{HttpClient, RequestSpec},
        timeouts::RequestClass,
    },
    session::state::{Finding, SessionState, TechniqueKind},
    target::{
        injection::{
            FILTER_STREAK_LIMIT, ProbeOpts, is_app_filter_block, is_ignored, payload_budget,
        },
        markers::MarkerSet,
        parameters::{ParameterLocation, TargetParameter},
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::{
        boolean::{detector::BooleanDetector, payloads::boolean_payloads_for},
        error::detector::ErrorDetector,
        json::detector::JsonDetector,
        nosql::{detector::NosqlDetector, payloads::nosql_payloads},
        oob::{
            detector::OobDetector,
            payloads::{is_valid_oob_domain, new_token, oob_payloads_for},
        },
        payload_opts::{PayloadOpts, build_final_payload_with_rng},
        stacked::{detector::StackedDetector, payloads::stacked_payloads_for},
        tamper::{Tamper, boolean_safe_transformation_sets, tamper_transformation_sets},
        time::{detector::TimeDetector, payloads::all_time_payloads},
        union::{detector::UnionDetector, payloads::union_payloads_for},
    },
};
use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

#[allow(clippy::too_many_arguments)]
#[allow(clippy::similar_names)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn test_boolean_bounded(
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
    deadline: Option<std::time::Instant>,
    generative_mode: crate::generation::GenerativeMode,
    max_generated: u8,
) {
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
                let mut gen_pool = crate::generation::dedupe_against(pool, &historical_true);
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
    let baseline_body =
        matcher.pre_process(&baseline.strip_dynamic_content(&baseline.representative_body_str()));
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
                    .map(super::super::techniques::tamper::Tamper::name)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            // 3 trials confirmation
            let mut trials: Vec<crate::detection::confirmation::Trial> = Vec::with_capacity(3);
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
                let true_body = matcher.pre_process(&baseline.strip_dynamic_content(&true_raw));
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
                let false_body = matcher.pre_process(&baseline.strip_dynamic_content(&false_raw));
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
                if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
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
                if matcher.gate_boolean(&last_true, &last_false, last_t_status, last_f_status)
                    == Some(false)
                {
                    continue;
                }
                // P0.2 — contrôle à arithmétique aléatoire (`checkFalsePositives`) :
                // avant d'enregistrer, re-tester le même point avec `r=r` (doit
                // rester baseline-like) et `r1=r2` (doit s'en écarter). Une page
                // qui ne suit pas ce sens (filtre de motif, reflet, instabilité)
                // est un faux positif. Budget borné : +2 requêtes, uniquement
                // pour une paire déjà confirmée ; `None`/transport = neutre.
                let control_label = match crate::detection::control_pair::derive_control_pair(
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
                            crate::detection::control_pair::ControlVerdict::Veto => continue,
                            crate::detection::control_pair::ControlVerdict::Keep => "ok",
                            crate::detection::control_pair::ControlVerdict::Neutral => "skip",
                        }
                    }
                };
                // Evidence shows the measured majority across trials, not
                // whichever trial ran last (a trailing neutral/glitch trial
                // must not rewrite the confirmed differential).
                let (agg_true, agg_false) = crate::detection::confirmation::aggregate_sims(&trials);
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
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn test_error_bounded(
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
    boolean_enabled: bool,
    seed: Option<u64>,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
) {
    use crate::techniques::error::detector::is_payload_reflected;

    let (top_dbms, top_prob) = dbms_belief.top_candidate();
    debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "error: context-aware detection");
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    let detector = ErrorDetector::new();
    // DBMS-aware error payloads once the belief is actionable (>= 0.85);
    // otherwise generic polyglots (unchanged default).
    let payloads =
        crate::techniques::error::payloads::error_payloads_for(dbms_payload_label(dbms_belief));
    let tamper_sets = tamper_transformation_sets(tampers);
    // Baseline evaluated once per parameter: vetoes footer/banner FPs
    // (e.g. verbose `MySQL 5.7` footer already present without injection).
    // P1.1 — purge des zones dynamiques marquées avant comparaison.
    let baseline_body =
        matcher.pre_process(&baseline.strip_dynamic_content(&baseline.representative_body_str()));
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
            let (raw_body, _ms, status) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
                popts,
            )
            .await;
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
                    let token = rand::Rng::random::<u32>(&mut control_rng);
                    let control_payload = format!("z{token:08x}");
                    let (control_raw, _control_ms, control_status) = fetch_for_payload(
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
                    )
                    .await;
                    if control_status != 0 && !is_ignored(control_status, ignore_codes) {
                        let control_body = matcher.pre_process(&control_raw);
                        if crate::techniques::error::detector::classify_cast_error(&control_body) {
                            debug!(
                                param = param.key(),
                                "error: cast-error negative control reproduced on a non-numeric value — parameter type parsing, not SQLi (candidate vetoed)"
                            );
                            continue;
                        }
                    }
                }
                let tamper_label = if trans.is_empty() {
                    "none".to_owned()
                } else {
                    trans
                        .iter()
                        .map(super::super::techniques::tamper::Tamper::name)
                        .collect::<Vec<_>>()
                        .join(",")
                };
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
}

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
                        .map(super::super::techniques::tamper::Tamper::name)
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

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn test_union_bounded(
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
    deadline: Option<std::time::Instant>,
) {
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
                let tampered = build_final_payload_with_rng(&p.payload, trans, popts, &mut rng);
                let (raw_body, ms, status) = fetch_for_payload(
                    client, state, cancel, target, target_str, param, &tampered, marker_set, raw,
                    opts, popts,
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
                            .map(super::super::techniques::tamper::Tamper::name)
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
                let tampered = build_final_payload_with_rng(&p.payload, trans, popts, &mut rng);
                let (raw_body, ms, status) = fetch_for_payload(
                    client, state, cancel, target, target_str, param, &tampered, marker_set, raw,
                    opts, popts,
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
                            .map(super::super::techniques::tamper::Tamper::name)
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
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn test_stacked_bounded(
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
                client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
                popts,
            )
            .await;
            let body = matcher.pre_process(&raw_body);
            // `--ignore-code`: an ignored status is skipped, never a finding.
            if is_ignored(status, ignore_codes) {
                continue;
            }
            let r = detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, p, &tampered);
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
                let confirm_payloads = stacked_payloads_for(dbms_payload_label(dbms_belief));
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
                        .map(super::super::techniques::tamper::Tamper::name)
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
}

/// JSON-function injection: boolean differential over `JSON_EXTRACT` / `->>` /
/// `JSON_VALUE` pairs (3-trial confirmation) plus a single-shot error probe
/// (`__bad__` sentinel document → per-DBMS JSON error text).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::similar_names)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn test_json_bounded(
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
                    .map(super::super::techniques::tamper::Tamper::name)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            // Channel 1 — boolean differential with confirmation (3 trials)
            let mut trials: Vec<crate::detection::confirmation::Trial> = Vec::with_capacity(3);
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
                if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
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
                if matcher.gate_boolean(&last_true, &last_false, last_t_status, last_f_status)
                    == Some(false)
                {
                    continue;
                }
                // Evidence shows the measured majority across trials, not
                // whichever trial ran last (a trailing neutral/glitch trial
                // must not rewrite the confirmed differential).
                let (agg_true, agg_false) = crate::detection::confirmation::aggregate_sims(&trials);
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
}

/// `NoSQL` (MongoDB) operator injection: boolean differential over `$gt`/`$ne`/
/// `$regex` operator pairs (3-trial confirmation) plus a single-shot error
/// probe (`$where` JS invalide / opérateur inconnu → messages MongoDB).
///
/// Deux chemins d'injection :
/// - bodies JSON (`param` Body + corps JSON) : la feuille
///   `{"user":"admin"}` devient un **objet** `{"user":{"$gt":""}}` via
///   `inject_json_operator` (bypass `{"user": {"$gt": ""}}` sans identifiants).
///   Les tampers chaîne ne s'appliquent pas ici (un opérateur doit rester du
///   JSON valide) ;
/// - Query / Form / Header / Cookie : les mêmes opérateurs sont envoyés comme
///   **chaînes** (`{"$gt": ""}` en valeur de param) via le chemin générique
///   (tampers boolean-safe + `--prefix`/`--suffix` honorés).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::similar_names)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn test_nosql_bounded(
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
) {
    if context.json {
        debug!(
            param = param.key(),
            "nosql: json context, nosql priors boosted"
        );
    }
    debug!(
        param = param.key(),
        context = context.summary(),
        "nosql: context-aware detection"
    );
    let mut rng = crate::seeded_rng::make_rng(seed);
    let detector = NosqlDetector::new();
    let payloads = nosql_payloads();
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let tamper_sets = boolean_safe_transformation_sets(tampers);
    // Chemin opérateur JSON ? Body + corps JSON + feuille scalaire.
    let json_operator_path: Option<String> = match &param.location {
        ParameterLocation::Body => {
            let body_opt = raw.and_then(|r| r.body.as_deref());
            let ct = raw.and_then(|r| r.content_type());
            body_opt
                .filter(|body| {
                    crate::target::structured::sniff_kind(ct, body)
                        == crate::target::structured::StructuredKind::Json
                })
                .map(str::to_owned)
        }
        _ => None,
    };
    for p in payloads
        .iter()
        .take(payload_budget(level, 2, payloads.len()))
    {
        if cancel.is_cancelled() {
            break;
        }
        let mut found = false;
        // Tampers chaîne uniquement pour le chemin non-JSON ; le chemin
        // opérateur envoie du JSON valide tel quel (1 seul set `none`).
        let tamper_rounds: usize = if json_operator_path.is_some() {
            1
        } else {
            tamper_sets.len().max(1)
        };
        for round in 0..tamper_rounds {
            if cancel.is_cancelled() {
                break;
            }
            let trans: &[Tamper] = if json_operator_path.is_some() {
                &[]
            } else {
                tamper_sets.get(round).map_or(&[], Vec::as_slice)
            };
            let tamper_label = if trans.is_empty() {
                "none".to_owned()
            } else {
                trans
                    .iter()
                    .map(super::super::techniques::tamper::Tamper::name)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            // Channel 1 — boolean differential with confirmation (3 trials)
            let mut trials: Vec<crate::detection::confirmation::Trial> = Vec::with_capacity(3);
            let mut last_true = String::new();
            let mut last_false = String::new();
            let mut last_t_status: u16 = 0;
            #[allow(clippy::similar_names)]
            let mut last_f_status: u16 = 0;
            for _ in 0..3 {
                if cancel.is_cancelled() {
                    break;
                }
                let (true_raw, true_ms, true_status) = fetch_nosql_boolean(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    param,
                    raw,
                    json_operator_path.as_deref(),
                    &p.true_operator,
                    &p.true_payload,
                    trans,
                    marker_set,
                    opts,
                    popts,
                    &mut rng,
                )
                .await;
                let true_body = matcher.pre_process(&true_raw);
                let (false_raw, false_ms, false_status) = fetch_nosql_boolean(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    param,
                    raw,
                    json_operator_path.as_deref(),
                    &p.false_operator,
                    &p.false_payload,
                    trans,
                    marker_set,
                    opts,
                    popts,
                    &mut rng,
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
                if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
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
                if matcher.gate_boolean(&last_true, &last_false, last_t_status, last_f_status)
                    == Some(false)
                {
                    continue;
                }
                // Evidence shows the measured majority across trials, not
                // whichever trial ran last (a trailing neutral/glitch trial
                // must not rewrite the confirmed differential).
                let (agg_true, agg_false) = crate::detection::confirmation::aggregate_sims(&trials);
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Nosql,
                    conf.score,
                    format!(
                        "nosql channel=boolean vector={} dbms=mongodb true_sim={:.2} false_sim={:.2} trials={}/3 fp={:.2} tamper={}{}{}{}{}",
                        p.vector,
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
                finding.dbms = Some("mongodb".to_owned());
                state.write().await.push_finding(finding);
                found = true;
                break;
            }
            // Channel 2 — single-shot NoSQL error probe
            let (raw_body, _ms, status) = fetch_nosql_error(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                raw,
                json_operator_path.as_deref(),
                &p.error_payload,
                trans,
                marker_set,
                opts,
                popts,
                &mut rng,
            )
            .await;
            let body = matcher.pre_process(&raw_body);
            if is_ignored(status, ignore_codes) {
                continue;
            }
            let r = detector.evaluate_error(&body);
            if r.is_vulnerable {
                if matcher.matches(&body, status) == Some(false) {
                    continue;
                }
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Nosql,
                    r.confidence,
                    format!(
                        "nosql channel=error vector={} pattern={:?} tamper={}{}{}{}",
                        p.vector,
                        r.matched_pattern,
                        tamper_label,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix()
                    ),
                );
                finding.dbms = Some("mongodb".to_owned());
                state.write().await.push_finding(finding);
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }
}

/// Fetch du bras TRUE/FALSE `NoSQL` : objet opérateur sur bodies JSON,
/// chaîne tamperisée ailleurs. Retourne `(body, ms, status)` comme
/// `fetch_for_payload_with_class` (classe `Boolean`, statut 0 = transport).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_nosql_boolean(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    raw: Option<&RawRequest>,
    json_body: Option<&str>,
    operator: &serde_json::Value,
    string_payload: &str,
    trans: &[Tamper],
    marker_set: &MarkerSet,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    rng: &mut rand::rngs::StdRng,
) -> (String, f64, u16) {
    if let Some(original) = json_body
        && let Some(injected) =
            crate::target::structured::inject_json_operator(original, &param.name, operator)
    {
        let spec = nosql_json_body_spec(target, raw, &injected);
        return fetch_spec_boolean(client, state, cancel, spec).await;
    }
    let final_payload = build_final_payload_with_rng(string_payload, trans, popts, rng);
    fetch_for_payload_with_class(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        &final_payload,
        marker_set,
        raw,
        opts,
        popts,
        RequestClass::Boolean,
    )
    .await
}

/// Fetch de la sonde d'erreur `NoSQL` : objet `$where`/opérateur inconnu sur
/// bodies JSON (parsé depuis le littéral, repli chaîne), chaîne ailleurs.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_nosql_error(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    raw: Option<&RawRequest>,
    json_body: Option<&str>,
    error_payload: &str,
    trans: &[Tamper],
    marker_set: &MarkerSet,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    rng: &mut rand::rngs::StdRng,
) -> (String, f64, u16) {
    if let Some(original) = json_body
        && let Ok(op) = serde_json::from_str::<serde_json::Value>(error_payload)
        && op.is_object()
        && let Some(injected) =
            crate::target::structured::inject_json_operator(original, &param.name, &op)
    {
        let spec = nosql_json_body_spec(target, raw, &injected);
        return fetch_spec_boolean(client, state, cancel, spec).await;
    }
    let final_payload = build_final_payload_with_rng(error_payload, trans, popts, rng);
    fetch_for_payload(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        &final_payload,
        marker_set,
        raw,
        opts,
        popts,
    )
    .await
}

/// `RequestSpec` POST JSON pour un body opérateur déjà injecté (headers
/// préservés, `content-length` recalculé par la stack HTTP).
pub(crate) fn nosql_json_body_spec(
    target: &TargetUrl,
    raw: Option<&RawRequest>,
    injected_body: &str,
) -> RequestSpec {
    let method = raw
        .and_then(|r| http::Method::from_bytes(r.method.as_bytes()).ok())
        .unwrap_or(http::Method::POST);
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    if let Some(r) = raw {
        for (k, v) in &r.headers {
            if k.eq_ignore_ascii_case("content-type") || k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                headers.insert(name, val);
            }
        }
    }
    RequestSpec::new(method, target.as_str().to_owned())
        .with_headers(headers)
        .with_body(injected_body.as_bytes().to_vec())
}

/// Envoi basse-niveau d'un `RequestSpec` `NoSQL` sous timeout booléen
/// (`RequestClass::Boolean`), compté et borné comme les autres sondes.
/// Transport/body-read en échec → `(String::new(), ms, 0)` (jamais scoré).
pub(crate) async fn fetch_spec_boolean(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    spec: RequestSpec,
) -> (String, f64, u16) {
    let start = Instant::now();
    let resp = client
        .send_with_retry_for_class(spec, RequestClass::Boolean, cancel)
        .await;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    state.write().await.increment_requests();
    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match client
                .read_body_string_for_class(r, RequestClass::Boolean)
                .await
            {
                Ok(body) => (body, elapsed, status),
                Err(e) => {
                    warn!(error=%e, "nosql probe body read failed, skipping score");
                    (String::new(), elapsed, 0)
                }
            }
        }
        Err(e) => {
            warn!(error=%e, "nosql probe request failed, skipping score");
            (String::new(), elapsed, 0)
        }
    }
}

/// OOB detection: send DNS/HTTP probes embedding a unique token, then poll the
/// collaborator for the callback.
///
/// OPT-IN: skipped silently when `oob_domain` is `None` (no infra). Invalid
/// domains are rejected with a warning. Without `oob_poll_url` probes are
/// still sent but never auto-confirmed — the operator checks the collaborator
/// UI manually for `<token>.<domain>` (no finding is emitted without
/// evidence, to avoid false positives).
///
/// Flow per parameter: one fresh token per payload index (up to 3
/// DBMS-generic probes, each with tamper variants), cancellable
/// send→wait→poll per variant with early-break on the first token-verified
/// callback (`HttpPollVerifier`). A finding (`TechniqueKind::Oob`,
/// confidence 0.95) is pushed only on callback.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn test_oob_bounded(
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
    oob_domain: Option<String>,
    oob_poll_url: Option<String>,
    oob_wait_secs: u64,
    seed: Option<u64>,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
) {
    use crate::techniques::oob::verifier::OobVerifier as _;
    let (top_dbms, top_prob) = dbms_belief.top_candidate();
    debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "oob: context-aware detection");
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    let Some(domain) = oob_domain else {
        return;
    };
    if !is_valid_oob_domain(&domain) {
        warn!(domain=%domain, "invalid --oob-domain, skipping OOB probes");
        return;
    }
    let detector = OobDetector::new(domain.clone());
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    // DBMS-aware OOB cores once the belief is actionable (>= 0.85, same bar
    // as `fill_missing_dbms`); otherwise the generic 3-probe sweep.
    // OOB-2: one fresh token per payload index. The token is embedded
    // verbatim in `payload`/`fqdn` at build time (`build_subdomain`), so the
    // whole vector is regenerated per index and the element at that index is
    // taken (O(N²), N<=4) — never a clone+rewrite.
    let dbms_label = dbms_payload_label(dbms_belief);
    let total_payloads = oob_payloads_for(dbms_label, &domain, "oobcount").len();
    let budget = payload_budget(level, 3, total_payloads);
    let tamper_sets = tamper_transformation_sets(tampers);
    let has_poll_url = oob_poll_url
        .as_deref()
        .is_some_and(|u| !u.trim().is_empty());

    // OOB-2 — per-payload loop: send tamper-variants of the regenerated
    // payload, wait for the async DB-side execution, then poll for THIS
    // token (up to 3 polls spaced 2s). A token-verified callback freezes the
    // proof on the triggering payload/token and breaks globally (early-break).
    // Keep the last response for evidence; OOB is async so the body is
    // expected to match baseline.
    let mut last_body = baseline_body.clone();
    let mut last_ms = baseline.mean_ms;
    let mut last_status: u16 = 0;
    let mut probes_sent = 0usize;

    if !has_poll_url {
        // Manual mode (no confirmation infra): one variant per payload is
        // enough; the operator checks the collaborator UI manually. Never a
        // finding without evidence.
        let mut manual_payload: Option<crate::techniques::oob::payloads::OobPayload> = None;
        for payload_idx in 0..budget {
            if cancel.is_cancelled() {
                return;
            }
            let token_for_variant = new_token();
            let Some(payload_for_variant) =
                oob_payloads_for(dbms_label, &domain, &token_for_variant)
                    .into_iter()
                    .nth(payload_idx)
            else {
                continue;
            };
            if manual_payload.is_none() {
                manual_payload = Some(payload_for_variant.clone());
            }
            // Without confirmation infra one variant per payload is enough;
            // the operator checks the collaborator UI manually.
            if let Some(first_set) = tamper_sets.first() {
                if cancel.is_cancelled() {
                    return;
                }
                let tampered = build_final_payload_with_rng(
                    &payload_for_variant.payload,
                    first_set,
                    popts,
                    &mut rng,
                );
                let (raw_body, ms, status) = fetch_for_payload_with_class(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    param,
                    &tampered,
                    marker_set,
                    raw,
                    opts,
                    popts,
                    RequestClass::Oob,
                )
                .await;
                probes_sent += 1;
                // `--ignore-code`: an ignored probe response is discarded
                // (kept baseline-neutral). No finding follows in manual mode.
                if !is_ignored(status, ignore_codes) {
                    last_body = matcher.pre_process(&raw_body);
                    last_ms = ms;
                    manual_payload = Some(payload_for_variant.clone());
                }
            }
        }
        if probes_sent == 0 {
            return;
        }
        let Some(manual_probe) = manual_payload else {
            return;
        };
        let eval_outcome = detector.evaluate_without_callback(
            &baseline_body,
            &last_body,
            baseline.mean_ms,
            last_ms,
            &manual_probe,
        );
        if eval_outcome.confidence >= 0.35 {
            info!(
                token=%manual_probe.token,
                fqdn=%manual_probe.fqdn,
                channel=%manual_probe.channel.to_string(),
                "oob probe sent (no --oob-poll-url) — check collaborator for callback, no auto-finding"
            );
        }
        return;
    }

    let poll_verifier = crate::techniques::oob::verifier::HttpPollVerifier::new(
        oob_poll_url.clone().unwrap_or_default(),
        8,
    );
    let full_wait = core::time::Duration::from_secs(oob_wait_secs.clamp(0, 30));
    let mut trigger_payload: Option<crate::techniques::oob::payloads::OobPayload> = None;
    for payload_idx in 0..budget {
        if cancel.is_cancelled() {
            return;
        }
        let token_for_variant = new_token();
        let Some(payload_for_variant) = oob_payloads_for(dbms_label, &domain, &token_for_variant)
            .into_iter()
            .nth(payload_idx)
        else {
            continue;
        };
        for trans_set in &tamper_sets {
            if cancel.is_cancelled() {
                return;
            }
            let tampered = build_final_payload_with_rng(
                &payload_for_variant.payload,
                trans_set,
                popts,
                &mut rng,
            );
            let (raw_body, ms, status) = fetch_for_payload_with_class(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                &tampered,
                marker_set,
                raw,
                opts,
                popts,
                RequestClass::Oob,
            )
            .await;
            probes_sent += 1;
            // `--ignore-code`: an ignored probe response is discarded
            // (kept baseline-neutral); a token-verified callback below still
            // overrides the veto (OOB-3).
            if is_ignored(status, ignore_codes) {
                last_status = status;
                continue;
            }
            last_body = matcher.pre_process(&raw_body);
            last_ms = ms;
            last_status = status;
        }
        if probes_sent == 0 {
            continue;
        }
        // Async DB execution + collaborator propagation lag. Full wait for
        // the first payload, then `min(wait, 2s)`: DB-side executions
        // overlap while we poll, so later variants need only a short settle.
        let wait_for_variant = if payload_idx == 0 {
            full_wait
        } else {
            core::cmp::min(full_wait, core::time::Duration::from_secs(2))
        };
        if !wait_for_variant.is_zero() {
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(wait_for_variant) => {},
            }
        }
        let mut callback_seen = false;
        for attempt_idx in 0..3 {
            if cancel.is_cancelled() {
                return;
            }
            if poll_verifier.verify(&token_for_variant).await {
                callback_seen = true;
                break;
            }
            if attempt_idx + 1 < 3 {
                tokio::select! {
                    () = cancel.cancelled() => return,
                    () = tokio::time::sleep(core::time::Duration::from_secs(2)) => {},
                }
            }
        }
        if callback_seen {
            // Freeze the proof on the triggering payload/token.
            trigger_payload = Some(payload_for_variant);
            break;
        }
    }
    if probes_sent == 0 {
        return;
    }
    // No token-verified callback across all variants: inconclusive, never a
    // finding (`evaluate_with_callback` only confirms on callback).
    let Some(trigger_probe) = trigger_payload else {
        return;
    };
    let eval_outcome = detector.evaluate_with_callback(
        &baseline_body,
        &last_body,
        baseline.mean_ms,
        last_ms,
        &trigger_probe,
        true,
    );
    if eval_outcome.is_vulnerable {
        // Token-verified collaborator proof outranks response
        // heuristics: OOB executes async and returns a baseline-like
        // page, so a `--ignore-code` hit or `--string`/`--code`
        // mismatch on the last variant must not veto a confirmed
        // callback (vetoing here was a systematic false negative:
        // `evaluate_with_callback` only confirms on callback).
        debug!(param=%param.key(), status=last_status, "oob callback proof overrides response vetos");
        let mut finding = crate::session::state::Finding::new(
            target.as_str(),
            param.key(),
            crate::session::state::TechniqueKind::Oob,
            eval_outcome.confidence,
            format!(
                "oob channel={} dbms={} token={} fqdn={} probes={}{}{}{}",
                eval_outcome.channel,
                eval_outcome.dbms.as_deref().unwrap_or("?"),
                eval_outcome.token,
                trigger_probe.fqdn,
                probes_sent,
                opts.evidence_suffix(),
                popts.evidence_suffix(),
                matcher.evidence_suffix(),
            ),
        )
        // C7: collaborator callback = strongest confirmation available.
        .with_false_positive_prob(0.01)
        .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
        finding.dbms = eval_outcome.dbms.clone();
        state.write().await.push_finding(finding);
    }
}
