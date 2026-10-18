//! Boolean/JSON/NoSQL second-pass (`SecondPassCand` + `confirm_boolean_second_pass`).
//! Moved verbatim from `confirm.rs` (P1-fin); no behaviour change.

use crate::{
    dbms::context::InjectionContext,
    detection::baseline,
    engine::fetch::{fetch_for_payload, fetch_for_payload_with_class},
    http::{client::HttpClient, timeouts::RequestClass},
    session::state::{Finding, SessionState, TechniqueKind},
    target::{
        injection::{ProbeOpts, is_ignored},
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

use self::setup::{BooleanSecondPassSetup, SecondPassCand, build_second_pass_setup};
use super::push_confirm_trace;

mod setup;

/// Boolean/Json/NoSQL second-pass: fresh TRUE/FALSE pairs (derived seed),
/// same 3-trial `confirm_either` majority bar as the first pass (identical
/// payloads re-sent per trial for `--seed` determinism). Findings whose
/// evidence carries `channel=error` (JSON `__bad__` / `NoSQL` `$where`) are
/// re-probed on the error channel instead: one error payload per candidate,
/// mirroring `test_json_bounded` / `test_nosql_bounded` (1 request each).
///
/// Bounded retry: tries up to `payload_budget(level, 2, len)` candidates
/// (boolean capped at 3 pairs x 3 trials x 2 requests = 18 requests). JSON
/// candidates come from `json_scan_payloads` (direct sweep + GraphQL
/// `variables` envelope) and `NoSQL` from the full catalogue, exactly like the
/// first pass. Keep iff ANY candidate re-confirms; drop only when ALL
/// candidates conclusively fail. Cancel keeps immediately; a run that never
/// manages a measured probe (all transport-neutral) also keeps instead of
/// dropping on network flakes.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn confirm_boolean_second_pass(
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
    context: &InjectionContext,
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let setup = build_second_pass_setup(
        finding,
        param,
        raw,
        baseline,
        matcher,
        effective_tampers,
        context,
        level,
    );
    let BooleanSecondPassSetup {
        candidates,
        safe,
        json_operator_path,
        error_channel,
        baseline_body,
    } = setup;
    if candidates.is_empty() {
        return true;
    }

    let trans: &[Tamper] = if json_operator_path.is_some() {
        &[]
    } else {
        &safe
    };
    // Fail-open ledger: if NO candidate manages a single measured probe (every
    // probe transport-neutral), the finding could not actually be re-probed —
    // keep it instead of dropping on network flakes.
    let mut any_measured = false;
    for cand in &candidates {
        if cancel.is_cancelled() {
            return true;
        }
        if error_channel {
            match cand {
                SecondPassCand::Json(p) => {
                    let probe =
                        build_final_payload_with_rng(&p.error_payload, &safe, popts, &mut rng);
                    let (raw_body, ms, status) = fetch_for_payload(
                        client, state, cancel, target, target_str, param, &probe, marker_set, raw,
                        opts, popts,
                    )
                    .await;
                    // Transport/cancel: candidate not measured, never a veto.
                    if cancel.is_cancelled() || status == 0 {
                        continue;
                    }
                    if is_ignored(status, ignore_codes) {
                        continue;
                    }
                    let body = matcher.pre_process(&baseline.strip_dynamic_content(&raw_body));
                    let r = crate::techniques::json::detector::JsonDetector::new()
                        .evaluate_error(&body);
                    push_confirm_trace(
                        state,
                        &param.key(),
                        finding.technique,
                        mutation_plan,
                        seed,
                        &probe,
                        &body,
                        if r.is_vulnerable { r.confidence } else { 0.1 },
                        ms,
                    )
                    .await;
                    any_measured = true;
                    // Same bar as the first pass: signature still present and
                    // the matcher does not veto the error page.
                    if r.is_vulnerable && matcher.matches(&body, status) != Some(false) {
                        return true;
                    }
                }
                SecondPassCand::Nosql(p) => {
                    let (raw_body, ms, status) = crate::techniques::nosql::scan::fetch_nosql_error(
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
                    if cancel.is_cancelled() || status == 0 {
                        continue;
                    }
                    if is_ignored(status, ignore_codes) {
                        continue;
                    }
                    let body = matcher.pre_process(&baseline.strip_dynamic_content(&raw_body));
                    let r = crate::techniques::nosql::detector::NosqlDetector::new()
                        .evaluate_error(&body);
                    push_confirm_trace(
                        state,
                        &param.key(),
                        finding.technique,
                        mutation_plan,
                        seed,
                        &p.error_payload,
                        &body,
                        if r.is_vulnerable { r.confidence } else { 0.1 },
                        ms,
                    )
                    .await;
                    any_measured = true;
                    if r.is_vulnerable && matcher.matches(&body, status) != Some(false) {
                        return true;
                    }
                }
                // Boolean findings never carry `channel=error`; nothing to do.
                SecondPassCand::Boolean { .. } => {}
            }
            continue;
        }
        // Build the payload pair once: the 3 trials must re-send the IDENTICAL
        // payloads (seed determinism — the RNG must not advance per trial).
        // NoSQL builds its string form inside `fetch_nosql_boolean` (operator
        // path sends the pre-parsed `Value` as-is), exactly like first pass.
        let (true_payload, false_payload) = match cand {
            SecondPassCand::Boolean {
                true_base,
                false_base,
            } => (
                build_final_payload_with_rng(true_base, &safe, popts, &mut rng),
                build_final_payload_with_rng(false_base, &safe, popts, &mut rng),
            ),
            SecondPassCand::Json(p) => (
                build_final_payload_with_rng(&p.true_payload, &safe, popts, &mut rng),
                build_final_payload_with_rng(&p.false_payload, &safe, popts, &mut rng),
            ),
            SecondPassCand::Nosql(p) => (p.true_payload.clone(), p.false_payload.clone()),
        };
        // 3-trial confirmation per pair (same bar as the first pass):
        // re-send the IDENTICAL payloads (seed determinism — the RNG must
        // not advance per trial) and require a `confirm_either` majority
        // instead of trusting one lucky trial.
        let mut trials: Vec<crate::detection::confirmation::Trial> = Vec::with_capacity(3);
        let mut last_true = String::new();
        let mut last_false = String::new();
        let mut last_true_status: u16 = 0;
        let mut last_false_status: u16 = 0;
        let mut last_true_ms = 0.0;
        let mut last_false_ms = 0.0;
        for _ in 0..3 {
            if cancel.is_cancelled() {
                return true;
            }
            // NoSQL operator/JSON-body parity: `fetch_nosql_boolean` selects
            // the operator-object or string shape exactly like first pass;
            // boolean/JSON use the generic boolean fetch.
            let (true_raw, true_ms, true_status, false_raw, false_ms, false_status) = match cand {
                SecondPassCand::Nosql(p) => {
                    let (true_raw, true_ms, true_status) =
                        crate::techniques::nosql::scan::fetch_nosql_boolean(
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
                    let (false_raw, false_ms, false_status) =
                        crate::techniques::nosql::scan::fetch_nosql_boolean(
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
                    (
                        true_raw,
                        true_ms,
                        true_status,
                        false_raw,
                        false_ms,
                        false_status,
                    )
                }
                SecondPassCand::Boolean { .. } | SecondPassCand::Json(_) => {
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
                    (
                        true_raw,
                        true_ms,
                        true_status,
                        false_raw,
                        false_ms,
                        false_status,
                    )
                }
            };
            if cancel.is_cancelled() {
                return true;
            }
            // Transport/body failure: neutral trial (never confirms), not a veto.
            if true_status == 0 || false_status == 0 {
                trials.push(crate::detection::confirmation::Trial {
                    true_conf: 0.5,
                    false_conf: 0.5,
                });
                continue;
            }
            // Ignored status: negative trial, never a finding.
            if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
                trials.push(crate::detection::confirmation::Trial {
                    true_conf: 0.0,
                    false_conf: 1.0,
                });
                continue;
            }
            let true_body = matcher.pre_process(&baseline.strip_dynamic_content(&true_raw));
            let false_body = matcher.pre_process(&baseline.strip_dynamic_content(&false_raw));
            let res = if finding.technique == TechniqueKind::Json {
                crate::techniques::json::detector::JsonDetector::new()
                    .evaluate_boolean_with_match_ratio(
                        &baseline_body,
                        &true_body,
                        &false_body,
                        baseline.mean_ms,
                        true_ms,
                        false_ms,
                        baseline.match_ratio(),
                    )
            } else if finding.technique == TechniqueKind::Nosql {
                crate::techniques::nosql::detector::NosqlDetector::new()
                    .evaluate_boolean_with_match_ratio(
                        &baseline_body,
                        &true_body,
                        &false_body,
                        baseline.mean_ms,
                        true_ms,
                        false_ms,
                        baseline.match_ratio(),
                    )
            } else {
                // P1.2 — veto empirique sur la branche booléenne pure, comme
                // les wrappers JSON/NoSQL ci-dessus (même plancher appris).
                crate::techniques::boolean::detector::BooleanDetector::new()
                    .evaluate_with_match_ratio(
                        &baseline_body,
                        &true_body,
                        &false_body,
                        baseline.mean_ms,
                        true_ms,
                        false_ms,
                        baseline.match_ratio(),
                    )
            };
            // P1.2 : même traduction trial neutre qu'en première passe quand
            // le plancher de bruit a vetoé la paire (`noise_vetoed`, exposé
            // par les trois détecteurs).
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
            last_true_status = true_status;
            last_false_status = false_status;
            last_true_ms = true_ms;
            last_false_ms = false_ms;
            any_measured = true;
        }
        let (conf, inverted) = crate::detection::confirmation::confirm_either(&trials);
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &true_payload,
            &last_true,
            conf.score,
            last_true_ms,
        )
        .await;
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &false_payload,
            &last_false,
            conf.score,
            last_false_ms,
        )
        .await;
        if matcher.gate_boolean(&last_true, &last_false, last_true_status, last_false_status)
            == Some(false)
        {
            continue;
        }
        if conf.confirmed {
            // P0.2 — contrôle à arithmétique aléatoire : la même page doit
            // encore distinguer `r=r` (baseline-like) de `r1=r2` (différent),
            // dans le sens `inverted` de la paire re-confirmée. Contradiction
            // mesurée → candidat suivant ; transport/`None` → neutre (le
            // finding reste conservé, comme aujourd'hui). Budget borné :
            // +2 requêtes seulement ici.
            match crate::detection::control_pair::derive_control_pair(
                &true_payload,
                &false_payload,
                seed,
            ) {
                None => {}
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
                        return true;
                    }
                    let verdict = if ctl_true_status == 0 || ctl_false_status == 0 {
                        crate::detection::control_pair::ControlVerdict::Neutral
                    } else {
                        crate::detection::control_pair::control_verdict_with_match_ratio(
                            &baseline_body,
                            &matcher.pre_process(&baseline.strip_dynamic_content(&ctl_true_raw)),
                            &matcher.pre_process(&baseline.strip_dynamic_content(&ctl_false_raw)),
                            baseline.mean_ms,
                            ctl_true_ms,
                            ctl_false_ms,
                            inverted,
                            baseline.match_ratio(),
                        )
                    };
                    if verdict == crate::detection::control_pair::ControlVerdict::Veto {
                        continue;
                    }
                }
            }
            return true;
        }
    }
    if !any_measured {
        return true;
    }
    false
}
