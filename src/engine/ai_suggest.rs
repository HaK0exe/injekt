#![deny(unsafe_code)]

//! AI-suggest second-pass (P1): opt-in LLM pair probing + trace.
//! Extracted verbatim from `orchestrator.rs`; no behaviour change.

use super::config::{BudgetConfig, EngineConfig};
use super::fetch::fetch_for_payload_with_class;
use super::schedule::{check_deadline, dbms_payload_label, is_technique_enabled};
use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    detection::baseline,
    http::{client::HttpClient, timeouts::RequestClass},
    session::state::{Finding, SessionState, TechniqueKind},
    target::{
        injection::{ProbeOpts, baseline_all_error, is_app_filter_block, is_ignored},
        markers::MarkerSet,
        parameters::TargetParameter,
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::{
        boolean::detector::BooleanDetector,
        payload_opts::{PayloadOpts, build_final_payload_with_rng},
        tamper::Tamper,
    },
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// `--ai-suggest` second-pass (opt-in post-échec / WAF-block uniquement).
///
/// Un seul passage par paramètre et par run (verrou `ai_attempted` partagé
/// entre le hook détection et le hook post-confirm), seulement si le run est
/// reparti bredouille face à un signal actionnable : WAF bloquant
/// (`is_waf_blocked() || is_waf_blocking()`), filtre applicatif (`400`
/// streak mémorisé par [`SessionState::note_app_filter_hit`]), empreinte WAF
/// live, ou `--confirm` droppé (`confirm_dropped`, hook post-confirm).
///
/// Bornes : 0 appel LLM quand OFF/incomplet/déjà-tenté/annulé/budget/deadline
/// (fail silencieux), au plus `max_suggestions` paires validées × 2 requêtes
/// (défaut 3 paires = 6 requêtes/param). Chaque paire passe par le validator
/// local avant envoi ; l'évaluation reprend `BooleanDetector` + veto matcher
/// (single-trial, `trials=1/1` en évidence — le confirm 3-trials reste une
/// option V2). Échec silencieux : aucun finding inventé, finding originel
/// jamais modifié (aucun n'existe sur ce param par construction du gate).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn run_ai_suggest_for_param(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
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
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
    deadline: Option<std::time::Instant>,
    confirm_dropped: bool,
) {
    use crate::ai::{
        AiSuggestConfig, ai_hard_stop, ai_plan_label, ai_trigger, should_attempt_ai_suggest,
    };
    let ai: &AiSuggestConfig = &config.ai;
    if !ai.enabled {
        return;
    }
    let param_key = param.key();
    // Gate synchrone (0 requête) : findings vides sur ce param + trigger +
    // verrous (budget/deadline/cancel/origine down/boolean désactivé).
    let findings_empty = !state
        .read()
        .await
        .findings()
        .iter()
        .any(|f| f.parameter == param_key);
    let waf_signal = baseline.is_waf_blocked() || baseline.is_waf_blocking();
    let filter_hit = state.read().await.app_filter_hit(&param_key);
    // Empreinte WAF live en phase détection : un WAF qui ne bloque que les
    // payloads (baseline 200 propre) ne laisse aucun signal baseline, mais
    // chaque sonde bloquée est mémorisée par param dans
    // `fetch_for_payload_with_class` (les compteurs `detectability` ne sont
    // absorbés qu'en fin de run — trop tard pour ce hook).
    let live_waf_hit = state.read().await.waf_hit(&param_key);
    let trigger = ai_trigger(waf_signal, filter_hit, confirm_dropped) || live_waf_hit;
    let budget_spent = BudgetConfig::is_over_request_budget(
        state.read().await.request_count(),
        config.budget.request_budget,
    );
    let hard_stop = ai_hard_stop(
        baseline_all_error(&baseline.status_codes),
        budget_spent,
        BudgetConfig::is_past_deadline(deadline),
        cancel.is_cancelled(),
        !is_technique_enabled(&config.techniques, TechniqueKind::Boolean),
    );
    if !should_attempt_ai_suggest(ai.enabled, findings_empty, trigger, hard_stop) {
        return;
    }
    if !ai.is_complete() {
        debug!(param = param_key, "ai-suggest skipped: incomplete config");
        return;
    }
    // Verrou un-passage-par-param : le hook détection et le hook
    // post-confirm partagent ce verrou (un fetch échoué ne retente pas —
    // borné avant persistant, documenté).
    if state.read().await.has_ai_attempted(&param_key) {
        return;
    }
    state.write().await.note_ai_attempted(&param_key);
    info!(
        param = param_key,
        provider = ai.provider.map(crate::ai::AiProviderKind::name),
        waf_signal,
        filter_hit,
        "ai-suggest second-pass start (bounded, silent on failure)"
    );
    // Signaux abstraits uniquement (0 secret) + squelettes des paires L1
    // historiques pour interdire au LLM de les répéter à l'identique.
    let failed_shapes: Vec<String> =
        crate::techniques::boolean::payloads::boolean_payloads_for(dbms_payload_label(dbms_belief))
            .iter()
            .take(2)
            .map(|p| {
                crate::ai::prompt::skeletonize(&format!("{} / {}", p.true_payload, p.false_payload))
            })
            .collect();
    let signals = crate::ai::prompt::AiSignals::collect(
        context,
        dbms_belief,
        baseline.waf_vendor.as_deref(),
        &baseline.waf_hits,
        baseline.is_waf_blocking(),
        &failed_shapes,
        &context.comment.to_string(),
    );
    let system = crate::ai::prompt::system_prompt();
    let user = crate::ai::prompt::build_user_prompt(&signals, ai.max_suggestions);
    let Some(provider) = ai.provider else {
        return;
    };
    let suggested = match crate::ai::provider::fetch_suggestions(ai, system, &user, cancel).await {
        Ok(pairs) => pairs,
        Err(e) => {
            debug!(param = param_key, error = %e, "ai-suggest fetch failed, skipping silently");
            return;
        }
    };
    // Cohérence WAF-bypass (ex. auto space2comment) sans casser le
    // différentiel TRUE/FALSE : tampers effectifs filtrés boolean-safe, comme
    // `confirm_error_with_boolean`. RNG seedé : même seed → mêmes variantes.
    let mut rng = crate::seeded_rng::make_rng(seed);
    let safe_trans: Vec<Tamper> = tampers
        .iter()
        .filter(|t| t.is_boolean_safe())
        .cloned()
        .collect();
    let tamper_label = if safe_trans.is_empty() {
        "none".to_owned()
    } else {
        safe_trans
            .iter()
            .map(super::super::techniques::tamper::Tamper::name)
            .collect::<Vec<_>>()
            .join(",")
    };
    let detector = BooleanDetector::new();
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let mut tried: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut validated: u8 = 0;
    for (idx, pair) in suggested.iter().enumerate() {
        if cancel.is_cancelled() || check_deadline(deadline, &param_key, "ai-suggest") {
            break;
        }
        if validated >= ai.max_suggestions {
            break;
        }
        if BudgetConfig::is_over_request_budget(
            state.read().await.request_count(),
            config.budget.request_budget,
        ) {
            debug!(param = param_key, "ai-suggest stopping on request-budget");
            break;
        }
        let Ok(valid) =
            crate::ai::validator::validate_ai_pair(&pair.true_branch, &pair.false_branch, &tried)
        else {
            debug!(
                param = param_key,
                index = idx,
                "ai-suggest pair rejected by validator"
            );
            continue;
        };
        tried.insert(valid.true_payload.clone());
        tried.insert(valid.false_payload.clone());
        validated = validated.saturating_add(1);
        let true_payload =
            build_final_payload_with_rng(&valid.true_payload, &safe_trans, popts, &mut rng);
        let false_payload =
            build_final_payload_with_rng(&valid.false_payload, &safe_trans, popts, &mut rng);
        let plan = ai_plan_label(provider, validated.saturating_sub(1));
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
        // Transport/ignore/filtre : jamais scoré, jamais de finding (même
        // rigueur que `test_boolean_bounded`, en single-trial ici).
        if true_status == 0 || false_status == 0 {
            push_ai_trace(
                state,
                &param_key,
                &plan,
                seed,
                0.2,
                2.0,
                &valid.true_payload,
                &valid.false_payload,
            )
            .await;
            continue;
        }
        if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
            push_ai_trace(
                state,
                &param_key,
                &plan,
                seed,
                0.2,
                2.0,
                &valid.true_payload,
                &valid.false_payload,
            )
            .await;
            continue;
        }
        if is_app_filter_block(true_status, false_status) {
            push_ai_trace(
                state,
                &param_key,
                &plan,
                seed,
                0.2,
                2.0,
                &valid.true_payload,
                &valid.false_payload,
            )
            .await;
            continue;
        }
        let res = detector.evaluate(
            &baseline_body,
            &true_body,
            &false_body,
            baseline.mean_ms,
            true_ms,
            false_ms,
        );
        if !res.is_vulnerable
            || matcher.gate_boolean(&true_body, &false_body, true_status, false_status)
                == Some(false)
        {
            push_ai_trace(
                state,
                &param_key,
                &plan,
                seed,
                res.confidence.min(0.2),
                2.0,
                &valid.true_payload,
                &valid.false_payload,
            )
            .await;
            continue;
        }
        let fp = (1.0 - res.confidence).clamp(0.0, 1.0);
        let evidence = format!(
            "boolean true_sim={:.2} false_sim={:.2} trials=1/1 fp={fp:.2} tamper={tamper_label} {plan}{}",
            res.true_similarity,
            res.false_similarity,
            matcher.evidence_suffix(),
        );
        let finding = Finding::new(
            target.as_str(),
            param_key.clone(),
            TechniqueKind::Boolean,
            res.confidence,
            evidence,
        )
        .with_false_positive_prob(fp)
        .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
        let mut finding = finding;
        finding.dbms = None;
        state.write().await.push_finding(finding);
        push_ai_trace(
            state,
            &param_key,
            &plan,
            seed,
            res.confidence,
            2.0,
            &valid.true_payload,
            &valid.false_payload,
        )
        .await;
        info!(
            param = param_key,
            plan,
            confidence = res.confidence,
            "ai-suggest confirmed finding"
        );
        break;
    }
}

/// Trace hashes-only d'une paire IA sondée (jamais de payload en clair).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn push_ai_trace(
    state: &Arc<RwLock<SessionState>>,
    param_key: &str,
    plan: &str,
    seed: Option<u64>,
    posterior: f64,
    cost: f64,
    true_payload: &str,
    false_payload: &str,
) {
    let mut st = state.write().await;
    let seq = st.next_trace_seq();
    let req_hash = crate::reasoning::trace::hash_str_hex(&format!(
        "{param_key}:ai:{plan}:{}",
        seed.map_or("none".to_owned(), |s| s.to_string())
    ));
    let resp_hash = crate::reasoning::trace::hash_str_hex(&format!(
        "{param_key}:ai:{plan}:t={}f={}",
        crate::session::scrubber::Scrubber::hash_truncated(true_payload),
        crate::session::scrubber::Scrubber::hash_truncated(false_payload),
    ));
    st.push_trace(crate::reasoning::ProbeRecord::new(
        seq,
        param_key.to_owned(),
        TechniqueKind::Boolean.to_string(),
        plan.to_owned(),
        seed,
        req_hash,
        resp_hash,
        posterior.clamp(0.0, 1.0),
        cost,
    ));
}
