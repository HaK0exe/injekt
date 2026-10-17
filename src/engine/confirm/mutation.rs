//! Mini-mutation second-pass (`mutation_base_payload`, `run_mutation_for_finding`,
//! `mutate_and_trace`, `mutation_diff_signal`). Moved verbatim from `confirm.rs`
//! (P1-fin); no behaviour change.

use crate::{
    dbms::context::InjectionContext,
    detection::baseline,
    engine::fetch::fetch_for_payload_with_class,
    http::{client::HttpClient, timeouts::RequestClass},
    session::state::{Finding, SessionState, TechniqueKind},
    target::{
        injection::ProbeOpts, markers::MarkerSet, parameters::TargetParameter,
        raw_request::RawRequest, url::TargetUrl,
    },
    techniques::{
        payload_opts::{PayloadOpts, build_final_payload_with_rng},
        tamper::Tamper,
    },
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use super::{
    dbms_label_from_finding, is_confirmed_finding, push_confirm_trace,
    union::union_marker_for_finding,
};

/// C5-tardif base payload for mutation: one raw base string per technique.
///
/// - `boolean`/`json`/`nosql` : le côté `TRUE` de la première paire (la mutation
///   vérifie que `TRUE` reste `≈baseline`, 1 requête par variante).
/// - `error`/`time`/`union`/`stacked` : le premier core DBMS-aware.
/// - `oob` : `None` (jamais muté).
///
/// `None` = pas de base disponible → 0 requête de mutation.
pub(crate) fn mutation_base_payload(finding: &Finding) -> Option<String> {
    let label = dbms_label_from_finding(finding);
    match finding.technique {
        TechniqueKind::Boolean => crate::techniques::boolean::payloads::boolean_payloads_for(label)
            .first()
            .map(|p| p.true_payload.clone()),
        TechniqueKind::Json => crate::techniques::json::payloads::json_payloads_for(label)
            .first()
            .map(|p| p.true_payload.clone()),
        TechniqueKind::Nosql => crate::techniques::nosql::payloads::nosql_payloads()
            .first()
            .map(|p| p.true_payload.clone()),
        TechniqueKind::Error => crate::techniques::error::payloads::error_payloads_for(label)
            .first()
            .map(|p| p.payload.clone()),
        TechniqueKind::Time => crate::techniques::time::payloads::time_payloads_for(label, 3)
            .first()
            .map(|p| p.payload.clone()),
        TechniqueKind::Union => crate::techniques::union::payloads::union_payloads_for(label, 3)
            .first()
            .map(|p| p.payload.clone()),
        TechniqueKind::Stacked => crate::techniques::stacked::payloads::stacked_payloads_for(label)
            .first()
            .map(|p| p.payload.clone()),
        TechniqueKind::Oob => None,
    }
}

/// C5-tardif mini-mutation second-pass (confirmés seuls).
///
/// Appelée **uniquement** depuis [`Engine::run_confirm_second_pass`], après
/// une re-validation réussie, donc uniquement sur des findings déjà
/// confirmés — jamais en détection première, jamais sur cible propre.
/// Garanties :
/// - gate [`crate::mutation::should_attempt_mutation`] : `--no-mutation`,
///   WAF blocking, non-confirmé, OOB → 0 requête, 0 trace.
/// - borné : ≤ [`crate::mutation::MAX_MUTATION_VARIANTS`] variantes,
///   1 requête chacune, ≤ [`crate::mutation::MAX_MUTATION_REQUESTS_PER_FINDING`]
///   par finding (4 effectives).
/// - seedé : `seed` dérivée du run (`derive_confirm_seed`).
/// - tracé : chaque sonde pousse un `ProbeRecord` `mutation:<famille>`.
/// - échec silencieux : le résultat ne crée ni ne supprime aucun finding ;
///   le finding d'origine est toujours conservé.
///   Retourne le nombre de requêtes de mutation envoyées (0..=4).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_mutation_for_finding(
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
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    context: &InjectionContext,
    no_mutation: bool,
    seed: Option<u64>,
) -> usize {
    use crate::mutation::{MiniMutator, should_attempt_mutation};
    let baseline_blocking = baseline.is_waf_blocking() || baseline.is_waf_blocked();
    let confirmed = is_confirmed_finding(finding);
    let is_oob = finding.technique == TechniqueKind::Oob;
    if !should_attempt_mutation(no_mutation, baseline_blocking, confirmed, is_oob) {
        debug!(
            param = %finding.parameter,
            technique = %finding.technique,
            no_mutation,
            baseline_blocking,
            confirmed,
            "mutation skipped (gate)"
        );
        return 0;
    }
    let Some(base) = mutation_base_payload(finding) else {
        return 0;
    };
    let variants = MiniMutator::all_enabled().generate(&base, context, seed);
    if variants.is_empty() {
        return 0;
    }
    mutate_and_trace(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        finding,
        marker_set,
        raw,
        baseline,
        effective_tampers,
        opts,
        popts,
        matcher,
        &variants,
        seed,
    )
    .await
}

/// Boucle d'envoi des variantes mutées (extrait de [`run_mutation_for_finding`]).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mutate_and_trace(
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
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    variants: &[crate::mutation::MutatedVariant],
    seed: Option<u64>,
) -> usize {
    // Boolean-safe : les paires TRUE/FALSE exigent des transforms qui
    // préservent le différentiel (même filtre que la détection première).
    let boolean_safe: Vec<Tamper> = effective_tampers
        .iter()
        .filter(|t| t.is_boolean_safe())
        .cloned()
        .collect();
    let tampers_for_variant: &[Tamper] = match finding.technique {
        TechniqueKind::Boolean | TechniqueKind::Json | TechniqueKind::Nosql => &boolean_safe,
        _ => effective_tampers,
    };
    let class = match finding.technique {
        TechniqueKind::Boolean | TechniqueKind::Json | TechniqueKind::Nosql => {
            RequestClass::Boolean
        }
        TechniqueKind::Time => RequestClass::Time,
        _ => RequestClass::Default,
    };
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let mut rng = crate::seeded_rng::make_rng(seed);
    let mut sent = 0usize;
    // Échec silencieux : chaque variante est tracée, jamais touchée aux
    // findings ; le résultat ne crée ni ne supprime rien.
    for variant in variants.iter().take(
        crate::mutation::MAX_MUTATION_REQUESTS_PER_FINDING
            .min(crate::mutation::MAX_MUTATION_VARIANTS),
    ) {
        if cancel.is_cancelled() {
            break;
        }
        let final_payload =
            build_final_payload_with_rng(&variant.payload, tampers_for_variant, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload_with_class(
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
            class,
        )
        .await;
        if cancel.is_cancelled() || status == 0 {
            continue;
        }
        sent = sent.saturating_add(1);
        let body = matcher.pre_process(&raw_body);
        let diff = mutation_diff_signal(
            finding,
            baseline,
            &baseline_body,
            &body,
            ms,
            status,
            &final_payload,
        );
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            &variant.plan_label,
            seed,
            &final_payload,
            &body,
            diff,
            ms,
        )
        .await;
        debug!(
            param = %finding.parameter,
            technique = %finding.technique,
            plan = %variant.plan_label,
            diff,
            status,
            "mutation probe traced (silent, finding kept)"
        );
    }
    if sent > 0 {
        info!(
            param = %finding.parameter,
            technique = %finding.technique,
            sent,
            "mutation second-pass traced (finding kept regardless)"
        );
    }
    sent
}

/// Signal `diff` informatif pour une sonde mutée (traçabilité uniquement).
///
/// Borné `[0.0, 1.0]`, jamais utilisé pour créer/supprimer un finding :
/// la mutation est une preuve d'évasion citée, pas un verdict.
/// `sent_payload` est la chaîne exacte envoyée sur le fil (tampers inclus),
/// exigée par le veto anti-réflexion du détecteur UNION.
pub(crate) fn mutation_diff_signal(
    finding: &Finding,
    baseline: &baseline::Baseline,
    baseline_body: &str,
    body: &str,
    ms: f64,
    _status: u16,
    sent_payload: &str,
) -> f64 {
    match finding.technique {
        TechniqueKind::Boolean | TechniqueKind::Json | TechniqueKind::Nosql => {
            crate::detection::response_diff::adaptive_similarity(baseline_body, body)
                .clamp(0.0, 1.0)
        }
        TechniqueKind::Error => {
            let r = crate::techniques::error::detector::ErrorDetector::new().evaluate_with_context(
                baseline_body,
                body,
                body,
            );
            if r.is_vulnerable { 0.9 } else { 0.1 }
        }
        TechniqueKind::Time => {
            let detector = crate::techniques::time::detector::TimeDetector::from_baseline(baseline);
            if ms > detector.threshold() { 0.9 } else { 0.1 }
        }
        TechniqueKind::Union => {
            let detector = crate::techniques::union::detector::UnionDetector::new();
            let marker = union_marker_for_finding(finding);
            let r = detector.evaluate(
                baseline_body,
                body,
                baseline.mean_ms,
                ms,
                3,
                &marker,
                sent_payload,
            );
            if r.is_vulnerable { 0.85 } else { 0.1 }
        }
        TechniqueKind::Stacked => {
            if body.contains("injekt") || body != baseline_body {
                0.8
            } else {
                0.1
            }
        }
        TechniqueKind::Oob => 0.0,
    }
}
