use super::dispatch::confirm_finding_second_pass;
use super::mutation::run_mutation_for_finding;
use super::params::param_from_finding;
use super::scope::{ConfirmScope, in_confirm_scope};
use crate::dbms::context::{DbmsBelief, InjectionContext};
use crate::detection::baseline;
use crate::engine::{
    ai_suggest::run_ai_suggest_for_param,
    config::{BudgetConfig, EngineConfig},
    schedule::mutation_plan_label,
};
use crate::http::client::HttpClient;
use crate::session::state::{Finding, SessionState};
use crate::target::{
    injection::ProbeOpts, markers::MarkerSet, raw_request::RawRequest, url::TargetUrl,
};
use crate::techniques::tamper::Tamper;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// C6 strict second-pass (real, not a `warn!`).
///
/// Re-sonde confirmed findings with fresh payloads + derived seed
/// (`derive_confirm_seed(base, idx)`), OOB excluded. [`ConfirmScope::All`]
/// (`--confirm`) covers every confirmed finding and documents the ~2x
/// request worst-case; [`ConfirmScope::MediumRisk`] (default) covers only
/// findings below the `High` bucket (bounded anti-FP, 0 request when the
/// snapshot holds none). Never creates new findings — only drops those
/// that fail re-validation, so N1/N2 stay at 0 FP by construction.
/// Inconclusive outcomes (transport error, `--ignore-code`, cancel) keep
/// the finding (fail-open toward the first pass, fail-closed toward new
/// FPs).
///
/// C5-tardif extension (`--confirm` only): after a finding is re-validated
/// (`ok == true`), the mini-mutation ([`crate::mutation`]) probes ≤4
/// deterministic variants (1 request each, `mutation:<famille>` traced,
/// silent failure). The mutation never runs in first-pass detection, never
/// on unconfirmed findings, never under WAF blocking, never when
/// `--no-mutation` is set, and never in the automatic medium-risk scope.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn run_confirm_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    target: &TargetUrl,
    target_str: &str,
    marker_set: &MarkerSet,
    raw_request: &Arc<Option<RawRequest>>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    effective_opts: ProbeOpts,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
    detection_started: std::time::Instant,
    scope: ConfirmScope,
) {
    let snapshot = state.read().await.findings().to_vec();
    let candidates: Vec<(usize, Finding)> = snapshot
        .into_iter()
        .enumerate()
        .filter(|(_, f)| in_confirm_scope(f, scope))
        .collect();
    if candidates.is_empty() {
        match scope {
            ConfirmScope::All => {
                debug!("--confirm second-pass: no confirmed non-OOB findings, 0 extra requests");
            }
            ConfirmScope::MediumRisk => {
                debug!("auto second-pass (medium-risk, non-high): no candidates, 0 extra requests");
            }
        }
        return;
    }
    match scope {
        ConfirmScope::All => info!(
            count = candidates.len(),
            "--confirm second-pass start (OOB excluded)"
        ),
        ConfirmScope::MediumRisk => info!(
            count = candidates.len(),
            "auto second-pass (medium-risk, non-high) start (OOB excluded)"
        ),
    }
    let plan = mutation_plan_label(effective_tampers);
    for (idx, finding) in candidates {
        if cancel.is_cancelled() {
            break;
        }
        let derived = crate::reasoning::derive_confirm_seed(config.seed, idx);
        let param = param_from_finding(&finding);
        let ok = confirm_finding_second_pass(
            client,
            state,
            cancel,
            target,
            target_str,
            &param,
            &finding,
            marker_set,
            raw_request.as_ref().as_ref(),
            baseline,
            effective_tampers,
            &plan,
            effective_opts,
            &config.evasion.payload_opts,
            &config.matcher,
            &config.net.ignore_codes,
            derived,
            context,
            config.budget.level,
        )
        .await;
        if ok {
            info!(
                param = %finding.parameter,
                technique = %finding.technique,
                "--confirm re-validated"
            );
            // Link the finding to its confirm trace (opaque hash ref).
            let trace_ref = {
                let st = state.read().await;
                st.trace().records_for(&finding.parameter).last().map(|r| {
                    format!(
                        "confirm#{}:{}",
                        r.seq,
                        r.request_hash.chars().take(16).collect::<String>()
                    )
                })
            };
            if let Some(tref) = trace_ref {
                let mut st = state.write().await;
                if let Some(f) = st
                    .findings_mut()
                    .iter_mut()
                    .find(|x| x.parameter == finding.parameter && x.technique == finding.technique)
                {
                    let current = f.evidence.clone();
                    if !current.contains("confirm=second-pass") {
                        f.evidence = format!("{current} confirm=second-pass");
                    }
                    f.evidence_detail.trace_ref = Some(tref);
                }
            }
            // C5-tardif mini-mutation (`--confirm` only: the mutation is
            // tied to the explicit flag): confirmed-only, bounded, seeded,
            // traced, silent failure (never drops the finding).
            if scope == ConfirmScope::All {
                run_mutation_for_finding(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    &param,
                    &finding,
                    marker_set,
                    raw_request.as_ref().as_ref(),
                    baseline,
                    effective_tampers,
                    effective_opts,
                    &config.evasion.payload_opts,
                    &config.matcher,
                    context,
                    config.no_mutation,
                    derived,
                )
                .await;
            }
        } else {
            warn!(
                param = %finding.parameter,
                technique = %finding.technique,
                "--confirm re-validation failed, dropping finding (was likely FP)"
            );
            let mut st = state.write().await;
            st.findings_mut().retain(|x| {
                !(x.parameter == finding.parameter && x.technique == finding.technique)
            });
            drop(st);
            // `--ai-suggest` post-confirm (opt-in) : le finding droppé
            // rouvre une seconde chance bornée avec des formes inédites
            // (trigger `confirm_dropped`). Gate interne : 0 requête quand
            // OFF/déjà-tenté/sous verrou ; échec silencieux.
            if config.ai.enabled && !cancel.is_cancelled() {
                let ai_deadline = BudgetConfig::detection_deadline(
                    detection_started,
                    config.budget.max_duration_secs,
                );
                run_ai_suggest_for_param(
                    client,
                    state,
                    cancel,
                    config,
                    target,
                    target_str,
                    &param,
                    baseline,
                    marker_set,
                    raw_request.as_ref().as_ref(),
                    effective_tampers,
                    effective_opts,
                    &config.evasion.payload_opts,
                    &config.matcher,
                    &config.net.ignore_codes,
                    derived,
                    context,
                    dbms_belief,
                    ai_deadline,
                    true,
                )
                .await;
            }
        }
    }
    match scope {
        ConfirmScope::All => info!("--confirm second-pass done"),
        ConfirmScope::MediumRisk => info!("auto second-pass done"),
    }
}
