use std::sync::Arc;

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::{dispatch::run_one_technique, shared::DetectionShared};
use crate::engine::ai_suggest::run_ai_suggest_for_param;
use crate::engine::config::{BudgetConfig, EngineConfig};
use crate::engine::schedule::{
    build_scheduler_for_param, detection_order, is_technique_enabled, log_scheduler_state,
};
use crate::{
    detection::scanner::scheduler::ensure_union_starvation_guard,
    http::client::HttpClient,
    reasoning::Hypothesis,
    session::state::{SessionState, TechniqueKind},
    target::{injection::ProbeOpts, parameters::TargetParameter, raw_request::RawRequest},
};

/// Per-parameter C3+C4 loop: 7 hypotheses seeded by calibrated priors, each
/// `test_*_bounded` outcome mapped to probe/trial/WAF updates. Findings stay
/// untouched; prune/confirm only gate logging + early skip of terminal hyps.
///
/// [`detection_order`] only sets the creation order so the JSON / ORDER BY
/// context feeds priors (EVI input), while execution follows scheduler
/// `score = EVI * 1.0 / cost` via [`Scheduler::pop`] (budget + [`EarlyStop`]
/// gated). Payload volume per technique stays enveloped by
/// `payload_budget(level, ..)` inside `test_*_bounded`.
#[allow(clippy::too_many_lines)]
pub(super) async fn run_detection_for_param(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    shared: &DetectionShared,
    raw_request: &Arc<Option<RawRequest>>,
    param: &TargetParameter,
) {
    if cancel.is_cancelled() {
        return;
    }
    let param_key = param.key();
    let mut hyps: Vec<Hypothesis> = detection_order(&shared.context)
        .iter()
        .map(|kind| {
            Hypothesis::new(
                param_key.clone(),
                *kind,
                shared.dbms_belief.clone(),
                shared.context.clone(),
            )
        })
        .collect();
    let mut scheduler = build_scheduler_for_param(
        config,
        &param_key,
        &hyps,
        shared.context_probes,
        shared.baseline.mean_ms,
    );
    log_scheduler_state(&scheduler, &param_key, "start");
    let mut executed_kinds: Vec<TechniqueKind> = Vec::with_capacity(hyps.len());
    // Live belief: starts as the adaptive `<=8`-probe belief, then any
    // confirmed technique with a DBMS label (`>= 0.85` bar, same as
    // `fill_missing_dbms`) promotes it for the *next* tour on this param.
    // Payload selection reads `live_shared` (not the frozen `shared`), so
    // quote/comment styles stay quote-correct without re-spraying generics.
    let mut live_shared = shared.clone();
    while let Some(probe) = scheduler.pop() {
        if cancel.is_cancelled() {
            break;
        }
        // Phase 3 `--max-duration`: budget temps global partagé (voir
        // `DetectionShared::started`). `None` = illimité, byte-identique.
        if BudgetConfig::is_over_max_duration(shared.started, config.budget.max_duration_secs) {
            warn!(
                param = param_key,
                max_duration_secs = ?config.budget.max_duration_secs,
                "max-duration exceeded, stopping detection early"
            );
            break;
        }
        // CODE calibration `--request-budget`: plafond global OPT-IN sur le
        // `request_count` partagé (les schedulers sont per-param : seul ce
        // compteur global borne le total N1/N2). `None` = illimité,
        // byte-identique (le helper court-circuite sans lock supplémentaire
        // au-delà de ce `read`). Coopératif : la technique en cours finit,
        // aucune nouvelle ne démarre, fin en `Inconclusive` sans finding
        // (ni erreur, ni finding inventé). Un léger dépassement reste possible sous
        // concurrence (un tour par param en vol).
        {
            let spent = state.read().await.request_count();
            if BudgetConfig::is_over_request_budget(spent, config.budget.request_budget) {
                warn!(
                    param = param_key,
                    request_budget = ?config.budget.request_budget,
                    requests = spent,
                    "request-budget exceeded, stopping detection early"
                );
                break;
            }
        }
        let Some(hyp) = hyps.iter_mut().find(|h| h.technique == probe.technique) else {
            continue;
        };
        // Never prune before the first probe: OOB prior (0.02) starts below
        // the refuted threshold but still deserves its gated run.
        if hyp.cost_spent > 0 && hyp.is_refuted() {
            debug!(param = param_key, technique = %hyp.technique, posterior = hyp.posterior, "hypothesis pruned, skipping technique");
            continue;
        }
        if hyp.cost_spent > 0 && hyp.is_terminal() {
            continue;
        }
        // Per-family veto streak: a new technique family starts with a fresh
        // negative counter, so the N1/N2 veto only *arms* on a single
        // family spending >= 25 negative requests — and `Scheduler::pop`
        // additionally gates enforcement on a full pass (B1), so an armed
        // veto never blocks never-attempted families (boolean-negative !=
        // nosql-negative; cross-family starvation would be a silent false
        // negative). `confirmed` survives (only `reset_for_new_param`
        // clears it).
        scheduler.early_stop_mut().reset_negative_streak();
        let before_cost = hyp.cost_spent;
        run_one_technique(
            client,
            state,
            cancel,
            config,
            &live_shared,
            raw_request,
            param,
            hyp,
        )
        .await;
        executed_kinds.push(probe.technique);
        let spent_delta = hyp.cost_spent.saturating_sub(before_cost).max(1);
        let confirmed = hyp.is_confirmed();
        let refuted = hyp.is_refuted();
        let posterior = hyp.posterior;
        let technique = hyp.technique;
        let trials = hyp.trials_passed;
        let (top_kind, top_prob) = hyp.dbms_belief.top_candidate();
        scheduler.record_outcome(&param_key, confirmed, spent_delta);
        // `>= 0.85` DBMS promotion becomes the prior for the next tour:
        // live payload belief + pending hypotheses + stored findings.
        if confirmed && top_prob >= 0.85 && top_kind != crate::dbms::common::DbmsKind::Unknown {
            live_shared.dbms_belief = hyp.dbms_belief.clone();
            for pending in hyps.iter_mut().filter(|h| h.cost_spent == 0) {
                pending.dbms_belief = live_shared.dbms_belief.clone();
            }
            state.write().await.fill_missing_dbms(top_kind);
        }
        if confirmed {
            debug!(param = param_key, technique = %technique, posterior, trials, "hypothesis confirmed");
        } else if refuted {
            debug!(param = param_key, technique = %technique, posterior, "hypothesis refuted (posterior <= 0.04)");
        }
    }
    // Starvation guard: `union` keeps >= 1 probe when enabled, even if the
    // score order truncated it away. Skipped once the global `--request-budget`
    // is spent (le plafond gagne sur la couverture ; l'épuisement per-param
    // implique l'épuisement global car le total partagé majore tout total
    // per-param, donc un seul test global suffit), and once `--max-duration`
    // is exceeded (a hard user time budget must never be silently overshot:
    // a single L2 union run can park ~100 req / ~100s on a slow target, as
    // seen live when detection ran 205s under `--max-duration 120`).
    // NOTE: the EarlyStop veto is intentionally NOT consulted here — the
    // guard's contract is union coverage even on vetoed params (the veto
    // still kills error/time/json/nosql/oob/stacked, saving the bulk).
    let union_enabled = is_technique_enabled(&config.techniques, TechniqueKind::Union);
    let pre_guard_len = executed_kinds.len();
    ensure_union_starvation_guard(&mut executed_kinds, union_enabled);
    let budget_spent = BudgetConfig::is_over_request_budget(
        state.read().await.request_count(),
        config.budget.request_budget,
    );
    let duration_spent =
        BudgetConfig::is_over_max_duration(shared.started, config.budget.max_duration_secs);
    if budget_spent {
        debug!(
            param = param_key,
            request_budget = ?config.budget.request_budget,
            "request-budget spent, skipping union starvation guard"
        );
    } else if duration_spent {
        warn!(
            param = param_key,
            max_duration_secs = ?config.budget.max_duration_secs,
            "max-duration exceeded, skipping union starvation guard"
        );
    } else if executed_kinds.len() > pre_guard_len
        && !cancel.is_cancelled()
        && let Some(hyp) = hyps
            .iter_mut()
            .find(|h| h.technique == TechniqueKind::Union && h.cost_spent == 0)
    {
        debug!(
            param = param_key,
            "union starvation guard: forcing >=1 union probe"
        );
        run_one_technique(
            client,
            state,
            cancel,
            config,
            &live_shared,
            raw_request,
            param,
            hyp,
        )
        .await;
        scheduler.record_outcome(&param_key, hyp.is_confirmed(), hyp.cost_spent.max(1));
    }
    // `--ai-suggest` second-pass (opt-in post-échec/WAF) : gate synchrone
    // interne (0 requête quand OFF/incomplet/déjà-tenté/sans trigger/sous
    // verrou). Borné à `max_suggestions` paires × 2 requêtes, échec
    // silencieux sans finding inventé.
    if config.ai.enabled && !cancel.is_cancelled() {
        let ai_deadline =
            BudgetConfig::detection_deadline(shared.started, config.budget.max_duration_secs);
        run_ai_suggest_for_param(
            client,
            state,
            cancel,
            config,
            &shared.target,
            &shared.target_str,
            param,
            &shared.baseline,
            &shared.marker_set,
            raw_request.as_ref().as_ref(),
            &shared.tampers,
            ProbeOpts::new(config.evasion.hpp, config.evasion.chunked),
            &config.evasion.payload_opts,
            &config.matcher,
            &config.net.ignore_codes,
            config.seed,
            &shared.context,
            &live_shared.dbms_belief,
            ai_deadline,
            false,
        )
        .await;
    }
    // Visibilité du plafond OPT-IN : le scheduler per-param est seedé avec la
    // même valeur (`budget_total`), donc son épuisement confirme l'arrêt sur
    // budget (le `warn!` global ci-dessus a déjà annoncé le stop). `None` =
    // `is_exhausted()` toujours faux : 0 log, chemin inchangé.
    if scheduler.budget().is_exhausted() {
        info!(
            param = param_key,
            request_budget = ?config.budget.request_budget,
            spent = scheduler.budget_spent(),
            "request-budget exhausted for param, detection stopped early (inconclusive without findings)"
        );
    }
    log_scheduler_state(&scheduler, &param_key, "done");
}
