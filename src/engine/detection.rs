//! Detection phase moved out of `orchestrator.rs` (P1-fin): per-parameter
//! C3+C4 loop (scheduler + hypotheses), technique dispatch and outcome folding.
//!
//! Behavior-neutral move: bodies are verbatim `Engine::run_detection` /
//! `run_detection_for_param` / `run_one_technique` / `dispatch_probe_*` /
//! `apply_outcome_to_hypothesis`; `self.*` became explicit params.

use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    detection::{baseline, scanner::scheduler::ensure_union_starvation_guard},
    http::client::HttpClient,
    reasoning::Hypothesis,
    session::state::{Finding, SessionState, TechniqueKind},
    target::{
        injection::ProbeOpts, markers::MarkerSet, parameters::TargetParameter,
        raw_request::RawRequest, url::TargetUrl,
    },
    techniques::tamper::Tamper,
};
use futures::StreamExt as _;
use indicatif::{ProgressBar, ProgressStyle};
use std::{io::IsTerminal as _, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::{
    ai_suggest::run_ai_suggest_for_param,
    config::{BudgetConfig, EngineConfig},
    probes::{
        test_boolean_bounded, test_error_bounded, test_json_bounded, test_nosql_bounded,
        test_oob_bounded, test_stacked_bounded, test_time_bounded, test_union_bounded,
    },
    schedule::{
        build_scheduler_for_param, detection_order, is_technique_enabled, log_scheduler_state,
        mutation_plan_label, parse_finding_dbms,
    },
};

fn progress_bar(len: u64) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{bar:40} {pos}/{len} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );
    pb
}

/// Runs boolean/error/time/union/stacked/json/nosql/oob detection for every
/// candidate parameter with bounded concurrency (respects `--threads`).
/// Minimal C3 loop: one [`Hypothesis`] per (param, technique) seeded by
/// `compute_calibrated_prior(context, dbms_belief)`; each
/// `test_*_bounded` outcome maps to `record_probe/record_trial/
/// record_waf_penalty`; prune at `posterior <= 0.04`, confirm at
/// `>= 0.85 + trials_passed > 0`. `Finding` emission is unchanged.
/// `context_probes` (the `<=8` adaptive probes) seeds every per-parameter
/// scheduler budget so the global cost stays visible in `budget_spent`
/// from the first `pop` (the true cross-param total is
/// `SessionState::request_count`).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_detection(
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
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
    context_probes: usize,
    to_test: Vec<TargetParameter>,
) {
    let pb2 = if to_test.len() > 1 {
        Arc::new(progress_bar(to_test.len() as u64))
    } else {
        Arc::new(indicatif::ProgressBar::hidden())
    };
    let concurrency = config.budget.threads.clamp(1, 32);
    let detection_started = Instant::now();
    let shared = Arc::new(DetectionShared {
        target: target.clone(),
        target_str: target_str.to_owned(),
        marker_set: marker_set.clone(),
        baseline: baseline.clone(),
        tampers: effective_tampers.to_vec(),
        context: context.clone(),
        dbms_belief: dbms_belief.clone(),
        context_probes,
        started: detection_started,
    });
    let stream = futures::stream::iter(to_test)
        .map(|param| {
            let shared = Arc::clone(&shared);
            let client = client.clone();
            let state = Arc::clone(state);
            let cancel = cancel.clone();
            let config = config.clone();
            let pb2 = Arc::clone(&pb2);
            let raw_request = Arc::clone(raw_request);
            async move {
                run_detection_for_param(
                    &client,
                    &state,
                    &cancel,
                    &config,
                    &shared,
                    &raw_request,
                    &param,
                )
                .await;
                pb2.inc(1);
            }
        })
        .buffer_unordered(concurrency);

    stream.collect::<Vec<()>>().await;
    // Clear the bar so the `detection done in …` summary logged by the
    // caller stays on a clean line (no `████ 1/1 …` glued to logs).
    // Single global bar (X/Y over blind spinner); hidden when stderr
    // is not a TTY (MCP/CI), where it would only spam + burn CPU.
    pb2.finish_and_clear();
}

/// Shared immutable detection inputs cloned once per `run_detection`.
#[derive(Debug, Clone)]
struct DetectionShared {
    target: TargetUrl,
    target_str: String,
    marker_set: MarkerSet,
    baseline: baseline::Baseline,
    tampers: Vec<Tamper>,
    context: InjectionContext,
    dbms_belief: DbmsBelief,
    /// Adaptive context probes already spent (`<=8` by `MAX_CONTEXT_PROBES`):
    /// seeded into every per-parameter scheduler budget.
    context_probes: usize,
    /// Shared detection clock for `--max-duration` (Phase 3): set once in
    /// `run_detection`, read in every `run_detection_for_param` iteration.
    /// Starts AFTER baseline + context, so `--max-duration` covers detection
    /// loops only — never the total run (documented in `--help`).
    started: Instant,
}

/// Per-parameter C3+C4 loop: 7 hypotheses seeded by calibrated priors, each
/// `test_*_bounded` outcome mapped to probe/trial/WAF updates. Findings stay
/// untouched; prune/confirm only gate logging + early skip of terminal hyps.
///
/// [`detection_order`] only sets the creation order so the JSON / ORDER BY
/// context feeds priors (EVI input), while execution follows scheduler
/// `score = EVI * 1.0 / cost` via [`Scheduler::pop`] (budget + [`EarlyStop`]
/// gated). Payload volume per technique stays enveloped by
/// `payload_budget(level, ..)` inside `test_*_bounded`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_detection_for_param(
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

/// Dispatch one technique, snapshot findings/requests, fold the outcome into
/// `hyp` via `record_probe/record_trial/record_waf_penalty`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_one_technique(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    shared: &DetectionShared,
    raw_request: &Arc<Option<RawRequest>>,
    param: &TargetParameter,
    hyp: &mut Hypothesis,
) {
    let kind = hyp.technique;
    let before_findings = state.read().await.findings().len();
    let before_requests = state.read().await.request_count();
    if matches!(
        kind,
        TechniqueKind::Boolean | TechniqueKind::Error | TechniqueKind::Time | TechniqueKind::Union
    ) {
        dispatch_probe_first_half(
            client,
            state,
            cancel,
            config,
            shared,
            raw_request,
            param,
            kind,
        )
        .await;
    } else {
        dispatch_probe_second_half(
            client,
            state,
            cancel,
            config,
            shared,
            raw_request,
            param,
            kind,
        )
        .await;
    }
    let snapshot = state.read().await;
    let new_findings: Vec<Finding> = snapshot
        .findings()
        .iter()
        .skip(before_findings)
        .filter(|f| f.parameter == param.key() && f.technique == kind)
        .cloned()
        .collect();
    let after_requests = snapshot.request_count();
    drop(snapshot);
    // `request_count` is `u64`, costs are `usize`: saturate on 32-bit targets.
    #[allow(clippy::cast_possible_truncation)]
    let cost = after_requests
        .saturating_sub(before_requests)
        .min(usize::MAX as u64) as usize;
    apply_outcome_to_hypothesis(hyp, kind, &new_findings, cost.max(1), &shared.baseline);
    // C6 trace: one summary record per (param, technique) — hashes only, no
    // clear payload/body. `mutation_plan` cites the effective tamper set so
    // `--explain` / replay can attribute cost without storing secrets.
    {
        let plan = mutation_plan_label(&shared.tampers);
        let mut st = state.write().await;
        let seq = st.next_trace_seq();
        let req_hash = crate::reasoning::trace::hash_str_hex(&format!(
            "{}:{}:{}:{}",
            param.key(),
            kind,
            plan,
            config.seed.map_or("none".to_owned(), |s| s.to_string())
        ));
        let resp_hash = crate::reasoning::trace::hash_str_hex(&format!(
            "{}:{}:findings={}",
            param.key(),
            kind,
            new_findings.len()
        ));
        #[allow(clippy::cast_precision_loss)]
        let cost_f = cost.max(1) as f64;
        st.push_trace(crate::reasoning::ProbeRecord::new(
            seq,
            param.key(),
            kind.to_string(),
            plan,
            config.seed,
            req_hash,
            resp_hash,
            hyp.posterior.clamp(0.0, 1.0),
            cost_f,
        ));
    }
}

/// First half of the technique dispatch (boolean/error/time/union).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn dispatch_probe_first_half(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    shared: &DetectionShared,
    raw_request: &Arc<Option<RawRequest>>,
    param: &TargetParameter,
    kind: TechniqueKind,
) {
    let opts = ProbeOpts::new(config.evasion.hpp, config.evasion.chunked);
    let raw = raw_request.as_ref().as_ref();
    // Shared `--max-duration` deadline for the long per-technique loops
    // (boolean payloads, ORDER BY enumeration, union matrix): a single
    // technique must not silently overshoot an explicit user budget.
    // `None` = unlimited, historical behaviour byte-identical.
    let deadline =
        BudgetConfig::detection_deadline(shared.started, config.budget.max_duration_secs);
    match kind {
        TechniqueKind::Boolean => {
            test_boolean_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
                deadline,
                config.generative.mode,
                config.generative.max_generated,
            )
            .await;
        }
        TechniqueKind::Error => {
            let boolean_enabled = is_technique_enabled(&config.techniques, TechniqueKind::Boolean);
            test_error_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                boolean_enabled,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        TechniqueKind::Time => {
            test_time_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        TechniqueKind::Union => {
            test_union_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
                deadline,
            )
            .await;
        }
        _ => {}
    }
}

/// Second half of the technique dispatch (stacked/json/nosql/oob).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn dispatch_probe_second_half(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    shared: &DetectionShared,
    raw_request: &Arc<Option<RawRequest>>,
    param: &TargetParameter,
    kind: TechniqueKind,
) {
    let opts = ProbeOpts::new(config.evasion.hpp, config.evasion.chunked);
    let raw = raw_request.as_ref().as_ref();
    match kind {
        TechniqueKind::Stacked => {
            test_stacked_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        TechniqueKind::Json => {
            test_json_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        TechniqueKind::Nosql => {
            test_nosql_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
            )
            .await;
        }
        TechniqueKind::Oob => {
            test_oob_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.oob.oob_domain.clone(),
                config.oob.oob_poll_url.clone(),
                config.oob.oob_wait_secs,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        _ => {}
    }
}

/// Fold a technique outcome into `hyp`. `Finding`s are untouched; only the
/// belief moves. Unconfirmed error hits stay probe-only (no trial) so they
/// can never reach the `>= 0.85 + trial` confirmed state.
/// A confirmed DBMS label (`fill_missing_dbms` bar: `>= 0.85`) also promotes
/// `hyp.dbms_belief` for the next tour: the following technique on the same
/// parameter selects quote-correct, engine-specific payloads instead of
/// re-spraying generics.
pub(crate) fn apply_outcome_to_hypothesis(
    hyp: &mut Hypothesis,
    kind: TechniqueKind,
    new_findings: &[Finding],
    cost: usize,
    baseline: &baseline::Baseline,
) {
    if baseline.is_waf_blocking() {
        hyp.record_waf_penalty();
    }
    if new_findings.is_empty() {
        hyp.record_probe(false, 0.0, cost);
        return;
    }
    let unconfirmed_only = new_findings
        .iter()
        .all(|f| f.evidence.contains("unconfirmed"));
    let (signal, trials) = infer_signal_and_trials(kind, new_findings, unconfirmed_only);
    hyp.record_probe(true, signal, cost);
    for _ in 0..trials {
        hyp.record_trial(true);
    }
    if !unconfirmed_only {
        for finding in new_findings {
            if let Some(dbms_kind) = parse_finding_dbms(finding.dbms.as_deref()) {
                hyp.dbms_belief.update_with_signal(dbms_kind, 0.9);
                break;
            }
        }
    }
}

/// Default positive signal strength + confirming trials per technique.
/// `confirm_either` 3-trial logic lives inside the detectors and is unchanged;
/// one passed detector confirmation counts as one hypothesis trial here.
///
/// Provisional calibration (v0.5): `boolean`/`error` 0.9, `union` 0.85,
/// `time`/`stacked` 0.8 mirror the historical detector confidences
/// (`diff_against_baseline` 0.75/0.85 branches, 3-trial `confirm_either`).
/// Recalibrate against `bench/reports/history.jsonl` once 5+ runs per
/// scenario exist (`run.py compare --from v0.4`): `high` must hold precision
/// `>= 95%`, `medium >= 80%`, else adjust here and re-run the bench matrix.
pub(crate) fn infer_signal_and_trials(
    kind: TechniqueKind,
    new_findings: &[Finding],
    unconfirmed_only: bool,
) -> (f64, usize) {
    if unconfirmed_only {
        return (0.4, 0);
    }
    match kind {
        TechniqueKind::Boolean | TechniqueKind::Error => (0.9, 1),
        TechniqueKind::Time | TechniqueKind::Stacked => (0.8, 1),
        TechniqueKind::Union => (0.85, 1),
        TechniqueKind::Json | TechniqueKind::Nosql => {
            let boolean_channel = new_findings
                .iter()
                .any(|f| f.evidence.contains("channel=boolean"));
            if boolean_channel { (0.9, 1) } else { (0.75, 1) }
        }
        TechniqueKind::Oob => (1.0, 1),
    }
}
