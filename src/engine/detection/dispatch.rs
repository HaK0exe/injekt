use std::sync::Arc;

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use super::{outcome::apply_outcome_to_hypothesis, shared::DetectionShared};
use crate::{
    engine::{
        config::{BudgetConfig, EngineConfig},
        schedule::{is_technique_enabled, mutation_plan_label},
    },
    http::client::HttpClient,
    reasoning::Hypothesis,
    session::state::{Finding, SessionState, TechniqueKind},
    target::{injection::ProbeOpts, parameters::TargetParameter, raw_request::RawRequest},
    techniques::technique::{TechniqueCtx, technique_for},
};

/// Build the shared [`TechniqueCtx`] for one (param, technique) dispatch.
fn build_technique_ctx<'a>(
    client: &'a HttpClient,
    state: &'a Arc<RwLock<SessionState>>,
    cancel: &'a CancellationToken,
    config: &'a EngineConfig,
    shared: &'a DetectionShared,
    raw_request: &'a Arc<Option<RawRequest>>,
    param: &'a TargetParameter,
) -> TechniqueCtx<'a> {
    TechniqueCtx {
        client,
        state,
        cancel,
        target: &shared.target,
        target_str: &shared.target_str,
        param,
        baseline: &shared.baseline,
        marker_set: &shared.marker_set,
        raw: raw_request.as_ref().as_ref(),
        tampers: &shared.tampers,
        opts: ProbeOpts::new(config.evasion.hpp, config.evasion.chunked),
        popts: &config.evasion.payload_opts,
        matcher: &config.matcher,
        level: config.budget.level,
        ignore_codes: &config.net.ignore_codes,
        seed: config.seed,
        context: &shared.context,
        dbms_belief: &shared.dbms_belief,
        deadline: BudgetConfig::detection_deadline(shared.started, config.budget.max_duration_secs),
        boolean_enabled: is_technique_enabled(&config.techniques, TechniqueKind::Boolean),
        generative_mode: config.generative.mode,
        max_generated: config.generative.max_generated,
        oob_domain: config.oob.oob_domain.as_ref(),
        oob_poll_url: config.oob.oob_poll_url.as_ref(),
        oob_wait_secs: config.oob.oob_wait_secs,
    }
}

/// Dispatch one technique, snapshot findings/requests, fold the outcome into
/// `hyp` via `record_probe/record_trial/record_waf_penalty`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_one_technique(
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
    let Some(technique) = technique_for(kind) else {
        return;
    };
    let ctx = build_technique_ctx(client, state, cancel, config, shared, raw_request, param);
    technique.probe(&ctx).await;
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
