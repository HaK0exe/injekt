//! Offline probe-order planner (0 requête): lexical URL/raw-request parse,
//! passive context, calibrated priors, then scheduler score order
//! (`score = EVI × boost / cost` : OFF = `1.0` neutre byte-identique, ON =
//! `scheduled_boost_for` `1+alpha [0.5,1.5]` puis clamp `[0.5,2.0]`,
//! déterministe FIFO tie-break, no RNG on this path).

use crate::{
    dbms::context::{DbmsBelief, InjectionContext, infer_passive_context},
    detection::scanner::scheduler::{
        EarlyStop, RequestBudget, Scheduler, cost_for, evi_for, score_for,
    },
    engine::orchestrator::{EngineConfig, filter_params},
    reasoning::hypothesis::compute_calibrated_prior,
    reasoning::knowledge::{normalize_dbms, scheduled_boost_for},
    target::{
        markers::MarkerSet,
        parameters::{ParameterLocation, TargetParameter, collect_from_raw_request},
        raw_request::RawRequest,
        url::TargetUrl,
    },
};

use super::model::{ExecutionPlan, PlannedParam, PlannedProbe};

/// Canonical technique creation order (matches the orchestrator default
/// `detection_order` else-branch): priors carry the JSON/`ORDER BY` context,
/// the scheduler score decides execution afterwards.
const fn canonical_order() -> [crate::session::state::TechniqueKind; 8] {
    use crate::session::state::TechniqueKind as K;
    [
        K::Boolean,
        K::Error,
        K::Time,
        K::Union,
        K::Stacked,
        K::Json,
        K::Nosql,
        K::Oob,
    ]
}

/// Expand CLI technique names to kinds (`all` = 8 kinds, case-insensitive).
/// Unknown names are ignored (the engine warns at runtime; the plan stays
/// offline and total).
#[must_use]
pub fn technique_kinds_for_names(names: &[String]) -> Vec<crate::session::state::TechniqueKind> {
    use crate::session::state::TechniqueKind as K;
    let wants_all = names.iter().any(|n| n.trim().eq_ignore_ascii_case("all"));
    if wants_all || names.is_empty() {
        return canonical_order().to_vec();
    }
    let mut out = Vec::new();
    for name in names {
        let kind = match name.trim().to_ascii_lowercase().as_str() {
            "boolean" => Some(K::Boolean),
            "error" => Some(K::Error),
            "time" => Some(K::Time),
            "union" => Some(K::Union),
            "stacked" => Some(K::Stacked),
            "json" => Some(K::Json),
            "nosql" => Some(K::Nosql),
            "oob" => Some(K::Oob),
            _ => None,
        };
        if let Some(k) = kind
            && !out.contains(&k)
        {
            out.push(k);
        }
    }
    if out.is_empty() {
        canonical_order().to_vec()
    } else {
        // Keep canonical creation order for deterministic FIFO tie-breaks.
        let order = canonical_order();
        out.sort_by_key(|k| order.iter().position(|o| o == k).unwrap_or(usize::MAX));
        out
    }
}

/// Offline marker set: `MarkerSet::detect(target)` OR-ed with `--marker`.
/// Mirrors `Engine::effective_marker_set` without touching the engine.
#[must_use]
pub fn effective_marker_set(target_str: &str, marker_flag: Option<&str>) -> MarkerSet {
    let mut set = MarkerSet::detect(target_str);
    if let Some(m) = marker_flag {
        let lower = m.to_ascii_lowercase();
        if m.contains('*') || lower.contains("%2a") {
            set.asterisk = true;
        }
        if m.contains('§') || lower.contains("%c2%a7") {
            set.section = true;
        }
        if m.contains("{{") && m.contains("}}") {
            set.double_brace = true;
        }
    }
    set
}

/// Offline parameter list for `target_str` (lexical parse only, no DNS, no
/// HTTP): marker synthetics + URL query + raw-request body/cookie/headers,
/// exotic headers (L2+ : UA/Referer/XFF), synthetic `id` fallback, then `-p`
/// filtering via [`filter_params`].
///
/// `level` mirrors the orchestrator gate : `< 2` = historique byte-identique
/// (aucun synthétique), `>= 2` = exotiques ajoutés quand absents.
///
/// # Errors
/// Returns a message when the target URL fails lexical parsing.
pub fn params_for_target_offline(
    target_str: &str,
    allow_private: bool,
    test_params: &[String],
    raw: Option<&RawRequest>,
    marker_flag: Option<&str>,
    level: u8,
) -> Result<(MarkerSet, Vec<TargetParameter>), String> {
    let target =
        TargetUrl::parse(target_str, allow_private).map_err(|e| format!("invalid target: {e}"))?;
    let marker_set = effective_marker_set(target_str, marker_flag);
    let mut params = Vec::new();
    if marker_set.asterisk {
        params.push(TargetParameter::new(
            "marker_asterisk",
            ParameterLocation::Query,
            "*",
        ));
    }
    if marker_set.section {
        params.push(TargetParameter::new(
            "marker_section",
            ParameterLocation::Query,
            "§",
        ));
    }
    if marker_set.double_brace {
        params.push(TargetParameter::new(
            "marker_brace",
            ParameterLocation::Query,
            "{{}}",
        ));
    }
    params.extend(crate::target::parameters::collect_from_url_query(&target));
    if let Some(r) = raw {
        params.extend(collect_from_raw_request(r));
    }
    if level >= 2 {
        params.extend(crate::target::parameters::synthetic_exotic_headers(&params));
    }
    let mut to_test = if params.is_empty() {
        vec![TargetParameter::new("id", ParameterLocation::Query, "1")]
    } else {
        params
    };
    if !test_params.is_empty() {
        to_test = filter_params(to_test, test_params);
    }
    Ok((marker_set, to_test))
}

/// Passive DBMS belief: `--dbms` hint pinned (0 probe), else uniform.
#[must_use]
pub fn dbms_belief_for_hint(hint: Option<&str>) -> DbmsBelief {
    hint.map_or_else(DbmsBelief::uniform, DbmsBelief::from_hint)
}

/// C13 knowledge boost pour le plan offline : `None` quand OFF (neutre,
/// byte-identique), `Some(clampé [0.5,2.0])` quand ON. Même résolution DBMS
/// que l'orchestrateur (hint > belief top), jamais de veto.
#[must_use]
pub fn plan_knowledge_boost(
    cfg: &EngineConfig,
    kind: crate::session::state::TechniqueKind,
    ctx: &InjectionContext,
    top_kind: &crate::dbms::DbmsKind,
) -> Option<f64> {
    let store = cfg.knowledge.as_ref()?;
    let dbms_label = if let Some(hint) = cfg.dbms_hint.as_deref() {
        normalize_dbms(hint).to_owned()
    } else {
        normalize_dbms(&top_kind.to_string()).to_owned()
    };
    scheduled_boost_for(Some(store), kind, &dbms_label, ctx)
}

/// Build the offline execution plan for one target (0 requête).
///
/// Pure over `target_str` + `EngineConfig`: lexical URL parse, passive
/// context, calibrated priors, scheduler score order. Never touches
/// [`HttpClient`](crate::http::client::HttpClient), never resolves DNS.
///
/// # Errors
/// Returns a message when the target URL fails lexical parsing.
pub fn build_plan(target_str: &str, cfg: &EngineConfig) -> Result<ExecutionPlan, String> {
    let raw = cfg.raw_request.clone();
    let allow_private = cfg.net.allow_private;
    let (_markers, to_test) = params_for_target_offline(
        target_str,
        allow_private,
        &cfg.test_params,
        raw.as_ref(),
        cfg.marker.as_deref(),
        cfg.budget.level,
    )?;
    let kinds = technique_kinds_for_names(&cfg.techniques);
    let seed = cfg.seed;
    let budget_total = cfg.budget.request_budget;

    // Scheduler global : OFF (`None`) = boost 1.0 neutre, byte-identique au
    // sans-knowledge. ON = `scheduled_boost_for` (`1+alpha [0.5,1.5]` puis
    // clamp `[0.5,2.0]`, jamais de veto), même porte que l'orchestrateur.
    let mut scheduler =
        Scheduler::new(RequestBudget::new(budget_total, None), EarlyStop::default());
    // (param, technique) -> (prior, evi, cost, score) for pop-order rebuild.
    let mut meta: std::collections::HashMap<(String, String), (f64, f64, f64, f64)> =
        std::collections::HashMap::new();
    let mut per_param: Vec<PlannedParam> = Vec::new();

    for param in &to_test {
        let key = param.key();
        let ctx: InjectionContext = infer_passive_context(param, raw.as_ref());
        let belief: DbmsBelief = dbms_belief_for_hint(cfg.dbms_hint.as_deref());
        let (top_kind, top_prob) = belief.top_candidate();
        let dbms_top = if belief == DbmsBelief::uniform() {
            "uniform".to_owned()
        } else {
            top_kind.to_string()
        };
        let mut probes = Vec::new();
        for kind in &kinds {
            let prior = compute_calibrated_prior(*kind, &ctx, &belief);
            let evi = evi_for(*kind, prior);
            let cost = cost_for(*kind);
            let boost = plan_knowledge_boost(cfg, *kind, &ctx, &top_kind);
            let score = score_for(*kind, prior, boost);
            let tech_name = kind.to_string();
            meta.insert((key.clone(), tech_name.clone()), (prior, evi, cost, score));
            scheduler.push(key.clone(), *kind, tech_name.clone(), evi, cost, boost);
            probes.push(PlannedProbe {
                param: key.clone(),
                technique: tech_name,
                prior,
                evi,
                cost,
                score,
                seed,
            });
        }
        // Per-param score order (deterministic, no RNG).
        probes.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        per_param.push(PlannedParam {
            param: key.clone(),
            location: param.location.to_string(),
            quote: ctx.quote.to_string(),
            numeric: ctx.numeric,
            json: ctx.json,
            order_by: ctx.order_by,
            context_summary: ctx.summary(),
            dbms_top,
            dbms_prob: top_prob,
            probes,
        });
    }

    // Global score order = scheduler pop order (budget-gated).
    let mut ordered = Vec::new();
    while let Some(popped) = scheduler.pop() {
        let tech_name = popped.technique.to_string();
        if let Some((prior, evi, cost, score)) =
            meta.get(&(popped.param.clone(), tech_name.clone()))
        {
            ordered.push(PlannedProbe {
                param: popped.param.clone(),
                technique: tech_name,
                prior: *prior,
                evi: *evi,
                cost: *cost,
                score: *score,
                seed,
            });
        }
    }
    let total_probes = ordered.len();

    Ok(ExecutionPlan {
        target: target_str.to_owned(),
        seed,
        level: cfg.budget.level,
        threads: cfg.budget.threads,
        techniques: cfg.techniques.clone(),
        dbms_hint: cfg.dbms_hint.clone(),
        budget_spent: 0,
        budget_total,
        dry_run: true,
        total_probes,
        params: per_param,
        ordered,
    })
}
