#![deny(unsafe_code)]

//! C11 Developer Experience: offline execution-plan construction (0 requête).
//!
//! [`build_plan`] builds the ordered probe list a `scan`/`recon` run *would*
//! execute, without sending any network request:
//!
//! * parameters come from lexical URL + `--raw-file`/`--data`/`--headers`/
//!   `--cookies` fusion only ([`TargetUrl::parse`] + `collect_*`, no DNS
//!   resolution, no [`HttpClient`](crate::http::client::HttpClient));
//! * per-parameter [`InjectionContext`] comes from
//!   [`infer_passive_context`](crate::dbms::context::infer_passive_context)
//!   (0 req) plus the `--dbms` hint ([`DbmsBelief::from_hint`], 0 probe);
//! * per-`(param, technique)` priors come from
//!   [`compute_calibrated_prior`](crate::reasoning::hypothesis::compute_calibrated_prior);
//! * ordering comes from [`Scheduler`] (`score = EVI × boost / cost` :
//!   OFF = `1.0` neutre byte-identique, ON = `scheduled_boost_for`
//!   `1+alpha [0.5,1.5]` puis clamp `[0.5,2.0]`, déterministe FIFO tie-break,
//!   no RNG on this path).
//!
//! The CLI `--dry-run` printers and the MCP `plan` tool are thin renderers
//! over this module; the engine itself is untouched.

use crate::{
    dbms::context::{DbmsBelief, InjectionContext, infer_passive_context},
    detection::scanner::scheduler::{
        EarlyStop, RequestBudget, Scheduler, cost_for, evi_for, score_for,
    },
    engine::orchestrator::{EngineConfig, filter_params},
    reasoning::hypothesis::compute_calibrated_prior,
    reasoning::knowledge::{normalize_dbms, scheduled_boost_for},
    session::scrubber::Scrubber,
    target::{
        markers::MarkerSet,
        parameters::{ParameterLocation, TargetParameter, collect_from_raw_request},
        raw_request::RawRequest,
        url::TargetUrl,
    },
};
use serde::{Deserialize, Serialize};

/// One scheduled probe in the offline plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct PlannedProbe {
    pub param: String,
    pub technique: String,
    pub prior: f64,
    pub evi: f64,
    pub cost: f64,
    pub score: f64,
    pub seed: Option<u64>,
}

/// One parameter with its passive context + per-technique probes (score order).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct PlannedParam {
    pub param: String,
    pub location: String,
    pub quote: String,
    pub numeric: bool,
    pub json: bool,
    pub order_by: bool,
    pub context_summary: String,
    pub dbms_top: String,
    pub dbms_prob: f64,
    pub probes: Vec<PlannedProbe>,
}

/// Full offline execution plan for one target (0 requête envoyée).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct ExecutionPlan {
    pub target: String,
    pub seed: Option<u64>,
    pub level: u8,
    pub threads: usize,
    pub techniques: Vec<String>,
    pub dbms_hint: Option<String>,
    /// Requests already spent by passive inference: always 0 by construction.
    pub budget_spent: usize,
    /// Configured global envelope (`None` = unlimited, historical behaviour).
    pub budget_total: Option<usize>,
    /// Always `true`: this plan never sent a request.
    pub dry_run: bool,
    pub total_probes: usize,
    pub params: Vec<PlannedParam>,
    /// Global score order across all params (scheduler `pop` order).
    pub ordered: Vec<PlannedProbe>,
}

impl PlannedProbe {
    #[must_use]
    pub fn scrubbed(&self, scrubber: &Scrubber) -> Self {
        Self {
            param: scrubber.scrub(&self.param),
            technique: self.technique.clone(),
            prior: self.prior,
            evi: self.evi,
            cost: self.cost,
            score: self.score,
            seed: self.seed,
        }
    }
}

impl PlannedParam {
    #[must_use]
    pub fn scrubbed(&self, scrubber: &Scrubber) -> Self {
        Self {
            param: scrubber.scrub(&self.param),
            location: self.location.clone(),
            quote: self.quote.clone(),
            numeric: self.numeric,
            json: self.json,
            order_by: self.order_by,
            context_summary: scrubber.scrub(&self.context_summary),
            dbms_top: self.dbms_top.clone(),
            dbms_prob: self.dbms_prob,
            probes: self.probes.iter().map(|p| p.scrubbed(scrubber)).collect(),
        }
    }
}

impl ExecutionPlan {
    #[must_use]
    pub fn scrubbed(&self, scrubber: &Scrubber) -> Self {
        Self {
            target: scrubber.scrub(&self.target),
            seed: self.seed,
            level: self.level,
            threads: self.threads,
            techniques: self.techniques.clone(),
            dbms_hint: self.dbms_hint.clone(),
            budget_spent: self.budget_spent,
            budget_total: self.budget_total,
            dry_run: self.dry_run,
            total_probes: self.total_probes,
            params: self.params.iter().map(|p| p.scrubbed(scrubber)).collect(),
            ordered: self.ordered.iter().map(|p| p.scrubbed(scrubber)).collect(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }
}

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

/// Human-readable multi-line render (scrubbed when `no_redact == false`).
#[must_use]
pub fn render_human(plan: &ExecutionPlan, resolution: &str, no_redact: bool) -> String {
    use core::fmt::Write as _;
    let scrubber = Scrubber::new(no_redact);
    let mut out = String::new();
    out.push_str("dry-run: execution plan (0 request sent)\n");
    let _ = writeln!(out, "  target: {}", scrubber.scrub(&plan.target));
    out.push_str("  resolution: ");
    out.push_str(resolution);
    out.push('\n');
    let techs = if plan.techniques.is_empty() {
        "all".to_owned()
    } else {
        plan.techniques.join(",")
    };
    let _ = writeln!(
        out,
        "  seed={} level={} threads={} techniques={}",
        plan.seed.map_or("none".to_owned(), |s| s.to_string()),
        plan.level,
        plan.threads,
        techs,
    );
    let _ = writeln!(
        out,
        "  dbms_hint={} budget_spent={} budget_total={} dry_run={}",
        plan.dbms_hint.as_deref().unwrap_or("none"),
        plan.budget_spent,
        plan.budget_total
            .map_or("unlimited".to_owned(), |b| b.to_string()),
        plan.dry_run,
    );
    out.push_str("  params: ");
    out.push_str(&plan.params.len().to_string());
    out.push('\n');
    for p in &plan.params {
        let _ = writeln!(
            out,
            "    - {} [{}] {} dbms={}@{:.2}",
            scrubber.scrub(&p.param),
            p.location,
            scrubber.scrub(&p.context_summary),
            p.dbms_top,
            p.dbms_prob,
        );
    }
    out.push_str("  ordered probes: ");
    out.push_str(&plan.ordered.len().to_string());
    out.push('\n');
    for (idx, probe) in plan.ordered.iter().enumerate() {
        let _ = writeln!(
            out,
            "    {}. {} {} prior={:.2} evi={:.2} cost={:.2} score={:.3} seed={}",
            idx + 1,
            scrubber.scrub(&probe.param),
            probe.technique,
            probe.prior,
            probe.evi,
            probe.cost,
            probe.score,
            probe.seed.map_or("none".to_owned(), |s| s.to_string()),
        );
    }
    out.push_str("  0 requête envoyée (HttpClient.send jamais appelé)\n");
    out
}

/// Offline `--explain` helper: scrubbed evidence → [`crate::reasoning::explain_line`].
#[must_use]
pub fn explain_offline(
    param: &str,
    evidence: &str,
    confidence: f64,
    requests: u64,
    seed: Option<u64>,
    no_redact: bool,
) -> String {
    let scrubber = Scrubber::new(no_redact);
    let clean_evidence = scrubber.scrub(evidence);
    let trace = crate::reasoning::ReasoningTrace::new();
    crate::reasoning::explain_line(
        &clean_evidence,
        confidence.clamp(0.0, 1.0),
        param,
        &trace,
        requests,
        seed,
    )
}

/// Extract `(evidence, confidence, requests, seed)` for `param` from a
/// decrypted snapshot / findings JSON value (offline, mirrors
/// `replay::print_snapshot_explain` matching: case-insensitive exact param).
#[must_use]
pub fn finding_from_export(
    export: &serde_json::Value,
    param: &str,
) -> Option<(String, f64, u64, Option<u64>)> {
    let want = param.trim().to_ascii_lowercase();
    let findings = export.get("findings")?.as_array()?;
    let mut matched: Option<(String, f64)> = None;
    for f in findings {
        let p = f.get("parameter")?.as_str().unwrap_or("");
        if p.to_ascii_lowercase() == want {
            let ev = f
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned();
            let conf = f
                .get("confidence")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0);
            matched = Some((ev, conf));
            break;
        }
    }
    let (evidence, confidence) = matched?;
    let requests = export
        .get("request_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let seed = export.get("seed").and_then(serde_json::Value::as_u64);
    Some((evidence, confidence, requests, seed))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_cfg() -> EngineConfig {
        let mut cfg = EngineConfig::default();
        cfg.net.allow_private = true;
        cfg
    }

    #[test]
    fn empty_techniques_means_all_eight() {
        let kinds = technique_kinds_for_names(&[]);
        assert_eq!(kinds.len(), 8);
        let all = technique_kinds_for_names(&["all".to_owned()]);
        assert_eq!(all.len(), 8);
    }

    #[test]
    fn unknown_techniques_fall_back_to_all() {
        let kinds = technique_kinds_for_names(&["nope".to_owned()]);
        assert_eq!(kinds.len(), 8);
    }

    #[test]
    fn plan_is_offline_and_nonempty() {
        let mut cfg = test_cfg();
        cfg.techniques = vec!["all".to_owned()];
        let plan = build_plan("http://example.com/?id=1", &cfg).expect("plan");
        assert!(plan.dry_run);
        assert_eq!(plan.budget_spent, 0);
        assert!(!plan.is_empty());
        assert_eq!(plan.params.len(), 1);
        assert_eq!(plan.ordered.len(), 8);
        // `boolean` leads on a bare numeric param (entropie binaire Phase 0 :
        // EVI `4·p·(1-p)·base` → boolean prior 0.26 ⇒ 0.77 vs `error` prior
        // 0.15 ⇒ 0.46 ; l'ancien `(1-p)·base` donnait `error` 0.765 vs
        // `boolean` 0.74 — bugfix documenté, ordre L1 changé voulu), and
        // scores never rise.
        assert_eq!(plan.ordered[0].technique, "boolean");
        let mut prev = f64::INFINITY;
        for probe in &plan.ordered {
            assert!(
                probe.score <= prev + 1e-12,
                "scores not ordered: {} > {prev}",
                probe.score
            );
            prev = probe.score;
        }
    }

    #[test]
    fn exotic_headers_gated_by_level() {
        // L1 : byte-identique historique (query seule, 0 synthétique).
        let (_, l1) =
            params_for_target_offline("http://example.com/?id=1", true, &[], None, None, 1)
                .expect("plan l1");
        assert_eq!(l1.len(), 1);
        assert_eq!(l1[0].key(), "id@query");
        // L2+ : UA/Referer/XFF/X-Real-IP ajoutés (second-order via header).
        let (_, l2) =
            params_for_target_offline("http://example.com/?id=1", true, &[], None, None, 2)
                .expect("plan l2");
        assert_eq!(l2.len(), 5);
        for name in ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"] {
            assert!(
                l2.iter()
                    .any(|p| p.key() == format!("{name}@header:{name}")),
                "missing {name}: {:?}",
                l2.iter().map(TargetParameter::key).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn plan_is_deterministic_for_same_seed() {
        let mut a = test_cfg();
        a.seed = Some(42);
        let mut b = test_cfg();
        b.seed = Some(42);
        let pa = build_plan("http://example.com/?id=1", &a).expect("pa");
        let pb = build_plan("http://example.com/?id=1", &b).expect("pb");
        assert_eq!(pa.ordered, pb.ordered);
    }

    #[test]
    fn plan_never_carries_secret_values() {
        let mut cfg = test_cfg();
        cfg.raw_request = Some(RawRequest {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            headers: [("cookie".to_owned(), "sess=supersecret123".to_owned())]
                .into_iter()
                .collect(),
            body: None,
            http_version: "HTTP/1.1".to_owned(),
        });
        let plan = build_plan("http://example.com/?id=1", &cfg).expect("plan");
        let json = serde_json::to_string(&plan.scrubbed(&Scrubber::new(false))).expect("json");
        assert!(!json.contains("supersecret123"), "{json}");
    }

    #[test]
    fn explain_offline_matches_roadmap_shape() {
        let line = explain_offline(
            "id@query",
            "boolean true_sim=0.91 false_sim=0.22 trials=3/3",
            0.95,
            14,
            Some(42),
            false,
        );
        assert_eq!(
            line,
            "TRUE≈baseline 0.91, FALSE≠baseline 0.22, 3/3, waf=none, 14 req, seed 42"
        );
    }
}
