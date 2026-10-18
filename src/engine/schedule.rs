#![deny(unsafe_code)]

//! Detection scheduling helpers (P1): technique ordering, payload ordering,
//! scheduler construction. Extracted verbatim from `orchestrator.rs`.

use super::config::EngineConfig;
use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    detection::scanner::scheduler::{
        EarlyStop, RequestBudget, Scheduler, cost_for, cost_for_with_ttfb, evi_for,
    },
    reasoning::{
        Hypothesis,
        knowledge::{normalize_dbms, scheduled_boost_for},
    },
    session::state::TechniqueKind,
    techniques::{
        json::payloads::{JsonPayload, graphql_probes_for, json_payloads_for},
        tamper::Tamper,
    },
};
use tracing::debug;

/// CLI technique name for a [`TechniqueKind`].
pub(crate) const fn technique_config_name(kind: TechniqueKind) -> &'static str {
    match kind {
        TechniqueKind::Boolean => "boolean",
        TechniqueKind::Error => "error",
        TechniqueKind::Time => "time",
        TechniqueKind::Union => "union",
        TechniqueKind::Stacked => "stacked",
        TechniqueKind::Json => "json",
        TechniqueKind::Nosql => "nosql",
        TechniqueKind::Transit => "transit",
        TechniqueKind::Orm => "orm",
        TechniqueKind::Graphql => "graphql",
        TechniqueKind::Oob => "oob",
    }
}

/// `true` when `--techniques` enables `kind` (or `"all"`).
pub(crate) fn is_technique_enabled(configured: &[String], kind: TechniqueKind) -> bool {
    let name = technique_config_name(kind);
    configured.iter().any(|t| t == name || t == "all")
}

/// Tamper-set label for trace `mutation_plan` (names only, never payloads).
/// `[]` → `"none"`, else comma-joined (`space2comment,randomcase`).
pub(crate) fn mutation_plan_label(tampers: &[Tamper]) -> String {
    if tampers.is_empty() {
        return "none".to_owned();
    }
    tampers
        .iter()
        .map(super::super::techniques::tamper::Tamper::name)
        .collect::<Vec<_>>()
        .join(",")
}

/// Context-aware creation order (simple `if`s): JSON context seeds `json`
/// then `nosql` first, ORDER BY context seeds `union` early. This only shapes
/// priors via `compute_calibrated_prior` (EVI input); execution order is
/// decided by the scheduler score afterwards, never by this fixed order.
pub(crate) fn detection_order(context: &InjectionContext) -> [TechniqueKind; 11] {
    use TechniqueKind as K;
    if context.json {
        [
            K::Json,
            K::Nosql,
            K::Boolean,
            K::Error,
            K::Time,
            K::Union,
            K::Stacked,
            K::Transit,
            K::Orm,
            K::Graphql,
            K::Oob,
        ]
    } else if context.order_by {
        [
            K::Boolean,
            K::Union,
            K::Error,
            K::Time,
            K::Stacked,
            K::Json,
            K::Nosql,
            K::Transit,
            K::Orm,
            K::Graphql,
            K::Oob,
        ]
    } else {
        [
            K::Boolean,
            K::Error,
            K::Time,
            K::Union,
            K::Stacked,
            K::Json,
            K::Nosql,
            K::Transit,
            K::Orm,
            K::Graphql,
            K::Oob,
        ]
    }
}

/// JSON scan payloads: direct `json_payloads_for` first, then the GraphQL
/// `variables`-envelope probes (P0-2).
///
/// The envelope probes reuse the same TRUE/FALSE/error shape with the SQL
/// breakout riding inside `"variables"` instead of the query text, so WAFs
/// keyed on `query:` miss them while vulnerable resolvers still interpolate
/// them. Appended last (never first) so L1 (`take(2)`) stays byte-identical
/// to the historical direct sweep and `mutation_base_payload` (`.first()`)
/// keeps pointing at a direct probe.
pub(crate) fn json_scan_payloads(label: Option<&str>) -> Vec<JsonPayload> {
    let mut out = json_payloads_for(label);
    out.extend(graphql_probes_for(label));
    out
}

/// DBMS label for `*_payloads_for(Some(..))` once the belief is actionable.
///
/// Returns `Some("mysql" | "postgres" | "mssql" | "oracle" | "sqlite")` when the top
/// candidate reaches the `0.85` fill threshold (same bar as the early
/// `fill_missing_dbms` in `run_internal`), else `None` (generic polyglots).
/// Threaded into every `test_*_bounded` so quote/comment styles stay
/// quote-correct for the suspected engine instead of spraying generics.
pub(crate) fn dbms_payload_label(belief: &DbmsBelief) -> Option<&'static str> {
    let (kind, prob) = belief.top_candidate();
    if prob < 0.85 {
        return None;
    }
    match kind {
        crate::dbms::common::DbmsKind::MySql => Some("mysql"),
        crate::dbms::common::DbmsKind::Postgres => Some("postgres"),
        crate::dbms::common::DbmsKind::MsSql => Some("mssql"),
        crate::dbms::common::DbmsKind::Oracle => Some("oracle"),
        crate::dbms::common::DbmsKind::Sqlite => Some("sqlite"),
        crate::dbms::common::DbmsKind::Unknown => None,
    }
}

/// Parse a `Finding.dbms` string back to [`crate::dbms::common::DbmsKind`]
/// so a confirmed technique can promote the hypothesis belief for the next
/// tour (see `apply_outcome_to_hypothesis`). Returns `None` for missing or
/// unrecognized labels (never panics on operator-controlled evidence).
pub(crate) fn parse_finding_dbms(label: Option<&str>) -> Option<crate::dbms::common::DbmsKind> {
    let v = label?.trim().to_ascii_lowercase();
    match v.as_str() {
        "mysql" | "mariadb" => Some(crate::dbms::common::DbmsKind::MySql),
        "postgres" | "postgresql" | "pgsql" => Some(crate::dbms::common::DbmsKind::Postgres),
        "mssql" | "sqlserver" | "sql-server" | "tsql" => Some(crate::dbms::common::DbmsKind::MsSql),
        "oracle" | "ora" => Some(crate::dbms::common::DbmsKind::Oracle),
        "sqlite" => Some(crate::dbms::common::DbmsKind::Sqlite),
        _ => None,
    }
}

/// Quote-aware boolean payload order: L1 only tries the first 2 entries, so
/// the inferred [`QuoteContext`] must lead. Numeric bare contexts
/// (`quote=None + numeric`) move the `1 AND/OR …` pair first, double-quote
/// contexts move the `"` pair first, paren contexts move the `)` family
/// first; single-quote (the default head polyglot) keeps historical order.
/// Deterministic, no RNG on this path.
pub(crate) fn order_boolean_by_context(
    payloads: &mut [crate::techniques::boolean::payloads::BooleanPayload],
    context: &InjectionContext,
) {
    use crate::dbms::context::QuoteContext as Q;
    let leading: fn(&str) -> bool = match context.quote {
        Q::DoubleQuote => |s: &str| s.starts_with('"'),
        Q::Parenthesis => |s: &str| s.starts_with(')'),
        Q::None if context.numeric => |s: &str| s.starts_with('1'),
        _ => return,
    };
    let mut front = 0usize;
    let mut i = 0usize;
    while i < payloads.len() {
        if leading(payloads[i].true_payload.as_str()) {
            payloads.swap(front, i);
            front += 1;
        }
        i += 1;
    }
}

/// Quote-aware ORDER BY prefix for union enumeration: the inferred quote
/// context leads so `order_by` sinks confirm with the historical 10-probe
/// budget instead of burning a full prefix cycle. Unknown contexts keep the
/// historical single-quote prefix (byte-identical default); the UNION
/// payloads themselves stay polyglot (`'\"())) …`) so column-count inference
/// never loses coverage, only the enumeration prefix is quote-correct.
pub(crate) fn order_by_prefix_for_context(context: &InjectionContext) -> &'static str {
    use crate::dbms::context::QuoteContext as Q;
    match context.quote {
        Q::DoubleQuote => "\"",
        Q::Parenthesis => ")",
        Q::None if context.numeric => "",
        _ => "'",
    }
}

/// Build the per-parameter [`Scheduler`] ordered by EVI/cost (knowledge-neutral
/// when `config.knowledge` is `None`).
///
/// Insertion order follows `hyps` (itself seeded by [`detection_order`], so
/// `json`-first / `order_by` only shape priors via `compute_calibrated_prior`,
/// never the execution order afterwards). Heap tie-break by insertion id keeps
/// the order deterministic per `--seed` (no RNG on this path).
/// `context_probes` (the `<=8` adaptive probes) is seeded into the budget so
/// `budget_spent`/`budget_total`/`next_best_probe` account the global cost,
/// and the [`EarlyStop`] is explicitly reset for the new parameter
/// (inter-param isolation for the N1/N2 `<=25 req` veto).
///
/// C13 : avec `config.knowledge = Some(store)`, chaque hypothèse reçoit
/// `boost = store.boost_for_context(technique, dbms, context)` (`1.0` neutre
/// sous `MIN_SAMPLES`, `[0.5,1.5]` sinon, clamp scheduler `[0.5,2.0]`
/// conservé). Avec `None` (défaut OFF), `boost = None` → `1.0` neutre,
/// **byte-identique** au comportement historique (`score == evi / cost`,
/// aucune lecture/écriture disque).
///
/// Phase 3 : `mean_ms` (baseline TTFB) module le coût `time` via
/// [`cost_for_with_ttfb`] (`mean <= 2000` ou `0` = coût statique inchangé,
/// byte-identique). Seul le canal lent `time` est gonflé sur cible lente
/// (les différentiels rapides gardent leur priorité).
///
/// PR20 — pourquoi `oob`/`stacked` restent statiques (choix volontaire,
/// pas d'extension) : seul `time` parque un permit du pool isolé
/// `TIME_POOL_SLOTS` pendant toute la sonde (jitter + retries inclus) avec
/// un timeout de classe 15s — sur cible lente (mean 5s) une sonde `sleep 5s`
/// bloque ~10s + risque timeout, son score EVI/coût doit chuter face aux
/// différentiels bon marché. `oob` attend le collaborateur en async
/// (`oob_wait_secs`, défaut 5s, classe `oob` sans permit `time`) : sa latence
/// est bornée par le poll, pas par le TTFB cible. `stacked` tourne en classe
/// `Default` (latence statique 0.5s, coût = risque retry, pas blocage TTFB).
/// Gonfler aussi `oob` (EVI 0.4) / `stacked` (EVI 0.5) les affamerait sur
/// cibles lentes (jamais schedulés) sans bénéfice mesuré — le
/// `scheduler_ttfb_static_by_default_and_dynamic_when_slow` couvre le
/// comportement `time`-only.
pub(crate) fn build_scheduler_for_param(
    config: &EngineConfig,
    param_key: &str,
    hyps: &[Hypothesis],
    context_probes: usize,
    mean_ms: f64,
) -> Scheduler {
    let mut scheduler = Scheduler::new(
        RequestBudget::new(config.budget.request_budget, None),
        EarlyStop::default(),
    );
    scheduler.early_stop_mut().reset_for_new_param();
    if context_probes > 0 {
        scheduler
            .budget_mut()
            .record_request(param_key, context_probes);
    }
    for hyp in hyps {
        if !is_technique_enabled(&config.techniques, hyp.technique) {
            continue;
        }
        let evi = evi_for(hyp.technique, hyp.posterior);
        let base = cost_for(hyp.technique);
        let cost = if hyp.technique == TechniqueKind::Time {
            cost_for_with_ttfb(base, mean_ms)
        } else {
            base
        };
        // C13 : OFF (`None`) = `None` → boost neutre 1.0, byte-identique.
        // ON = boost `1+alpha` (`alpha<=0.5`, `[0.5,1.5]`) puis clamp final
        // `[0.5,2.0]` via `scheduled_boost_for` (jamais de veto).
        let knowledge_boost: Option<f64> = config.knowledge.as_ref().map(|ks| {
            let dbms_label = if let Some(hint) = config.dbms_hint.as_deref() {
                normalize_dbms(hint).to_owned()
            } else {
                let (kind, _) = hyp.dbms_belief.top_candidate();
                normalize_dbms(&kind.to_string()).to_owned()
            };
            scheduled_boost_for(Some(ks), hyp.technique, &dbms_label, &hyp.context).unwrap_or(1.0)
        });
        debug!(
            param = param_key,
            technique = %hyp.technique,
            posterior = hyp.posterior,
            evi,
            cost,
            knowledge_boost = ?knowledge_boost,
            "scheduler scored technique"
        );
        scheduler.push(
            param_key,
            hyp.technique,
            technique_config_name(hyp.technique),
            evi,
            cost,
            knowledge_boost,
        );
    }
    scheduler
}

/// One-line scheduler visibility: `budget_spent` / `budget_total` /
/// `next_best_probe` for stealth budgets (C4).
pub(crate) fn log_scheduler_state(scheduler: &Scheduler, param_key: &str, stage: &str) {
    if let Some(probe) = scheduler.next_best_probe() {
        debug!(
            param = param_key,
            stage,
            budget_spent = scheduler.budget_spent(),
            budget_total = ?scheduler.budget_total(),
            next_technique = %probe.technique,
            next_score = probe.score,
            queued = scheduler.len(),
            "scheduler state"
        );
    } else {
        debug!(
            param = param_key,
            stage,
            budget_spent = scheduler.budget_spent(),
            budget_total = ?scheduler.budget_total(),
            queued = scheduler.len(),
            "scheduler state (empty)"
        );
    }
}

/// Mid-technique `--max-duration` check for the long per-technique loops.
/// Moved verbatim from `orchestrator.rs` (P1); no behaviour change.
pub(crate) fn check_deadline(
    deadline: Option<std::time::Instant>,
    param: &str,
    technique: &str,
) -> bool {
    if super::config::BudgetConfig::is_past_deadline(deadline) {
        tracing::warn!(
            param,
            technique,
            "max-duration exceeded inside probes, stopping technique early"
        );
        return true;
    }
    false
}
