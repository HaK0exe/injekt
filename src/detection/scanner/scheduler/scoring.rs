use crate::session::state::TechniqueKind;
use std::cmp::Ordering;

/// Neutral knowledge multiplier: cold-start (empty knowledge) leaves the
/// score as `evi / cost`, bit-identical to a knowledge-free run (C13).
pub const KNOWLEDGE_NEUTRAL_BOOST: f64 = 1.0;
/// Lower bound of the knowledge multiplier (stats advise, evidence decides).
pub const MIN_KNOWLEDGE_BOOST: f64 = 0.5;
/// Upper bound of the knowledge multiplier (never a veto).
pub const MAX_KNOWLEDGE_BOOST: f64 = 2.0;
/// Starvation guard: `union` always gets at least this many probes when enabled.
pub const UNION_GUARANTEED_PROBES: usize = 1;

/// Base Expected Value of Information per technique (uncertainty reduction
/// weight before posterior scaling). Ordered by historical yield:
/// cheap differentials first, slow/noisy channels last.
#[must_use]
pub const fn base_evi_for(kind: TechniqueKind) -> f64 {
    match kind {
        TechniqueKind::Boolean => 1.0,
        TechniqueKind::Error => 0.9,
        TechniqueKind::Union
        | TechniqueKind::Json
        | TechniqueKind::Nosql
        | TechniqueKind::Transit
        | TechniqueKind::Orm
        | TechniqueKind::Graphql
        | TechniqueKind::Elasticsearch => 0.8,
        TechniqueKind::Time => 0.7,
        TechniqueKind::Stacked => 0.5,
        TechniqueKind::Oob => 0.4,
    }
}

/// Expected latency class in seconds per technique (slow channels cost more:
/// `time` sleeps, `oob` waits on the collaborator, `stacked` risks retries).
#[must_use]
pub const fn latency_secs_for(kind: TechniqueKind) -> f64 {
    match kind {
        TechniqueKind::Boolean | TechniqueKind::Error => 0.0,
        TechniqueKind::Union
        | TechniqueKind::Json
        | TechniqueKind::Nosql
        | TechniqueKind::Transit
        | TechniqueKind::Orm
        | TechniqueKind::Graphql
        | TechniqueKind::Elasticsearch => 0.3,
        TechniqueKind::Stacked | TechniqueKind::Oob => 0.5,
        TechniqueKind::Time => 1.5,
    }
}

/// WAF exposure risk per technique (noisy payload families cost more).
#[must_use]
pub const fn waf_risk_for(kind: TechniqueKind) -> f64 {
    match kind {
        TechniqueKind::Boolean | TechniqueKind::Error => 0.0,
        TechniqueKind::Union
        | TechniqueKind::Json
        | TechniqueKind::Nosql
        | TechniqueKind::Transit
        | TechniqueKind::Orm
        | TechniqueKind::Graphql
        | TechniqueKind::Elasticsearch => 0.2,
        TechniqueKind::Stacked | TechniqueKind::Time | TechniqueKind::Oob => 0.5,
    }
}

/// Estimated cost in requests, latency weight, and WAF exposure risk:
/// `1 + latency_secs + waf_risk`.
///
/// Totals: `boolean` 1.0, `error` 1.0, `union` 1.5, `json` 1.5, `nosql` 1.5,
/// `stacked` 2.0, `oob` 2.0, `time` 3.0.
#[must_use]
pub const fn cost_for(kind: TechniqueKind) -> f64 {
    1.0 + latency_secs_for(kind) + waf_risk_for(kind)
}

/// TTFB-aware dynamic cost (Phase 3 perf baseline/contexte/time).
///
/// Scales a static `base_cost` (typically [`cost_for`]) when the baseline
/// mean exceeds 2000ms: `base * (1 + mean_ms / 5000)`. Below/at 2000ms (or on
/// non-finite input) the cost is returned unchanged, so `mean_ms = 0`
/// (unknown baseline) keeps the historical static schedule byte-identical.
///
/// Rationale: on a slow target (mean 5s) a `time` sleep probe parks a slot
/// for ~10s + class timeout risk, so its EVI/cost score must drop relative
/// to cheap differentials. The caller applies this selectively to slow
/// channels (`time`); fast techniques keep the static cost. `oob`/`stacked`
/// deliberately stay static too (see `build_scheduler_for_param`: async
/// collaborator wait / `Default`-class latency, not `TIME_POOL_SLOTS`
/// blocking — scaling them would starve already-low-EVI slow channels).
#[must_use]
pub fn cost_for_with_ttfb(base_cost: f64, mean_ms: f64) -> f64 {
    if !base_cost.is_finite() || !mean_ms.is_finite() || mean_ms <= 2000.0 {
        return base_cost;
    }
    base_cost * (1.0 + mean_ms / 5000.0)
}

/// Expected Value of Information for a technique at `posterior`:
/// binary variance `4·p·(1-p)·base_evi`, peak `base_evi` at `p = 0.5`
/// (max uncertainty), zero at convergence (0 or 1).
///
/// Phase 0 bugfix (documenté) : l'ancien `(1-posterior)·base` décroissait
/// monotonement et favorisait toujours le prior le plus faible (ex. `oob`
/// 0.02 → EVI ~0.98·base) au lieu de la réduction d'incertitude maximale.
/// La variance binaire normalisée (`4·p·(1-p)`, max 1.0 à 0.5) restaure le
/// pic à 0.5 ; `score = evi / cost` inchangé. L'ordre L1 change sur priors
/// calibrés (voulu : prioriser l'incertitude, pas le plus petit prior).
#[must_use]
pub fn evi_for(kind: TechniqueKind, posterior: f64) -> f64 {
    let p = posterior.clamp(0.0, 1.0);
    4.0 * p * (1.0 - p) * base_evi_for(kind)
}

/// Clamp a knowledge multiplier to `[0.5, 2.0]`; non-finite input is neutral.
#[must_use]
pub fn clamp_knowledge_boost(boost: f64) -> f64 {
    if boost.is_finite() {
        boost.clamp(MIN_KNOWLEDGE_BOOST, MAX_KNOWLEDGE_BOOST)
    } else {
        KNOWLEDGE_NEUTRAL_BOOST
    }
}

/// Final priority score: `(evi * clamped_boost) / cost`.
/// With neutral knowledge (`None` / `1.0`), `score == evi / cost`.
#[must_use]
pub fn score_for(kind: TechniqueKind, posterior: f64, knowledge_boost: Option<f64>) -> f64 {
    let evi = evi_for(kind, posterior);
    let cost = cost_for(kind).max(0.01);
    (evi * clamp_knowledge_boost(knowledge_boost.unwrap_or(KNOWLEDGE_NEUTRAL_BOOST))) / cost
}

/// Order `(technique, posterior)` candidates by descending `score`.
///
/// Deterministic: no RNG on this path, so the same seed yields the same
/// order. Ties (within `1e-12`) break by insertion id (FIFO), matching the
/// [`crate::detection::scanner::scheduler::ScoredProbe`] heap tie-break. `_seed` is accepted so callers thread the
/// run seed explicitly; insertion order itself is already seed-deterministic.
#[must_use]
pub fn ordered_techniques_by_score(
    candidates: &[(TechniqueKind, f64)],
    knowledge_boost: Option<f64>,
    _seed: Option<u64>,
) -> Vec<TechniqueKind> {
    let mut scored: Vec<(usize, TechniqueKind, f64)> = candidates
        .iter()
        .enumerate()
        .map(|(idx, (kind, posterior))| (idx, *kind, score_for(*kind, *posterior, knowledge_boost)))
        .collect();
    scored.sort_by(|a, b| {
        let ord = b.2.partial_cmp(&a.2).unwrap_or(Ordering::Equal);
        if (b.2 - a.2).abs() < 1e-12 {
            a.0.cmp(&b.0)
        } else {
            ord
        }
    });
    scored.into_iter().map(|(_, kind, _)| kind).collect()
}
/// Starvation guard: when `union` is enabled it keeps at least
/// [`UNION_GUARANTEED_PROBES`] probe in `order` (appends it if truncated away).
pub fn ensure_union_starvation_guard(order: &mut Vec<TechniqueKind>, union_enabled: bool) {
    if union_enabled && !order.contains(&TechniqueKind::Union) {
        order.push(TechniqueKind::Union);
    }
}

/// `payload_budget` envelope mirror: number of base payloads to try per
/// technique for a tuning `--level`. L1 is the historical budget, L2 doubles
/// it, L3+ exhausts the list. Detectors slice via this envelope, so the
/// scheduler never schedules work beyond it.
#[must_use]
pub fn payload_allowance(level: u8, default_take: usize, total: usize) -> usize {
    match level {
        0 | 1 => default_take.min(total),
        2 => (default_take * 2).min(total),
        _ => total,
    }
}
