#![deny(unsafe_code)]

use crate::session::state::TechniqueKind;
use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap},
};

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
        TechniqueKind::Union | TechniqueKind::Json | TechniqueKind::Nosql => 0.8,
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
        TechniqueKind::Union | TechniqueKind::Json | TechniqueKind::Nosql => 0.3,
        TechniqueKind::Stacked | TechniqueKind::Oob => 0.5,
        TechniqueKind::Time => 1.5,
    }
}

/// WAF exposure risk per technique (noisy payload families cost more).
#[must_use]
pub const fn waf_risk_for(kind: TechniqueKind) -> f64 {
    match kind {
        TechniqueKind::Boolean | TechniqueKind::Error => 0.0,
        TechniqueKind::Union | TechniqueKind::Json | TechniqueKind::Nosql => 0.2,
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
/// [`ScoredProbe`] heap tie-break. `_seed` is accepted so callers thread the
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

/// Tracks global and per-parameter request consumption against configured limits.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RequestBudget {
    max_requests: Option<usize>,
    max_per_param: Option<usize>,
    spent_total: usize,
    spent_per_param: HashMap<String, usize>,
}

impl RequestBudget {
    #[must_use]
    pub fn new(max_requests: Option<usize>, max_per_param: Option<usize>) -> Self {
        Self {
            max_requests,
            max_per_param,
            spent_total: 0,
            spent_per_param: HashMap::new(),
        }
    }

    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            max_requests: None,
            max_per_param: None,
            spent_total: 0,
            spent_per_param: HashMap::new(),
        }
    }

    pub fn record_request(&mut self, param: &str, count: usize) {
        self.spent_total = self.spent_total.saturating_add(count);
        let entry = self.spent_per_param.entry(param.to_owned()).or_insert(0);
        *entry = entry.saturating_add(count);
    }

    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        if let Some(max) = self.max_requests {
            self.spent_total >= max
        } else {
            false
        }
    }

    #[must_use]
    pub fn is_param_exhausted(&self, param: &str) -> bool {
        if self.is_exhausted() {
            return true;
        }
        if let Some(max_p) = self.max_per_param {
            let spent = self.spent_per_param.get(param).copied().unwrap_or(0);
            spent >= max_p
        } else {
            false
        }
    }

    #[must_use]
    pub fn remaining_total(&self) -> Option<usize> {
        self.max_requests
            .map(|max| max.saturating_sub(self.spent_total))
    }

    #[must_use]
    pub const fn spent_total(&self) -> usize {
        self.spent_total
    }

    #[must_use]
    pub const fn max_requests(&self) -> Option<usize> {
        self.max_requests
    }

    #[must_use]
    pub fn spent_for_param(&self, param: &str) -> usize {
        self.spent_per_param.get(param).copied().unwrap_or(0)
    }
}

/// Early stopping mechanism for clean targets (N1/N2 veto: 25 negatives)
/// and early resolution on confirmed vulnerabilities.
///
/// Counts consecutive negative **requests within the current technique
/// family** (per-request cost, not per technique): `record_requests`
/// adds `spent` on a negative outcome. The streak resets at every
/// technique boundary via [`EarlyStop::reset_negative_streak`] (called by
/// the orchestrator when it pops the next family), so the veto only *arms*
/// on a single family spending `>= max_negative_probes` negative
/// requests (e.g. a full L2 boolean matrix on a clean target).
///
/// Enforcement is separate: [`Scheduler::pop`] only honors the veto after
/// a full pass (every enqueued family dequeued at least once), so an armed
/// veto can never starve never-attempted families (a boolean-negative
/// target may still be nosql-positive; cross-family starvation would be a
/// silent false negative, the worst failure mode for a scanner). B1: the
/// pre-fix `pop` checked the veto *before* the boundary reset could run,
/// so L2 boolean (~40 req, top EVI) vetoed error/time/union/nosql unseen.
///
/// Inter-param isolation is separate: each parameter repart d'un compteur
/// frais via [`EarlyStop::reset_for_new_param`] (called by the orchestrator
/// at each parameter boundary), while the cross-param total stays visible
/// in `SessionState::request_count` and in the [`RequestBudget`]. Any
/// confirmed finding locks `confirmed` and disables the stop for the rest
/// of the parameter (both resets preserve it).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EarlyStop {
    /// Maximum consecutive negative outcomes before early stopping on a clean parameter.
    pub max_negative_probes: usize,
    /// Consecutive negative probes observed on the current parameter.
    pub negative_count: usize,
    /// Whether any confirmed finding was recorded for this parameter.
    pub confirmed: bool,
}

impl Default for EarlyStop {
    fn default() -> Self {
        Self {
            max_negative_probes: 25,
            negative_count: 0,
            confirmed: false,
        }
    }
}

impl EarlyStop {
    #[must_use]
    pub const fn new(max_negative_probes: usize) -> Self {
        Self {
            max_negative_probes,
            negative_count: 0,
            confirmed: false,
        }
    }

    pub fn record_result(&mut self, is_finding: bool) {
        self.record_requests(is_finding, 1);
    }

    /// Per-request variant (Phase 0) : ajoute `requests_spent` (pas 1) sur
    /// négatif, de sorte que `max_negative_probes` se compare à des
    /// requêtes et trippe mid-pass sur cible propre.
    pub fn record_requests(&mut self, is_finding: bool, requests_spent: usize) {
        if is_finding {
            self.confirmed = true;
        } else {
            self.negative_count = self.negative_count.saturating_add(requests_spent.max(1));
        }
    }

    #[must_use]
    pub fn should_stop(&self) -> bool {
        if self.confirmed {
            return false;
        }
        self.max_negative_probes > 0 && self.negative_count >= self.max_negative_probes
    }

    pub fn reset_for_new_param(&mut self) {
        self.negative_count = 0;
        self.confirmed = false;
    }

    /// Reset the negative streak at a technique-family boundary (the
    /// orchestrator calls this when it starts a new family on the same
    /// parameter). Unlike [`EarlyStop::reset_for_new_param`], `confirmed`
    /// is preserved: a confirmed finding keeps disabling the veto for the
    /// rest of the parameter.
    pub fn reset_negative_streak(&mut self) {
        self.negative_count = 0;
    }
}

/// A candidate probe prioritised by Expected Value of Information (EVI) per unit cost.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ScoredProbe {
    pub id: usize,
    pub param: String,
    pub technique: TechniqueKind,
    pub payload: String,
    /// Expected Value of Information (reduction in posterior entropy / uncertainty).
    pub evi: f64,
    /// Estimated cost in requests, latency weight, and WAF exposure risk.
    pub cost: f64,
    /// Multiplicative boost from knowledge engine (bounded in [0.5, 2.0], 1.0 = neutral).
    pub knowledge_boost: f64,
    /// Final priority score: (evi * `knowledge_boost`) / cost.
    pub score: f64,
}

impl PartialEq for ScoredProbe {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ScoredProbe {}

impl PartialOrd for ScoredProbe {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScoredProbe {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher score comes first in BinaryHeap (Max-Heap).
        // Tie-breaker: lower ID (FIFO order for equal score) ensures deterministic reproducibility.
        self.score
            .partial_cmp(&other.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.id.cmp(&self.id))
    }
}

/// Cost-based probe scheduler maintaining a max-heap of scored probes.
///
/// B1: the scheduler tracks `enqueued_kinds` (every family pushed) vs
/// `attempted_kinds` (every family dequeued via [`Scheduler::pop`]) and
/// only enforces the [`EarlyStop`] veto once the full pass is complete.
/// Pop-side tracking (rather than orchestrator `executed_kinds` plumbing)
/// keeps [`Scheduler::record_outcome`]'s signature stable and covers the
/// orchestrator's skip paths for already-terminal hypotheses.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Scheduler {
    heap: BinaryHeap<ScoredProbe>,
    budget: RequestBudget,
    early_stop: EarlyStop,
    next_id: usize,
    enqueued_kinds: Vec<TechniqueKind>,
    attempted_kinds: Vec<TechniqueKind>,
}

impl Scheduler {
    #[must_use]
    pub fn new(budget: RequestBudget, early_stop: EarlyStop) -> Self {
        Self {
            heap: BinaryHeap::new(),
            budget,
            early_stop,
            next_id: 0,
            enqueued_kinds: Vec::new(),
            attempted_kinds: Vec::new(),
        }
    }

    /// Enqueue a probe with EVI, cost, and optional knowledge boost.
    ///
    /// The knowledge boost is strictly clamped to [0.5, 2.0]. When knowledge is
    /// empty (neutrality at cold-start), boost is 1.0, making score == evi / cost.
    pub fn push(
        &mut self,
        param: impl Into<String>,
        technique: TechniqueKind,
        payload: impl Into<String>,
        evi: f64,
        cost: f64,
        knowledge_boost: Option<f64>,
    ) {
        self.next_id = self.next_id.saturating_add(1);
        let boost = clamp_knowledge_boost(knowledge_boost.unwrap_or(KNOWLEDGE_NEUTRAL_BOOST));
        let safe_cost = cost.max(0.01);
        let score = (evi * boost) / safe_cost;
        if !self.enqueued_kinds.contains(&technique) {
            self.enqueued_kinds.push(technique);
        }

        self.heap.push(ScoredProbe {
            id: self.next_id,
            param: param.into(),
            technique,
            payload: payload.into(),
            evi,
            cost: safe_cost,
            knowledge_boost: boost,
            score,
        });
    }

    /// Enqueue one probe for `technique` at `posterior` using the calibrated
    /// [`evi_for`]/[`cost_for`] models (knowledge-neutral unless `boost` given).
    pub fn push_for_posterior(
        &mut self,
        param: impl Into<String>,
        technique: TechniqueKind,
        payload: impl Into<String>,
        posterior: f64,
        knowledge_boost: Option<f64>,
    ) {
        let evi = evi_for(technique, posterior);
        let cost = cost_for(technique);
        self.push(param, technique, payload, evi, cost, knowledge_boost);
    }

    /// Dequeue the next highest-scoring probe, respecting budget and early-stop limits.
    ///
    /// B1: the [`EarlyStop`] veto is only enforced after a full pass (every
    /// enqueued family dequeued at least once) — before that, an armed veto
    /// never blocks a never-attempted family. On veto, returns `None`
    /// immediately WITHOUT draining the heap (the old `continue` emptied it,
    /// starving the survivors permanently).
    #[must_use]
    pub fn pop(&mut self) -> Option<ScoredProbe> {
        if self.budget.is_exhausted() {
            return None;
        }
        if self.early_stop.should_stop() && self.full_pass_complete() {
            return None;
        }

        while let Some(probe) = self.heap.pop() {
            if self.budget.is_param_exhausted(&probe.param) {
                continue;
            }
            self.mark_attempted(probe.technique);
            return Some(probe);
        }

        None
    }

    /// `true` once every enqueued family was dequeued at least once (B1
    /// full-pass gate for the [`EarlyStop`] veto). Vacuously `true` when
    /// nothing was enqueued, matching the pre-fix veto behavior.
    #[must_use]
    fn full_pass_complete(&self) -> bool {
        self.enqueued_kinds
            .iter()
            .all(|kind| self.attempted_kinds.contains(kind))
    }

    /// Record a dequeued family (pop-side, so orchestrator skip paths for
    /// already-terminal hypotheses count as attempted too).
    fn mark_attempted(&mut self, technique: TechniqueKind) {
        if !self.attempted_kinds.contains(&technique) {
            self.attempted_kinds.push(technique);
        }
    }

    /// Record probe execution outcome and spent requests.
    ///
    /// The [`RequestBudget`] (global `--request-budget` envelope, seeded with
    /// the `<=8` context probes by the orchestrator) advances by the spent
    /// requests; the [`EarlyStop`] negative streak advances by the same
    /// spent requests. The streak resets at every technique boundary
    /// ([`EarlyStop::reset_negative_streak`], called by the orchestrator),
    /// so the 25-negative veto only *arms* on a single family spending that
    /// much with zero signal — and [`Scheduler::pop`] additionally gates
    /// enforcement on a full pass (B1), so arming never blocks untested
    /// families. `budget_spent`, `next_best_probe` et le câblage
    /// N1/N2 restent cohérents.
    pub fn record_outcome(&mut self, param: &str, is_finding: bool, requests_spent: usize) {
        self.budget.record_request(param, requests_spent);
        self.early_stop.record_requests(is_finding, requests_spent);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    #[must_use]
    pub fn budget(&self) -> &RequestBudget {
        &self.budget
    }

    /// Mutable budget: the orchestrator seeds the `<=8` context probes here
    /// so the per-parameter scheduler accounts the global cost from the
    /// first `pop` (see `build_scheduler_for_param`).
    pub fn budget_mut(&mut self) -> &mut RequestBudget {
        &mut self.budget
    }

    /// Requests spent globally (`budget_spent` surface for stealth budgets).
    #[must_use]
    pub const fn budget_spent(&self) -> usize {
        self.budget.spent_total()
    }

    /// Configured global budget, if any (`budget_total` surface).
    #[must_use]
    pub const fn budget_total(&self) -> Option<usize> {
        self.budget.max_requests()
    }

    /// Preview of the next probe `pop` would return (heap top) without
    /// consuming it. `None` when the budget is exhausted, the param is
    /// exhausted, or [`EarlyStop`] says to stop past a full pass (B1 gate,
    /// mirroring [`Scheduler::pop`]). Best-effort preview: `pop`
    /// remains authoritative when deeper entries are still eligible.
    #[must_use]
    pub fn next_best_probe(&self) -> Option<ScoredProbe> {
        if self.budget.is_exhausted()
            || (self.early_stop.should_stop() && self.full_pass_complete())
        {
            return None;
        }
        let top = self.heap.peek()?;
        if self.budget.is_param_exhausted(&top.param) {
            return None;
        }
        Some(top.clone())
    }

    #[must_use]
    pub fn early_stop(&self) -> &EarlyStop {
        &self.early_stop
    }

    /// Mutable early-stop: the orchestrator calls
    /// [`EarlyStop::reset_for_new_param`] here at each parameter boundary
    /// (inter-param isolation for the N1/N2 veto).
    pub fn early_stop_mut(&mut self) -> &mut EarlyStop {
        &mut self.early_stop
    }
}

// Legacy Task compatibility
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Task {
    pub id: usize,
    pub url: String,
    pub param: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_heap_ordering_by_score() {
        let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());

        // Low score: evi 0.2, cost 2.0 -> score 0.1
        s.push("id", TechniqueKind::Time, "sleep", 0.2, 2.0, None);
        // High score: evi 0.8, cost 1.0 -> score 0.8
        s.push("id", TechniqueKind::Boolean, "1=1", 0.8, 1.0, None);
        // Medium score: evi 0.5, cost 1.0 -> score 0.5
        s.push("id", TechniqueKind::Error, "xpath", 0.5, 1.0, None);

        let p1 = s.pop().expect("first probe");
        assert_eq!(p1.technique, TechniqueKind::Boolean);

        let p2 = s.pop().expect("second probe");
        assert_eq!(p2.technique, TechniqueKind::Error);

        let p3 = s.pop().expect("third probe");
        assert_eq!(p3.technique, TechniqueKind::Time);
    }

    #[test]
    fn test_knowledge_boost_bounds_and_neutrality() {
        let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());

        // Neutral boost (None or 1.0)
        s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
        s.push("id", TechniqueKind::Error, "p2", 1.0, 1.0, Some(1.0));

        let p1 = s.pop().expect("p1");
        assert!((p1.score - 1.0).abs() < 1e-6);
        let p2 = s.pop().expect("p2");
        assert!((p2.score - 1.0).abs() < 1e-6);

        // Boost clamping: requested 10.0 -> clamped to 2.0
        s.push("id", TechniqueKind::Union, "p3", 1.0, 1.0, Some(10.0));
        let p3 = s.pop().expect("p3");
        assert!((p3.knowledge_boost - 2.0).abs() < 1e-6);
        assert!((p3.score - 2.0).abs() < 1e-6);

        // Boost clamping: requested 0.01 -> clamped to 0.5
        s.push("id", TechniqueKind::Stacked, "p4", 1.0, 1.0, Some(0.01));
        let p4 = s.pop().expect("p4");
        assert!((p4.knowledge_boost - 0.5).abs() < 1e-6);
        assert!((p4.score - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_request_budget_exhaustion() {
        let budget = RequestBudget::new(Some(10), None);
        let mut s = Scheduler::new(budget, EarlyStop::default());

        s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
        s.record_outcome("id", false, 10);

        assert!(s.budget().is_exhausted());
        assert!(s.pop().is_none());
    }

    #[test]
    fn test_early_stop_clean_target() {
        let early_stop = EarlyStop::new(5);
        let mut s = Scheduler::new(RequestBudget::unlimited(), early_stop);

        s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
        s.push("id", TechniqueKind::Boolean, "p2", 1.0, 1.0, None);

        // Real flow: pop marks the family attempted, then negatives accumulate.
        let first = s.pop().expect("first probe");
        assert_eq!(first.technique, TechniqueKind::Boolean);

        // 5 consecutive negatives
        for _ in 0..5 {
            s.record_outcome("id", false, 1);
        }

        assert!(s.early_stop().should_stop());
        // Full pass complete (sole enqueued family attempted): veto honored
        // with an immediate None that leaves the heap intact (no drain).
        assert!(s.pop().is_none());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn test_cost_time_greater_than_boolean() {
        assert!((cost_for(TechniqueKind::Boolean) - 1.0).abs() < 1e-12);
        assert!((cost_for(TechniqueKind::Error) - 1.0).abs() < 1e-12);
        assert!((cost_for(TechniqueKind::Union) - 1.5).abs() < 1e-12);
        assert!((cost_for(TechniqueKind::Json) - 1.5).abs() < 1e-12);
        assert!((cost_for(TechniqueKind::Nosql) - 1.5).abs() < 1e-12);
        assert!((cost_for(TechniqueKind::Stacked) - 2.0).abs() < 1e-12);
        assert!((cost_for(TechniqueKind::Oob) - 2.0).abs() < 1e-12);
        assert!((cost_for(TechniqueKind::Time) - 3.0).abs() < 1e-12);
        assert!(cost_for(TechniqueKind::Time) > cost_for(TechniqueKind::Boolean));
    }

    #[test]
    fn test_cost_for_with_ttfb_static_by_default() {
        // mean 0 (unknown) / fast baseline => static cost unchanged.
        let base = cost_for(TechniqueKind::Time);
        assert!((cost_for_with_ttfb(base, 0.0) - base).abs() < 1e-12);
        assert!((cost_for_with_ttfb(base, 500.0) - base).abs() < 1e-12);
        assert!((cost_for_with_ttfb(base, 2000.0) - base).abs() < 1e-12);
        // Non-finite inputs are pass-through (never NaN-poison the heap).
        assert!((cost_for_with_ttfb(base, f64::NAN) - base).abs() < 1e-12);
    }

    #[test]
    fn test_cost_for_with_ttfb_scales_slow_targets() {
        // mean 5s => factor (1 + 5000/5000) = 2.0, time 3.0 -> 6.0.
        let base = cost_for(TechniqueKind::Time);
        let scaled = cost_for_with_ttfb(base, 5000.0);
        assert!((scaled - 6.0).abs() < 1e-12, "got {scaled}");
        assert!(scaled > base);
        // Boundary just above 2000ms scales slightly.
        let just_over = cost_for_with_ttfb(base, 2001.0);
        assert!(just_over > base);
        assert!((just_over - base * (1.0 + 2001.0 / 5000.0)).abs() < 1e-9);
    }

    #[test]
    fn test_evi_entropy_peaks_at_half() {
        // Phase 0 : variance binaire normalisée `4·p·(1-p)·base`
        // (pic `base` à 0.5, 0 aux convergences 0/1).
        let base = base_evi_for(TechniqueKind::Boolean);
        assert!((evi_for(TechniqueKind::Boolean, 0.5) - base).abs() < 1e-12);
        assert!((evi_for(TechniqueKind::Boolean, 0.0)).abs() < 1e-12);
        assert!((evi_for(TechniqueKind::Boolean, 1.0)).abs() < 1e-12);
        assert!((evi_for(TechniqueKind::Boolean, 0.1) - 0.36 * base).abs() < 1e-12);
        assert!((evi_for(TechniqueKind::Boolean, 0.8) - 0.64 * base).abs() < 1e-12);
        // Symétrie p ↔ 1-p, pic strict à 0.5.
        assert!(
            (evi_for(TechniqueKind::Boolean, 0.2) - evi_for(TechniqueKind::Boolean, 0.8)).abs()
                < 1e-12
        );
        assert!(evi_for(TechniqueKind::Boolean, 0.5) > evi_for(TechniqueKind::Boolean, 0.8));
        assert!(evi_for(TechniqueKind::Boolean, 0.5) > evi_for(TechniqueKind::Boolean, 0.1));
        // Score hérite du pic sous knowledge neutre.
        assert!(
            score_for(TechniqueKind::Boolean, 0.5, None)
                > score_for(TechniqueKind::Boolean, 0.8, None)
        );
        assert!(
            score_for(TechniqueKind::Boolean, 0.5, None)
                > score_for(TechniqueKind::Boolean, 0.1, None)
        );
    }

    #[test]
    fn test_early_stop_counts_requests_trips_mid_pass() {
        // Phase 0 : `max_negative_probes` se compare à des requêtes.
        // 3 outcomes × 10 req = 30 ≥ 25 → stop (l'ancien comptage par
        // technique aurait exigé 25 outcomes et ne trippait jamais mid-pass
        // sur 8 techniques). B1 : le pop préalable marque la famille
        // tentée (full pass complet sur une seule famille enfilée), donc
        // le veto armé s'applique sans drainer le heap.
        let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::new(25));
        s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
        s.push("id", TechniqueKind::Boolean, "p2", 1.0, 1.0, None);
        let _first = s.pop().expect("family attempted before outcomes");
        assert!(!s.early_stop().should_stop());
        s.record_outcome("id", false, 10);
        assert!(!s.early_stop().should_stop());
        s.record_outcome("id", false, 10);
        assert!(!s.early_stop().should_stop());
        s.record_outcome("id", false, 10);
        assert!(s.early_stop().should_stop());
        assert!(s.pop().is_none());
        assert_eq!(s.len(), 1);
        // Un finding verrouille `confirmed` et désactive le stop.
        let mut c = Scheduler::new(RequestBudget::unlimited(), EarlyStop::new(5));
        c.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
        c.record_outcome("id", false, 10);
        c.record_outcome("id", true, 1);
        assert!(!c.early_stop().should_stop());
    }

    #[test]
    fn test_early_stop_streak_resets_per_technique_family() {
        // No cross-family starvation: boolean 24 + error 40 must NOT block
        // nosql (boolean-negative != nosql-negative). The per-family reset
        // keeps arming per-family, while the B1 full-pass gate keeps an
        // armed veto from blocking never-attempted families. Guards
        // `nosql_in_all_techniques`.
        let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::new(25));
        s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
        s.push("id", TechniqueKind::Error, "p2", 1.0, 1.0, None);
        s.push("id", TechniqueKind::Nosql, "p3", 1.0, 1.0, None);
        // Family 1: pop (attempted), 24 negatives, then boundary reset.
        let first = s.pop().expect("boolean first (FIFO tie-break)");
        assert_eq!(first.technique, TechniqueKind::Boolean);
        s.record_outcome("id", false, 24);
        assert!(!s.early_stop().should_stop());
        s.early_stop_mut().reset_negative_streak();
        // Family 2: pop (attempted), 40 negatives -> veto ARMS, no reset:
        // the B1 gate alone must let the unattempted family through.
        let second = s.pop().expect("error serves: full pass incomplete");
        assert_eq!(second.technique, TechniqueKind::Error);
        s.record_outcome("id", false, 40);
        assert!(s.early_stop().should_stop());
        // Family 3 runs: armed veto does not block a never-attempted family.
        let third = s.pop().expect("B1: armed veto must not block nosql");
        assert_eq!(third.technique, TechniqueKind::Nosql);
        // But a single family spending >= 25 still trips once its pass is
        // complete (L2 long tails stay bounded, heap left intact).
        let mut t = Scheduler::new(RequestBudget::unlimited(), EarlyStop::new(25));
        t.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
        t.push("id", TechniqueKind::Boolean, "p2", 1.0, 1.0, None);
        let _ = t.pop().expect("family attempted before outcomes");
        t.record_outcome("id", false, 100);
        assert!(t.early_stop().should_stop());
        assert!(t.pop().is_none());
        assert_eq!(t.len(), 1);
        // `confirmed` survives the streak reset (veto stays off).
        let mut c = Scheduler::new(RequestBudget::unlimited(), EarlyStop::new(5));
        c.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
        c.record_outcome("id", true, 1);
        c.early_stop_mut().reset_negative_streak();
        assert!(!c.early_stop().should_stop());
    }

    #[test]
    fn test_early_stop_record_requests_unit() {
        let mut e = EarlyStop::new(5);
        e.record_requests(false, 3);
        assert_eq!(e.negative_count, 3);
        assert!(!e.should_stop());
        e.record_requests(false, 2);
        assert!(e.should_stop());
        // `record_result` reste l'alias 1-req pour compat.
        let mut r = EarlyStop::new(2);
        r.record_result(false);
        assert_eq!(r.negative_count, 1);
        r.record_result(false);
        assert!(r.should_stop());
    }

    #[test]
    fn test_early_stop_after_25_negatives_default() {
        let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());
        s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
        s.push("id", TechniqueKind::Boolean, "p2", 1.0, 1.0, None);
        let _ = s.pop().expect("family attempted before outcomes");
        for _ in 0..25 {
            s.record_outcome("id", false, 1);
        }
        assert!(s.early_stop().should_stop());
        assert!(s.pop().is_none());
        assert!(s.next_best_probe().is_none());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn test_b1_l2_boolean_negatives_do_not_starve_untested_nosql() {
        // B1 regression: at L2 the boolean family (top EVI/cost) spends ~40
        // negative requests (4 payloads x 5 sets x 2) before error/nosql ever
        // run. The 25-negative veto arms but must stay gated until every
        // enqueued family was attempted once, so a nosql-only target still
        // gets tested instead of `pop` returning `None` unseen.
        let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::new(25));
        s.push_for_posterior("id", TechniqueKind::Boolean, "b", 0.5, None);
        s.push_for_posterior("id", TechniqueKind::Error, "e", 0.15, None);
        s.push_for_posterior("id", TechniqueKind::Nosql, "n", 0.05, None);

        let first = s.pop().expect("boolean serves first (top EVI/cost)");
        assert_eq!(first.technique, TechniqueKind::Boolean);

        // L2 boolean matrix, all negative: veto arms...
        s.record_outcome("id", false, 40);
        assert!(s.early_stop().should_stop());

        // ...but the full pass is incomplete: preview + pop still serve error.
        assert!(s.next_best_probe().is_some());
        let second = s
            .pop()
            .expect("B1: armed veto must not block unattempted error");
        assert_eq!(second.technique, TechniqueKind::Error);
        s.record_outcome("id", false, 40);
        assert!(s.early_stop().should_stop());

        // nosql (never attempted) still pops: the nosql-only target is tested.
        let third = s
            .pop()
            .expect("B1: armed veto must not block unattempted nosql");
        assert_eq!(third.technique, TechniqueKind::Nosql);
    }

    #[test]
    fn test_boost_bounds_clamp_helper() {
        assert!((clamp_knowledge_boost(10.0) - 2.0).abs() < 1e-12);
        assert!((clamp_knowledge_boost(0.01) - 0.5).abs() < 1e-12);
        assert!((clamp_knowledge_boost(1.0) - 1.0).abs() < 1e-12);
        assert!((clamp_knowledge_boost(f64::NAN) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn test_same_seed_same_order() {
        use TechniqueKind as K;
        let candidates = [
            (K::Boolean, 0.2),
            (K::Error, 0.15),
            (K::Time, 0.1),
            (K::Union, 0.05),
            (K::Stacked, 0.05),
            (K::Json, 0.45),
            (K::Nosql, 0.05),
            (K::Oob, 0.02),
        ];
        let first = ordered_techniques_by_score(&candidates, None, Some(42));
        let second = ordered_techniques_by_score(&candidates, None, Some(42));
        assert_eq!(first, second);

        // Heap path is equally deterministic: same pushes -> same pop order.
        let mut a = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());
        let mut b = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());
        for (kind, posterior) in &candidates {
            a.push_for_posterior("id", *kind, "p", *posterior, None);
            b.push_for_posterior("id", *kind, "p", *posterior, None);
        }
        let mut order_a = Vec::new();
        let mut order_b = Vec::new();
        while let Some(p) = a.pop() {
            order_a.push(p.technique);
        }
        while let Some(p) = b.pop() {
            order_b.push(p.technique);
        }
        assert_eq!(order_a, order_b);
        assert_eq!(order_a, first);
    }

    #[test]
    fn test_union_starvation_guard() {
        let mut order = vec![TechniqueKind::Boolean, TechniqueKind::Error];
        ensure_union_starvation_guard(&mut order, true);
        assert!(order.contains(&TechniqueKind::Union));

        let mut already = vec![TechniqueKind::Boolean, TechniqueKind::Union];
        ensure_union_starvation_guard(&mut already, true);
        assert_eq!(
            already
                .iter()
                .filter(|k| **k == TechniqueKind::Union)
                .count(),
            1
        );

        let mut disabled = vec![TechniqueKind::Boolean];
        ensure_union_starvation_guard(&mut disabled, false);
        assert!(!disabled.contains(&TechniqueKind::Union));
    }

    #[test]
    fn test_budget_spent_total_next_best_probe() {
        let mut s = Scheduler::new(RequestBudget::new(Some(10), None), EarlyStop::default());
        assert_eq!(s.budget_spent(), 0);
        assert_eq!(s.budget_total(), Some(10));
        assert!(s.next_best_probe().is_none());
        s.push_for_posterior("id", TechniqueKind::Boolean, "p1", 0.2, None);
        s.push_for_posterior("id", TechniqueKind::Time, "p2", 0.1, None);
        let next = s.next_best_probe().expect("preview");
        assert_eq!(next.technique, TechniqueKind::Boolean);
        // Preview does not consume.
        assert_eq!(s.len(), 2);
        let first = s.pop().expect("pop");
        assert_eq!(first.technique, next.technique);
        s.record_outcome("id", false, 3);
        assert_eq!(s.budget_spent(), 3);
        assert_eq!(s.budget_total(), Some(10));
    }

    #[test]
    fn test_early_stop_reset_for_new_param_isolates_params() {
        // Inter-param isolation: a clean first param must not veto the next one.
        let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());
        s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
        for _ in 0..25 {
            s.record_outcome("id", false, 1);
        }
        assert!(s.early_stop().should_stop());
        s.early_stop_mut().reset_for_new_param();
        assert!(!s.early_stop().should_stop());
        // Seeding the global context cost keeps budget accounting honest.
        s.budget_mut().record_request("id2", 8);
        assert_eq!(s.budget_spent(), 33);
    }
}
