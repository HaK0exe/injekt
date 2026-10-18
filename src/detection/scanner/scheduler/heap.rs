use super::{
    EarlyStop, KNOWLEDGE_NEUTRAL_BOOST, RequestBudget, clamp_knowledge_boost, cost_for, evi_for,
};
use crate::session::state::TechniqueKind;
use std::{cmp::Ordering, collections::BinaryHeap};

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
/// only enforces the [`crate::detection::scanner::scheduler::EarlyStop`] veto once the full pass is complete.
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
    /// [`crate::detection::scanner::scheduler::evi_for`]/[`crate::detection::scanner::scheduler::cost_for`] models (knowledge-neutral unless `boost` given).
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
    /// B1: the [`crate::detection::scanner::scheduler::EarlyStop`] veto is only enforced after a full pass (every
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
    /// full-pass gate for the [`crate::detection::scanner::scheduler::EarlyStop`] veto). Vacuously `true` when
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
    /// The [`crate::detection::scanner::scheduler::RequestBudget`] (global `--request-budget` envelope, seeded with
    /// the `<=8` context probes by the orchestrator) advances by the spent
    /// requests; the [`crate::detection::scanner::scheduler::EarlyStop`] negative streak advances by the same
    /// spent requests. The streak resets at every technique boundary
    /// ([`crate::detection::scanner::scheduler::EarlyStop::reset_negative_streak`], called by the orchestrator),
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
    /// exhausted, or [`crate::detection::scanner::scheduler::EarlyStop`] says to stop past a full pass (B1 gate,
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
    /// [`crate::detection::scanner::scheduler::EarlyStop::reset_for_new_param`] here at each parameter boundary
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
