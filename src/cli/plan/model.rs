//! Serializable execution-plan model (`PlannedProbe`, `PlannedParam`,
//! `ExecutionPlan`) with scrubber support.

use crate::session::scrubber::Scrubber;
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
