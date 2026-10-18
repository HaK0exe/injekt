#![deny(unsafe_code)]

mod budget;
mod early_stop;
mod heap;
mod scoring;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

pub use budget::RequestBudget;
pub use early_stop::EarlyStop;
pub use heap::{Scheduler, ScoredProbe, Task};
pub use scoring::{
    KNOWLEDGE_NEUTRAL_BOOST, MAX_KNOWLEDGE_BOOST, MIN_KNOWLEDGE_BOOST, UNION_GUARANTEED_PROBES,
    base_evi_for, clamp_knowledge_boost, cost_for, cost_for_with_ttfb,
    ensure_union_starvation_guard, evi_for, latency_secs_for, ordered_techniques_by_score,
    payload_allowance, score_for, waf_risk_for,
};
