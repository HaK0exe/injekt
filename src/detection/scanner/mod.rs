#![deny(unsafe_code)]
pub mod engine;
pub mod scheduler;
pub use engine::{ScanConfig, ScanEngine};
pub use scheduler::{
    EarlyStop, KNOWLEDGE_NEUTRAL_BOOST, MAX_KNOWLEDGE_BOOST, MIN_KNOWLEDGE_BOOST, RequestBudget,
    Scheduler, ScoredProbe, Task, UNION_GUARANTEED_PROBES, base_evi_for, clamp_knowledge_boost,
    cost_for, ensure_union_starvation_guard, evi_for, latency_secs_for,
    ordered_techniques_by_score, payload_allowance, score_for, waf_risk_for,
};
