#![deny(unsafe_code)]
pub mod hypothesis;
pub mod knowledge;
pub mod trace;
pub use hypothesis::{
    HIGH_CONFIDENCE_THRESHOLD, Hypothesis, HypothesisState, MEDIUM_CONFIDENCE_THRESHOLD,
    REFUTED_POSTERIOR_THRESHOLD, compute_calibrated_prior,
};
pub use knowledge::{
    KNOWLEDGE_FILE_NAME, KNOWLEDGE_MAX_BOOST, KNOWLEDGE_MIN_BOOST, KNOWLEDGE_SCHEMA_VERSION,
    KnowledgeEntry, KnowledgeError, KnowledgeKey, KnowledgeStore, MAX_ALPHA, MIN_SAMPLES,
    all_techniques, context_class_for, default_knowledge_path, expand_enabled_techniques,
    learn_from_run, load_if_enabled, normalize_context_class, normalize_dbms, parse_technique,
    resolve_knowledge_path, save_delta_if_enabled, scheduled_boost_for,
};
pub use trace::{ProbeRecord, ReasoningTrace, derive_confirm_seed, explain_line};
