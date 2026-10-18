use super::types::{KNOWLEDGE_MAX_BOOST, KNOWLEDGE_MIN_BOOST, KnowledgeStore, MAX_ALPHA};
use crate::dbms::context::InjectionContext;
use crate::detection::scanner::scheduler::clamp_knowledge_boost;
use crate::session::state::TechniqueKind;

/// `boost = 1 + clamp(rate_laplace - 0.5, ±0.5)` (sans le clamp scheduler).
pub(super) fn boost_from_counts(success: u64, trials: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let (s, t) = (success as f64, trials.max(1) as f64);
    let rate = (s + 1.0) / (t + 2.0);
    let alpha = (rate - 0.5).clamp(-MAX_ALPHA, MAX_ALPHA);
    1.0 + alpha
}

pub(super) fn clamp_knowledge_range(boost: f64) -> f64 {
    if boost.is_finite() {
        boost.clamp(KNOWLEDGE_MIN_BOOST, KNOWLEDGE_MAX_BOOST)
    } else {
        1.0
    }
}

/// Boost final vu par le scheduler : borne knowledge puis clamp `[0.5, 2.0]`
/// existant conservé (jamais de veto).
#[must_use]
pub fn scheduled_boost_for(
    store: Option<&KnowledgeStore>,
    technique: TechniqueKind,
    dbms: &str,
    context: &InjectionContext,
) -> Option<f64> {
    let ks = store?;
    let raw = ks.boost_for_context(technique, dbms, context);
    Some(clamp_knowledge_boost(raw))
}
