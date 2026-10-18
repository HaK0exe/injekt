use std::time::Instant;

use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    detection::baseline,
    target::{markers::MarkerSet, url::TargetUrl},
    techniques::tamper::Tamper,
};

/// Shared immutable detection inputs cloned once per `run_detection`.
#[derive(Debug, Clone)]
pub(super) struct DetectionShared {
    pub(super) target: TargetUrl,
    pub(super) target_str: String,
    pub(super) marker_set: MarkerSet,
    pub(super) baseline: baseline::Baseline,
    pub(super) tampers: Vec<Tamper>,
    pub(super) context: InjectionContext,
    pub(super) dbms_belief: DbmsBelief,
    /// Adaptive context probes already spent (`<=8` by `MAX_CONTEXT_PROBES`):
    /// seeded into every per-parameter scheduler budget.
    pub(super) context_probes: usize,
    /// Shared detection clock for `--max-duration` (Phase 3): set once in
    /// `run_detection`, read in every `run_detection_for_param` iteration.
    /// Starts AFTER baseline + context, so `--max-duration` covers detection
    /// loops only — never the total run (documented in `--help`).
    pub(super) started: Instant,
}
