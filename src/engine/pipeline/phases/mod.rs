//! `run_internal` phase functions (P2 split): `early` covers
//! pre-flight/baseline/context, `late` detection through enumeration,
//! and `finalize` the terminal verdict. Bodies moved verbatim from the
//! inline pipeline; early exits drain detectability where inline code did.

pub(super) use self::early::{
    BaselinePhase, preflight_target, run_baseline_phase, run_context_phase,
};
pub(super) use self::finalize::finalize_run;
pub(super) use self::late::{
    run_detection_phase, run_enumeration_phase, run_extraction_phase, run_fingerprint_phase,
};

mod early;
mod finalize;
mod late;
