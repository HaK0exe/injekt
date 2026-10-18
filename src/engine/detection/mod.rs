//! Detection phase moved out of `orchestrator.rs` (P1-fin): per-parameter
//! C3+C4 loop (scheduler + hypotheses), technique dispatch and outcome folding.
//!
//! Behavior-neutral move: bodies are verbatim `Engine::run_detection` /
//! `run_detection_for_param` / `run_one_technique` / `dispatch_probe_*` /
//! `apply_outcome_to_hypothesis`; `self.*` became explicit params.

mod dispatch;
mod outcome;
mod param;
mod runner;
mod shared;

// `apply_outcome_to_hypothesis` / `infer_signal_and_trials`: consommés
// hors module uniquement par les tests cfg(test) d'`orchestrator` — le
// re-export n'est pas utilisé dans la production de la lib (même pattern
// que `confirm/mod.rs`).
#[allow(unused_imports)]
pub(crate) use outcome::{apply_outcome_to_hypothesis, infer_signal_and_trials};
pub(crate) use runner::run_detection;
