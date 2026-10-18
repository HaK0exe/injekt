#![deny(unsafe_code)]

//! C11 Developer Experience: offline execution-plan construction (0 requête).
//!
//! Layered planner (P3): the `planner` submodule builds the ordered probe
//! list a `scan`/`recon` run *would* execute ([`build_plan`]: lexical URL
//! plus `--raw-file` fusion only, no DNS, no `HttpClient`); the
//! `escalation` submodule builds the L1/L2/L3 passes `auto` runs; `model`
//! holds the serialisable plan types and `render` the CLI/MCP renderers.
//! The CLI `--dry-run` printers and the MCP `plan`/`explain` tools are thin
//! renderers over this module; the engine itself is untouched.

mod escalation;
mod model;
mod planner;
mod render;

#[cfg(test)]
mod tests;

pub use escalation::{EscalationStep, escalation_plan};
pub use model::{ExecutionPlan, PlannedParam, PlannedProbe};
pub use planner::{
    build_plan, dbms_belief_for_hint, effective_marker_set, params_for_target_offline,
    plan_knowledge_boost, technique_kinds_for_names,
};
pub use render::{explain_offline, finding_from_export, render_human};
