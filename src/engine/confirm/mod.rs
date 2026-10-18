#![deny(unsafe_code)]

//! Confirmation second-pass + mini-mutation (P1).
//! Extracted verbatim from `orchestrator.rs`; no behaviour change.

mod boolean;
mod dispatch;
mod error;
mod error_bool;
mod mutation;
mod params;
mod scope;
mod second_pass;
mod stacked;
mod time;
mod union;

pub(crate) use error_bool::{ErrorBoolConfirm, confirm_error_with_boolean};
pub(crate) use params::{dbms_label_from_finding, first_finding_param, push_confirm_trace};
pub(crate) use scope::{
    ConfirmScope, has_confirmed_finding, is_confirmed_finding, is_extraction_eligible,
};
pub(crate) use second_pass::run_confirm_second_pass;
// Only the `engine::orchestrator` gating tests (`cfg(test)`) use these through
// the historical `engine::confirm::X` paths; keep the re-exports so those
// paths stay stable without an unused-import warning in non-test builds.
#[allow(unused_imports)]
pub(crate) use scope::{in_confirm_scope, needs_auto_second_pass};
