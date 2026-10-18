#![deny(unsafe_code)]

//! Boolean-oracle confirmation: repeated TRUE/FALSE trials, a strict-majority
//! pass rule, and a statistically grounded false-positive estimate for
//! confirmed oracles (one-sided sign test weighted by effect size — see
//! [`confirm`]).

mod model;
mod stats;
#[cfg(test)]
mod tests;
mod verdict;

pub use model::{ConfirmationResult, Trial};
pub use verdict::{aggregate_sims, confirm, confirm_either};
