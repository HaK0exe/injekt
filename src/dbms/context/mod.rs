#![deny(unsafe_code)]

mod active;
mod errors;
mod model;
mod passive;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests;

pub use active::analyze_context;
pub use errors::check_sql_errors;
pub use model::{
    CommentStyle, ContextProbeResult, DbmsBelief, InjectionContext, MAX_CONTEXT_PROBES,
    QuoteContext,
};
pub use passive::infer_passive_context;
