#![deny(unsafe_code)]

//! CLI config resolution (P3): split by concern —
//! `snapshot` (single-load `ResolvedSnapshot` + `*_with` helpers),
//! `effective` (legacy getters), `ai`, `validate`, `opts`, `target`,
//! `net`, `auth`. All items are inherent `impl Cli` methods, so call
//! sites (`cli.effective_*`) are unchanged.

mod ai;
mod auth;
mod effective;
mod format;
mod net;
mod opts;
mod snapshot;
mod target;
mod validate;

#[cfg(test)]
mod tests;

pub use snapshot::ResolvedSnapshot;
