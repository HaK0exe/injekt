#![deny(unsafe_code)]

//! WAF / CDN fingerprinting from response headers + body.
//!
//! The legacy gate ([`crate::detection::baseline::Baseline::is_waf_blocked`])
//! only sees repeated `403`/`406`. Cloudflare usually answers `200` with a
//! managed challenge (`Just a moment`, `cf-ray`, `__cf_bm`) — invisible to a
//! status-only check, yet it silently filters long extraction payloads (the
//! noxtools pentest: detection `mysql_xpath 0.9` but every `extract=true`
//! oracle timed out / `inference inconsistency at pos 0`).
//!
//! Matching is plain case-insensitive `contains`, no regex: the marker set is
//! fixed and small, and a single `to_ascii_lowercase` over a truncated prefix
//! keeps the cost negligible. Header *values* are only ever inspected via
//! `contains` on a caller-truncated prefix (≤128 chars) and only signal
//! *names* are logged — never cookie/session contents (see OPSEC note on
//! [`detect_cloudflare_flat`]).

mod ct;
mod detectors;
mod registry;
mod vendor;

pub use ct::ct_mismatch_hit;
pub use detectors::{detect_cloudflare, detect_cloudflare_flat};
pub use registry::{HEADER_VALUE_KEEP, is_coroborating_status};
pub use vendor::{WafSignals, WafVendor, downgrade_for_waf};

#[cfg(test)]
mod tests;
