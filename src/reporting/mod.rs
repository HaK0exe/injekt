#![deny(unsafe_code)]
pub mod console;
pub mod evidence;
pub mod json;
pub use evidence::{Evidence, EvidenceCollector};
