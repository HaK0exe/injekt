#![deny(unsafe_code)]
pub mod detector;
pub mod payloads;
pub use detector::{StackedDetector, StackedResult};
pub use payloads::{StackedPayload, stacked_payloads_for};
