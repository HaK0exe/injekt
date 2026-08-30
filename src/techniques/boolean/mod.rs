#![deny(unsafe_code)]
pub mod detector;
pub mod payloads;
pub use detector::{BooleanDetector, BooleanResult};
pub use payloads::{BooleanPayload, boolean_payloads_for};
