#![deny(unsafe_code)]
pub mod detector;
pub mod payloads;
pub use detector::{ErrorDetector, ErrorResult};
pub use payloads::{ErrorPayload, error_payloads_for};
