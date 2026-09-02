#![deny(unsafe_code)]
pub mod detector;
pub mod payloads;
pub use detector::{JsonChannel, JsonDetector, JsonResult};
pub use payloads::{JsonPayload, json_payloads_for};
