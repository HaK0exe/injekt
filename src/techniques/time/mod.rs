#![deny(unsafe_code)]
pub mod detector;
pub mod payloads;
pub use detector::{TimeDetector, TimeResult};
pub use payloads::{TimePayload, time_payload_for};
