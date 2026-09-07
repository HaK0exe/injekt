#![deny(unsafe_code)]
pub mod detector;
pub mod payloads;
pub use detector::{TimeDetector, TimeResult};
pub use payloads::{TimePayload, all_time_payloads, time_payload_for, time_payloads_for};
