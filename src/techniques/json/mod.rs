#![deny(unsafe_code)]
pub mod detector;
pub mod payloads;
pub use detector::{JsonChannel, JsonDetector, JsonResult, extract_json_error_texts};
pub use payloads::{JsonPayload, graphql_envelope, graphql_probes_for, json_payloads_for};
