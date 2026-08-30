#![deny(unsafe_code)]
pub mod fingerprint;
pub mod payloads;
pub mod queries;
pub use fingerprint::MySqlDetector;
