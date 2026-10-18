#![deny(unsafe_code)]

//! Transit JSON / `HoneySQL` structured query-builder injection (proposed).
//!
//! See `docs/adr/0009-transit-honeysql.md`.

pub mod detector;
pub mod encoder;
pub mod payloads;
pub(crate) mod scan;

pub use detector::{TransitChannel, TransitDetector, TransitResult};
pub use encoder::{Node, encode_keyword, encode_map, encode_vector};
pub use payloads::{TransitPayload, transit_payloads};
