#![deny(unsafe_code)]

pub mod detector;
pub mod payloads;
pub use detector::{OrmDetector, OrmResult};
pub use payloads::{OrmPayload, orm_payloads};
pub(crate) mod scan;
