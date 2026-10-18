#![deny(unsafe_code)]

pub mod detector;
pub use detector::{GraphqlDetector, GraphqlResult};
pub(crate) mod scan;
