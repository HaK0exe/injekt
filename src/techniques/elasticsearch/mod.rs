#![deny(unsafe_code)]

pub mod detector;
pub mod payloads;
pub use detector::{ElasticsearchDetector, ElasticsearchResult};
pub use payloads::{ElasticsearchPayload, elasticsearch_payloads};
pub(crate) mod scan;
