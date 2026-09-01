#![deny(unsafe_code)]

pub mod crawler;
pub mod discovery;
pub mod filters;
pub mod parameter;

pub use crawler::{CrawlConfig, CrawlReport, Crawler};
pub use parameter::{CandidateMethod, FormContext, ParamType, ParameterCandidate};
