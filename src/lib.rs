#![deny(unsafe_code)]
#![allow(clippy::pedantic)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

pub mod cli;
pub mod dbms;
pub mod detection;
pub mod engine;
pub mod extraction;
pub mod http;
pub mod recon;
pub mod reporting;
pub mod session;
pub mod target;
pub mod techniques;

/// Crate-wide error type.
pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    #[non_exhaustive]
    pub enum InjektError {
        #[error("invalid target: {0}")]
        InvalidTarget(String),
        #[error("http error: {0}")]
        Http(String),
        #[error("detection failed: {0}")]
        Detection(String),
        #[error("extraction failed: {0}")]
        Extraction(String),
        #[error("session error: {0}")]
        Session(String),
        #[error("io error: {0}")]
        Io(String),
        #[error(transparent)]
        Other(#[from] anyhow::Error),
    }

    pub type Result<T, E = InjektError> = core::result::Result<T, E>;
}
