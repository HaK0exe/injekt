#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::todo)]

pub mod ai;
pub mod cli;
pub mod dbms;
pub mod detection;
pub mod engine;
pub mod extraction;
pub mod generation;
pub mod http;
pub mod mcp;
pub mod mutation;
pub mod reasoning;
pub mod recon;
pub mod reporting;
pub mod seeded_rng;
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
        #[error("no target provided. Use --target <URL> or `injekt scan --target <URL>`")]
        NoTarget,
        #[error("http error: {0}")]
        Http(String),
        #[error("detection failed: {0}")]
        Detection(String),
        #[error("extraction failed: {0}")]
        Extraction(String),
        #[error("session error: {0}")]
        Session(String),
        #[error("cancelled")]
        Cancelled,
        #[error("io error: {0}")]
        Io(String),
        #[error(transparent)]
        Other(Box<dyn std::error::Error + Send + Sync + 'static>),
    }

    impl From<std::io::Error> for InjektError {
        fn from(err: std::io::Error) -> Self {
            // Typed (not `Other`): IO failures get the `io error:` prefix in
            // CLI output instead of a bare boxed message.
            Self::Io(err.to_string())
        }
    }

    impl From<reqwest::Error> for InjektError {
        fn from(err: reqwest::Error) -> Self {
            // Typed (not `Other`): transport failures render as
            // `http error: …` like the hand-built `Http` sites.
            Self::Http(err.to_string())
        }
    }

    impl From<serde_json::Error> for InjektError {
        fn from(err: serde_json::Error) -> Self {
            Self::Other(Box::new(err))
        }
    }

    impl From<url::ParseError> for InjektError {
        fn from(err: url::ParseError) -> Self {
            Self::Other(Box::new(err))
        }
    }

    impl From<regex::Error> for InjektError {
        fn from(err: regex::Error) -> Self {
            Self::Other(Box::new(err))
        }
    }

    impl From<chrono::ParseError> for InjektError {
        fn from(err: chrono::ParseError) -> Self {
            Self::Other(Box::new(err))
        }
    }

    impl From<tokio::time::error::Elapsed> for InjektError {
        fn from(err: tokio::time::error::Elapsed) -> Self {
            Self::Other(Box::new(err))
        }
    }

    pub type Result<T, E = InjektError> = core::result::Result<T, E>;
}

#[cfg(test)]
mod tests {
    use super::error::InjektError;

    #[test]
    fn io_conversion_renders_typed_prefix() {
        let err = InjektError::from(std::io::Error::other("disk gone"));
        assert!(matches!(err, InjektError::Io(_)));
        let rendered = format!("{err}");
        assert!(rendered.starts_with("io error:"), "{rendered}");
    }
}
