use regex::Regex;
use secrecy::SecretString;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ErrorResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub matched_pattern: Option<String>,
    /// Extracted version/error fragment — secret by design (`SecretString`,
    /// zeroized on drop). Never log raw; use
    /// `crate::session::scrubber::Scrubber::hash_truncated` for traceability
    /// and `Finding::scrubbed` / `push_extracted` for persistence.
    pub extracted: Option<SecretString>,
}

#[derive(Debug)]
pub struct ErrorDetector {
    pub(super) patterns: Vec<(Regex, String)>,
}

impl Default for ErrorDetector {
    fn default() -> Self {
        Self::new()
    }
}
