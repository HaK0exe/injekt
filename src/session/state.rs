#![deny(unsafe_code)]

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Technique that produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TechniqueKind {
    Boolean,
    Time,
    Error,
    Union,
    Stacked,
}

impl core::fmt::Display for TechniqueKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Boolean => write!(f, "boolean"),
            Self::Time => write!(f, "time"),
            Self::Error => write!(f, "error"),
            Self::Union => write!(f, "union"),
            Self::Stacked => write!(f, "stacked"),
        }
    }
}

/// A single confirmed finding — kept in RAM only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Finding {
    pub target: String,
    pub parameter: String,
    pub technique: TechniqueKind,
    pub confidence: f64,
    pub dbms: Option<String>,
    pub evidence: String,
    pub timestamp: DateTime<Utc>,
}

impl Finding {
    #[must_use]
    pub fn new(
        target: impl Into<String>,
        parameter: impl Into<String>,
        technique: TechniqueKind,
        confidence: f64,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            target: target.into(),
            parameter: parameter.into(),
            technique,
            confidence,
            dbms: None,
            evidence: evidence.into(),
            timestamp: Utc::now(),
        }
    }
}

/// Session state — RAM only, zeroized on drop.
///
/// ```rust
/// use injekt::session::state::SessionState;
/// let mut s = SessionState::new();
/// s.increment_requests();
/// assert_eq!(s.request_count(), 1);
/// ```
#[derive(Debug, Default)]
pub struct SessionState {
    #[allow(dead_code)]
    findings: Vec<Finding>,
    // SecretString already zeroizes; we keep count and wipe on drop.
    extracted: Vec<SecretString>,
    request_count: u64,
    started_at: Option<DateTime<Utc>>,
}

impl Zeroize for SessionState {
    fn zeroize(&mut self) {
        self.findings.clear();
        self.extracted.zeroize();
        self.extracted.clear();
        self.request_count.zeroize();
        self.started_at = None;
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SessionState {}

impl SessionState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            extracted: Vec::new(),
            request_count: 0,
            started_at: Some(Utc::now()),
        }
    }

    pub fn push_finding(&mut self, f: Finding) {
        self.findings.push(f);
    }

    pub fn push_extracted(&mut self, s: SecretString) {
        self.extracted.push(s);
    }

    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    #[must_use]
    pub fn findings_mut(&mut self) -> &mut Vec<Finding> {
        &mut self.findings
    }

    /// Fill `None` dbms with guessed kind (e.g., from fingerprint).
    pub fn fill_missing_dbms(&mut self, kind: crate::dbms::DbmsKind) {
        let s = kind.to_string();
        if s == "unknown" {
            return;
        }
        for f in &mut self.findings {
            if f.dbms.is_none() {
                f.dbms = Some(s.clone());
            }
        }
    }

    #[must_use]
    pub fn extracted_count(&self) -> usize {
        self.extracted.len()
    }

    /// Returns cloned secrets — caller must handle sensitivity.
    #[must_use]
    pub fn extracted_exposed(&self) -> Vec<String> {
        self.extracted
            .iter()
            .map(|s| s.expose_secret().to_owned())
            .collect()
    }

    pub fn increment_requests(&mut self) {
        self.request_count = self.request_count.wrapping_add(1);
    }

    #[must_use]
    pub fn request_count(&self) -> u64 {
        self.request_count
    }

    #[must_use]
    pub fn started_at(&self) -> Option<DateTime<Utc>> {
        self.started_at
    }

    /// Wipe all sensitive data immediately.
    pub fn wipe(&mut self) {
        self.findings.clear();
        self.extracted.zeroize();
        self.extracted.clear();
        self.request_count = 0;
    }
}

// Manual Clone not derived because ZeroizeOnDrop + SecretString.
impl Clone for SessionState {
    fn clone(&self) -> Self {
        Self {
            findings: self.findings.clone(),
            extracted: self
                .extracted
                .iter()
                .map(|s| SecretString::from(s.expose_secret().to_owned()))
                .collect(),
            request_count: self.request_count,
            started_at: self.started_at,
        }
    }
}
