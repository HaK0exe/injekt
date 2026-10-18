#![deny(unsafe_code)]

//! Transit/HoneySQL detector: boolean differential + Clojure/HoneySQL/SQL
//! error signatures.

use crate::techniques::boolean::detector::{BooleanDetector, BooleanResult};
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransitChannel {
    Boolean,
    Error,
}

impl core::fmt::Display for TransitChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Boolean => write!(f, "boolean"),
            Self::Error => write!(f, "error"),
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TransitResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub channel: Option<TransitChannel>,
    pub matched_pattern: Option<String>,
}

#[derive(Debug)]
pub struct TransitDetector {
    boolean: BooleanDetector,
}

impl Default for TransitDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TransitDetector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            boolean: BooleanDetector::new(),
        }
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_boolean_with_match_ratio(
        &self,
        baseline_body: &str,
        true_body: &str,
        false_body: &str,
        baseline_ms: f64,
        true_ms: f64,
        false_ms: f64,
        match_ratio: Option<f64>,
    ) -> BooleanResult {
        self.boolean.evaluate_with_match_ratio(
            baseline_body,
            true_body,
            false_body,
            baseline_ms,
            true_ms,
            false_ms,
            match_ratio,
        )
    }

    #[must_use]
    pub fn evaluate_error(&self, body: &str) -> TransitResult {
        // Strong Clojure/HoneySQL/SQL error context. A body merely echoing the
        // payload is not enough.
        let patterns: &[(&str, &str)] = &[
            (r"(?i)clojure", "clojure"),
            (r"(?i)honey", "honeysql"),
            (r"(?i)muuntaja", "muuntaja"),
            (r"(?i)transit", "transit"),
            (r"(?i)sqlstate", "sqlstate"),
            (r"(?i)ora-\d+", "oracle"),
            (r"(?i)psycopg|pg::|postgres", "postgres"),
            (r"(?i)mysql", "mysql"),
            (r"(?i)mssql|sql server", "mssql"),
            (r"(?i)syntax error", "sql_syntax"),
            (r"(?i)exception", "exception"),
        ];
        for (pattern, name) in patterns {
            if let Ok(re) = Regex::new(pattern)
                && re.is_match(body)
            {
                // Require some error-ish context to avoid echo false positives.
                let lowered = body.to_ascii_lowercase();
                if lowered.contains("error")
                    || lowered.contains("exception")
                    || lowered.contains("invalid")
                    || lowered.contains("syntax")
                {
                    return TransitResult {
                        is_vulnerable: true,
                        confidence: 0.8,
                        channel: Some(TransitChannel::Error),
                        matched_pattern: Some((*name).to_owned()),
                    };
                }
            }
        }
        TransitResult {
            is_vulnerable: false,
            confidence: 0.0,
            channel: None,
            matched_pattern: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_error_is_detected() {
        let d = TransitDetector::new();
        let body = "clojure.lang.ExceptionInfo: HoneySQL syntax error";
        let r = d.evaluate_error(body);
        assert!(r.is_vulnerable);
    }

    #[test]
    fn echo_without_context_is_not_detected() {
        let d = TransitDetector::new();
        let body = "you sent: clojure";
        let r = d.evaluate_error(body);
        assert!(!r.is_vulnerable);
    }

    #[test]
    fn boolean_delegates() {
        let d = TransitDetector::new();
        let base = "stable baseline body token";
        let t = "stable baseline body token";
        let f = "totally different body";
        let r = d.evaluate_boolean_with_match_ratio(base, t, f, 10.0, 11.0, 12.0, None);
        assert!(r.true_similarity > 0.0);
    }
}
