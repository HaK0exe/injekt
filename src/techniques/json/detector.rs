#![deny(unsafe_code)]

//! Dual-channel JSON detector: boolean differential + JSON error signatures.
//!
//! A JSON injection point answers like classic `SQLi` when reached through JSON
//! functions, so detection mirrors `boolean` (TRUE≈baseline, FALSE≠baseline,
//! 3-trial confirmation in the orchestrator) plus an error channel keyed on
//! per-DBMS JSON error strings verified against vendor docs:
//! - MySQL: `Invalid JSON text`
//! - Postgres: `invalid input syntax for type json`
//! - MSSQL: `JSON text is not properly formatted` (Msg 13609)
//! - Oracle: `ORA-40442` (path syntax), `ORA-40454` (path not a literal)

use crate::techniques::boolean::detector::{BooleanDetector, BooleanResult};
use regex::Regex;

/// Which channel confirmed the JSON injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonChannel {
    Boolean,
    Error,
}

impl core::fmt::Display for JsonChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Boolean => write!(f, "boolean"),
            Self::Error => write!(f, "error"),
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JsonResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub dbms: Option<String>,
    pub channel: Option<JsonChannel>,
    pub matched_pattern: Option<String>,
}

#[derive(Debug)]
pub struct JsonDetector {
    boolean: BooleanDetector,
    patterns: Vec<(Regex, String, String)>,
}

impl Default for JsonDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonDetector {
    /// # Panics
    /// Panics if an internal static regex fails to compile (never happens in practice).
    #[must_use]
    pub fn new() -> Self {
        let patterns: Vec<(&str, &str, &str)> = vec![
            (r"invalid json text", "mysql_json", "mysql"),
            (
                r"invalid input syntax for type json",
                "postgres_json",
                "postgres",
            ),
            (
                r"json text is not properly formatted",
                "mssql_json",
                "mssql",
            ),
            (r"ora-40442|ora-40454", "oracle_json_path", "oracle"),
            (
                r"ora-01722.*json|json.*ora-01722",
                "oracle_json_cast",
                "oracle",
            ),
        ];
        let compiled = patterns
            .into_iter()
            .map(|(p, name, dbms)| {
                #[allow(clippy::expect_used)]
                let re = Regex::new(&format!("(?i){p}")).expect("static json pattern regex");
                (re, name.to_owned(), dbms.to_owned())
            })
            .collect();
        Self {
            boolean: BooleanDetector::new(),
            patterns: compiled,
        }
    }

    /// Boolean channel: delegate to the shared boolean differential.
    #[must_use]
    pub fn evaluate_boolean(
        &self,
        baseline_body: &str,
        true_body: &str,
        false_body: &str,
        baseline_ms: f64,
        true_ms: f64,
        false_ms: f64,
    ) -> BooleanResult {
        self.boolean.evaluate(
            baseline_body,
            true_body,
            false_body,
            baseline_ms,
            true_ms,
            false_ms,
        )
    }

    /// Error channel: JSON error signature + error context (avoids FP on pages
    /// merely echoing the payload without a DB error).
    #[must_use]
    pub fn evaluate_error(&self, body: &str) -> JsonResult {
        let lower = body.to_ascii_lowercase();
        let has_context = lower.contains("error")
            || lower.contains("exception")
            || lower.contains("ora-")
            || lower.contains("msg ")
            || lower.contains("sql");
        if !has_context {
            return JsonResult {
                is_vulnerable: false,
                confidence: 0.1,
                dbms: None,
                channel: None,
                matched_pattern: None,
            };
        }
        for (re, name, dbms) in &self.patterns {
            if re.is_match(body) {
                return JsonResult {
                    is_vulnerable: true,
                    confidence: 0.9,
                    dbms: Some(dbms.clone()),
                    channel: Some(JsonChannel::Error),
                    matched_pattern: Some(name.clone()),
                };
            }
        }
        JsonResult {
            is_vulnerable: false,
            confidence: 0.15,
            dbms: None,
            channel: None,
            matched_pattern: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_mysql_json_error() {
        let d = JsonDetector::new();
        let r =
            d.evaluate_error("SQL error: Invalid JSON text in argument 1 to function json_extract");
        assert!(r.is_vulnerable);
        assert_eq!(r.dbms, Some("mysql".to_owned()));
        assert_eq!(r.channel, Some(JsonChannel::Error));
    }

    #[test]
    fn detects_postgres_json_error() {
        let d = JsonDetector::new();
        let r = d.evaluate_error("ERROR: invalid input syntax for type json (SQLSTATE 22P02)");
        assert!(r.is_vulnerable);
        assert_eq!(r.dbms, Some("postgres".to_owned()));
    }

    #[test]
    fn detects_mssql_json_error() {
        let d = JsonDetector::new();
        let r =
            d.evaluate_error("Msg 13609, Level 16, State 2: JSON text is not properly formatted.");
        assert!(r.is_vulnerable);
        assert_eq!(r.dbms, Some("mssql".to_owned()));
    }

    #[test]
    fn detects_oracle_json_path_error() {
        let d = JsonDetector::new();
        let r = d.evaluate_error("ORA-40442: JSON path expression syntax error");
        assert!(r.is_vulnerable);
        assert_eq!(r.dbms, Some("oracle".to_owned()));
    }

    #[test]
    fn echo_without_error_context_is_not_vuln() {
        let d = JsonDetector::new();
        // Page reflects the payload but the DB never errored.
        let r = d.evaluate_error("you searched for json_extract foo, results: none");
        assert!(!r.is_vulnerable);
    }

    #[test]
    fn boolean_channel_matches_shared_detector() {
        let d = JsonDetector::new();
        let baseline = "welcome normal page id=1 content baseline 42";
        let r = d.evaluate_boolean(
            baseline,
            baseline,
            "completely different content — false branch unique marker 99",
            100.0,
            105.0,
            108.0,
        );
        assert!(r.is_vulnerable);
        assert!(r.confidence > 0.6);
    }

    #[test]
    fn boolean_channel_no_fp_on_identical() {
        let d = JsonDetector::new();
        let baseline = "welcome normal page id=1 content baseline 42";
        let r = d.evaluate_boolean(baseline, baseline, baseline, 100.0, 101.0, 102.0);
        assert!(!r.is_vulnerable);
    }
}
