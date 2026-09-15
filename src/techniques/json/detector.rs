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
}

impl Default for JsonDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// JSON error signatures compiled once and shared by all detector instances
/// (was `Regex::new` per `JsonDetector::new()`).
fn json_patterns() -> &'static [(Regex, &'static str, &'static str)] {
    use std::sync::OnceLock;
    static CELL: OnceLock<Vec<(Regex, &'static str, &'static str)>> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw: &[(&str, &str, &str)] = &[
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
        raw.iter()
            .filter_map(|(p, name, dbms)| {
                Regex::new(&format!("(?i){p}"))
                    .ok()
                    .map(|re| (re, *name, *dbms))
            })
            .collect()
    })
}

/// Extract DB error texts passthrough-wrapped in a JSON / GraphQL envelope.
///
/// GraphQL servers wrap backend failures as `{"errors":[{"message": ...}]}`
/// and REST APIs as `{"error":{"sqlMessage": ...}}` — the classic DB error
/// string survives verbatim inside the envelope but the raw body no longer
/// looks like a classic error page. Returns the collected message strings
/// (empty when the body is not JSON or carries no error envelope). Never
/// panics; parse failures yield an empty vec.
#[must_use]
pub fn extract_json_error_texts(body: &str) -> Vec<String> {
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    // `{"errors":[...]}` (GraphQL envelope).
    if let Some(errors) = value.get("errors").and_then(serde_json::Value::as_array) {
        for item in errors {
            push_error_strings(item, &mut out);
        }
    }
    // `{"error":{...}}` (REST envelope).
    if let Some(err) = value.get("error") {
        push_error_strings(err, &mut out);
    }
    // Root `message` only counts inside an error envelope (avoids scoring
    // benign `{"message":"ok"}` — the context guard below would reject it
    // anyway, this just keeps the extract clean).
    if (value.get("errors").is_some() || value.get("error").is_some())
        && let Some(msg) = value.get("message").and_then(serde_json::Value::as_str)
    {
        out.push(msg.to_owned());
    }
    out
}

/// Collect message-ish strings from one envelope node: `message`,
/// `sqlMessage`, and `extensions(.exception).sqlMessage/message`.
fn push_error_strings(node: &serde_json::Value, out: &mut Vec<String>) {
    if let Some(s) = node.as_str() {
        out.push(s.to_owned());
        return;
    }
    let Some(obj) = node.as_object() else {
        return;
    };
    for key in ["message", "sqlMessage", "sql_message"] {
        if let Some(s) = obj.get(key).and_then(serde_json::Value::as_str) {
            out.push(s.to_owned());
        }
    }
    if let Some(ext) = obj.get("extensions") {
        if let Some(ext_obj) = ext.as_object() {
            for key in ["message", "sqlMessage", "sql_message"] {
                if let Some(s) = ext_obj.get(key).and_then(serde_json::Value::as_str) {
                    out.push(s.to_owned());
                }
            }
            if let Some(exc) = ext_obj.get("exception") {
                if let Some(exc_obj) = exc.as_object() {
                    for key in ["message", "sqlMessage", "sql_message"] {
                        if let Some(s) = exc_obj.get(key).and_then(serde_json::Value::as_str) {
                            out.push(s.to_owned());
                        }
                    }
                } else if let Some(s) = exc.as_str() {
                    out.push(s.to_owned());
                }
            }
        } else if let Some(s) = ext.as_str() {
            out.push(s.to_owned());
        }
    }
}

/// Classic DB-error passthrough inside an extracted envelope text
/// (lowercased): `(needle, dbms, pattern)`. Substring matching on purpose —
/// the marker set is fixed and small, and envelope texts are short.
const PASSTHROUGH_MARKERS: &[(&str, &str, &str)] = &[
    ("xpath syntax error", "mysql", "graphql_passthrough_mysql"),
    ("sql syntax", "mysql", "graphql_passthrough_mysql"),
    ("invalid json text", "mysql", "graphql_passthrough_mysql"),
    (
        "invalid input syntax",
        "postgres",
        "graphql_passthrough_postgres",
    ),
    ("pg_query", "postgres", "graphql_passthrough_postgres"),
    ("msg 245", "mssql", "graphql_passthrough_mssql"),
    ("msg 8114", "mssql", "graphql_passthrough_mssql"),
    ("conversion failed", "mssql", "graphql_passthrough_mssql"),
    (
        "unclosed quotation mark",
        "mssql",
        "graphql_passthrough_mssql",
    ),
    ("ora-", "oracle", "graphql_passthrough_oracle"),
    ("unrecognized token", "sqlite", "graphql_passthrough_sqlite"),
    ("sqlite_error", "sqlite", "graphql_passthrough_sqlite"),
    ("queryexception", "", "graphql_passthrough_framework"),
    ("statementinvalid", "", "graphql_passthrough_framework"),
    ("sqlexception", "", "graphql_passthrough_framework"),
];

impl JsonDetector {
    #[must_use]
    pub fn new() -> Self {
        // Touch the static so a broken pattern surfaces early in tests
        // (empty table = error channel inert, never a panic).
        let _ = json_patterns();
        Self {
            boolean: BooleanDetector::new(),
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
    /// merely echoing the payload without a DB error). Falls back to the
    /// envelope passthrough: classic DB errors wrapped in
    /// `{"errors":[{"message":...}]}` / `{"error":{"sqlMessage":...}}`
    /// (GraphQL/REST) are matched on the extracted texts.
    #[must_use]
    pub fn evaluate_error(&self, body: &str) -> JsonResult {
        if let Some(hit) = Self::match_error_text(body) {
            return hit;
        }
        // Passthrough: match the envelope texts, not the JSON framing.
        let texts = extract_json_error_texts(body);
        if texts.is_empty() {
            return Self::no_finding(if has_error_context(body) { 0.15 } else { 0.1 });
        }
        let joined = texts.join("\n");
        if let Some(hit) = Self::match_error_text(&joined) {
            return hit;
        }
        if let Some(passthrough) = match_passthrough(&joined) {
            return passthrough;
        }
        Self::no_finding(0.15)
    }

    /// Direct JSON-function signature match on one text (raw body or joined
    /// envelope extracts). Returns `None` when nothing matches.
    fn match_error_text(text: &str) -> Option<JsonResult> {
        if !has_error_context(text) {
            return None;
        }
        for (re, name, dbms) in json_patterns() {
            if re.is_match(text) {
                return Some(JsonResult {
                    is_vulnerable: true,
                    confidence: 0.9,
                    dbms: Some((*dbms).to_owned()),
                    channel: Some(JsonChannel::Error),
                    matched_pattern: Some((*name).to_owned()),
                });
            }
        }
        None
    }

    fn no_finding(confidence: f64) -> JsonResult {
        JsonResult {
            is_vulnerable: false,
            confidence,
            dbms: None,
            channel: None,
            matched_pattern: None,
        }
    }
}

/// Error-context guard shared by the direct and passthrough channels.
#[must_use]
pub fn has_error_context(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("error")
        || lower.contains("exception")
        || lower.contains("ora-")
        || lower.contains("msg ")
        || lower.contains("sql")
}

/// Classic DB-error passthrough on lowercased envelope text. Wrapped errors
/// score 0.85 (just under a direct JSON-function signature at 0.9).
fn match_passthrough(joined: &str) -> Option<JsonResult> {
    let lower = joined.to_ascii_lowercase();
    // `"sql syntax"` alone is too broad (any ORM message) — require mysql.
    let mut scoped = lower.clone();
    if lower.contains("sql syntax") && !lower.contains("mysql") {
        scoped = scoped.replace("sql syntax", "sql-syntax");
    }
    for (needle, dbms, pattern) in PASSTHROUGH_MARKERS {
        if scoped.contains(needle) {
            return Some(JsonResult {
                is_vulnerable: true,
                confidence: 0.85,
                dbms: (!dbms.is_empty()).then(|| (*dbms).to_owned()),
                channel: Some(JsonChannel::Error),
                matched_pattern: Some((*pattern).to_owned()),
            });
        }
    }
    None
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
    fn graphql_errors_message_passthrough_mysql() {
        let d = JsonDetector::new();
        let body = r#"{"errors":[{"message":"You have an error in your SQL syntax; check the manual for MySQL near '\"'"}]}"#;
        let r = d.evaluate_error(body);
        assert!(r.is_vulnerable, "{r:?}");
        assert_eq!(r.dbms, Some("mysql".to_owned()));
        assert_eq!(r.channel, Some(JsonChannel::Error));
    }

    #[test]
    fn graphql_errors_message_passthrough_postgres() {
        let d = JsonDetector::new();
        let body =
            r#"{"errors":[{"message":"ERROR: invalid input syntax for type integer: \"abc\""}]}"#;
        let r = d.evaluate_error(body);
        assert!(r.is_vulnerable, "{r:?}");
        assert_eq!(r.dbms, Some("postgres".to_owned()));
    }

    #[test]
    fn rest_sql_message_passthrough() {
        let d = JsonDetector::new();
        let body = r#"{"error":{"sqlMessage":"XPATH syntax error: '~5.7~'"}}"#;
        let r = d.evaluate_error(body);
        assert!(r.is_vulnerable, "{r:?}");
        assert_eq!(r.dbms, Some("mysql".to_owned()));
    }

    #[test]
    fn graphql_extensions_sql_message_passthrough_oracle() {
        let d = JsonDetector::new();
        let body = r#"{"errors":[{"message":"fetch failed","extensions":{"exception":{"sqlMessage":"ORA-01722: invalid number"}}}]}"#;
        let r = d.evaluate_error(body);
        assert!(r.is_vulnerable, "{r:?}");
        assert_eq!(r.dbms, Some("oracle".to_owned()));
    }

    #[test]
    fn benign_graphql_data_is_not_vuln() {
        let d = JsonDetector::new();
        let r = d.evaluate_error(r#"{"data":{"node":{"id":"1"}}}"#);
        assert!(!r.is_vulnerable, "{r:?}");
        let r2 = d.evaluate_error(r#"{"errors":[{"message":"field 'node' not found"}]}"#);
        assert!(!r2.is_vulnerable, "{r2:?}");
    }

    #[test]
    fn extract_envelope_texts() {
        let texts = extract_json_error_texts(
            r#"{"errors":[{"message":"boom","extensions":{"sqlMessage":"ORA-1"}}]}"#,
        );
        assert!(texts.iter().any(|t| t == "boom"), "{texts:?}");
        assert!(texts.iter().any(|t| t == "ORA-1"), "{texts:?}");
        assert!(extract_json_error_texts("not json {{{").is_empty());
        assert!(extract_json_error_texts(r#"{"data":{"a":1}}"#).is_empty());
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
