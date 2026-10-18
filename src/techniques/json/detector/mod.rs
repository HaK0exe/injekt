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
use self::patterns::json_patterns;

mod patterns;

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
        self.evaluate_boolean_with_match_ratio(
            baseline_body,
            true_body,
            false_body,
            baseline_ms,
            true_ms,
            false_ms,
            None,
        )
    }

    /// Boolean channel with the learned noise floor (P1.2): same differential
    /// as [`Self::evaluate_boolean`], plus `noise_vetoed` exposure so callers
    /// deciding on raw `Trial`s can translate a vetoed pair into a neutral
    /// trial. `None` keeps the historical verdict exactly.
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
