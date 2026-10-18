#![deny(unsafe_code)]

//! Non-destructive Transit/HoneySQL probes.

use super::encoder::{Node, encode_keyword, encode_map, encode_vector};
use serde_json::Value;

/// A non-destructive Transit probe.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TransitPayload {
    /// Stable probe name.
    pub name: String,
    /// Rendered Transit JSON body.
    pub body: String,
    /// Optional expected SQL shape for documentation/tests.
    pub expected_sql_shape: Option<String>,
}

impl TransitPayload {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        body: impl Into<String>,
        expected_sql_shape: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
            expected_sql_shape,
        }
    }
}

/// Minimal non-destructive probe set.
#[must_use]
pub fn transit_payloads() -> Vec<TransitPayload> {
    let select_one = encode_map(&[(
        "user-id",
        Node::Map(vec![(
            encode_keyword("select"),
            encode_vector(vec![Node::Int(1)]),
        )]),
    )])
    .render();

    let select_zero = encode_map(&[(
        "user-id",
        Node::Map(vec![(
            encode_keyword("select"),
            encode_vector(vec![Node::Int(0)]),
        )]),
    )])
    .render();

    let select_with_from = encode_map(&[(
        "user-id",
        Node::Map(vec![
            (encode_keyword("select"), encode_vector(vec![Node::Int(1)])),
            (
                encode_keyword("from"),
                encode_vector(vec![encode_keyword("dual")]),
            ),
        ]),
    )])
    .render();

    vec![
        TransitPayload::new("select-one", select_one, Some("(SELECT 1)".to_owned())),
        TransitPayload::new("select-zero", select_zero, Some("(SELECT 0)".to_owned())),
        TransitPayload::new(
            "select-with-from",
            select_with_from,
            Some("SELECT 1 FROM dual".to_owned()),
        ),
    ]
}

/// Helper kept for future use; currently unused but documents the intended
/// Clojure keyword encoding.
#[must_use]
pub fn encode_keyword_string(name: &str) -> String {
    format!("~:{name}")
}

/// Avoid unused import warnings in minimal builds.
#[allow(dead_code)]
fn _use_value(_: Value) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_non_empty_and_distinct() {
        let v = transit_payloads();
        assert!(!v.is_empty());
        for p in &v {
            assert_ne!(p.name, "");
            assert_ne!(p.body, "");
            assert!(p.body.starts_with('['));
        }
        assert_ne!(v[0].body, v[1].body);
    }

    #[test]
    fn select_one_shape() {
        let v = transit_payloads();
        assert!(v[0].body.contains("~:select"));
        assert!(v[0].body.contains('1'));
    }

    #[test]
    fn keyword_string_helper() {
        assert_eq!(encode_keyword_string("foo"), "~:foo");
    }
}
