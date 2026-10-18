#![deny(unsafe_code)]

//! Minimal encoder for the subset of Transit JSON needed by the structured
//! query-builder probes.
//!
//! This is intentionally not a full Transit implementation. It only supports:
//! - keywords (`~:name`);
//! - strings;
//! - integers;
//! - maps (`["^ ", key, value, ...]`);
//! - vectors (`[elem, ...]`).
//!
//! The output is valid JSON and matches the shape produced by Muuntaja for
//! simple Clojure maps/keywords.

use serde_json;

/// A minimal Transit value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Node {
    /// Clojure keyword.
    Keyword(String),
    /// JSON string.
    Str(String),
    /// Integer.
    Int(i64),
    /// Clojure map.
    Map(Vec<(Node, Node)>),
    /// Clojure vector.
    Vec(Vec<Node>),
}

impl Node {
    /// Render this node as Transit JSON.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Keyword(name) => {
                serde_json::to_string(&format!("~:{name}")).unwrap_or_else(|_| "\"~:x\"".to_owned())
            }
            Self::Str(value) => serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned()),
            Self::Int(value) => value.to_string(),
            Self::Map(entries) => {
                let mut parts = Vec::with_capacity(entries.len() * 2 + 1);
                parts.push("\"^ \"".to_owned()); // placeholder replaced below
                // We build the array manually to keep the exact "^ " marker.
                let mut rendered = String::from("[\"^ \"");
                for (key, value) in entries {
                    rendered.push(',');
                    rendered.push_str(&key.render());
                    rendered.push(',');
                    rendered.push_str(&value.render());
                }
                rendered.push(']');
                let _ = parts;
                rendered
            }
            Self::Vec(items) => {
                let mut rendered = String::from("[");
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        rendered.push(',');
                    }
                    rendered.push_str(&item.render());
                }
                rendered.push(']');
                rendered
            }
        }
    }
}

/// Encode a Clojure keyword.
#[must_use]
pub fn encode_keyword(name: &str) -> Node {
    Node::Keyword(name.to_owned())
}

/// Encode a map from string keys (converted to keywords) and already-encoded
/// node values.
#[must_use]
pub fn encode_map(entries: &[(impl AsRef<str>, Node)]) -> Node {
    Node::Map(
        entries
            .iter()
            .map(|(key, value)| (Node::Keyword(key.as_ref().to_owned()), value.clone()))
            .collect(),
    )
}

/// Encode a vector.
#[must_use]
pub fn encode_vector(items: Vec<Node>) -> Node {
    Node::Vec(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_rendering() {
        assert_eq!(
            Node::Keyword("user-id".to_owned()).render(),
            "\"~:user-id\""
        );
    }

    #[test]
    fn map_rendering_matches_user_example_shape() {
        let node = Node::Map(vec![(
            Node::Keyword("user-id".to_owned()),
            Node::Map(vec![
                (
                    Node::Keyword("from".to_owned()),
                    Node::Vec(vec![Node::Keyword("core_user".to_owned())]),
                ),
                (
                    Node::Keyword("select".to_owned()),
                    Node::Vec(vec![Node::Keyword("password".to_owned())]),
                ),
            ]),
        )]);
        assert_eq!(
            node.render(),
            "[\"^ \",\"~:user-id\",[\"^ \",\"~:from\",[\"~:core_user\"],\"~:select\",[\"~:password\"]]]"
        );
    }

    #[test]
    fn vector_rendering() {
        assert_eq!(
            Node::Vec(vec![Node::Int(1), Node::Int(2)]).render(),
            "[1,2]"
        );
    }

    #[test]
    fn string_rendering_escapes() {
        assert_eq!(Node::Str("a\"b".to_owned()).render(), "\"a\\\"b\"");
    }
}
