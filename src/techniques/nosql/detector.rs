#![deny(unsafe_code)]

//! Détecteur `NoSQL` (MongoDB) double canal : différentiel booléen + erreurs.
//!
//! Le canal booléen réutilise le différentiel partagé (`TRUE≈baseline`,
//! `FALSE≠baseline`, confirmation 3 essais dans l'orchestrateur) : un bypass
//! `{"$gt": ""}` répond comme un `OR 1=1` classique quand l'opérateur est
//! interprété par MongoDB.
//!
//! Le canal erreur scrute les messages MongoDB documentés :
//! - `MongoError` / `MongoServerError` (enveloppe générique)
//! - `unknown operator` (sonde `$invalidOpInjekt`)
//! - `BSON` / `invalid BSON` / `FailedToParse` (document malformé)
//! - `$where` + `SyntaxError` / `ReferenceError` (JS invalide)
//! - `CastError` / `Cast to` (mongoose : type inattendu)
//! - `Plan executor error` (requête abortée côté serveur)

use crate::techniques::boolean::detector::{BooleanDetector, BooleanResult};
use regex::Regex;

/// Canal ayant confirmé l'injection `NoSQL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NosqlChannel {
    Boolean,
    Error,
}

impl core::fmt::Display for NosqlChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Boolean => write!(f, "boolean"),
            Self::Error => write!(f, "error"),
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NosqlResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub channel: Option<NosqlChannel>,
    pub matched_pattern: Option<String>,
}

#[derive(Debug)]
pub struct NosqlDetector {
    boolean: BooleanDetector,
}

impl Default for NosqlDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Signatures d'erreur MongoDB compilées une fois et partagées.
fn nosql_patterns() -> &'static [(Regex, &'static str)] {
    use std::sync::OnceLock;
    static CELL: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw: &[(&str, &str)] = &[
            (r"unknown operator", "mongo_unknown_operator"),
            (r"mongoerror|mongoservererror", "mongo_error"),
            (r"invalid bson|failedtoparse|bson.*error", "mongo_bson"),
            (
                r"\$where.*(syntaxerror|referenceerror)|syntaxerror.*\$where",
                "mongo_where_js",
            ),
            (r"casterror|cast to.*failed|cast to.*bson", "mongo_cast"),
            (r"plan executor error", "mongo_executor"),
        ];
        raw.iter()
            .filter_map(|(p, name)| Regex::new(&format!("(?i){p}")).ok().map(|re| (re, *name)))
            .collect()
    })
}

impl NosqlDetector {
    #[must_use]
    pub fn new() -> Self {
        let _ = nosql_patterns();
        Self {
            boolean: BooleanDetector::new(),
        }
    }

    /// Canal booléen : délègue au différentiel partagé.
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

    /// Canal erreur : signature MongoDB + contexte d'erreur (évite les FP
    /// sur les pages qui se contentent de refléter la sonde sans erreur DB).
    #[must_use]
    pub fn evaluate_error(&self, body: &str) -> NosqlResult {
        let lower = body.to_ascii_lowercase();
        let has_context = lower.contains("error")
            || lower.contains("exception")
            || lower.contains("mongo")
            || lower.contains("bson")
            || lower.contains("e11000")
            || lower.contains("server error")
            || lower.contains("syntaxerror")
            || lower.contains("referenceerror");
        if !has_context {
            return NosqlResult {
                is_vulnerable: false,
                confidence: 0.1,
                channel: None,
                matched_pattern: None,
            };
        }
        for (re, name) in nosql_patterns() {
            if re.is_match(body) {
                return NosqlResult {
                    is_vulnerable: true,
                    confidence: 0.9,
                    channel: Some(NosqlChannel::Error),
                    matched_pattern: Some((*name).to_owned()),
                };
            }
        }
        NosqlResult {
            is_vulnerable: false,
            confidence: 0.15,
            channel: None,
            matched_pattern: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_unknown_operator() {
        let d = NosqlDetector::new();
        let r = d.evaluate_error("MongoServerError: unknown operator: $invalidOpInjekt");
        assert!(r.is_vulnerable);
        assert_eq!(r.channel, Some(NosqlChannel::Error));
    }

    #[test]
    fn detects_where_js_syntax_error() {
        let d = NosqlDetector::new();
        let r = d.evaluate_error("SyntaxError in $where clause: unexpected token");
        assert!(r.is_vulnerable);
    }

    #[test]
    fn detects_bson_error() {
        let d = NosqlDetector::new();
        let r = d.evaluate_error("BSON error: FailedToParse: invalid document");
        assert!(r.is_vulnerable);
    }

    #[test]
    fn echo_without_error_context_is_not_vuln() {
        let d = NosqlDetector::new();
        let r = d.evaluate_error("you searched for {\"$gt\": \"\"}, results: none");
        assert!(!r.is_vulnerable);
    }

    #[test]
    fn boolean_channel_matches_shared_detector() {
        let d = NosqlDetector::new();
        let baseline = "welcome normal page user=admin content baseline 42";
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
        let d = NosqlDetector::new();
        let baseline = "welcome normal page user=admin content baseline 42";
        let r = d.evaluate_boolean(baseline, baseline, baseline, 100.0, 101.0, 102.0);
        assert!(!r.is_vulnerable);
    }
}
