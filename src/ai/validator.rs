#![deny(unsafe_code)]

//! Validation locale des paires suggérées par LLM — bloquante, 0 requête
//! cible si échec.
//!
//! Garanties avant tout envoi vers la cible :
//! - paire TRUE/FALSE non vide, distincte, de forme booléenne (`OR`/`AND`) ;
//! - longueur bornée (anti-flood) ;
//! - charset SQL whitelist (pas d'échappement de contexte : backslash,
//!   retours ligne, unicode louche rejetés) ;
//! - blacklist stacked/RCE/time déguisé (le second-pass IA est booléen
//!   uniquement : `;`, `xp_`, `EXEC`, `OUTFILE`/`LOAD_FILE`/`DUMPFILE`,
//!   `SLEEP`/`PG_SLEEP`/`WAITFOR`/`BENCHMARK`/`DBMS_PIPE` rejetés) ;
//! - équivalent `is_boolean_safe` : rejet des transforms qui effondrent le
//!   différentiel (base64-opaque, quote-escaped inerte) ;
//! - dédup contre les payloads déjà essayés (hash set session).
//!
//! Les payloads ne sont jamais loggés en clair : l'appelant trace des
//! hashes (`ai:<provider>+<n>`, voir [`crate::ai::ai_plan_label`]).

use std::collections::HashSet;
use thiserror::Error;

/// Longueur maximale d'une branche (anti-flood, anti-WAF-spray large).
pub const MAX_AI_BRANCH_LEN: usize = 512;

/// Paire validée, prête à sonder (TRUE puis FALSE, même shape).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ValidatedPair {
    /// Branche TRUE.
    pub true_payload: String,
    /// Branche FALSE (même shape, flip minimal).
    pub false_payload: String,
}

/// Motif de rejet (jamais de payload en clair dans le message).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidatorError {
    /// Branche vide après trim.
    #[error("empty branch")]
    Empty,
    /// Branche trop longue (`> MAX_AI_BRANCH_LEN`).
    #[error("branch too long")]
    TooLong,
    /// TRUE == FALSE (différentiel effondré).
    #[error("collapsed pair")]
    Collapsed,
    /// Pas de forme booléenne (`OR`/`AND` absents des deux branches).
    #[error("not a boolean pair")]
    NotBoolean,
    /// Caractère hors whitelist.
    #[error("forbidden char")]
    ForbiddenChar,
    /// Motif stacked/RCE/time déguisé.
    #[error("forbidden pattern")]
    ForbiddenPattern,
    /// Transform inerte/opaque (différentiel indistinguable).
    #[error("inert transform")]
    Inert,
    /// Déjà sondé (dédup session).
    #[error("duplicate")]
    Duplicate,
}

/// Valide une paire suggérée. `already_tried` contient les payloads (TRUE et
/// FALSE) déjà sondés ce run (strings exactes) pour la dédup.
///
/// Pure, 0 I/O. Ne loggue jamais les payloads (l'appelant trace des hashes).
///
/// # Errors
/// Retourne un [`ValidatorError`] quand la paire est vide, trop longue,
/// effondrée, non booléenne, hors charset, à motif interdit, inerte ou
/// déjà sondée.
pub fn validate_ai_pair<S: std::hash::BuildHasher>(
    true_branch: &str,
    false_branch: &str,
    already_tried: &HashSet<String, S>,
) -> Result<ValidatedPair, ValidatorError> {
    let t = true_branch.trim();
    let f = false_branch.trim();
    if t.is_empty() || f.is_empty() {
        return Err(ValidatorError::Empty);
    }
    if t.len() > MAX_AI_BRANCH_LEN || f.len() > MAX_AI_BRANCH_LEN {
        return Err(ValidatorError::TooLong);
    }
    if t == f {
        return Err(ValidatorError::Collapsed);
    }
    // Diagnostics sécurité d'abord (motif stacked/RCE, transform inerte),
    // forme booléenne ensuite : un `; DROP` sans `OR` reste un
    // `ForbiddenPattern`, un base64-opaque sans mot-clé reste `Inert`.
    if has_forbidden_pattern(t) || has_forbidden_pattern(f) {
        return Err(ValidatorError::ForbiddenPattern);
    }
    if is_inert(t) || is_inert(f) {
        return Err(ValidatorError::Inert);
    }
    if !looks_boolean(t) || !looks_boolean(f) {
        return Err(ValidatorError::NotBoolean);
    }
    if let Some(c) = first_forbidden_char(t).or_else(|| first_forbidden_char(f)) {
        let _ = c;
        return Err(ValidatorError::ForbiddenChar);
    }
    if already_tried.contains(t) || already_tried.contains(f) {
        return Err(ValidatorError::Duplicate);
    }
    Ok(ValidatedPair {
        true_payload: t.to_owned(),
        false_payload: f.to_owned(),
    })
}

/// Forme booléenne minimale : contient `OR` ou `AND` comme mot (insensible
/// à la casse). Les deux branches doivent la partager pour garder le
/// différentiel interprétable par `BooleanDetector`.
fn looks_boolean(branch: &str) -> bool {
    let upper = branch.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let has_word = |needle: &[u8]| {
        bytes.windows(needle.len()).enumerate().any(|(i, w)| {
            if w != needle {
                return false;
            }
            let before = if i == 0 { None } else { Some(bytes[i - 1]) };
            let after = bytes.get(i + needle.len()).copied();
            let boundary =
                |c: Option<u8>| c.is_none_or(|b| !(b.is_ascii_alphanumeric() || b == b'_'));
            boundary(before) && boundary(after)
        })
    };
    has_word(b"OR") || has_word(b"AND")
}

/// Whitelist : alphanum + ponctuation SQL du second-pass booléen.
/// Autorisé : ` _'\"()=,*/#%+-.!<>` + backtick (identifiant MySQL) + tab et
/// newline (séparateurs natifs génératifs, `%09`/`%0A` sur le fil ; jamais
/// loggés en clair). Refusés : `&|:?;` (entités, casts, URLs ; le `;`
/// stacked est couvert par `ForbiddenPattern` avec un meilleur diagnostic).
fn is_allowed_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            ' ' | '\t'
                | '\n'
                | '_'
                | '\''
                | '"'
                | '('
                | ')'
                | '='
                | ','
                | '*'
                | '/'
                | '#'
                | '%'
                | '+'
                | '-'
                | '.'
                | '!'
                | '<'
                | '>'
                | '`'
        )
}

fn first_forbidden_char(branch: &str) -> Option<char> {
    branch.chars().find(|c| !is_allowed_char(*c))
}

/// Blacklist stacked/RCE/time (insensible à la casse, match substring —
/// volontairement large : le second-pass IA est booléen uniquement).
/// Vérifiée AVANT forme et charset pour un diagnostic précis (`; DROP` sans
/// `OR` reste un stacked, pas un simple non-booléen) ; le terminateur
/// légitime `;/*` vient des tampers locaux, jamais du LLM.
fn has_forbidden_pattern(branch: &str) -> bool {
    const PATTERNS: &[&str] = &[
        ";",
        "xp_",
        "exec",
        "outfile",
        "load_file",
        "dumpfile",
        "sleep",
        "pg_sleep",
        "waitfor",
        "benchmark",
        "dbms_pipe",
        "utl_http",
        "utl_inaddr",
        "load_extension",
    ];
    let lower = branch.to_ascii_lowercase();
    PATTERNS.iter().any(|p| lower.contains(p))
}

/// Transforms qui effondrent le différentiel même avec `true != false` :
/// - quote-escaped inerte (`\u0027`/`\u0022` : plus de quote à fermer, les
///   deux branches sont également fausses) ;
/// - base64-opaque (alphabet `[A-Za-z0-9+/=]` seul, longueur ≥ 32, sans
///   mot-clé SQL : le backend ne décode pas, TRUE≈FALSE).
fn is_inert(branch: &str) -> bool {
    if branch.contains("\\u0027") || branch.contains("\\u0022") {
        return true;
    }
    looks_base64_opaque(branch)
}

fn looks_base64_opaque(branch: &str) -> bool {
    let t = branch.trim();
    if t.len() < 32 {
        return false;
    }
    let b64 = t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if !b64 {
        return false;
    }
    let upper = t.to_ascii_uppercase();
    !upper.contains("OR") && !upper.contains("AND") && !upper.contains("SELECT")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn empty_tried() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn accepts_canonical_pair() {
        let r = validate_ai_pair("' OR 1=1 -- -", "' OR 1=2 -- -", &empty_tried());
        assert!(r.is_ok());
        let p = r.unwrap_or_else(|_| ValidatedPair {
            true_payload: String::new(),
            false_payload: String::new(),
        });
        assert_eq!(p.true_payload, "' OR 1=1 -- -");
        assert_eq!(p.false_payload, "' OR 1=2 -- -");
    }

    #[test]
    fn rejects_empty_and_too_long() {
        assert_eq!(
            validate_ai_pair("", "' OR 1=2 -- -", &empty_tried()),
            Err(ValidatorError::Empty)
        );
        assert_eq!(
            validate_ai_pair("' OR 1=1 -- -", "   ", &empty_tried()),
            Err(ValidatorError::Empty)
        );
        let big = format!("' OR {} -- -", "1".repeat(MAX_AI_BRANCH_LEN));
        assert_eq!(
            validate_ai_pair(&big, "' OR 1=2 -- -", &empty_tried()),
            Err(ValidatorError::TooLong)
        );
    }

    #[test]
    fn rejects_collapsed_and_non_boolean() {
        assert_eq!(
            validate_ai_pair("' OR 1=1 -- -", "' OR 1=1 -- -", &empty_tried()),
            Err(ValidatorError::Collapsed)
        );
        assert_eq!(
            validate_ai_pair("hello world", "hello mars", &empty_tried()),
            Err(ValidatorError::NotBoolean)
        );
        // Une seule branche booléenne ne suffit pas.
        assert_eq!(
            validate_ai_pair("' OR 1=1 -- -", "just a string", &empty_tried()),
            Err(ValidatorError::NotBoolean)
        );
    }

    #[test]
    fn rejects_forbidden_chars() {
        // Backslash, unicode, `&|:?;` refusés (`\n` et `\t` sont des
        // séparateurs légitimes, couverts par l'acceptation ci-dessous).
        for bad in [
            "' OR 1=1\\ -- -",
            "' OR 1=1é -- -",
            "' OR 1=1& -- -",
            "' OR 1=1| -- -",
            "' OR 1=1: -- -",
            "' OR 1=1? -- -",
        ] {
            assert_eq!(
                validate_ai_pair(bad, "' OR 1=2 -- -", &empty_tried()),
                Err(ValidatorError::ForbiddenChar),
                "bad={bad:?}"
            );
        }
        // Backtick MySQL accepté.
        assert!(validate_ai_pair("` OR 1=1 -- -", "` OR 1=2 -- -", &empty_tried()).is_ok());
        // Séparateurs natifs tab/newline acceptés (jamais loggés en clair).
        assert!(validate_ai_pair("'\tOR\t1=1 -- -", "'\tOR\t1=2 -- -", &empty_tried()).is_ok());
        assert!(validate_ai_pair("'\nOR\n1=1 -- -", "'\nOR\n1=2 -- -", &empty_tried()).is_ok());
        // `/**/` inline accepté.
        assert!(
            validate_ai_pair("'/**/OR/**/1=1 -- -", "'/**/OR/**/1=2 -- -", &empty_tried()).is_ok()
        );
    }

    #[test]
    fn rejects_stacked_rce_and_time() {
        for bad in [
            "' OR 1=1; DROP TABLE users -- -",
            "' OR 1=1 xp_cmdshell -- -",
            "' OR 1=1 EXEC sp_help -- -",
            "' OR 1=1 OUTFILE -- -",
            "' OR 1=1 LOAD_FILE -- -",
            "' OR SLEEP(5) -- -",
            "' OR pg_sleep(5) -- -",
            "' OR 1=1 WAITFOR -- -",
            "' OR BENCHMARK(1) -- -",
        ] {
            assert_eq!(
                validate_ai_pair("' OR 1=1 -- -", bad, &empty_tried()),
                Err(ValidatorError::ForbiddenPattern),
                "bad={bad:?}"
            );
        }
    }

    #[test]
    fn rejects_inert_transforms() {
        // JSON-unicode escape : plus de quote à fermer.
        assert_eq!(
            validate_ai_pair("\\u0027 OR 1=1 -- -", "\\u0027 OR 1=2 -- -", &empty_tried()),
            Err(ValidatorError::Inert)
        );
        // Base64-opaque long sans mot-clé.
        let opaque_true = "JyBPUiAxPTEgLS0gLQAAAAAAAAAAAAAAAAAAAAAAAAAA==";
        let opaque_false = "JyBPUiAxPTIgLS0gLQAAAAAAAAAAAAAAAAAAAAAAAAAA==";
        assert_eq!(
            validate_ai_pair(opaque_true, opaque_false, &empty_tried()),
            Err(ValidatorError::Inert)
        );
    }

    #[test]
    fn rejects_duplicates() {
        let mut tried = HashSet::new();
        tried.insert("' OR 1=1 -- -".to_owned());
        assert_eq!(
            validate_ai_pair("' OR 1=1 -- -", "' OR 1=2 -- -", &tried),
            Err(ValidatorError::Duplicate)
        );
        tried.clear();
        tried.insert("' OR 1=2 -- -".to_owned());
        assert_eq!(
            validate_ai_pair("' OR 1=1 -- -", "' OR 1=2 -- -", &tried),
            Err(ValidatorError::Duplicate)
        );
    }

    #[test]
    fn word_boundary_or_anderson_not_boolean() {
        // `OR` dans `ANDERSON` ne doit pas valider à lui seul.
        assert_eq!(
            validate_ai_pair("ANDERSON", "ANDERSOB", &empty_tried()),
            Err(ValidatorError::NotBoolean)
        );
    }
}
