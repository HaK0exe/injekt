#![deny(unsafe_code)]

//! Read-only SQL validation gate for interactive extraction.
//!
//! This module is intentionally isolated: it only validates operator-supplied
//! SQL and reports whether a prior scan confirmed stacked-query execution. It
//! performs no I/O, spawns no tasks, and never touches the network.
//!
//! Expected coordinator flow (wiring is done by the coordinator, not here):
//!
//! 1. `stacked_ok = stacked_confirmed(findings)`.
//! 2. `sql = validate_select_only(operator_input, stacked_ok)?`.
//! 3. Hand `sql` to the existing extraction oracle (not implemented here).
//!
//! Validation rules applied by [`validate_select_only`]:
//!
//! | Rule | `stacked_ok = false` | `stacked_ok = true` |
//! | ---- | -------------------- | ------------------- |
//! | Empty (after trim) rejected | yes | yes |
//! | Byte length `> MAX_SQL_LEN` rejected | yes | yes |
//! | `;` anywhere rejected | yes | yes |
//! | Must start with `SELECT`, `WITH`, `VALUES`, or `EXPLAIN SELECT` | yes | no (any single statement allowed) |
//! | Forbidden keywords rejected (whole-word, case-insensitive) | yes | no |
//!
//! Forbidden keywords: `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`,
//! `CREATE`, `GRANT`, `TRUNCATE`, `REPLACE`, `INTO OUTFILE`, `INTO DUMPFILE`,
//! `LOAD_FILE`, `XP_CMDSHELL`, `PG_READ_FILE`, `COPY`, `VACUUM`, `CALL`,
//! `EXEC`, `EXECUTE`.
//!
//! Strictness notes (documented limitations):
//!
//! - No leading `(` is accepted: `(SELECT 1)` is rejected even though the
//!   inner statement is read-only. The prefix check is a strict
//!   case-insensitive prefix match.
//! - The keyword matcher is deliberately naive: it folds case and splits on
//!   non-word characters without understanding string literals, quoted
//!   identifiers, or comments. `SELECT 'insert'` is therefore conservatively
//!   rejected. This fail-closed behaviour is intentional.

use crate::error::InjektError;
use crate::session::state::{Finding, TechniqueKind};

/// Maximum accepted SQL length in bytes (checked on the raw input).
pub const MAX_SQL_LEN: usize = 500;

/// Global guard for interactive extraction (seconds).
///
/// Upper bound the coordinator should enforce around an interactive extraction
/// session. Kept here so the gate and its budget live next to each other.
pub const PER_CHAR_TIMEOUT_SECS: u64 = 120;

/// Single-word keywords forbidden unless `stacked_ok` is `true`.
/// Compared against whole tokens of the upper-cased statement, so `RECALL`
/// does not match `CALL` and `EXECUTION_TIME` does not match `EXECUTE`.
const FORBIDDEN_WORDS: &[&str] = &[
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "ALTER",
    "CREATE",
    "GRANT",
    "TRUNCATE",
    "REPLACE",
    "LOAD_FILE",
    "XP_CMDSHELL",
    "PG_READ_FILE",
    "COPY",
    "VACUUM",
    "CALL",
    "EXEC",
    "EXECUTE",
];

/// Returns `true` for characters that belong to a SQL word token.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Case-sensitive prefix check with a word boundary: the character following
/// `keyword` (if any) must not be a word character, so `SELECTED` does not
/// match `SELECT` while `SELECT(1)` and `SELECT *` do.
fn starts_with_keyword(haystack: &str, keyword: &str) -> bool {
    if let Some(rest) = haystack.strip_prefix(keyword) {
        rest.chars().next().is_none_or(|c| !is_word_char(c))
    } else {
        false
    }
}

/// Whether the upper-cased, whitespace-normalized statement starts with a
/// read-only prefix. No leading parenthesis is accepted (strict).
fn has_read_only_prefix(upper: &str) -> bool {
    starts_with_keyword(upper, "SELECT")
        || starts_with_keyword(upper, "WITH")
        || starts_with_keyword(upper, "VALUES")
        || starts_with_keyword(upper, "EXPLAIN SELECT")
}

/// First forbidden keyword or phrase found in the upper-cased statement, if
/// any. Token-based (whole-word) matching; the two multi-word file-exfil
/// phrases are detected as consecutive tokens.
fn find_forbidden_keyword(upper: &str) -> Option<String> {
    let mut prev_token: Option<&str> = None;
    for token in upper
        .split(|c: char| !is_word_char(c))
        .filter(|t| !t.is_empty())
    {
        if FORBIDDEN_WORDS.contains(&token) {
            return Some(token.to_owned());
        }
        if let Some(prev) = prev_token
            && prev == "INTO"
            && (token == "OUTFILE" || token == "DUMPFILE")
        {
            return Some(format!("{prev} {token}"));
        }
        prev_token = Some(token);
    }
    None
}

/// Validates operator-supplied SQL as read-only and returns the
/// trimmed/normalized statement (leading/trailing whitespace removed, every
/// run of whitespace collapsed to a single space).
///
/// When `stacked_ok` is `true` (a prior finding confirmed stacked-query
/// execution via [`stacked_confirmed`]), the read-only prefix and forbidden
/// keyword checks are lifted: any single statement passes. The empty, length,
/// and `;` checks always apply.
///
/// # Errors
///
/// Returns [`InjektError::Extraction`] when the input is empty, exceeds
/// [`MAX_SQL_LEN`] bytes, contains `;`, lacks a read-only prefix (unless
/// `stacked_ok`), or contains a forbidden keyword (unless `stacked_ok`).
///
/// # Panics
///
/// Never panics: all operations are char-boundary safe (`split_whitespace`,
/// `to_uppercase`, `strip_prefix`, `chars`) and no indexing is used.
///
/// ```rust
/// use injekt::engine::sql::{stacked_confirmed, validate_select_only};
///
/// // 1. The coordinator derives `stacked_ok` from prior findings.
/// let stacked_ok = stacked_confirmed(&[]);
/// assert!(!stacked_ok);
///
/// // 2. The gate validates (and normalizes) operator input.
/// let checked = validate_select_only("SELECT  id   FROM users", stacked_ok);
/// assert!(checked.is_ok());
/// if let Ok(sql) = checked {
///     assert_eq!(sql, "SELECT id FROM users");
///     // 3. `sql` is then handed to the existing extraction oracle
///     //    (not implemented here).
/// }
/// ```
pub fn validate_select_only(sql: &str, stacked_ok: bool) -> Result<String, InjektError> {
    if sql.len() > MAX_SQL_LEN {
        return Err(InjektError::Extraction(format!(
            "refusing SQL of {} bytes: exceeds MAX_SQL_LEN ({MAX_SQL_LEN})",
            sql.len()
        )));
    }
    let normalized: String = sql.split_whitespace().collect::<Vec<&str>>().join(" ");
    if normalized.is_empty() {
        return Err(InjektError::Extraction(
            "refusing empty SQL: interactive extraction requires a read-only statement".to_owned(),
        ));
    }
    if normalized.contains(';') {
        return Err(InjektError::Extraction(
            "refusing SQL containing ';': statement chaining is never allowed".to_owned(),
        ));
    }
    if stacked_ok {
        return Ok(normalized);
    }
    let upper = normalized.to_uppercase();
    if !has_read_only_prefix(&upper) {
        return Err(InjektError::Extraction(
            "refusing SQL without read-only prefix: must start with SELECT, WITH, VALUES, or EXPLAIN SELECT"
                .to_owned(),
        ));
    }
    if let Some(keyword) = find_forbidden_keyword(&upper) {
        return Err(InjektError::Extraction(format!(
            "refusing SQL containing forbidden keyword '{keyword}': read-only statements only"
        )));
    }
    Ok(normalized)
}

/// Reports whether any prior finding confirmed stacked-query execution.
///
/// # Panics
///
/// Never panics: pure iteration with no indexing.
///
/// ```rust
/// use injekt::engine::sql::stacked_confirmed;
/// use injekt::session::state::{Finding, TechniqueKind};
///
/// assert!(!stacked_confirmed(&[]));
/// let findings = [Finding::new(
///     "http://target.test/?id=1",
///     "id",
///     TechniqueKind::Stacked,
///     0.9,
///     "second statement executed",
/// )];
/// assert!(stacked_confirmed(&findings));
/// ```
#[must_use]
pub fn stacked_confirmed(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.technique == TechniqueKind::Stacked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_select() {
        assert!(validate_select_only("SELECT id FROM users", false).is_ok());
    }

    #[test]
    fn accepts_lowercase_select() {
        assert!(validate_select_only("select id from users", false).is_ok());
    }

    #[test]
    fn accepts_with_prefix() {
        assert!(validate_select_only("WITH c AS (SELECT 1) SELECT * FROM c", false).is_ok());
    }

    #[test]
    fn accepts_values_prefix() {
        assert!(validate_select_only("VALUES (1, 2), (3, 4)", false).is_ok());
    }

    #[test]
    fn accepts_explain_select() {
        assert!(validate_select_only("EXPLAIN SELECT * FROM users", false).is_ok());
    }

    #[test]
    fn collapses_inner_whitespace() {
        let result = validate_select_only("SELECT   id\t\n  FROM   users", false);
        assert!(result.is_ok());
        let Ok(normalized) = result else {
            return;
        };
        assert_eq!(normalized, "SELECT id FROM users");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let result = validate_select_only("   SELECT 1   ", false);
        assert!(result.is_ok());
        let Ok(normalized) = result else {
            return;
        };
        assert_eq!(normalized, "SELECT 1");
    }

    #[test]
    fn rejects_insert_without_stacked() {
        assert!(validate_select_only("INSERT INTO users VALUES (1)", false).is_err());
    }

    #[test]
    fn accepts_insert_with_stacked_ok() {
        let result = validate_select_only("INSERT INTO users VALUES (1)", true);
        assert!(result.is_ok());
        let Ok(normalized) = result else {
            return;
        };
        assert_eq!(normalized, "INSERT INTO users VALUES (1)");
    }

    #[test]
    fn rejects_semicolon_always() {
        assert!(validate_select_only("SELECT 1;", false).is_err());
        assert!(validate_select_only("SELECT 1;", true).is_err());
        assert!(validate_select_only("SELECT 1; DROP TABLE users", true).is_err());
    }

    #[test]
    fn rejects_drop_table() {
        assert!(validate_select_only("DROP TABLE users", false).is_err());
        assert!(validate_select_only("SELECT * FROM t WHERE x = 1 DROP TABLE t", false).is_err());
    }

    #[test]
    fn rejects_mixed_case_keyword() {
        assert!(validate_select_only("SeLeCt * FrOm t WhErE x = 1 dRoP TaBlE t", false).is_err());
    }

    #[test]
    fn rejects_empty_and_blank() {
        assert!(validate_select_only("", false).is_err());
        assert!(validate_select_only("     ", false).is_err());
        assert!(validate_select_only("", true).is_err());
    }

    #[test]
    fn rejects_overlong_input() {
        let long = format!("SELECT {}", "a".repeat(600));
        assert!(long.len() > MAX_SQL_LEN);
        assert!(validate_select_only(&long, false).is_err());
        assert!(validate_select_only(&long, true).is_err());
    }

    #[test]
    fn accepts_exactly_max_len() {
        let padding = "a".repeat(MAX_SQL_LEN - "SELECT ".len());
        let sql = format!("SELECT {padding}");
        assert_eq!(sql.len(), MAX_SQL_LEN);
        assert!(validate_select_only(&sql, false).is_ok());
    }

    #[test]
    fn rejects_into_outfile_and_dumpfile() {
        assert!(validate_select_only("SELECT * FROM t INTO OUTFILE '/tmp/x'", false).is_err());
        assert!(validate_select_only("select * from t into dumpfile '/tmp/x'", false).is_err());
    }

    #[test]
    fn rejects_leading_paren_strict() {
        // Strict prefix: no leading `(` even around a read-only statement.
        assert!(validate_select_only("(SELECT 1)", false).is_err());
    }

    #[test]
    fn rejects_non_select_prefix() {
        assert!(validate_select_only("SELECTED 1", false).is_err());
        assert!(validate_select_only("EXPLAIN DELETE FROM t", false).is_err());
    }

    #[test]
    fn string_literal_match_is_conservatively_rejected() {
        // LIMITATION: the matcher is token-based and does not understand
        // string literals, so a forbidden word inside quotes still rejects
        // the statement (fail-closed by design).
        assert!(validate_select_only("SELECT 'insert'", false).is_err());
        // ...but the same statement passes once stacked execution is proven.
        assert!(validate_select_only("SELECT 'insert'", true).is_ok());
    }

    #[test]
    fn word_boundary_allows_substring_matches() {
        // `RECALL` must not match `CALL`; `EXECUTION_TIME` must not match `EXEC`/`EXECUTE`.
        assert!(validate_select_only("SELECT recall FROM t", false).is_ok());
        assert!(validate_select_only("SELECT execution_time FROM t", false).is_ok());
    }

    #[test]
    fn unicode_and_emoji_never_panic() {
        assert!(validate_select_only("SELECT 'héllo 🌍'", false).is_ok());
        assert!(validate_select_only("🔥🔥", false).is_err());
        assert!(validate_select_only("SELECT 'drop table everywhere 🎉'", false).is_err());
    }

    #[test]
    fn stacked_confirmed_detects_stacked_technique() {
        assert!(!stacked_confirmed(&[]));
        let boolean_only = [Finding::new(
            "http://target.test/?id=1",
            "id",
            TechniqueKind::Boolean,
            0.8,
            "content diff",
        )];
        assert!(!stacked_confirmed(&boolean_only));
        let with_stacked = [
            Finding::new(
                "http://target.test/?id=1",
                "id",
                TechniqueKind::Boolean,
                0.8,
                "content diff",
            ),
            Finding::new(
                "http://target.test/?id=1",
                "id",
                TechniqueKind::Stacked,
                0.9,
                "second statement executed",
            ),
        ];
        assert!(stacked_confirmed(&with_stacked));
    }

    #[test]
    fn guard_constants_have_expected_values() {
        assert_eq!(MAX_SQL_LEN, 500);
        assert_eq!(PER_CHAR_TIMEOUT_SECS, 120);
    }
}
