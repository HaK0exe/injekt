#![deny(unsafe_code)]
#[must_use]
pub fn pg_time(secs: u64) -> String {
    format!("'; SELECT pg_sleep({secs}) --")
}
