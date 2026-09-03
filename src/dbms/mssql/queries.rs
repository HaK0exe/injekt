#![deny(unsafe_code)]
#[must_use]
pub fn version() -> &'static str {
    "SELECT @@version"
}
#[must_use]
pub fn current_db() -> &'static str {
    "SELECT DB_NAME()"
}
#[must_use]
pub fn user() -> &'static str {
    // Server login, not DB principal (see fingerprint.rs): sqlmap parity.
    "SELECT SUSER_SNAME()"
}
#[must_use]
pub fn banner() -> &'static str {
    "SELECT @@version"
}
#[must_use]
pub fn hostname() -> &'static str {
    "SELECT @@SERVERNAME"
}
