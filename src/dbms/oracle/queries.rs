#![deny(unsafe_code)]
#[must_use]
pub fn version() -> &'static str {
    "SELECT banner FROM v$version WHERE ROWNUM=1"
}
#[must_use]
pub fn current_db() -> &'static str {
    "SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual"
}
#[must_use]
pub fn user() -> &'static str {
    "SELECT USER FROM dual"
}
#[must_use]
pub fn banner() -> &'static str {
    "SELECT banner FROM v$version WHERE ROWNUM=1"
}
#[must_use]
pub fn hostname() -> &'static str {
    "SELECT SYS_CONTEXT('USERENV','SERVER_HOST') FROM dual"
}
