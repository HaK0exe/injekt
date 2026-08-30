#![deny(unsafe_code)]
#[must_use]
pub fn version() -> &'static str {
    "SELECT @@version, @@version_comment"
}
#[must_use]
pub fn current_db() -> &'static str {
    "SELECT DATABASE()"
}
#[must_use]
pub fn user() -> &'static str {
    "SELECT USER()"
}
