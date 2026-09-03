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
#[must_use]
pub fn banner() -> &'static str {
    "SELECT @@version"
}
#[must_use]
pub fn hostname() -> &'static str {
    "SELECT @@hostname"
}
