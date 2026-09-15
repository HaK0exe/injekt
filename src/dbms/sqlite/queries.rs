#![deny(unsafe_code)]
#[must_use]
pub fn version() -> &'static str {
    "SELECT sqlite_version()"
}
#[must_use]
pub fn current_db() -> &'static str {
    "SELECT 'main'"
}
#[must_use]
pub fn user() -> &'static str {
    "SELECT 'sqlite'"
}
#[must_use]
pub fn banner() -> &'static str {
    "SELECT sqlite_version()"
}
#[must_use]
pub fn hostname() -> &'static str {
    "SELECT 'localhost'"
}
