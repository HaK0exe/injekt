#![deny(unsafe_code)]
#[must_use]
pub fn version() -> &'static str {
    "SELECT version()"
}
#[must_use]
pub fn current_db() -> &'static str {
    "SELECT current_database()"
}
#[must_use]
pub fn user() -> &'static str {
    "SELECT current_user"
}
#[must_use]
pub fn banner() -> &'static str {
    "SELECT version()"
}
#[must_use]
pub fn hostname() -> &'static str {
    "SELECT inet_server_addr()::text"
}
