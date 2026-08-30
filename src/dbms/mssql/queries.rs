#![deny(unsafe_code)]
#[must_use]
pub fn version() -> &'static str {
    "SELECT @@version"
}
