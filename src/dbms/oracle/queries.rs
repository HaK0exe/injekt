#![deny(unsafe_code)]
#[must_use]
pub fn version() -> &'static str {
    "SELECT banner FROM v$version WHERE ROWNUM=1"
}
