#![deny(unsafe_code)]

pub mod bulk;
pub mod ingest;
pub mod markers;
pub mod parameters;
pub mod raw_request;
pub mod structured;
pub mod url;

pub use markers::{InjectionMarker, MarkerSet};
pub use parameters::{ParameterLocation, TargetParameter};
pub use raw_request::{RawRequest, RawRequestError};
pub use url::{TargetUrl, UrlError};

/// Percent-encode one `OpenAPI` query name/value (`application/x-www-form-urlencoded`
/// shape, no new dependency): unreserved bytes pass through, space becomes
/// `+`, everything else becomes `%XX` (uppercase hex).
#[must_use]
pub fn openapi_encode(input: &str) -> String {
    use core::fmt::Write as _;
    const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if UNRESERVED.contains(&b) {
            out.push(b as char);
        } else if b == b' ' {
            out.push('+');
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}
