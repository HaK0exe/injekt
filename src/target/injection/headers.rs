/// Headers for a structured injection: force `content_type` (JSON/XML) but
/// preserve every other raw header (cookies, auth, UA). `content-length` is
/// always dropped (recomputed by the HTTP stack).
pub fn headers_preserving_raw(
    raw: Option<&crate::target::raw_request::RawRequest>,
    content_type: &'static str,
) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(content_type),
    );
    if let Some(r) = raw {
        for (k, v) in &r.headers {
            if k.eq_ignore_ascii_case("content-type") || k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                headers.insert(name, val);
            }
        }
    }
    headers
}

/// Headers for a multipart injection: keep the original `Content-Type`
/// (boundary included) verbatim, drop only `content-length`.
#[must_use]
pub fn headers_preserving_raw_keep_ct(
    raw: Option<&crate::target::raw_request::RawRequest>,
) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    if let Some(r) = raw {
        for (k, v) in &r.headers {
            if k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                headers.insert(name, val);
            }
        }
    }
    headers
}
