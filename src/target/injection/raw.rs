use crate::target::raw_request::RawRequest;
use std::collections::HashMap;

/// Build a synthetic raw request from `--data` so body params are preserved
/// through baseline + injection (same path as `--raw-file`).
/// Uses [`crate::target::structured::sniff_kind`] from `target::structured` for robust content-type
/// detection: checks `Content-Type` first, then falls back to body shape
/// (`{` → JSON, `<` → XML, else → urlencoded).
#[must_use]
pub fn synthetic_raw_from_data(data: &str) -> Option<RawRequest> {
    use crate::target::structured::sniff_kind;
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return None;
    }
    let kind = sniff_kind(None, trimmed);
    let content_type = match kind {
        crate::target::structured::StructuredKind::Json => "application/json",
        crate::target::structured::StructuredKind::Xml => "application/xml",
        _ => "application/x-www-form-urlencoded",
    };
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_owned(), content_type.to_owned());
    Some(RawRequest {
        method: "POST".to_owned(),
        path: "/".to_owned(),
        headers,
        body: Some(trimmed.to_owned()),
        http_version: "HTTP/1.1".to_owned(),
    })
}
