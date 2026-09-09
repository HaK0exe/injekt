#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Where a parameter lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ParameterLocation {
    Query,
    Body,
    Header(String),
    Cookie,
}

impl core::fmt::Display for ParameterLocation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Query => write!(f, "query"),
            Self::Body => write!(f, "body"),
            Self::Header(h) => write!(f, "header:{h}"),
            Self::Cookie => write!(f, "cookie"),
        }
    }
}

/// Single injectable parameter with original value preserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TargetParameter {
    pub name: String,
    pub location: ParameterLocation,
    pub original_value: String,
}

impl TargetParameter {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        location: ParameterLocation,
        original_value: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            location,
            original_value: original_value.into(),
        }
    }

    /// Unique key for reporting.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}@{}", self.name, self.location)
    }
}

/// Collect all parameter locations from URL + body + headers (helper).
#[must_use]
pub fn collect_from_url_query(url: &crate::target::url::TargetUrl) -> Vec<TargetParameter> {
    url.query_params()
        .into_iter()
        .map(|(k, v)| TargetParameter::new(k, ParameterLocation::Query, v))
        .collect()
}

#[must_use]
pub fn collect_from_body(body: &str) -> Vec<TargetParameter> {
    collect_from_body_with_ct(body, None)
}

/// Same as [`collect_from_body`] but routed by `Content-Type` (JSON / XML /
// multipart) instead of body shape alone. Keeps the old top-level JSON
/// fast path for backwards compatibility, then falls back to the structured
/// helpers (`json_paths` for nested JSON, `xml_tags` for XML/SOAP,
/// multipart field names).
#[must_use]
pub fn collect_from_body_with_ct(body: &str, content_type: Option<&str>) -> Vec<TargetParameter> {
    if body.is_empty() {
        return Vec::new();
    }
    let kind = crate::target::structured::sniff_kind(content_type, body);
    match kind {
        crate::target::structured::StructuredKind::Json => {
            // Nested JSON: `json:/a/0/b` paths (round-trip via `inject_json_path`).
            // Top-level keys keep their bare names (`a`, not `json:/a`) for
            // backwards compatibility (`-p a`, existing tests); deeper paths
            // stay prefixed so `inject_json_path` can round-trip them.
            let paths = crate::target::structured::json_paths(body);
            if !paths.is_empty() {
                return paths
                    .into_iter()
                    .map(|(k, v)| {
                        let name = k
                            .strip_prefix("json:/")
                            .filter(|rest| !rest.is_empty() && !rest.contains('/'))
                            .map_or(k.clone(), |bare| {
                                // Unescape `~1`/`~0` for display parity with old keys.
                                bare.replace("~1", "/").replace("~0", "~")
                            });
                        TargetParameter::new(name, ParameterLocation::Body, v)
                    })
                    .collect();
            }
            // Fall through to form parsing for non-object JSON (e.g. root array).
        }
        crate::target::structured::StructuredKind::Xml => {
            let tags = crate::target::structured::xml_tags(body);
            if !tags.is_empty() {
                return tags
                    .into_iter()
                    .map(|(k, v)| TargetParameter::new(k, ParameterLocation::Body, v))
                    .collect();
            }
            return Vec::new();
        }
        crate::target::structured::StructuredKind::Form => {
            // Multipart: extract `name="field"` parts as body params.
            if content_type
                .is_some_and(|ct| ct.to_ascii_lowercase().contains("multipart/form-data"))
                || looks_multipart(body)
            {
                let parts = multipart_field_names(body);
                if !parts.is_empty() {
                    return parts
                        .into_iter()
                        .map(|(k, v)| TargetParameter::new(k, ParameterLocation::Body, v))
                        .collect();
                }
            }
        }
    }
    let trimmed = body.trim();
    // JSON bodies (`--data '{"a":1}'`): expose top-level keys as body params.
    // Urlencoded parsing would otherwise yield a single aberrant `{"a":1}` key.
    if trimmed.starts_with('{')
        && trimmed.ends_with('}')
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
        && let Some(obj) = value.as_object()
    {
        return obj
            .iter()
            .map(|(k, v)| {
                let s = match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Null => String::new(),
                    _ => v.to_string(),
                };
                TargetParameter::new(k.clone(), ParameterLocation::Body, s)
            })
            .collect();
    }
    url::form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| TargetParameter::new(k.into_owned(), ParameterLocation::Body, v.into_owned()))
        .collect()
}

/// Heuristic: `--` boundary lines + `Content-Disposition` without needing the
/// `Content-Type` header (raw files sometimes drop it).
fn looks_multipart(body: &str) -> bool {
    body.contains("Content-Disposition:") && body.contains("name=\"")
}

/// Minimal multipart field scan: `name="field"` → value = first line after
/// the blank line following the part headers (truncated to 512 chars).
/// Pure, never panics, caps at 500 pairs like the structured helpers.
fn multipart_field_names(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (idx, part) in body.split("Content-Disposition:").enumerate() {
        if idx == 0 {
            continue;
        }
        if out.len() >= crate::target::structured::MAX_STRUCTURED_PAIRS {
            break;
        }
        let Some(name_start) = part.find("name=\"") else {
            continue;
        };
        let rest = &part[name_start + 6..];
        let Some(name_end) = rest.find('"') else {
            continue;
        };
        let name = &rest[..name_end];
        if name.is_empty() {
            continue;
        }
        // Value: after the part-header blank line (`\n\n` or `\r\n\r\n`).
        let value = part
            .find("\r\n\r\n")
            .map(|i| &part[i + 4..])
            .or_else(|| part.find("\n\n").map(|i| &part[i + 2..]))
            .map(|v| {
                let line = v.lines().next().unwrap_or_default();
                line.chars().take(512).collect::<String>()
            })
            .unwrap_or_default();
        out.push((name.to_owned(), value));
    }
    out
}

#[must_use]
pub fn collect_from_raw_request(
    req: &crate::target::raw_request::RawRequest,
) -> Vec<TargetParameter> {
    let mut out = Vec::new();
    if let Some(body) = &req.body {
        out.extend(collect_from_body_with_ct(body, req.content_type()));
    }
    // `Cookie` pairs become Cookie params (`--cookies` merges into the same
    // header via `merged_raw_request`, so CLI cookies are covered too).
    if let Some(cookie) = req.headers.get("cookie") {
        for part in cookie.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                let name = k.trim();
                if !name.is_empty() {
                    out.push(TargetParameter::new(
                        name.to_owned(),
                        ParameterLocation::Cookie,
                        v.trim().to_owned(),
                    ));
                }
            }
        }
    }
    // Headers as injectable params (`--headers` merges here as well).
    // Transport + secret headers are never fuzzed: `host`/`content-length`
    // would break framing, `authorization`/`proxy-authorization` would spray
    // credentials across hundreds of probes (OPSEC). Everything else —
    // `user-agent`, `referer`, `x-forwarded-for`, custom `x-*` — is fair
    // game (sqlmap tests UA/Referer at level 3; ghauri claims header inj).
    for (k, v) in &req.headers {
        if is_nontestable_header(k) {
            continue;
        }
        out.push(TargetParameter::new(
            k.clone(),
            ParameterLocation::Header(k.clone()),
            v.clone(),
        ));
    }
    out
}

/// Headers excluded from auto-discovery (framing breakage or secret spray).
/// Compared case-insensitively: `RawRequest::parse` lowercases keys, but
/// synthetic raws may carry any case.
#[must_use]
pub fn is_nontestable_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "content-length"
            | "content-type"
            | "connection"
            | "transfer-encoding"
            | "authorization"
            | "proxy-authorization"
            | "cookie"
            | "accept"
            | "accept-encoding"
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn raw_with(
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> crate::target::raw_request::RawRequest {
        crate::target::raw_request::RawRequest {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<HashMap<_, _>>(),
            body: body.map(str::to_owned),
            http_version: "HTTP/1.1".to_owned(),
        }
    }

    #[test]
    fn collects_cookie_pairs() {
        let req = raw_with(&[("cookie", "sess=1; theme=dark")], None);
        let params = collect_from_raw_request(&req);
        let cookies: Vec<_> = params
            .iter()
            .filter(|p| p.location == ParameterLocation::Cookie)
            .collect();
        assert_eq!(cookies.len(), 2);
        assert!(
            cookies
                .iter()
                .any(|p| p.name == "sess" && p.original_value == "1")
        );
    }

    #[test]
    fn collects_testable_headers_skips_denylist() {
        let req = raw_with(
            &[
                ("host", "x"),
                ("authorization", "Bearer secret"),
                ("content-type", "application/json"),
                ("x-user-id", "1"),
                ("user-agent", "bench"),
            ],
            None,
        );
        let params = collect_from_raw_request(&req);
        let headers: Vec<_> = params
            .iter()
            .filter_map(|p| match &p.location {
                ParameterLocation::Header(h) => Some(h.clone()),
                _ => None,
            })
            .collect();
        assert!(headers.contains(&"x-user-id".to_owned()), "got {headers:?}");
        assert!(
            headers.contains(&"user-agent".to_owned()),
            "got {headers:?}"
        );
        assert!(
            !headers.iter().any(|h| h == "authorization"),
            "secret spray: {headers:?}"
        );
        assert!(!headers.iter().any(|h| h == "host"), "got {headers:?}");
    }

    #[test]
    fn denylist_is_case_insensitive() {
        assert!(is_nontestable_header("Authorization"));
        assert!(is_nontestable_header("CONTENT-TYPE"));
        assert!(!is_nontestable_header("x-user-id"));
    }
}
