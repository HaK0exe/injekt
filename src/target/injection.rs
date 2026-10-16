#![deny(unsafe_code)]

use crate::{
    http::client::RequestSpec,
    target::{
        markers::MarkerSet,
        parameters::{ParameterLocation, TargetParameter},
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::{
        payload_opts::{PayloadOpts, encode_with_safe_chars},
        request_tamper::{hpp_body_str, hpp_query_url, should_apply_chunked},
        tamper::Tamper,
    },
};
use http::Method;
use std::collections::HashMap;

/// HPP/chunked switches for one probe. `Copy` so detection workers and
/// extraction oracles can capture it cheaply.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ProbeOpts {
    /// HTTP Parameter Pollution: duplicate `?id=1&id=<PAYLOAD>` (Query/Body).
    pub hpp: bool,
    /// Chunked transfer: `Transfer-Encoding: chunked` streaming body (Body only).
    pub chunked: bool,
}

impl ProbeOpts {
    #[must_use]
    pub const fn new(hpp: bool, chunked: bool) -> Self {
        Self { hpp, chunked }
    }

    #[must_use]
    pub const fn is_active(self) -> bool {
        self.hpp || self.chunked
    }

    /// Short evidence suffix, e.g. `" hpp=true chunked=false"`, or `""` when inactive.
    #[must_use]
    pub fn evidence_suffix(self) -> String {
        if !self.is_active() {
            return String::new();
        }
        format!(" hpp={} chunked={}", self.hpp, self.chunked)
    }
}

/// Filter testable parameters by `-p` selection (case-insensitive).
/// Accepts bare names (`id`), `location:name` (`body:user`,
/// `cookie:PHPSESSID`, `header:X-Forwarded-For`) or full keys (`id@query`).
/// Empty filter returns all params. Marker synthetics are always preserved
/// when markers are present.
#[must_use]
pub fn filter_params(params: Vec<TargetParameter>, filter: &[String]) -> Vec<TargetParameter> {
    if filter.is_empty() {
        return params;
    }
    let lowered: Vec<String> = filter
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if lowered.is_empty() {
        return params;
    }
    params
        .into_iter()
        .filter(|p| {
            if p.name.starts_with("marker_") {
                return true;
            }
            let name_l = p.name.to_ascii_lowercase();
            let key_l = p.key().to_ascii_lowercase();
            lowered.iter().any(|f| {
                // Bare name (`id`) or full key (`id@query`, `x@header:y`).
                if f == &name_l || f == &key_l {
                    return true;
                }
                // `location:name` form (e.g. `body:user`, `cookie:PHPSESSID`).
                let Some((loc, n)) = f.split_once(':') else {
                    return false;
                };
                match &p.location {
                    ParameterLocation::Header(h) => {
                        // `header:X-Forwarded-For` matches header params by
                        // header name; full `header:h` display also accepted.
                        loc == "header" && (name_l == n || h.to_ascii_lowercase() == n)
                    }
                    other => other.to_string().to_ascii_lowercase() == loc && name_l == n,
                }
            })
        })
        .collect()
}

/// Number of base payloads to try per technique for a tuning `--level`.
/// L1 is the historical budget (byte-identical default), L2 doubles it,
/// L3+ exhausts the whole list. Pure and unit-testable.
#[must_use]
pub fn payload_budget(level: u8, default_take: usize, total: usize) -> usize {
    match level {
        // 0 is unreachable via CLI (clap range 1..=5); treated as L1 defensively.
        0 | 1 => default_take.min(total),
        2 => (default_take * 2).min(total),
        _ => total,
    }
}

/// `--ignore-code`: a response status listed in `codes` is treated as a
/// negative probe (never a finding). The baseline (including WAF detection)
/// runs before this filter and is never ignored.
#[must_use]
pub fn is_ignored(status: u16, codes: &[u16]) -> bool {
    codes.contains(&status)
}

/// App-level signature filter status (e.g. bench A1 `400 {"error":"invalid
/// parameter"}` on spaced keywords). Distinct from WAF `403`/`406` (see
/// `Baseline::is_waf_blocked`): the baseline sees clean `200`s so no
/// auto-tamper fires, yet every spaced boolean payload returns `400`/`400`.
/// Callers use this to prune the payload loop early instead of burning the
/// full L3 matrix on an obviously filtered sink. Narrow to `400`/`400` only
/// so N1/N2 (`200`) and WAF blocks (`403`/`406`) never trip it.
pub const APP_FILTER_STATUS: u16 = 400;
/// Consecutive fully-filtered `(payload, tamper-set)` probes before pruning.
pub const FILTER_STREAK_LIMIT: usize = 3;

#[must_use]
pub const fn is_app_filter_block(true_status: u16, false_status: u16) -> bool {
    true_status == APP_FILTER_STATUS && false_status == APP_FILTER_STATUS
}

/// `true` when every baseline sample is a server error (5xx: origin down,
/// CF 520–524, …). Detection differentials against error pages are
/// meaningless (static pages refute everything), so the caller warns loudly
/// instead of burning hundreds of probes silently. Empty = `false`
/// (no samples is a different failure, handled upstream). Pure and
/// unit-testable.
#[must_use]
pub fn baseline_all_error(statuses: &[u16]) -> bool {
    !statuses.is_empty() && statuses.iter().all(|s| (500..600).contains(s))
}

/// Auto-tampers applied when a blocking WAF is seen and the user gave none:
/// `space2comment` (space-signature bypass) + `randomcase` (case-signature
/// bypass, 429 rate-limit hardening). Pure and unit-testable. HPP/chunked
/// are never auto-enabled (request-shape changes stay explicit opt-in).
#[must_use]
pub fn waf_auto_tampers() -> Vec<Tamper> {
    vec![Tamper::Space2Comment, Tamper::RandomCase]
}

/// Resolve the effective tamper set for a run: the WAF auto-pair when
/// `waf_blocking` fired and the user gave none, otherwise the user set
/// unchanged (explicit `--tamper` always wins). Pure and unit-testable.
#[must_use]
pub fn resolve_effective_tampers(waf_blocking: bool, user_tampers: &[Tamper]) -> Vec<Tamper> {
    if waf_blocking && user_tampers.is_empty() {
        waf_auto_tampers()
    } else {
        user_tampers.to_vec()
    }
}

/// Build a synthetic raw request from `--data` so body params are preserved
/// through baseline + injection (same path as `--raw-file`).
/// Uses [`sniff_kind`] from `target::structured` for robust content-type
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

#[must_use]
pub fn inject_param(
    target: &TargetUrl,
    param: &TargetParameter,
    payload: &str,
    safe: &[char],
    skip_urlencode: bool,
) -> String {
    // naive: replace query param value
    let mut url = target.inner().clone();
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut found = false;
    for (k, v) in &mut pairs {
        if k == &param.name {
            payload.clone_into(v);
            found = true;
        }
    }
    if !found {
        pairs.push((param.name.clone(), payload.to_owned()));
    }
    // Default path (no --safe-chars/--skip-urlencode): standard encoding,
    // byte-identical to the historical behaviour.
    if safe.is_empty() && !skip_urlencode {
        url.query_pairs_mut().clear();
        for (k, v) in pairs {
            url.query_pairs_mut().append_pair(&k, &v);
        }
        return url.to_string();
    }
    // Custom encoding: keys stay standard, values honour safe/skip.
    let query = pairs
        .iter()
        .map(|(k, v)| {
            let ek: String = url::form_urlencoded::byte_serialize(k.as_bytes()).collect();
            format!("{ek}={}", encode_with_safe_chars(v, safe, skip_urlencode))
        })
        .collect::<Vec<_>>()
        .join("&");
    url.set_query(Some(&query));
    url.to_string()
}

#[allow(clippy::collapsible_if)]
#[must_use]
pub fn inject_with_marker(target_str: &str, payload: &str, marker_set: &MarkerSet) -> String {
    let mut s = target_str.to_owned();
    if marker_set.asterisk {
        if s.contains('*') {
            // Replace only first occurrence to avoid over-broad replacement
            if let Some(pos) = s.find('*') {
                s.replace_range(pos..=pos, payload);
                return s;
            }
        } else {
            // Handle encoded asterisk %2A (case-insensitive) when URL is percent-encoded
            let lower = s.to_ascii_lowercase();
            if let Some(pos) = lower.find("%2a") {
                s.replace_range(pos..pos + 3, payload);
                return s;
            }
        }
    }
    if marker_set.section {
        // §payload§ -> replace inner
        if let Some(start) = s.find('§')
            && let Some(end) = s[start + '§'.len_utf8()..].find('§')
        {
            let sec_end = start + '§'.len_utf8() + end + '§'.len_utf8();
            s.replace_range(start..sec_end, payload);
            return s;
        }
    }
    if marker_set.double_brace && s.contains("{{") && s.contains("}}") {
        if let Some(start) = s.find("{{")
            && let Some(end) = s[start..].find("}}")
        {
            let brace_end = start + end + "}}".len();
            s.replace_range(start..brace_end, payload);
            return s;
        }
    }
    // fallback: append as query
    if s.contains('?') {
        format!("{s}&injekt={payload}")
    } else {
        format!("{s}?injekt={payload}")
    }
}

#[must_use]
pub fn inject_param_or_marker(
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    payload: &str,
    marker_set: &MarkerSet,
) -> String {
    if marker_set.has_any() && param.name.starts_with("marker_") {
        inject_with_marker(target_str, payload, marker_set)
    } else {
        inject_param(target, param, payload, &[], false)
    }
}

#[allow(clippy::too_many_lines)]
pub fn inject_body_param(
    raw: Option<&crate::target::raw_request::RawRequest>,
    param: &TargetParameter,
    payload: &str,
    hpp: bool,
    safe: &[char],
    skip_urlencode: bool,
) -> (Method, String, http::HeaderMap) {
    let method = raw
        .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
        .unwrap_or(Method::POST);
    let existing_body = raw.and_then(|r| r.body.as_deref());
    // Structured bodies: `json:/a/0/b` and `xml:Tag` params (see
    // `target::structured`) inject via path/tag helpers so nested JSON and
    // XML/SOAP flow as valid documents instead of urlencoded noise.
    // Multipart `name="field"` parts are replaced in place with the boundary
    // preserved.
    if let Some(body) = existing_body {
        let (kind, rest) = crate::target::structured::split_name(&param.name);
        match kind {
            crate::target::structured::StructuredKind::Json => {
                if let Some(injected) =
                    crate::target::structured::inject_json_path(body, rest, payload)
                {
                    return (
                        method,
                        injected,
                        headers_preserving_raw(raw, "application/json"),
                    );
                }
            }
            crate::target::structured::StructuredKind::Xml => {
                if let Some(injected) =
                    crate::target::structured::inject_xml_tag(body, rest, payload)
                {
                    let ct = raw
                        .and_then(|r| r.content_type())
                        .unwrap_or("application/xml");
                    let ct_static: &'static str = if ct.to_ascii_lowercase().contains("soap") {
                        "application/soap+xml"
                    } else {
                        "application/xml"
                    };
                    return (method, injected, headers_preserving_raw(raw, ct_static));
                }
            }
            crate::target::structured::StructuredKind::Form => {
                let ct = raw.and_then(|r| r.content_type()).unwrap_or_default();
                if ct.to_ascii_lowercase().contains("multipart/form-data")
                    && let Some(injected) = inject_multipart_field(body, &param.name, payload)
                {
                    return (method, injected, headers_preserving_raw_keep_ct(raw));
                }
            }
        }
    }
    // JSON bodies (`--data '{"a":1}'`): replace the key inside the object so
    // blind payloads flow as valid JSON instead of urlencoded noise.
    if let Some(body) = existing_body {
        let trimmed = body.trim();
        if trimmed.starts_with('{')
            && trimmed.ends_with('}')
            && let Ok(serde_json::Value::Object(mut obj)) =
                serde_json::from_str::<serde_json::Value>(trimmed)
        {
            obj.insert(
                param.name.clone(),
                serde_json::Value::String(payload.to_owned()),
            );
            let json_body =
                serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_else(|_| {
                    format!("{{\"{}\":\"{payload}\"}}", param.name.replace('"', "\\\""))
                });
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if k.eq_ignore_ascii_case("content-type")
                        || k.eq_ignore_ascii_case("content-length")
                    {
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
            return (method, json_body, headers);
        }
    }
    if hpp {
        // HPP: keep original fields, append param=payload as duplicate.
        let body_str = hpp_body_str(existing_body, &param.name, payload);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        if let Some(r) = raw {
            for (k, v) in &r.headers {
                if k.eq_ignore_ascii_case("content-type")
                    || k.eq_ignore_ascii_case("content-length")
                {
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
        return (method, body_str, headers);
    }
    let body_str = if let Some(body) = existing_body {
        // Preserve other body fields, replace only target param
        let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let mut found = false;
        for (k, v) in &mut pairs {
            if k == &param.name {
                payload.clone_into(v);
                found = true;
            }
        }
        if !found {
            pairs.push((param.name.clone(), payload.to_owned()));
        }
        // Default path: standard encoding. Custom path (--safe-chars/
        // --skip-urlencode): keys stay standard, values honour safe/skip.
        if safe.is_empty() && !skip_urlencode {
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish()
        } else {
            pairs
                .iter()
                .map(|(k, v)| {
                    let ek: String = url::form_urlencoded::byte_serialize(k.as_bytes()).collect();
                    format!("{ek}={}", encode_with_safe_chars(v, safe, skip_urlencode))
                })
                .collect::<Vec<_>>()
                .join("&")
        }
    } else {
        format!(
            "{}={}",
            param.name,
            url::form_urlencoded::byte_serialize(payload.as_bytes()).collect::<String>()
        )
    };
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    // Preserve other headers from raw request (e.g., Host, User-Agent)
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
    (method, body_str, headers)
}

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

/// Replace the value of a `name="field"` multipart part in place, preserving
/// boundaries and other parts. Returns `None` when the field is absent.
#[must_use]
pub fn inject_multipart_field(body: &str, field: &str, payload: &str) -> Option<String> {
    let needle = format!("name=\"{field}\"");
    let pos = body.find(&needle)?;
    // Value starts after the part-header blank line following the needle.
    let after = &body[pos + needle.len()..];
    let value_start_rel = after
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| after.find("\n\n").map(|i| i + 2))?;
    let value_start = pos + needle.len() + value_start_rel;
    // Value ends at the next line starting with `--` (boundary) or end.
    let rest = &body[value_start..];
    let value_end_rel = rest.find("\r\n--").map(|i| i + 2).or_else(|| {
        // `\n--boundary` fallback; keep the leading newline out of the value.
        rest.find("\n--").map(|i| i + 1)
    });
    let value_end = value_end_rel.map_or(body.len(), |rel| value_start + rel);
    let mut out = String::with_capacity(body.len() + payload.len());
    out.push_str(&body[..value_start]);
    out.push_str(payload);
    out.push_str(&body[value_end..]);
    Some(out)
}

#[must_use]
pub fn request_spec_from_raw(target: &TargetUrl, raw: &RawRequest) -> RequestSpec {
    let method = Method::from_bytes(raw.method.as_bytes()).unwrap_or(Method::GET);
    let mut headers = http::HeaderMap::new();
    for (k, v) in &raw.headers {
        if k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("host") {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(k.as_bytes()),
            http::HeaderValue::from_str(v),
        ) {
            headers.insert(name, value);
        }
    }
    let mut spec = RequestSpec::new(method, target.as_str().to_owned()).with_headers(headers);
    if let Some(body) = &raw.body {
        spec = spec.with_body(body.as_bytes().to_vec());
    }
    spec
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn build_injection_spec_with_raw(
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    payload: &str,
    marker_set: &MarkerSet,
    raw: Option<&crate::target::raw_request::RawRequest>,
    opts: ProbeOpts,
    popts: &PayloadOpts,
) -> Option<RequestSpec> {
    // Returns `None` when the injection cannot be represented (header/cookie
    // value rejected by `http::HeaderValue`, e.g. a newline from
    // `space2newline`): callers must skip the probe WITHOUT scoring and
    // without counting a request — sending an un-injected request and
    // scoring it as negative would be a silent false negative.
    // Custom value encoding (--safe-chars/--skip-urlencode); collected once
    // per injection (requests dominate the cost).
    let safe: Vec<char> = popts.safe_chars.chars().collect();
    let skip = popts.skip_urlencode;
    if marker_set.has_any() && param.name.starts_with("marker_") {
        let url = inject_with_marker(target_str, payload, marker_set);
        // Preserve method from raw request if available
        let method = raw
            .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
            .unwrap_or(Method::GET);
        return Some(RequestSpec::new(method, url));
    }
    match &param.location {
        ParameterLocation::Query => {
            let url = if opts.hpp {
                hpp_query_url(target.inner(), &param.name, payload)
            } else {
                inject_param(target, param, payload, &safe, skip)
            };
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            Some(RequestSpec::new(method, url))
        }
        ParameterLocation::Body => {
            let (method, body_str, mut headers) =
                inject_body_param(raw, param, payload, opts.hpp, &safe, skip);
            if should_apply_chunked(true, opts.chunked) {
                headers.remove(http::header::CONTENT_LENGTH);
                headers.insert(
                    http::header::TRANSFER_ENCODING,
                    http::HeaderValue::from_static("chunked"),
                );
            }
            RequestSpec::new(method, target.as_str().to_owned())
                .with_headers(headers)
                .with_body(body_str.into_bytes())
                .into()
        }
        ParameterLocation::Header(h) => {
            let mut headers = http::HeaderMap::new();
            // Preserve existing headers from raw request
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::from_bytes(h.as_bytes()),
                http::HeaderValue::from_str(payload),
            ) {
                headers.insert(name, val);
            } else {
                // The payload cannot travel in a header value (e.g. a
                // newline from `space2newline`): sending the request
                // without the injection and scoring it as a negative
                // trial would be a silent false negative.
                tracing::warn!(param=%param.key(), "header injection value rejected, skipping probe");
                return None;
            }
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            Some(RequestSpec::new(method, target.as_str().to_owned()).with_headers(headers))
        }
        ParameterLocation::Cookie => {
            let mut headers = http::HeaderMap::new();
            // Preserve existing headers, but rebuild Cookie header to preserve other cookies
            let mut cookies: Vec<(String, String)> = Vec::new();
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if k.eq_ignore_ascii_case("cookie") {
                        for part in v.split(';') {
                            if let Some((ck, cv)) = part.trim().split_once('=') {
                                cookies.push((ck.trim().to_owned(), cv.trim().to_owned()));
                            }
                        }
                    } else if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            // Replace or insert target cookie
            let mut found = false;
            for (ck, cv) in &mut cookies {
                if ck == &param.name {
                    payload.clone_into(cv);
                    found = true;
                }
            }
            if !found {
                cookies.push((param.name.clone(), payload.to_owned()));
            }
            let cookie_val = cookies
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            let Ok(val) = http::HeaderValue::from_str(&cookie_val) else {
                // Same fail-closed rule as header injection above: never
                // send (and score) a request that silently lost its payload.
                tracing::warn!(param=%param.key(), "cookie injection value rejected, skipping probe");
                return None;
            };
            headers.insert(http::header::COOKIE, val);
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            Some(RequestSpec::new(method, target.as_str().to_owned()).with_headers(headers))
        }
    }
}
