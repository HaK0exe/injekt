use super::headers::{headers_preserving_raw, headers_preserving_raw_keep_ct};
use crate::target::markers::MarkerSet;
use crate::target::parameters::TargetParameter;
use crate::target::url::TargetUrl;
use crate::techniques::payload_opts::encode_with_safe_chars;
use crate::techniques::request_tamper::hpp_body_str;
use http::Method;

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
