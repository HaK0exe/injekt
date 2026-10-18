use super::inject::{inject_body_param, inject_param, inject_with_marker};
use super::opts::ProbeOpts;
use crate::http::client::RequestSpec;
use crate::target::markers::MarkerSet;
use crate::target::parameters::{ParameterLocation, TargetParameter};
use crate::target::raw_request::RawRequest;
use crate::target::url::TargetUrl;
use crate::techniques::payload_opts::PayloadOpts;
use crate::techniques::request_tamper::{hpp_query_url, should_apply_chunked};
use http::Method;

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
