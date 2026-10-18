//! Redirect-hop safety: RFC method/body rewrites, relative `Location`
//! resolution, same-origin gating (operator headers never cross hosts) and
//! URL-validation -> `ClientError` mapping.

use http::{HeaderMap, Method};

use super::{ClientError, RequestSpec};

pub(super) fn map_url_error(url: &str, e: &crate::target::url::UrlError) -> ClientError {
    use crate::target::url::UrlError;
    match e {
        // Scrubbed: `spec.url` may carry `?token=` secrets or userinfo and
        // this error surfaces in `eprintln!`/logs via `Display`.
        UrlError::PrivateIp => {
            ClientError::PrivateHost(crate::session::scrubber::Scrubber::new(false).scrub(url))
        }
        UrlError::Invalid(reason) => ClientError::InvalidUrl(reason.clone()),
        UrlError::Scheme(scheme) => {
            ClientError::InvalidUrl(format!("unsupported scheme: {scheme}"))
        }
        UrlError::Dns { host, reason } => {
            ClientError::InvalidUrl(format!("DNS resolution failed for '{host}': {reason}"))
        }
    }
}

pub(super) fn is_redirect_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

/// Resolve a `Location` value (absolute or relative) against the current URL.
pub(super) fn resolve_redirect_url(
    current_url: &str,
    location: &str,
) -> Result<String, ClientError> {
    if location.is_empty() {
        return Err(ClientError::InvalidRedirect(
            "empty Location header".to_owned(),
        ));
    }
    // Absolute URL: use as-is (validated by caller).
    if let Ok(parsed) = url::Url::parse(location) {
        if matches!(parsed.scheme(), "http" | "https") {
            return Ok(parsed.to_string());
        }
        return Err(ClientError::InvalidRedirect(format!(
            "unsupported scheme in redirect: {}",
            parsed.scheme()
        )));
    }
    // Relative: join against the current URL.
    let base = url::Url::parse(current_url).map_err(|e| ClientError::InvalidUrl(e.to_string()))?;
    base.join(location)
        .map(|u| u.to_string())
        .map_err(|e| ClientError::InvalidRedirect(e.to_string()))
}

/// Build the follow-up spec for a redirect hop: rewrite method/body per RFC
/// and drop per-request headers cross-host to avoid credential leaks.
/// (`CookieJar` is already scoped per URL in `build_request`; operator
/// `--headers`/`--cookies` live in `HttpClient::user_headers` and are gated
/// same-origin with the initial target in `send_with_retry`, so they never
/// reach a cross-host hop even though `reqwest` `default_headers` would.)
pub(super) fn follow_spec(
    current: &RequestSpec,
    status: reqwest::StatusCode,
    next_url: String,
) -> RequestSpec {
    let next_method = redirect_method(&current.method, status);
    let method_changed = next_method != current.method;
    let same_host = is_same_host(&current.url, &next_url);
    let mut headers = if same_host {
        current.headers.clone()
    } else {
        // Cross-host: do not forward per-request headers (auth/cookies).
        HeaderMap::new()
    };
    if method_changed {
        // GET must not carry a body; strip body-framing headers with it.
        headers.remove(http::header::CONTENT_LENGTH);
        headers.remove(http::header::CONTENT_TYPE);
        headers.remove(http::header::TRANSFER_ENCODING);
    }
    let body = if method_changed {
        None
    } else {
        current.body.clone()
    };
    RequestSpec {
        method: next_method,
        url: next_url,
        headers,
        body,
    }
}

fn redirect_method(current: &Method, status: reqwest::StatusCode) -> Method {
    match status.as_u16() {
        // `303 See Other`: always GET (except HEAD, which we never send).
        303 => Method::GET,
        // Historic compatibility: `301/302` rewrite POST to GET.
        301 | 302 if *current == Method::POST => Method::GET,
        // `307/308`: strict method + body preservation.
        _ => current.clone(),
    }
}

pub(super) fn is_same_host(a: &str, b: &str) -> bool {
    let (Ok(ua), Ok(ub)) = (url::Url::parse(a), url::Url::parse(b)) else {
        return false;
    };
    ua.host_str() == ub.host_str()
        && ua.port_or_known_default() == ub.port_or_known_default()
        && ua.scheme() == ub.scheme()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_host_error_scrubs_url_secrets() {
        let err = map_url_error(
            "http://user:pass@127.0.0.1/?token=secret123",
            &crate::target::url::UrlError::PrivateIp,
        );
        let rendered = format!("{err}");
        assert!(!rendered.contains("secret123"), "{rendered}");
        assert!(!rendered.contains("pass"), "{rendered}");
        assert!(rendered.contains("127.0.0.1"), "{rendered}");
    }
}
