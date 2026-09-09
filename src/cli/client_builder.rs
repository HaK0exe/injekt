#![deny(unsafe_code)]

use crate::{
    cli::args::Cli,
    error::InjektError,
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
};
use http::{HeaderName, HeaderValue};
use std::{sync::Arc, time::Duration};

/// Build HTTP client from CLI network options (type-state: timeout mandatory).
///
/// # Errors
/// Returns an error if `--proxy`, `--headers`, or `--cookies` fail to parse,
/// or if the underlying client fails to build.
pub fn build_client(cli: &Cli, allow_private: bool) -> crate::error::Result<HttpClient> {
    let jitter = {
        let s = cli.effective_jitter();
        let parts: Vec<f64> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
        match parts.as_slice() {
            [mean, std] => Jitter::new(*mean, *std),
            _ => Jitter::default(),
        }
    };

    let rl = Arc::new(RateLimiter::new(cli.effective_rate_limit()));

    let retry = crate::http::retry::RetryPolicy {
        max_retries: cli.effective_retries(),
        base_delay: Duration::from_millis(cli.effective_delay()),
        max_delay: Duration::from_secs(5),
    };

    let mut builder = HttpClient::builder().timeout(Duration::from_secs(cli.effective_timeout()));
    // Realistic browser identity (UA + Sec-CH-UA + Accept*): without it every
    // request goes out with no User-Agent at all, which trips protocol-anomaly
    // rules (e.g. CRS 920320) and contradicts the documented OPSEC posture.
    // One identity per scan (rotation across scans); per-request spec headers
    // still win on conflict.
    builder = builder.identity(crate::http::identity::Identity::random());
    builder = builder
        .jitter(jitter)
        .rate_limiter(rl)
        .retry_policy(retry)
        .allow_private(allow_private);

    if let Some(proxy) = cli.effective_proxy() {
        match crate::http::proxy::ProxyConfig::parse(&proxy) {
            Ok(p) => builder = builder.proxy(p),
            Err(e) => {
                return Err(InjektError::Http(format!("invalid proxy '{proxy}': {e}")));
            }
        }
    }

    for header in &cli.headers {
        let Some((name, value)) = header.split_once(':') else {
            return Err(InjektError::Http(format!(
                "invalid --headers value '{header}', expected 'Name: value'"
            )));
        };
        // Same-origin only: stored per-request, never as reqwest
        // `default_headers` (which would leak cross-host on redirect).
        builder = builder.user_header(
            HeaderName::from_bytes(name.trim().as_bytes())
                .map_err(|e| InjektError::Http(format!("invalid header name '{name}': {e}")))?,
            HeaderValue::from_str(value.trim())
                .map_err(|e| InjektError::Http(format!("invalid header value '{value}': {e}")))?,
        );
    }

    if let Some(cookies) = &cli.cookies {
        builder = builder.user_header(
            http::header::COOKIE,
            HeaderValue::from_str(cookies)
                .map_err(|e| InjektError::Http(format!("invalid --cookies header value: {e}")))?,
        );
    }

    builder
        .build()
        .map_err(|e| InjektError::Http(format!("client build: {e}")))
}
