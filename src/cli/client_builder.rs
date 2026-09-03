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
    let _ = allow_private;

    let jitter = cli
        .jitter
        .as_deref()
        .map(|s| {
            let parts: Vec<f64> = s.split(',').filter_map(|x| x.parse().ok()).collect();
            match parts.as_slice() {
                [mean, std] => Jitter::new(*mean, *std),
                _ => Jitter::default(),
            }
        })
        .unwrap_or_default();

    let rl = cli
        .rate_limit
        .map(RateLimiter::new)
        .map_or_else(|| Arc::new(RateLimiter::new(10.0)), Arc::new);

    let retry = crate::http::retry::RetryPolicy {
        max_retries: cli.retries,
        base_delay: Duration::from_millis(cli.delay),
        max_delay: Duration::from_secs(5),
    };

    let mut builder = HttpClient::builder().timeout(Duration::from_secs(cli.timeout));
    builder = builder.jitter(jitter).rate_limiter(rl).retry_policy(retry);

    if let Some(proxy) = &cli.proxy {
        match crate::http::proxy::ProxyConfig::parse(proxy) {
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
        builder = builder.header(
            HeaderName::from_bytes(name.trim().as_bytes())
                .map_err(|e| InjektError::Http(format!("invalid header name '{name}': {e}")))?,
            HeaderValue::from_str(value.trim())
                .map_err(|e| InjektError::Http(format!("invalid header value '{value}': {e}")))?,
        );
    }

    if let Some(cookies) = &cli.cookies {
        builder = builder.header(
            http::header::COOKIE,
            HeaderValue::from_str(cookies)
                .map_err(|e| InjektError::Http(format!("invalid --cookies header value: {e}")))?,
        );
    }

    builder
        .build()
        .map_err(|e| InjektError::Http(format!("client build: {e}")))
}
