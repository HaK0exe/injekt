#![deny(unsafe_code)]

use crate::{
    cli::args::Cli,
    error::InjektError,
    http::{
        client::HttpClient,
        jitter::{JITTER_FLOOR_MS, Jitter},
        rate_limit::RateLimiter,
    },
};
use http::{HeaderName, HeaderValue};
use std::{sync::Arc, time::Duration};

/// Parse `--jitter "mean_ms,std_ms"` with the OPSEC floor enforced (C10):
/// the 200ms floor is a minimum, never a target — low explicit values are
/// lifted, `stealth` cadence (`1200,400`) is untouched, nothing is ever sped
/// up. Unparseable input falls back to [`Jitter::default`] (already floored).
#[must_use]
pub fn jitter_from_str(s: &str) -> Jitter {
    let parts: Vec<f64> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
    match parts.as_slice() {
        [mean, std] => Jitter::new(*mean, *std).with_min(JITTER_FLOOR_MS),
        _ => Jitter::default(),
    }
}

/// Build HTTP client from CLI network options (type-state: timeout mandatory).
///
/// Per-class timeouts (C10: `boolean` ≤10s, `time` ≤15s, `oob`/default base)
/// derive from the effective `--timeout` inside
/// [`HttpClient::build`](crate::http::client::ClientBuilder::build); the
/// isolated 2-slot `time` pool is always on.
///
/// # Errors
/// Returns an error if `--proxy`, `--headers`, or `--cookies` fail to parse,
/// or if the underlying client fails to build.
pub fn build_client(cli: &Cli, allow_private: bool) -> crate::error::Result<HttpClient> {
    let jitter = jitter_from_str(&cli.effective_jitter());

    let rl = Arc::new(RateLimiter::new(cli.effective_rate_limit()));

    let retry = crate::http::retry::RetryPolicy {
        max_retries: cli.effective_retries(),
        base_delay: Duration::from_millis(cli.effective_delay()),
        max_delay: Duration::from_secs(5),
    };

    let mut builder = HttpClient::builder().timeout(Duration::from_secs(cli.effective_timeout()));
    // Seeded UA rotation + jitter/retry: the same `--seed` yields the same
    // identity pick and delay sequence (C1 metrology); `None` preserves the
    // historical OS-random behaviour.
    let seed = cli.effective_seed();
    let mut seed_rng = crate::seeded_rng::make_rng(seed);
    // Realistic browser identity (UA + Sec-CH-UA + Accept*): without it every
    // request goes out with no User-Agent at all, which trips protocol-anomaly
    // rules (e.g. CRS 920320) and contradicts the documented OPSEC posture.
    // One identity per scan (rotation across scans); per-request spec headers
    // still win on conflict.
    builder = builder.identity(crate::http::identity::Identity::random_with_rng(
        &mut seed_rng,
    ));
    builder = builder
        .seed(seed)
        .jitter(jitter)
        .rate_limiter(rl)
        .retry_policy(retry)
        .allow_private(allow_private);

    if let Some(proxy) = cli.effective_proxy() {
        match crate::http::proxy::ProxyConfig::parse(&proxy) {
            Ok(p) => builder = builder.proxy(p),
            Err(e) => {
                // Never echo the raw proxy URL: it may carry `user:pass@`.
                // `ProxyError::Invalid` is already credential-redacted; keep
                // the message generic so nothing else leaks.
                return Err(InjektError::Http(format!("invalid proxy: {e}")));
            }
        }
    }

    for header in &cli.headers {
        let Some((name, value)) = header.split_once(':') else {
            // Never echo the raw header: it may be `Authorization: <secret>`.
            return Err(InjektError::Http(
                "invalid --headers value (expected 'Name: value')".to_owned(),
            ));
        };
        // Same-origin only: stored per-request, never as reqwest
        // `default_headers` (which would leak cross-host on redirect).
        builder = builder.user_header(
            HeaderName::from_bytes(name.trim().as_bytes())
                .map_err(|e| InjektError::Http(format!("invalid header name '{name}': {e}")))?,
            HeaderValue::from_str(value.trim()).map_err(|e| {
                InjektError::Http(format!("invalid header value for '{name}': {e}"))
            })?,
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
