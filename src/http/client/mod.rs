#![deny(unsafe_code)]

//! Shared HTTP client (P4 split): `HttpClient` + accessors and the
//! request/response models (`RequestSpec`, `TimedResponse`). Components:
//! `builder` (typestate builder, `timeout()` mandatory), `sender`
//! (retry/redirect-chasing send path), `body` (bounded reads), `redirect`
//! (hop safety + RFC method rewrites), `throttle` (detectability counters).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::{HeaderMap, Method};
use reqwest::Client;

use crate::http::{
    cookies::CookieJar,
    jitter::Jitter,
    rate_limit::RateLimiter,
    redirects::RedirectPolicy,
    retry::RetryPolicy,
    timeouts::{ClassTimeouts, RequestClass},
};
use tokio::sync::{RwLock, Semaphore};

mod body;
mod builder;
mod error;
mod redirect;
mod sender;
mod throttle;

pub use body::MAX_RESPONSE_BODY_BYTES;
pub use builder::{ClientBuilder, HasTimeout, NeedTimeout};
pub use error::ClientError;

/// Shared HTTP client (Arc internally).
#[derive(Clone)]
#[non_exhaustive]
pub struct HttpClient {
    inner: Arc<Client>,
    jitter: Jitter,
    rate_limiter: Arc<RateLimiter>,
    cookies: Arc<RwLock<CookieJar>>,
    retry: RetryPolicy,
    timeout: Duration,
    /// Per-class timeouts (C10): `boolean` 10s, `time` 15s, `oob`/default 30s.
    timeouts: ClassTimeouts,
    /// Isolated `time`-class pool (C10, [`TIME_POOL_SLOTS`](crate::http::timeouts::TIME_POOL_SLOTS) permits): only
    /// [`RequestClass::Time`] probes acquire it, so a slow `pg_sleep` can
    /// never saturate the `buffer_unordered` lanes used by `boolean`/`error`.
    /// The permit is RAII-held for the whole probe (jitter + retries
    /// included) and released on drop — including on cancellation, so no
    /// orphaned permit can wedge the pool.
    time_slots: Arc<Semaphore>,
    /// Detectability counters (C10, bench Annexe A): every `403`/`429`
    /// response observed on any hop, including responses consumed by a retry.
    /// Drained per run by the orchestrator via
    /// [`Self::take_detectability_counts`].
    throttle_403: Arc<AtomicU64>,
    throttle_429: Arc<AtomicU64>,
    redirect_policy: RedirectPolicy,
    allow_private: bool,
    user_headers: HeaderMap,
    remote_dns: bool,
    /// Shared run RNG for jitter sleeps and retry backoff, seeded from
    /// `--seed` (`None` = OS randomness, historical behaviour). Shared via
    /// `Arc` so cloned clients draw from one sequence; the lock is held only
    /// to draw a delay value, never across `.await`.
    rng: Arc<std::sync::Mutex<rand::rngs::StdRng>>,
}

impl core::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpClient")
            .field("jitter", &self.jitter)
            .field("rate_limiter", &self.rate_limiter)
            .field("retry", &self.retry)
            .field("timeout", &self.timeout)
            .field("timeouts", &self.timeouts)
            .field("throttle_403", &self.throttle_403.load(Ordering::Relaxed))
            .field("throttle_429", &self.throttle_429.load(Ordering::Relaxed))
            .field("redirect_policy", &self.redirect_policy)
            .field("allow_private", &self.allow_private)
            .field("user_headers", &"[REDACTED]")
            .field("remote_dns", &self.remote_dns)
            .finish_non_exhaustive()
    }
}

/// Request specification for generic HTTP calls (2026 best practice).
///
/// `Debug` is manual: `url` is scrubbed (query secrets, userinfo), headers
/// never render (cookies/auth), body shows its length only.
#[derive(Clone)]
#[non_exhaustive]
pub struct RequestSpec {
    pub method: Method,
    pub url: String,
    pub headers: HeaderMap,
    pub body: Option<bytes::Bytes>,
}

impl core::fmt::Debug for RequestSpec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let scrubber = crate::session::scrubber::Scrubber::new(false);
        f.debug_struct("RequestSpec")
            .field("method", &self.method)
            .field("url", &scrubber.scrub(&self.url))
            .field("headers", &"[REDACTED]")
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.as_ref().map(bytes::Bytes::len))
            .finish_non_exhaustive()
    }
}

impl RequestSpec {
    #[must_use]
    pub fn new(method: Method, url: String) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
        }
    }

    #[must_use]
    pub fn get(url: String) -> Self {
        Self::new(Method::GET, url)
    }

    #[must_use]
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(bytes::Bytes::from(body));
        self
    }
}

/// Pure send timing for a class-aware request (P0-VAGUE-1).
///
/// `resp` is the final response (after redirects/retries, same as
/// [`HttpClient::send_with_retry_for_class`]). `elapsed_send` is the wall
/// time of **only** the last successful `timeout(class_timeout, req.send())`
/// — never a sum, never jitter / rate-limiter / sleeps / backoff /
/// `Retry-After`. `attempts` counts every `req.send()` tentative across
/// retries and redirect hops; `retried` is `attempts > 1`.
///
/// `Debug` is manual: reqwest's `Response` debug renders URL + headers, so
/// only the scrubbed URL, status and timings are shown.
#[non_exhaustive]
pub struct TimedResponse {
    pub resp: reqwest::Response,
    pub elapsed_send: Duration,
    pub attempts: u32,
    pub retried: bool,
}

impl core::fmt::Debug for TimedResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let scrubber = crate::session::scrubber::Scrubber::new(false);
        f.debug_struct("TimedResponse")
            .field("url", &scrubber.scrub(self.resp.url().as_str()))
            .field("status", &self.resp.status())
            .field("elapsed_send", &self.elapsed_send)
            .field("attempts", &self.attempts)
            .field("retried", &self.retried)
            .finish_non_exhaustive()
    }
}

impl HttpClient {
    #[must_use]
    pub fn builder() -> ClientBuilder<NeedTimeout> {
        ClientBuilder::new()
    }

    #[must_use]
    pub fn client(&self) -> Arc<Client> {
        Arc::clone(&self.inner)
    }

    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Per-class timeout (C10): `boolean` 10s, `time` 15s, `oob`/default base.
    #[must_use]
    pub fn timeout_for(&self, class: RequestClass) -> Duration {
        self.timeouts.for_class(class)
    }

    #[must_use]
    pub const fn timeouts(&self) -> ClassTimeouts {
        self.timeouts
    }

    #[must_use]
    pub fn redirect_policy(&self) -> RedirectPolicy {
        self.redirect_policy
    }

    /// Whether private/loopback targets are allowed (lab only).
    #[must_use]
    pub const fn allow_private(&self) -> bool {
        self.allow_private
    }

    /// Whether DNS is resolved remotely by the proxy (`socks5h://`).
    /// When `true`, local DNS-time SSRF resolution is skipped (no local leak).
    #[must_use]
    pub const fn uses_remote_dns(&self) -> bool {
        self.remote_dns
    }

    #[must_use]
    pub fn jitter(&self) -> Jitter {
        self.jitter
    }

    #[must_use]
    pub fn rate_limiter(&self) -> Arc<RateLimiter> {
        Arc::clone(&self.rate_limiter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_spec_debug_redacts_url_and_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("session=secret123"),
        );
        let spec = RequestSpec::get("https://example.com/?token=secret123".to_owned())
            .with_headers(headers)
            .with_body(b"password=secret123".to_vec());
        let rendered = format!("{spec:?}");
        assert!(!rendered.contains("secret123"), "{rendered}");
        assert!(rendered.contains("example.com"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        assert!(rendered.contains("body_len"), "{rendered}");
    }
}
