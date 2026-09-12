#![deny(unsafe_code)]

use crate::http::{
    cookies::CookieJar,
    identity::Identity,
    jitter::Jitter,
    proxy::{ProxyConfig, ProxyError},
    rate_limit::RateLimiter,
    redirects::RedirectPolicy,
    retry::RetryPolicy,
    timeouts::{ClassTimeouts, RequestClass, TIME_POOL_SLOTS},
};
use crate::target::url::TargetUrl;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use reqwest::{Client, RequestBuilder};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::sync::{RwLock, Semaphore};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error("timeout not set — builder requires timeout() before build()")]
    MissingTimeout,
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Proxy(#[from] ProxyError),
    #[error("cancelled")]
    Cancelled,
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("invalid header: {0}")]
    InvalidHeader(String),
    #[error("SSRF blocked: private/loopback host rejected: {0}")]
    PrivateHost(String),
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("invalid redirect location: {0}")]
    InvalidRedirect(String),
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("response body exceeded {0} bytes cap")]
    BodyTooLarge(usize),
}

/// Hard cap on a single response body read (`read_body_with_timeout` /
/// `read_body_string_with_timeout`): a malicious or misconfigured target
/// streaming an unbounded/huge body must not be allowed to exhaust memory —
/// the stream is read incrementally and aborted the moment this is exceeded,
/// so at most one chunk beyond the cap is ever buffered.
pub const MAX_RESPONSE_BODY_BYTES: usize = 10 * 1024 * 1024;

///Marker types for typestate.
#[derive(Debug)]
pub struct NeedTimeout;
#[derive(Debug)]
pub struct HasTimeout;

/// Builder with typestate: timeout mandatory.
#[derive(Debug)]
pub struct ClientBuilder<State> {
    timeout: Option<Duration>,
    /// Per-class overrides (C10): unset = derived from `timeout` via
    /// [`ClassTimeouts::from_default`] (`boolean` ≤10s, `time` ≤15s).
    boolean_timeout: Option<Duration>,
    time_timeout: Option<Duration>,
    oob_timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    proxy: Option<ProxyConfig>,
    identity: Option<Identity>,
    jitter: Option<Jitter>,
    rate_limit: Option<Arc<RateLimiter>>,
    retry: RetryPolicy,
    redirect_policy: RedirectPolicy,
    extra_headers: HeaderMap,
    /// Operator-supplied headers (`--headers` / `--cookies`): per-request,
    /// same-origin only — never `default_headers`, so a cross-host redirect
    /// cannot leak `Authorization` / `Cookie` to the redirect target.
    user_headers: HeaderMap,
    allow_private: bool,
    /// Deterministic run seed (`--seed`): `None` preserves historical
    /// OS-random jitter/retry. Threaded into the shared run RNG at `build()`.
    seed: Option<u64>,
    _state: core::marker::PhantomData<State>,
}

impl ClientBuilder<NeedTimeout> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            timeout: None,
            boolean_timeout: None,
            time_timeout: None,
            oob_timeout: None,
            connect_timeout: None,
            proxy: None,
            identity: None,
            jitter: None,
            rate_limit: None,
            retry: RetryPolicy::default(),
            redirect_policy: RedirectPolicy::default(),
            extra_headers: HeaderMap::new(),
            user_headers: HeaderMap::new(),
            allow_private: false,
            seed: None,
            _state: core::marker::PhantomData,
        }
    }

    #[must_use]
    pub fn timeout(self, d: Duration) -> ClientBuilder<HasTimeout> {
        ClientBuilder {
            timeout: Some(d),
            boolean_timeout: self.boolean_timeout,
            time_timeout: self.time_timeout,
            oob_timeout: self.oob_timeout,
            connect_timeout: self.connect_timeout,
            proxy: self.proxy,
            identity: self.identity,
            jitter: self.jitter,
            rate_limit: self.rate_limit,
            retry: self.retry,
            redirect_policy: self.redirect_policy,
            extra_headers: self.extra_headers,
            user_headers: self.user_headers,
            allow_private: self.allow_private,
            seed: self.seed,
            _state: core::marker::PhantomData,
        }
    }
}

impl<State> ClientBuilder<State> {
    #[must_use]
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = Some(d);
        self
    }

    /// Override the derived `boolean`-class timeout (default: `min(base, 10s)`).
    #[must_use]
    pub fn boolean_timeout(mut self, d: Duration) -> Self {
        self.boolean_timeout = Some(d);
        self
    }

    /// Override the derived `time`-class timeout (default: `min(base, 15s)`).
    #[must_use]
    pub fn time_timeout(mut self, d: Duration) -> Self {
        self.time_timeout = Some(d);
        self
    }

    /// Override the `oob`-class timeout (default: the base `timeout`).
    #[must_use]
    pub fn oob_timeout(mut self, d: Duration) -> Self {
        self.oob_timeout = Some(d);
        self
    }

    #[must_use]
    pub fn proxy(mut self, p: ProxyConfig) -> Self {
        self.proxy = Some(p);
        self
    }

    #[must_use]
    pub fn identity(mut self, id: Identity) -> Self {
        self.identity = Some(id);
        self
    }

    #[must_use]
    pub fn jitter(mut self, j: Jitter) -> Self {
        self.jitter = Some(j);
        self
    }

    #[must_use]
    pub fn rate_limiter(mut self, rl: Arc<RateLimiter>) -> Self {
        self.rate_limit = Some(rl);
        self
    }

    #[must_use]
    pub fn retry_policy(mut self, r: RetryPolicy) -> Self {
        self.retry = r;
        self
    }

    #[must_use]
    pub fn redirect_policy(mut self, p: RedirectPolicy) -> Self {
        self.redirect_policy = p;
        self
    }

    /// Allow private/loopback targets (lab only, `--allow-private`).
    /// Defaults to `false` (SSRF-safe). Propagated from the CLI; when
    /// `false`, the initial URL and every redirect hop are re-validated
    /// lexically + DNS-time, and private hops are rejected.
    #[must_use]
    pub fn allow_private(mut self, allow: bool) -> Self {
        self.allow_private = allow;
        self
    }

    /// Deterministic run seed (`--seed`): seeds the shared run RNG used for
    /// jitter sleeps and retry backoff. `None` (default) preserves historical
    /// OS-random behaviour.
    #[must_use]
    pub fn seed(mut self, seed: Option<u64>) -> Self {
        self.seed = seed;
        self
    }

    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.extra_headers.insert(name, value);
        self
    }

    /// Operator-supplied header (`--headers` / `--cookies`): stored
    /// per-request and only sent same-origin (see `send_with_retry`).
    /// Prefer this over [`Self::header`] for anything sensitive.
    #[must_use]
    pub fn user_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.user_headers.insert(name, value);
        self
    }
}

impl ClientBuilder<HasTimeout> {
    /// # Errors
    /// Returns an error if timeout is missing or the underlying `reqwest` client fails to build.
    pub fn build(self) -> Result<HttpClient, ClientError> {
        let timeout = self.timeout.ok_or(ClientError::MissingTimeout)?;
        // SSRF: never let reqwest auto-follow. `Limited(n)` is enforced
        // manually in `send_with_retry` so every `Location` hop is
        // re-parsed via `TargetUrl` + DNS-checked before any connection.
        // `Policy::none()` here is intentional, not a behavior change for
        // callers: `HttpClient::redirect_policy()` still reports the
        // configured manual limit.
        let reqwest_policy = reqwest::redirect::Policy::none();
        let mut builder = Client::builder()
            .timeout(timeout)
            .connect_timeout(self.connect_timeout.unwrap_or(Duration::from_secs(10)))
            .gzip(true)
            .brotli(true)
            .cookie_store(false) // we manage cookies manually for OPSEC
            .use_rustls_tls()
            // Pool vs Cloudflare-style edge: CF closes idle keep-alive
            // connections without TLS `close_notify`, and rustls surfaces
            // the reuse as `UnexpectedEof` (see `retry::is_retryable_error`,
            // which transparently retries that exact race once). A short
            // idle timeout + small per-host pool shrinks the race window
            // without disabling reuse (default reqwest: 90s / unlimited).
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(8)
            .redirect(reqwest_policy);

        // `socks5h://` resolves remotely: remember it so `send_with_retry`
        // skips local DNS-time SSRF resolution (no local leak, `.onion`
        // works). Lexical + IP-literal checks still apply everywhere.
        let remote_dns = matches!(self.proxy, Some(ProxyConfig::Socks5h(_)));
        if let Some(proxy) = self.proxy {
            let p = reqwest::Proxy::all(proxy.as_str())?;
            builder = builder.proxy(p);
        }

        let mut default_headers = reqwest::header::HeaderMap::new();
        if let Some(id) = &self.identity {
            // Pre-built HeaderMap: no per-build String allocs / re-parsing.
            default_headers.extend(id.header_map());
        }
        for (k, v) in &self.extra_headers {
            default_headers.insert(k.clone(), v.clone());
        }
        // NOTE: `user_headers` are intentionally NOT in `default_headers`:
        // `reqwest` would re-apply them on every cross-host redirect hop.
        // They are injected per-request in `build_request` only when the hop
        // is same-origin with the initial target.
        builder = builder.default_headers(default_headers);

        let inner = builder.build()?;

        let mut timeouts = ClassTimeouts::from_default(timeout);
        if let Some(b) = self.boolean_timeout {
            timeouts.boolean = b;
        }
        if let Some(t) = self.time_timeout {
            timeouts.time = t;
        }
        if let Some(o) = self.oob_timeout {
            timeouts.oob = o;
        }

        Ok(HttpClient {
            inner: Arc::new(inner),
            jitter: self.jitter.unwrap_or_default(),
            rate_limiter: self.rate_limit.unwrap_or_else(|| {
                Arc::new(RateLimiter::new(crate::http::rate_limit::DEFAULT_RPS))
            }),
            cookies: Arc::new(RwLock::new(CookieJar::new())),
            retry: self.retry,
            timeout,
            timeouts,
            time_slots: Arc::new(Semaphore::new(TIME_POOL_SLOTS)),
            throttle_403: Arc::new(AtomicU64::new(0)),
            throttle_429: Arc::new(AtomicU64::new(0)),
            redirect_policy: self.redirect_policy,
            allow_private: self.allow_private,
            user_headers: self.user_headers,
            remote_dns,
            rng: Arc::new(std::sync::Mutex::new(crate::seeded_rng::make_rng(
                self.seed,
            ))),
        })
    }
}

impl Default for ClientBuilder<NeedTimeout> {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// Isolated `time`-class pool (C10, [`TIME_POOL_SLOTS`] permits): only
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
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RequestSpec {
    pub method: Method,
    pub url: String,
    pub headers: HeaderMap,
    pub body: Option<bytes::Bytes>,
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

    fn record_throttle(&self, status: u16) {
        if status == 403 {
            self.throttle_403.fetch_add(1, Ordering::Relaxed);
        } else if status == 429 {
            self.throttle_429.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drain the per-run detectability counters as `(403, 429)` (C10, bench
    /// Annexe A `detectability`). Take-semantics (`swap(0)`) so the
    /// orchestrator absorbs each run exactly once, even when the client is
    /// reused across runs.
    #[must_use]
    pub fn take_detectability_counts(&self) -> (u64, u64) {
        (
            self.throttle_403.swap(0, Ordering::Relaxed),
            self.throttle_429.swap(0, Ordering::Relaxed),
        )
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

    /// Generic send with jitter, rate-limit, retry, timeout and cancellation.
    ///
    /// Default-class overload of [`Self::send_with_retry_for_class`]
    /// (baseline, context, `error`/`union`/`stacked`/`json` probes).
    ///
    /// SSRF hardening (OWASP): the initial URL and **every** redirect hop are
    /// re-validated lexically via [`TargetUrl`] before connecting, plus
    /// DNS-time unless the proxy resolves remotely (`socks5h://`, see
    /// `remote_dns`: local `lookup_host` would leak the hostname and break
    /// `.onion`, and cannot prove the IP the proxy will dial — TOCTOU).
    /// `reqwest` auto-follow is disabled at build time; this method follows
    /// `Location` manually up to `redirect_policy`. The manual [`CookieJar`]
    /// is scoped per URL (never forwarded cross-host), per-request headers
    /// are dropped on cross-host hops, and operator `--headers`/`--cookies`
    /// (`user_headers`) are only sent same-origin with the initial target.
    ///
    /// # Errors
    /// Returns an error if the request is cancelled, times out, targets a
    /// private host without `allow_private`, exceeds the redirect limit, or
    /// fails after retries.
    pub async fn send_with_retry(
        &self,
        spec: RequestSpec,
        cancel: &CancellationToken,
    ) -> Result<reqwest::Response, ClientError> {
        self.send_with_retry_for_class(spec, RequestClass::Default, cancel)
            .await
    }

    /// Class-aware send (C10): `boolean`/`time`/`oob` probes pass their
    /// [`RequestClass`] so the matching per-class timeout applies, and
    /// [`RequestClass::Time`] additionally holds one of the
    /// [`TIME_POOL_SLOTS`] isolated pool permits for the whole probe —
    /// `boolean`/`error` traffic never waits on a slow `pg_sleep`.
    ///
    /// The permit acquisition itself is cancellable (`select!` on `cancel`),
    /// and the permit is RAII-released on every return path, so a mid-scan
    /// `Ctrl+C` leaves zero orphaned permits (the pool stays reusable).
    ///
    /// # Errors
    /// Returns an error if the request is cancelled, times out, targets a
    /// private host without `allow_private`, exceeds the redirect limit, or
    /// fails after retries.
    pub async fn send_with_retry_for_class(
        &self,
        spec: RequestSpec,
        class: RequestClass,
        cancel: &CancellationToken,
    ) -> Result<reqwest::Response, ClientError> {
        // Isolated time pool: at most `TIME_POOL_SLOTS` slow probes in
        // flight. Non-time classes skip this entirely (no starvation).
        let _time_permit = if matches!(class, RequestClass::Time) {
            let owned = self.time_slots.clone();
            let acquired = tokio::select! {
                () = cancel.cancelled() => return Err(ClientError::Cancelled),
                p = owned.acquire_owned() => p,
            };
            match acquired {
                Ok(permit) => Some(permit),
                // The semaphore is never closed; treat shutdown as cancel.
                Err(_) => return Err(ClientError::Cancelled),
            }
        } else {
            None
        };
        TargetUrl::validate_redirect_location_with_remote_dns(
            &spec.url,
            self.allow_private,
            self.remote_dns,
        )
        .await
        .map_err(|e| map_url_error(&spec.url, &e))?;
        // Cancellable jitter + rate-limit: internal sleeps are themselves
        // wrapped in `select!` so Ctrl+C aborts promptly (official tokio pattern).
        // The delay is drawn from the shared run RNG (seeded via `--seed`;
        // `None` = OS randomness) under a short lock, then slept without
        // holding the lock.
        if !self.rate_limiter.acquire_cancellable(cancel).await {
            return Err(ClientError::Cancelled);
        }
        let jitter_delay = {
            let mut guard = self
                .rng
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.jitter.next_delay_with_rng(&mut *guard)
        };
        let jitter_done = tokio::select! {
            () = cancel.cancelled() => false,
            () = tokio::time::sleep(jitter_delay) => true,
        };
        if !jitter_done {
            return Err(ClientError::Cancelled);
        }

        let origin_url = spec.url.clone();
        let mut current = spec;
        // Operator headers go to the origin; cross-host hops drop them.
        let mut include_user = true;
        let mut hops = 0_usize;
        loop {
            let resp = self
                .send_single_with_retry(&current, class, include_user, cancel)
                .await?;
            let status = resp.status();
            if !is_redirect_status(status) {
                return Ok(resp);
            }
            let Some(max) = self.redirect_policy.max_hops() else {
                // `RedirectPolicy::None`: return 3xx as-is, do not follow.
                return Ok(resp);
            };
            if hops >= max {
                return Err(ClientError::TooManyRedirects);
            }
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned);
            let Some(location) = location else {
                return Ok(resp);
            };
            // Resolve relative `Location` against the current URL; validate
            // the next hop BEFORE any connection (fail-closed).
            let next_url = resolve_redirect_url(&current.url, &location)?;
            TargetUrl::validate_redirect_location_with_remote_dns(
                &next_url,
                self.allow_private,
                self.remote_dns,
            )
            .await
            .map_err(|e| map_url_error(&next_url, &e))?;
            if cancel.is_cancelled() {
                return Err(ClientError::Cancelled);
            }
            // Bound redirect-chasing rate: one token per hop.
            if !self.rate_limiter.acquire_cancellable(cancel).await {
                return Err(ClientError::Cancelled);
            }
            // Same-origin gate for operator headers: compare against the
            // initial target, not just the previous hop (an open-redirect
            // chain A→B→A must not re-arm the leak on the way back unless B
            // equals the origin — strict, fail-closed).
            if !is_same_host(&origin_url, &next_url) {
                include_user = false;
            }
            current = follow_spec(&current, status, next_url);
            hops += 1;
        }
    }

    /// Single-hop send with retry (no redirect following).
    /// Every retry re-acquires the rate limiter so 429/5xx/timeout storms
    /// cannot exceed the configured RPS ceiling. The per-class timeout
    /// (`boolean` 10s, `time` 15s, `oob`/default base) bounds both the send
    /// and the retry sleeps are cancellable.
    async fn send_single_with_retry(
        &self,
        spec: &RequestSpec,
        class: RequestClass,
        include_user: bool,
        cancel: &CancellationToken,
    ) -> Result<reqwest::Response, ClientError> {
        let class_timeout = self.timeouts.for_class(class);
        let mut attempt = 0usize;
        loop {
            if cancel.is_cancelled() {
                return Err(ClientError::Cancelled);
            }
            let req = self.build_request(spec, include_user).await;

            // per-request timeout covers send() only; jitter/rate-limit already done
            let send_fut = req.send();
            let resp_res: Result<reqwest::Response, ClientError> = tokio::select! {
                () = cancel.cancelled() => return Err(ClientError::Cancelled),
                r = tokio::time::timeout(class_timeout, send_fut) => match r {
                    Ok(Ok(resp)) => Ok(resp),
                    Ok(Err(e)) => Err(e.into()),
                    Err(_) => Err(ClientError::Timeout(class_timeout)),
                }
            };

            match resp_res {
                Ok(resp) => {
                    // Store cookies with URL scope per RFC6265
                    let url_for_cookies = spec.url.clone();
                    for val in resp.headers().get_all(reqwest::header::SET_COOKIE) {
                        if let Ok(s) = val.to_str() {
                            let mut jar = self.cookies.write().await;
                            if let Ok(parsed) = url::Url::parse(&url_for_cookies) {
                                jar.parse_set_cookie_with_url(s, Some(&parsed));
                            } else {
                                jar.parse_set_cookie(s);
                            }
                        }
                    }
                    // Detectability (C10): every 403/429 counts, including
                    // ones consumed below by a retry.
                    let status_u16 = resp.status().as_u16();
                    self.record_throttle(status_u16);
                    if self.retry.should_retry(attempt, Some(status_u16)) {
                        attempt += 1;
                        let retry_after = resp
                            .headers()
                            .get(reqwest::header::RETRY_AFTER)
                            .and_then(|v| v.to_str().ok());
                        // Honor the server's ask twice, on throttling
                        // statuses only (429/503): pace the shared limiter
                        // (no immediate re-burst into an A3-style 5/s gate)
                        // AND sleep this request's backoff.
                        // `parse_retry_after_secs` caps at 60s (no parking).
                        let parsed_penalty =
                            retry_after.and_then(crate::http::retry::parse_retry_after_secs);
                        if matches!(status_u16, 429 | 503) {
                            self.rate_limiter.notify_rate_limited(parsed_penalty).await;
                        }
                        let delay = {
                            let mut guard = self
                                .rng
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            self.retry.delay_for_retry_after_with_rng(
                                attempt,
                                retry_after,
                                &mut *guard,
                            )
                        };
                        // Rate-limit retries: sleep the backoff AND take a token.
                        tokio::select! {
                            () = cancel.cancelled() => return Err(ClientError::Cancelled),
                            () = tokio::time::sleep(delay) => {},
                        }
                        if !self.rate_limiter.acquire_cancellable(cancel).await {
                            return Err(ClientError::Cancelled);
                        }
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    let retryable = match &e {
                        ClientError::Timeout(_) => true,
                        ClientError::Reqwest(e) => crate::http::retry::is_retryable_error(e),
                        _ => false,
                    } && self.retry.should_retry(attempt, None);
                    if retryable {
                        attempt += 1;
                        let delay = {
                            let mut guard = self
                                .rng
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            self.retry.delay_for_with_rng(attempt, &mut *guard)
                        };
                        tokio::select! {
                            () = cancel.cancelled() => return Err(ClientError::Cancelled),
                            () = tokio::time::sleep(delay) => {},
                        }
                        if !self.rate_limiter.acquire_cancellable(cancel).await {
                            return Err(ClientError::Cancelled);
                        }
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    async fn build_request(&self, spec: &RequestSpec, include_user: bool) -> RequestBuilder {
        let mut req = match spec.method {
            Method::GET => self.inner.get(&spec.url),
            Method::POST => self.inner.post(&spec.url),
            _ => self.inner.request(spec.method.clone(), &spec.url),
        };
        for (k, v) in &spec.headers {
            req = req.header(k, v);
        }
        // Operator headers (`--headers`/`--cookies`): same-origin only.
        // `spec.headers` (per-request, e.g. raw-file) always wins on conflict.
        if include_user {
            for (k, v) in &self.user_headers {
                if !spec.headers.contains_key(k) {
                    req = req.header(k, v);
                }
            }
        }
        if let Some(b) = &spec.body {
            // Chunked transfer: when Transfer-Encoding: chunked is set, stream the
            // body in small pieces so reqwest/hyper emits real chunk framing instead
            // of Content-Length. This bypasses WAFs inspecting content-length bodies.
            let is_chunked = spec
                .headers
                .get(http::header::TRANSFER_ENCODING)
                .is_some_and(|v| {
                    v.to_str()
                        .unwrap_or_default()
                        .to_ascii_lowercase()
                        .contains("chunked")
                });
            if is_chunked {
                let body = b.clone();
                let len = body.len();
                let stream = futures::stream::iter(
                    (0..len)
                        .step_by(8192)
                        .map(move |i| Ok::<_, std::io::Error>(body.slice(i..(i + 8192).min(len)))),
                );
                req = req.body(reqwest::Body::wrap_stream(stream));
            } else {
                req = req.body(b.clone());
            }
        }
        {
            let jar = self.cookies.read().await;
            // Scoped lookup only: never fall back to unscoped `header_value()`.
            // The fallback used to send ALL cookies (including Secure/Domain-mismatched
            // ones) when zero cookies passed the RFC6265 filter — a cross-origin
            // and http-downgrade leak. Absence of in-scope cookies means no header.
            if let Some(cv) = jar.header_value_for_url(Some(&spec.url)) {
                req = req.header(reqwest::header::COOKIE, cv);
            }
        }
        req
    }

    /// Cancellable GET with jitter/rate-limit/retry.
    ///
    /// # Errors
    /// Returns an error if the request is cancelled, times out, or fails after retries.
    pub async fn get_with_retry_cancellable(
        &self,
        url: String,
        cancel: &CancellationToken,
    ) -> Result<reqwest::Response, ClientError> {
        let spec = RequestSpec::get(url);
        self.send_with_retry(spec, cancel).await
    }

    /// Legacy GET with jitter/rate-limit/retry — delegates to
    /// [`Self::get_with_retry_cancellable`] with a detached token.
    ///
    /// # Errors
    /// Returns an error if the request times out or fails after retries.
    #[deprecated(
        since = "0.1.0",
        note = "use `get_with_retry_cancellable(url, cancel)` so Ctrl+C aborts the wait"
    )]
    pub async fn get_with_retry(&self, url: String) -> Result<reqwest::Response, ClientError> {
        let cancel = CancellationToken::new();
        self.get_with_retry_cancellable(url, &cancel).await
    }

    /// Read response body with timeout to prevent hanging on slow/incomplete responses.
    ///
    /// `ClientError::Timeout` (or any other error) must never be scored as an
    /// empty body — callers must skip scoring (`continue`/negative trial) so a
    /// transport failure cannot become a finding. `Timeout` is retryable in
    /// `send_with_retry`; body-read timeouts are surfaced here for the same
    /// treatment (retry/skip, never a finding).
    ///
    /// Default-class overload of [`Self::read_body_with_timeout_for_class`].
    ///
    /// # Errors
    /// Returns an error if reading the body times out or the underlying stream fails.
    ///
    /// # Errors
    /// Also returns [`ClientError::BodyTooLarge`] once the accumulated body
    /// exceeds [`MAX_RESPONSE_BODY_BYTES`] — the stream is dropped
    /// immediately rather than being drained to completion.
    pub async fn read_body_with_timeout(
        &self,
        resp: reqwest::Response,
    ) -> Result<Vec<u8>, ClientError> {
        self.read_body_with_timeout_for_class(resp, RequestClass::Default)
            .await
    }

    /// Class-aware body read (C10): the same per-class timeout that bounded
    /// the send bounds the body stream, so a `time` probe cannot linger on a
    /// dripping body past its 15s class budget.
    ///
    /// # Errors
    /// Returns an error if reading the body times out or the stream fails.
    pub async fn read_body_with_timeout_for_class(
        &self,
        resp: reqwest::Response,
        class: RequestClass,
    ) -> Result<Vec<u8>, ClientError> {
        use futures::StreamExt as _;
        let timeout = self.timeouts.for_class(class);
        let fut = async {
            let mut buf = Vec::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                buf.extend_from_slice(&chunk);
                if buf.len() > MAX_RESPONSE_BODY_BYTES {
                    return Err(ClientError::BodyTooLarge(MAX_RESPONSE_BODY_BYTES));
                }
            }
            Ok(buf)
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ClientError::Timeout(timeout))?
    }

    /// Bounded `String` body read: `read_body_with_timeout` + lossy UTF-8.
    ///
    /// Use this instead of `resp.text().await` everywhere — `text()` has no
    /// bound and `unwrap_or_default()` turns transport errors into `""`,
    /// which scores as similarity ~0 / confidence 0.75 (false positive).
    ///
    /// Default-class overload of [`Self::read_body_string_for_class`].
    ///
    /// # Errors
    /// Returns an error if reading the body times out or the stream fails.
    pub async fn read_body_string_with_timeout(
        &self,
        resp: reqwest::Response,
    ) -> Result<String, ClientError> {
        self.read_body_string_for_class(resp, RequestClass::Default)
            .await
    }

    /// Class-aware bounded `String` body read (C10).
    ///
    /// # Errors
    /// Returns an error if reading the body times out or the stream fails.
    pub async fn read_body_string_for_class(
        &self,
        resp: reqwest::Response,
        class: RequestClass,
    ) -> Result<String, ClientError> {
        let bytes = self.read_body_with_timeout_for_class(resp, class).await?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
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

fn map_url_error(url: &str, e: &crate::target::url::UrlError) -> ClientError {
    use crate::target::url::UrlError;
    match e {
        UrlError::PrivateIp => ClientError::PrivateHost(url.to_owned()),
        UrlError::Invalid(reason) => ClientError::InvalidUrl(reason.clone()),
        UrlError::Scheme(scheme) => {
            ClientError::InvalidUrl(format!("unsupported scheme: {scheme}"))
        }
        UrlError::Dns { host, reason } => {
            ClientError::InvalidUrl(format!("DNS resolution failed for '{host}': {reason}"))
        }
    }
}

fn is_redirect_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

/// Resolve a `Location` value (absolute or relative) against the current URL.
fn resolve_redirect_url(current_url: &str, location: &str) -> Result<String, ClientError> {
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
fn follow_spec(
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

fn is_same_host(a: &str, b: &str) -> bool {
    let (Ok(ua), Ok(ub)) = (url::Url::parse(a), url::Url::parse(b)) else {
        return false;
    };
    ua.host_str() == ub.host_str()
        && ua.port_or_known_default() == ub.port_or_known_default()
        && ua.scheme() == ub.scheme()
}
