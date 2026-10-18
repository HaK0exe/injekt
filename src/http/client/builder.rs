//! Typestate client builder: `timeout()` is mandatory before `build()`.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use crate::http::{
    cookies::CookieJar,
    identity::Identity,
    jitter::Jitter,
    proxy::ProxyConfig,
    rate_limit::RateLimiter,
    redirects::RedirectPolicy,
    retry::RetryPolicy,
    timeouts::{ClassTimeouts, TIME_POOL_SLOTS},
};
use http::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Client;

use super::{ClientError, HttpClient};
use tokio::sync::{RwLock, Semaphore};

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
