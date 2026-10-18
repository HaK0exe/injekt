//! Send path: cancellable jitter/rate-limit, retries, manual redirect
//! chasing with per-hop SSRF re-validation, and request building.

use std::time::Duration;

use http::Method;
use reqwest::RequestBuilder;

use crate::http::timeouts::RequestClass;
use crate::target::url::TargetUrl;

use super::redirect::{
    follow_spec, is_redirect_status, is_same_host, map_url_error, resolve_redirect_url,
};
use super::{ClientError, HttpClient, RequestSpec, TimedResponse};
use tokio_util::sync::CancellationToken;

impl HttpClient {
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
    /// `Location` manually up to `redirect_policy`. The manual [`CookieJar`](crate::http::cookies::CookieJar)
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
    /// [`TIME_POOL_SLOTS`](crate::http::timeouts::TIME_POOL_SLOTS) isolated pool permits for the whole probe —
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
        Ok(self
            .send_with_retry_timed_for_class(spec, class, cancel)
            .await?
            .resp)
    }

    /// Class-aware timed send (P0-VAGUE-1): same behaviour as
    /// [`Self::send_with_retry_for_class`], plus the pure send timing.
    ///
    /// `elapsed_send` is the wall time of **only** the last successful
    /// `timeout(class_timeout, req.send())` — never a sum, never jitter /
    /// rate-limiter / sleeps / backoff / `Retry-After`. `attempts` counts
    /// every `req.send()` tentative across retries and redirect hops;
    /// `retried` is `attempts > 1`.
    ///
    /// # Errors
    /// Returns an error if the request is cancelled, times out, targets a
    /// private host without `allow_private`, exceeds the redirect limit, or
    /// fails after retries.
    #[allow(clippy::too_many_lines)] // P0-VAGUE-1: instrumented copy of the retry path, keep identical.
    pub async fn send_with_retry_timed_for_class(
        &self,
        spec: RequestSpec,
        class: RequestClass,
        cancel: &CancellationToken,
    ) -> Result<TimedResponse, ClientError> {
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
        // Pure-send instrumentation: total `req.send()` tentatives across
        // hops/retries, and the last successful send's wall time only.
        let mut attempts = 0_u32;
        let mut elapsed_send: Duration;
        loop {
            let (resp, hop_elapsed, hop_attempts) = self
                .send_single_with_retry_timed(&current, class, include_user, cancel)
                .await?;
            attempts = attempts.saturating_add(hop_attempts);
            elapsed_send = hop_elapsed;
            let status = resp.status();
            if !is_redirect_status(status) {
                return Ok(TimedResponse {
                    resp,
                    elapsed_send,
                    attempts,
                    retried: attempts > 1,
                });
            }
            let Some(max) = self.redirect_policy.max_hops() else {
                // `RedirectPolicy::None`: return 3xx as-is, do not follow.
                return Ok(TimedResponse {
                    resp,
                    elapsed_send,
                    attempts,
                    retried: attempts > 1,
                });
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
                return Ok(TimedResponse {
                    resp,
                    elapsed_send,
                    attempts,
                    retried: attempts > 1,
                });
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
    /// Single-hop timed send with retry (no redirect following).
    /// Every retry re-acquires the rate limiter so 429/5xx/timeout storms
    /// cannot exceed the configured RPS ceiling. The per-class timeout
    /// (`boolean` 10s, `time` 15s, `oob`/default base) bounds the send and
    /// the retry sleeps are cancellable. Returns the response plus the wall
    /// time of only the last successful `timeout(class_timeout, req.send())`
    /// and the count of `req.send()` tentatives for this hop.
    #[allow(clippy::too_many_lines)] // P0-VAGUE-1: instrumented copy of the retry path, keep identical.
    async fn send_single_with_retry_timed(
        &self,
        spec: &RequestSpec,
        class: RequestClass,
        include_user: bool,
        cancel: &CancellationToken,
    ) -> Result<(reqwest::Response, Duration, u32), ClientError> {
        let class_timeout = self.timeouts.for_class(class);
        let mut attempt = 0usize;
        let mut attempts = 0_u32;
        let mut elapsed_send: Duration;
        loop {
            if cancel.is_cancelled() {
                return Err(ClientError::Cancelled);
            }
            let req = self.build_request(spec, include_user).await;

            // per-request timeout covers send() only; jitter/rate-limit already done.
            // `send_start` bounds only the `timeout(class_timeout, req.send())`
            // below: jitter / rate-limiter / backoff / `Retry-After` sleeps stay
            // outside, and only the last successful send's duration is kept.
            let send_start = std::time::Instant::now();
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
                    attempts = attempts.saturating_add(1);
                    elapsed_send = send_start.elapsed();
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
                    return Ok((resp, elapsed_send, attempts));
                }
                Err(e) => {
                    attempts = attempts.saturating_add(1);
                    let retryable = match &e {
                        ClientError::Timeout(_) => true,
                        // Idempotence-gated stale-pool EOF (PR20): `GET`/`HEAD`
                        // keep the Cloudflare keep-alive retry, `POST`/`PATCH`
                        // never replay the race (double-submit). `timeout` /
                        // `connect` / `body` stay retryable for all methods
                        // (historical behaviour).
                        ClientError::Reqwest(e) => {
                            crate::http::retry::is_retryable_error_for_method(e, &spec.method)
                        }
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
}
