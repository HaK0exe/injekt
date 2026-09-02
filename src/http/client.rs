#![deny(unsafe_code)]

use crate::http::{
    cookies::CookieJar, identity::Identity, jitter::Jitter, proxy::ProxyConfig,
    rate_limit::RateLimiter, redirects::RedirectPolicy, retry::RetryPolicy,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use reqwest::{Client, RequestBuilder};
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error("timeout not set — builder requires timeout() before build()")]
    MissingTimeout,
    #[error("reqwest error: {0}")]
    Reqwest(String),
    #[error("proxy error: {0}")]
    Proxy(String),
    #[error("cancelled")]
    Cancelled,
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("invalid header: {0}")]
    InvalidHeader(String),
}

///Marker types for typestate.
#[derive(Debug)]
pub struct NeedTimeout;
#[derive(Debug)]
pub struct HasTimeout;

/// Builder with typestate: timeout mandatory.
#[derive(Debug)]
pub struct ClientBuilder<State> {
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    proxy: Option<ProxyConfig>,
    identity: Option<Identity>,
    jitter: Option<Jitter>,
    rate_limit: Option<Arc<RateLimiter>>,
    retry: RetryPolicy,
    redirect_policy: RedirectPolicy,
    extra_headers: HeaderMap,
    _state: core::marker::PhantomData<State>,
}

impl ClientBuilder<NeedTimeout> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            timeout: None,
            connect_timeout: None,
            proxy: None,
            identity: None,
            jitter: None,
            rate_limit: None,
            retry: RetryPolicy::default(),
            redirect_policy: RedirectPolicy::default(),
            extra_headers: HeaderMap::new(),
            _state: core::marker::PhantomData,
        }
    }

    #[must_use]
    pub fn timeout(self, d: Duration) -> ClientBuilder<HasTimeout> {
        ClientBuilder {
            timeout: Some(d),
            connect_timeout: self.connect_timeout,
            proxy: self.proxy,
            identity: self.identity,
            jitter: self.jitter,
            rate_limit: self.rate_limit,
            retry: self.retry,
            redirect_policy: self.redirect_policy,
            extra_headers: self.extra_headers,
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

    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.extra_headers.insert(name, value);
        self
    }
}

impl ClientBuilder<HasTimeout> {
    pub fn build(self) -> Result<HttpClient, ClientError> {
        let timeout = self.timeout.ok_or(ClientError::MissingTimeout)?;
        let reqwest_policy = match self.redirect_policy {
            RedirectPolicy::None => reqwest::redirect::Policy::none(),
            RedirectPolicy::Limited(n) => reqwest::redirect::Policy::limited(n),
        };
        let mut builder = Client::builder()
            .timeout(timeout)
            .connect_timeout(self.connect_timeout.unwrap_or(Duration::from_secs(10)))
            .gzip(true)
            .brotli(true)
            .cookie_store(false) // we manage cookies manually for OPSEC
            .use_rustls_tls()
            .redirect(reqwest_policy);

        if let Some(proxy) = self.proxy {
            let p = reqwest::Proxy::all(proxy.as_str())
                .map_err(|e| ClientError::Proxy(e.to_string()))?;
            builder = builder.proxy(p);
        }

        let mut default_headers = reqwest::header::HeaderMap::new();
        if let Some(id) = &self.identity {
            for (k, v) in id.headers() {
                let hn = HeaderName::from_bytes(k.as_bytes())
                    .map_err(|e| ClientError::InvalidHeader(format!("{k}: {e}")))?;
                let hv = HeaderValue::from_str(&v)
                    .map_err(|e| ClientError::InvalidHeader(format!("{v}: {e}")))?;
                default_headers.insert(hn, hv);
            }
        }
        for (k, v) in &self.extra_headers {
            default_headers.insert(k.clone(), v.clone());
        }
        builder = builder.default_headers(default_headers);

        let inner = builder
            .build()
            .map_err(|e| ClientError::Reqwest(e.to_string()))?;

        Ok(HttpClient {
            inner: Arc::new(inner),
            jitter: self.jitter.unwrap_or_default(),
            rate_limiter: self
                .rate_limit
                .unwrap_or_else(|| Arc::new(RateLimiter::new(5.0))),
            cookies: Arc::new(RwLock::new(CookieJar::new())),
            retry: self.retry,
            timeout,
            redirect_policy: self.redirect_policy,
        })
    }
}

impl Default for ClientBuilder<NeedTimeout> {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared HTTP client (Arc internally).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpClient {
    inner: Arc<Client>,
    jitter: Jitter,
    rate_limiter: Arc<RateLimiter>,
    cookies: Arc<RwLock<CookieJar>>,
    retry: RetryPolicy,
    timeout: Duration,
    redirect_policy: RedirectPolicy,
}

/// Request specification for generic HTTP calls (2026 best practice).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RequestSpec {
    pub method: Method,
    pub url: String,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
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
        self.body = Some(body);
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

    #[must_use]
    pub fn redirect_policy(&self) -> RedirectPolicy {
        self.redirect_policy
    }

    /// Generic send with jitter, rate-limit, retry, timeout and cancellation.
    pub async fn send_with_retry(
        &self,
        spec: RequestSpec,
        cancel: &CancellationToken,
    ) -> Result<reqwest::Response, ClientError> {
        // cancellable jitter + rate-limit per 2026 tokio best practice
        tokio::select! {
            () = cancel.cancelled() => return Err(ClientError::Cancelled),
            () = self.rate_limiter.acquire() => {},
        }
        tokio::select! {
            () = cancel.cancelled() => return Err(ClientError::Cancelled),
            () = self.jitter.sleep() => {},
        }

        let mut attempt = 0usize;
        loop {
            if cancel.is_cancelled() {
                return Err(ClientError::Cancelled);
            }
            let req = self.build_request(&spec).await;

            // per-request timeout covers send() only; jitter/rate-limit already done
            let send_fut = req.send();
            let resp_res: Result<reqwest::Response, ClientError> = tokio::select! {
                () = cancel.cancelled() => return Err(ClientError::Cancelled),
                r = tokio::time::timeout(self.timeout, send_fut) => match r {
                    Ok(Ok(resp)) => Ok(resp),
                    Ok(Err(e)) => Err(ClientError::Reqwest(e.to_string())),
                    Err(_) => Err(ClientError::Timeout(self.timeout)),
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
                    if self
                        .retry
                        .should_retry(attempt, Some(resp.status().as_u16()))
                    {
                        attempt += 1;
                        let delay = self.retry.delay_for(attempt);
                        tokio::select! {
                            () = cancel.cancelled() => return Err(ClientError::Cancelled),
                            () = tokio::time::sleep(delay) => {},
                        }
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    let retryable = matches!(e, ClientError::Timeout(_) | ClientError::Reqwest(_))
                        && self.retry.should_retry(attempt, None);
                    if retryable {
                        attempt += 1;
                        let delay = self.retry.delay_for(attempt);
                        tokio::select! {
                            () = cancel.cancelled() => return Err(ClientError::Cancelled),
                            () = tokio::time::sleep(delay) => {},
                        }
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    async fn build_request(&self, spec: &RequestSpec) -> RequestBuilder {
        let mut req = match spec.method {
            Method::GET => self.inner.get(&spec.url),
            Method::POST => self.inner.post(&spec.url),
            _ => self.inner.request(spec.method.clone(), &spec.url),
        };
        for (k, v) in &spec.headers {
            req = req.header(k, v);
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
                let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = b
                    .chunks(5)
                    .map(|c| Ok(bytes::Bytes::copy_from_slice(c)))
                    .collect();
                let stream = futures::stream::iter(chunks);
                req = req.body(reqwest::Body::wrap_stream(stream));
            } else {
                req = req.body(b.clone());
            }
        }
        {
            let jar = self.cookies.read().await;
            if let Some(cv) = jar.header_value_for_url(Some(&spec.url)) {
                req = req.header(reqwest::header::COOKIE, cv);
            } else if let Some(cv) = jar.header_value() {
                req = req.header(reqwest::header::COOKIE, cv);
            }
        }
        req
    }

    /// Legacy GET with jitter/rate-limit/retry — delegates to `send_with_retry` with no cancellation.
    pub async fn get_with_retry(&self, url: String) -> Result<reqwest::Response, ClientError> {
        let spec = RequestSpec::get(url);
        // Use a detached token that never cancels for backwards compat
        let cancel = CancellationToken::new();
        self.send_with_retry(spec, &cancel).await
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
