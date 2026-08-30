#![deny(unsafe_code)]

use crate::http::{
    cookies::CookieJar, identity::Identity, jitter::Jitter, proxy::ProxyConfig,
    rate_limit::RateLimiter, retry::RetryPolicy,
};
use reqwest::{Client, RequestBuilder};
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error("timeout not set — builder requires timeout() before build()")]
    MissingTimeout,
    #[error("reqwest error: {0}")]
    Reqwest(String),
    #[error("proxy error: {0}")]
    Proxy(String),
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
}

impl ClientBuilder<HasTimeout> {
    pub fn build(self) -> Result<HttpClient, ClientError> {
        let timeout = self.timeout.ok_or(ClientError::MissingTimeout)?;
        let mut builder = Client::builder()
            .timeout(timeout)
            .connect_timeout(self.connect_timeout.unwrap_or(Duration::from_secs(10)))
            .gzip(true)
            .brotli(true)
            .cookie_store(false) // we manage cookies manually for OPSEC
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none());

        if let Some(proxy) = self.proxy {
            let p = reqwest::Proxy::all(proxy.as_str())
                .map_err(|e| ClientError::Proxy(e.to_string()))?;
            builder = builder.proxy(p);
        }

        let mut default_headers = reqwest::header::HeaderMap::new();
        if let Some(id) = &self.identity {
            for (k, v) in id.headers() {
                if let (Ok(hn), Ok(hv)) = (
                    reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                    reqwest::header::HeaderValue::from_str(&v),
                ) {
                    default_headers.insert(hn, hv);
                }
            }
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

    /// Execute with jitter, rate-limit, retry, timeout cancellation.
    pub async fn get_with_retry(&self, url: String) -> Result<reqwest::Response, ClientError> {
        self.rate_limiter.acquire().await;
        self.jitter.sleep().await;

        let mut attempt = 0usize;
        loop {
            // inject cookie header if present
            let mut req: RequestBuilder = self.inner.get(&url);
            {
                let jar = self.cookies.read().await;
                if let Some(cv) = jar.header_value() {
                    req = req.header(reqwest::header::COOKIE, cv);
                }
            }

            let fut = async { tokio::time::timeout(Duration::from_secs(15), req.send()).await };
            match fut.await {
                Ok(Ok(resp)) => {
                    // store Set-Cookie
                    for val in &resp.headers().get_all(reqwest::header::SET_COOKIE) {
                        if let Ok(s) = val.to_str() {
                            self.cookies.write().await.parse_set_cookie(s);
                        }
                    }
                    if self
                        .retry
                        .should_retry(attempt, Some(resp.status().as_u16()))
                    {
                        attempt += 1;
                        tokio::time::sleep(self.retry.delay_for(attempt)).await;
                        continue;
                    }
                    return Ok(resp);
                }
                Ok(Err(e)) => {
                    if self.retry.should_retry(attempt, None) {
                        attempt += 1;
                        tokio::time::sleep(self.retry.delay_for(attempt)).await;
                        continue;
                    }
                    return Err(ClientError::Reqwest(e.to_string()));
                }
                Err(_) => {
                    if self.retry.should_retry(attempt, None) {
                        attempt += 1;
                        tokio::time::sleep(self.retry.delay_for(attempt)).await;
                        continue;
                    }
                    return Err(ClientError::Reqwest("timeout".to_owned()));
                }
            }
        }
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
