//! HTTP client error taxonomy shared by every submodule.

use crate::http::proxy::ProxyError;
use std::time::Duration;
use thiserror::Error;

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
