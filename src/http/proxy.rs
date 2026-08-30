#![deny(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProxyError {
    #[error("invalid proxy url: {0}")]
    Invalid(String),
    #[error("socks5 without remote DNS (socks5://) leaks DNS — use socks5h://")]
    DnsLeak,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProxyConfig {
    Http(String),
    Socks5h(String),
}

impl ProxyConfig {
    pub fn parse(input: &str) -> Result<Self, ProxyError> {
        if input.starts_with("socks5://") {
            return Err(ProxyError::DnsLeak);
        }
        if input.starts_with("socks5h://") {
            return Ok(Self::Socks5h(input.to_owned()));
        }
        if input.starts_with("http://") || input.starts_with("https://") {
            return Ok(Self::Http(input.to_owned()));
        }
        Err(ProxyError::Invalid(input.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Http(s) | Self::Socks5h(s) => s,
        }
    }
}
