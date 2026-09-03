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

#[derive(Clone)]
#[non_exhaustive]
pub enum ProxyConfig {
    Http(String),
    Socks5h(String),
}

impl core::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Http(s) | Self::Socks5h(s) => {
                let redacted = redact_credentials(s);
                f.debug_tuple(match self {
                    Self::Http(_) => "Http",
                    Self::Socks5h(_) => "Socks5h",
                })
                .field(&redacted)
                .finish()
            }
        }
    }
}

fn redact_credentials(url: &str) -> String {
    if let Some(at_idx) = url.find('@') {
        let (before_at, after_at) = url.split_at(at_idx);
        if let Some(colon_idx) = before_at.rfind(':') {
            let scheme_and_user = &before_at[..colon_idx];
            format!("{scheme_and_user}:[REDACTED]@{after_at}")
        } else {
            url.to_owned()
        }
    } else {
        url.to_owned()
    }
}

impl ProxyConfig {
    /// # Errors
    /// Returns an error if `input` uses the unsupported `socks5://` scheme
    /// (DNS-leak risk) or otherwise fails to parse as a proxy URL.
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
