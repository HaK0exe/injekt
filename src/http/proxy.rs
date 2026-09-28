#![deny(unsafe_code)]

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProxyError {
    #[error("invalid proxy url: {0}")]
    Invalid(String),
    #[error("socks5 without remote DNS (socks5://) leaks DNS — use socks5h://")]
    DnsLeak,
}

/// Proxy endpoint. The URL (potentially `user:pass@`) is a [`SecretString`]:
/// zeroized on drop, `[REDACTED]` in derived positions. Only
/// [`ProxyConfig::as_str`] exposes it, and only for `reqwest::Proxy` setup.
#[derive(Clone)]
#[non_exhaustive]
pub enum ProxyConfig {
    Http(SecretString),
    Socks5h(SecretString),
}

impl core::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Full userinfo redacted (the username itself may be a token);
        // scheme + host kept for triage. Never log the credentials.
        let redacted = redact_userinfo(self.as_str());
        f.debug_tuple(match self {
            Self::Http(_) => "Http",
            Self::Socks5h(_) => "Socks5h",
        })
        .field(&redacted)
        .finish()
    }
}

/// `scheme://user:pass@host…` → `scheme://[REDACTED]@host…`. No `@` → as-is.
fn redact_userinfo(url: &str) -> String {
    let Some(at_idx) = url.find('@') else {
        return url.to_owned();
    };
    let Some(scheme_end) = url.find("://") else {
        return "[REDACTED]".to_owned();
    };
    format!(
        "{}[REDACTED]@{}",
        &url[..scheme_end + 3],
        &url[at_idx + 1..]
    )
}

impl ProxyConfig {
    /// # Errors
    /// Returns an error if `input` uses the unsupported `socks5://` scheme
    /// (DNS-leak risk) or otherwise fails to parse as a proxy URL.
    pub fn parse(input: &str) -> Result<Self, ProxyError> {
        let lowered = input.to_ascii_lowercase();
        if lowered.starts_with("socks5://") {
            return Err(ProxyError::DnsLeak);
        }
        // Plain `socks://` / `socks4://` are ambiguous (no remote-DNS guarantee).
        if lowered.starts_with("socks://") || lowered.starts_with("socks4://") {
            return Err(ProxyError::Invalid(redact_userinfo(input)));
        }
        if lowered.starts_with("socks5h://") {
            return Ok(Self::Socks5h(SecretString::from(input)));
        }
        if lowered.starts_with("http://") || lowered.starts_with("https://") {
            return Ok(Self::Http(SecretString::from(input)));
        }
        Err(ProxyError::Invalid(redact_userinfo(input)))
    }

    /// Expose the full proxy URL **only** for `reqwest::Proxy` setup. The
    /// returned reference must never be logged, formatted into errors, or
    /// stored in a `String`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Http(s) | Self::Socks5h(s) => s.expose_secret(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_full_userinfo_but_keeps_host() {
        let cfg = ProxyConfig::parse("socks5h://user:pass123@proxy:1080").unwrap();
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("pass123"), "{rendered}");
        assert!(!rendered.contains("user"), "{rendered}");
        assert!(rendered.contains("proxy:1080"), "{rendered}");
        // `as_str` still exposes the full URL for reqwest setup only.
        assert_eq!(cfg.as_str(), "socks5h://user:pass123@proxy:1080");
    }

    #[test]
    fn invalid_scheme_error_redacts_credentials() {
        let err = ProxyConfig::parse("socks://user:pass123@proxy:1080").unwrap_err();
        let rendered = format!("{err}");
        assert!(!rendered.contains("pass123"), "{rendered}");
    }

    #[test]
    fn socks5_without_remote_dns_rejected() {
        assert!(matches!(
            ProxyConfig::parse("socks5://proxy:1080"),
            Err(ProxyError::DnsLeak)
        ));
    }
}
