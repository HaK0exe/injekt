#![deny(unsafe_code)]

use thiserror::Error;
use url::Url;

/// Newtype against primitive obsession.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetUrl(Url);

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UrlError {
    #[error("invalid url: {0}")]
    Invalid(String),
    #[error("private/loopback IP rejected (anti-SSRF), use --allow-private to override")]
    PrivateIp,
    #[error("unsupported scheme: {0}")]
    Scheme(String),
}

impl TargetUrl {
    /// Parse strictly, normalize, reject private IPs unless `allow_private`.
    ///
    /// ```rust
    /// use injekt::target::url::TargetUrl;
    /// let t = TargetUrl::parse("http://example.com/?id=1", false).unwrap();
    /// assert_eq!(t.as_str(), "http://example.com/?id=1");
    /// ```
    #[track_caller]
    pub fn parse(input: &str, allow_private: bool) -> Result<Self, UrlError> {
        let url = Url::parse(input).map_err(|e| UrlError::Invalid(e.to_string()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(UrlError::Scheme(url.scheme().to_owned()));
        }
        if !allow_private && is_private_host(&url) {
            return Err(UrlError::PrivateIp);
        }
        Ok(Self(url))
    }

    #[must_use]
    pub fn inner(&self) -> &Url {
        &self.0
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Extract GET parameters as (key, value).
    #[must_use]
    pub fn query_params(&self) -> Vec<(String, String)> {
        self.0
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    /// Normalized URL (sorted query not applied; uses url crate normalization).
    #[must_use]
    pub fn normalized(&self) -> String {
        self.0.to_string()
    }
}

fn is_private_host(url: &Url) -> bool {
    let host = match url.host_str() {
        Some(h) => h,
        None => return false,
    };
    // localhost / loopback literals
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
        return true;
    }
    // Check IP literal
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return is_private_ip(ip);
    }
    // Hostname "private" heuristics: if it ends with .local etc, not blocked here.
    false
}

fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.octets()[0] == 10
                || (v4.octets()[0] == 192 && v4.octets()[1] == 168)
                || (v4.octets()[0] == 172 && (16..=31).contains(&v4.octets()[1]))
                || v4.octets()[0] == 169 && v4.octets()[1] == 254
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

impl core::fmt::Display for TargetUrl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid() {
        let u = TargetUrl::parse("https://example.com/search?q=hello&id=1", true).unwrap();
        assert_eq!(u.query_params().len(), 2);
    }

    #[test]
    fn rejects_private_by_default() {
        assert!(TargetUrl::parse("http://127.0.0.1/admin", false).is_err());
        assert!(TargetUrl::parse("http://192.168.1.1/", false).is_err());
        assert!(TargetUrl::parse("http://10.0.0.5/", false).is_err());
    }

    #[test]
    fn allows_private_with_flag() {
        assert!(TargetUrl::parse("http://127.0.0.1/admin", true).is_ok());
    }

    #[test]
    fn rejects_scheme() {
        assert!(TargetUrl::parse("ftp://example.com/", true).is_err());
    }
}
