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
    ///
    /// # Errors
    /// Returns an error if `input` fails to parse as a URL, uses a scheme other
    /// than `http`/`https`, or resolves to a private/loopback host and
    /// `allow_private` is `false`.
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
    use url::Host;
    match url.host() {
        None => false,
        // `Host::Ipv4/Ipv6` already strips brackets — the old `host_str()`
        // string comparison missed `[::1]` (brackets included) and every
        // IPv6 literal. Matching on the parsed host fixes that class.
        Some(Host::Ipv4(v4)) => is_private_ip(std::net::IpAddr::V4(v4)),
        Some(Host::Ipv6(v6)) => is_private_ip(std::net::IpAddr::V6(v6)),
        Some(Host::Domain(domain)) => {
            // Normalize case + trailing dot (`LOCALHOST.` resolves to loopback).
            let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
            if normalized == "localhost" {
                return true;
            }
            // Defense in depth: a domain that parses as IP (non-canonical
            // decimal/octal/hex forms like `2130706433` stay `Domain` here
            // and still need DNS-time enforcement — see issues).
            if let Ok(ip) = normalized.parse::<std::net::IpAddr>() {
                return is_private_ip(ip);
            }
            false
        }
    }
}

fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // CGNAT 100.64.0.0/10, IETF 192.0.0.0/24, TEST-NET etc. are not
                // covered by `is_private()` on all toolchains — check explicitly.
                || v4.octets()[0] == 10
                || (v4.octets()[0] == 192 && v4.octets()[1] == 168)
                || (v4.octets()[0] == 172 && (16..=31).contains(&v4.octets()[1]))
                || v4.octets()[0] == 169 && v4.octets()[1] == 254
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                // IPv4-mapped loopback/link-local (`::ffff:127.0.0.1`) bypassed the
                // old check because `is_loopback()` is false for mapped addrs.
                || v6.to_ipv4_mapped().is_some_and(is_private_ipv4_mapped)
        }
    }
}

/// Private check for the v4 behind an IPv6 `::ffff:a.b.c.d` mapping.
fn is_private_ipv4_mapped(v4: std::net::Ipv4Addr) -> bool {
    v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
}

impl core::fmt::Display for TargetUrl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    #[test]
    fn rejects_loopback_variants_and_mapped() {
        // Trailing dot + case variants resolve to loopback.
        assert!(TargetUrl::parse("http://localhost./", false).is_err());
        assert!(TargetUrl::parse("http://LOCALHOST/", false).is_err());
        // IPv4-mapped IPv6 loopback/link-local bypassed the old check.
        assert!(TargetUrl::parse("http://[::ffff:127.0.0.1]/", false).is_err());
        assert!(TargetUrl::parse("http://[::ffff:169.254.169.254]/", false).is_err());
        // CGNAT + 0/8 + ULA + link-local.
        assert!(TargetUrl::parse("http://100.64.0.1/", false).is_err());
        assert!(TargetUrl::parse("http://0.1.2.3/", false).is_err());
        assert!(TargetUrl::parse("http://[fc00::1]/", false).is_err());
        assert!(TargetUrl::parse("http://[fe80::1]/", false).is_err());
    }
}
