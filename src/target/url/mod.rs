#![deny(unsafe_code)]

use thiserror::Error;
use url::Url;

/// Newtype against primitive obsession.
///
/// `Debug` is manual + scrubbed: the URL may carry `?token=` secrets or
/// `user:pass@` userinfo, so a derived `Debug` would leak them into any
/// `tracing::debug!("{target:?}")`. `Display` stays the full URL on purpose
/// (it builds requests — never log it raw, use [`TargetUrl::scrubbed`]).
#[derive(Clone, PartialEq, Eq)]
pub struct TargetUrl(Url);

impl core::fmt::Debug for TargetUrl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let scrubber = crate::session::scrubber::Scrubber::new(false);
        f.debug_tuple("TargetUrl")
            .field(&scrubber.scrub(self.0.as_str()))
            .finish()
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UrlError {
    #[error("invalid url: {0}")]
    Invalid(String),
    #[error(
        "private/loopback target rejected (anti-SSRF): pass --allow-private to scan a lab target you own"
    )]
    PrivateIp,
    #[error("unsupported scheme: {0}")]
    Scheme(String),
    #[error("DNS resolution failed for host '{host}': {reason}")]
    Dns { host: String, reason: String },
}

impl TargetUrl {
    /// Parse strictly, normalize, reject private IPs unless `allow_private`.
    ///
    /// Bare hosts without a scheme (`example.com`, `example.com:8080/a?id=1`)
    /// default to `https://` (same rule as the recon crawler).
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
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(UrlError::Invalid("empty url".to_owned()));
        }
        // Bare hosts (`example.com`, `example.com:8080/path?id=1`) are
        // documented as valid targets (auto/recon accept them): default to
        // `https://` like the recon crawler does. Full URLs keep their scheme
        // so `ftp://` is still rejected as `Scheme`, not silently rewritten.
        let with_scheme = if trimmed.contains("://") {
            trimmed.to_owned()
        } else {
            format!("https://{trimmed}")
        };
        let url = Url::parse(&with_scheme).map_err(|e| UrlError::Invalid(e.to_string()))?;
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

    /// Scrubbed rendering for logs/reports (`?token=` values and userinfo
    /// redacted, host kept). Prefer this over `Display` anywhere operator
    /// logs or reports are produced.
    #[must_use]
    pub fn scrubbed(&self) -> String {
        crate::session::scrubber::Scrubber::new(false).scrub(self.0.as_str())
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

    /// DNS-time SSRF check (anti DNS-rebinding): resolves `host` and rejects
    /// if any resolved IP is private/loopback/link-local/etc.
    ///
    /// IP literals are checked directly without DNS. Bare hostnames are
    /// resolved via [`tokio::net::lookup_host`] (port 80; only the IPs
    /// matter). `allow_private=true` skips the check (lab only).
    ///
    /// # Errors
    /// Returns [`UrlError::PrivateIp`] if the host is `localhost` or resolves
    /// to a private IP, [`UrlError::Dns`] if resolution yields nothing,
    /// [`UrlError::Invalid`] if the host is empty.
    pub async fn resolve_and_check(host: &str, allow_private: bool) -> Result<(), UrlError> {
        if allow_private {
            return Ok(());
        }
        let normalized = host.trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(UrlError::Invalid("empty host".to_owned()));
        }
        if normalized == "localhost" {
            return Err(UrlError::PrivateIp);
        }
        // Fast path: IP literal (covers `127.0.0.1`, `::1` without brackets
        // since `host_str()` strips them, `::ffff:127.0.0.1`, etc.).
        if let Ok(ip) = normalized.parse::<std::net::IpAddr>() {
            if is_private_ip(ip) {
                return Err(UrlError::PrivateIp);
            }
            return Ok(());
        }
        // Non-canonical IPv4 forms (`2130706433`, `0x7f.0.0.1`,
        // `0177.0.0.1`, `127.1`) stay `Host::Domain` in the `url` crate but
        // `getaddrinfo`/libc resolve them to loopback/private. Parse them
        // lexically here so the check below (and the `remote_dns` path that
        // skips local resolution) cannot be bypassed via the proxy's resolver.
        // Numerically public but non-canonical forms still fall through to
        // the DNS rebinding check rather than trusting the lexical form.
        if let Some(v4) = parse_lossy_ipv4(&normalized)
            && is_private_ip(std::net::IpAddr::V4(v4))
        {
            return Err(UrlError::PrivateIp);
        }
        // DNS-time: a lexically public domain may still resolve to a private
        // IP (DNS rebinding / libc-parsed forms like `0x7f.0.0.1` that
        // `getaddrinfo` maps to loopback). Reject if ANY record is private.
        let addrs = tokio::net::lookup_host((normalized.as_str(), 80))
            .await
            .map_err(|e| UrlError::Dns {
                host: host.to_owned(),
                reason: e.to_string(),
            })?;
        let mut saw_any = false;
        for addr in addrs {
            saw_any = true;
            if is_private_ip(addr.ip()) {
                return Err(UrlError::PrivateIp);
            }
        }
        if saw_any {
            Ok(())
        } else {
            Err(UrlError::Dns {
                host: host.to_owned(),
                reason: "no addresses returned".to_owned(),
            })
        }
    }

    /// Full per-hop redirect validation (OWASP: re-validate every hop):
    /// lexical parse + scheme check + lexical private check, then DNS-time
    /// [`Self::resolve_and_check`].
    ///
    /// # Errors
    /// Returns an error if `url_str` fails to parse, uses a non-http(s)
    /// scheme, is lexically private, or DNS-resolves to a private IP while
    /// `allow_private` is `false`.
    pub async fn validate_redirect_location(
        url_str: &str,
        allow_private: bool,
    ) -> Result<Self, UrlError> {
        Self::validate_redirect_location_with_remote_dns(url_str, allow_private, false).await
    }

    /// Same as [`Self::validate_redirect_location`], but `remote_dns=true`
    /// skips the local DNS-time resolution (proxy resolves remotely, e.g.
    /// `socks5h://`): no local hostname leak, `.onion` works, and no false
    /// TOCTOU guarantee is implied. Lexical + IP-literal checks still apply.
    ///
    /// # Errors
    /// Returns an error if `url_str` fails to parse, uses a non-http(s)
    /// scheme, or is lexically private while `allow_private` is `false`.
    pub async fn validate_redirect_location_with_remote_dns(
        url_str: &str,
        allow_private: bool,
        remote_dns: bool,
    ) -> Result<Self, UrlError> {
        let parsed = Self::parse(url_str, allow_private)?;
        if !allow_private
            && !remote_dns
            && let Some(host) = parsed.inner().host_str()
        {
            // `host_str()` strips IPv6 brackets; `resolve_and_check`
            // handles both IP literals and domain names.
            Self::resolve_and_check(host, false).await?;
        }
        Ok(parsed)
    }
}

/// Parse one numeric IPv4 part: decimal (`123`), hex (`0x7f`/`0X7F`), or
/// octal (leading `0`, e.g. `0177`). Returns `None` on empty input, invalid
/// digits, or overflow beyond `u32`.
fn parse_ipv4_part(part: &str) -> Option<u32> {
    if part.is_empty() {
        return None;
    }
    if part.len() > 2 && (part.starts_with("0x") || part.starts_with("0X")) {
        return u32::from_str_radix(&part[2..], 16)
            .ok()
            .filter(|_| !part[2..].is_empty());
    }
    if part.len() > 1 && part.starts_with('0') && part.bytes().all(|b| b.is_ascii_digit()) {
        // Leading-zero octal per `inet_aton`; `08`/`09` are invalid octal.
        if part.bytes().any(|b| b == b'8' || b == b'9') {
            return None;
        }
        return u32::from_str_radix(part, 8).ok();
    }
    if part.bytes().all(|b| b.is_ascii_digit()) {
        return part.parse::<u32>().ok();
    }
    // Bare hex without `0x` is not a libc form — reject.
    None
}

/// Parse libc-style non-canonical IPv4 (`inet_aton` semantics): `2130706433`
/// (single 32-bit decimal), `127.1` / `10.1` (short dotted), octal
/// (`0177.0.0.1`) and hex (`0x7f.0.0.1`) parts. Returns `None` for real
/// hostnames. Each part must fit its width (1-part: `<= u32::MAX`, 2-part
/// last `<= 0xFF_FFFF`, 3-part last `<= 0xFFFF`, 4-part each `<= 0xFF`).
fn parse_lossy_ipv4(host: &str) -> Option<std::net::Ipv4Addr> {
    if host.is_empty() || host.contains(':') {
        return None;
    }
    // Fast reject: must be all digits/dots/x-letters to be a numeric form.
    if !host
        .bytes()
        .all(|b| b.is_ascii_hexdigit() || matches!(b, b'.' | b'x' | b'X'))
    {
        return None;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 4 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let nums: Option<Vec<u32>> = parts.iter().map(|p| parse_ipv4_part(p)).collect();
    let nums = nums?;
    let ip_u32: u32 = match nums.len() {
        1 => nums[0],
        2 => {
            if nums[0] > 0xFF || nums[1] > 0xFF_FFFF {
                return None;
            }
            (nums[0] << 24) | nums[1]
        }
        3 => {
            if nums[0] > 0xFF || nums[1] > 0xFF || nums[2] > 0xFFFF {
                return None;
            }
            (nums[0] << 24) | (nums[1] << 16) | nums[2]
        }
        4 => {
            if nums.iter().any(|n| *n > 0xFF) {
                return None;
            }
            (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
        }
        _ => return None,
    };
    Some(std::net::Ipv4Addr::from(ip_u32))
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
            // Non-canonical IPv4 (`0x7f.0.0.1`, `0177.0.0.1`, `2130706433`,
            // `127.1`): libc/`getaddrinfo` resolve these to loopback/private
            // even though `url` keeps them as `Domain`. Reject lexically so
            // the `remote_dns` (proxy-side resolution) path cannot SSRF the
            // proxy's local network.
            if let Some(v4) = parse_lossy_ipv4(&normalized) {
                return is_private_ip(std::net::IpAddr::V4(v4));
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
/// Unified with [`is_private_ip`] so CGNAT (`100.64/10`), `192.0.0.0/24`,
/// `0/8` and the other ranges covered there are not missed here.
fn is_private_ipv4_mapped(v4: std::net::Ipv4Addr) -> bool {
    is_private_ip(std::net::IpAddr::V4(v4))
}

impl core::fmt::Display for TargetUrl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
