#![deny(unsafe_code)]

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
struct CookieMeta {
    value: SecretString,
    path: String,
    domain: Option<String>,
    expires: Option<DateTime<Utc>>,
    secure: bool,
}

/// In-memory cookie jar, zeroized on drop. No disk persistence.
/// Stores per-cookie attributes per RFC6265 minimal subset.
#[derive(Debug, Default)]
pub struct CookieJar {
    cookies: HashMap<String, CookieMeta>,
}

impl CookieJar {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, name: impl Into<String>, value: SecretString) {
        self.cookies.insert(
            name.into(),
            CookieMeta {
                value,
                path: "/".to_owned(),
                domain: None,
                expires: None,
                secure: false,
            },
        );
    }

    pub fn set_raw(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.set(name, SecretString::from(value.into()));
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&SecretString> {
        self.cookies.get(name).map(|m| &m.value)
    }

    #[must_use]
    pub fn header_value(&self) -> Option<String> {
        self.header_value_for_url(None)
    }

    /// Scope-aware header value (filters by domain/path/expires/secure if url provided).
    #[must_use]
    pub fn header_value_for_url(&self, url: Option<&str>) -> Option<String> {
        if self.cookies.is_empty() {
            return None;
        }
        let now = Utc::now();
        // Parse the request URL once. A malformed URL must never degrade to
        // "send everything": fail closed and emit no Cookie header.
        let parsed_url = url.map(url::Url::parse);
        if url.is_some() && parsed_url.as_ref().is_none_or(Result::is_err) {
            return None;
        }
        let mut parts: Vec<String> = Vec::new();
        for (k, meta) in &self.cookies {
            if let Some(exp) = meta.expires
                && exp < now
            {
                continue;
            }
            if let Some(Ok(parsed)) = parsed_url.as_ref() {
                let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
                if let Some(d) = &meta.domain
                    && !(host == d.as_str() || host.ends_with(&format!(".{d}")))
                {
                    continue;
                }
                let path = parsed.path();
                if !path_matches(path, &meta.path) {
                    continue;
                }
                if meta.secure && parsed.scheme() != "https" {
                    continue;
                }
            }
            parts.push(format!("{k}={}", meta.value.expose_secret()));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        }
    }

    pub fn parse_set_cookie(&mut self, header: &str) {
        self.parse_set_cookie_with_url(header, None);
    }

    pub fn parse_set_cookie_with_url(&mut self, header: &str, url: Option<&url::Url>) {
        let mut parts = header.split(';').map(str::trim);
        let Some(pair) = parts.next() else { return };
        let Some((k, v)) = pair.split_once('=') else {
            return;
        };
        let name = k.trim();
        if name.is_empty() {
            return;
        }
        let mut meta = CookieMeta {
            value: SecretString::from(v.trim().to_owned()),
            path: url.map_or_else(|| "/".to_owned(), default_path),
            domain: None,
            expires: None,
            secure: false,
        };
        for attr in parts {
            if let Some((ak, av)) = attr.split_once('=') {
                match ak.trim().to_ascii_lowercase().as_str() {
                    "path" => av.trim().clone_into(&mut meta.path),
                    "domain" => {
                        meta.domain = Some(av.trim().trim_start_matches('.').to_ascii_lowercase());
                    }
                    "expires" => {
                        if let Ok(dt) =
                            chrono::DateTime::parse_from_rfc2822(av.trim()).or_else(|_| {
                                chrono::DateTime::parse_from_str(
                                    av.trim(),
                                    "%a, %d %b %Y %H:%M:%S %Z",
                                )
                            })
                        {
                            meta.expires = Some(dt.with_timezone(&Utc));
                        }
                    }
                    "max-age" => {
                        if let Ok(secs) = av.trim().parse::<i64>() {
                            meta.expires = Some(Utc::now() + chrono::Duration::seconds(secs));
                        }
                    }
                    _ => {}
                }
            } else {
                #[allow(clippy::match_same_arms)]
                match attr.to_ascii_lowercase().as_str() {
                    "secure" => meta.secure = true,
                    "httponly" => {}
                    _ => {}
                }
            }
        }
        // Domain validation if url present
        if let (Some(d), Some(u)) = (&meta.domain, url) {
            let host = u.host_str().unwrap_or("").to_ascii_lowercase();
            if !(host == d.as_str() || host.ends_with(&format!(".{d}"))) {
                return;
            }
        }
        self.cookies.insert(name.to_owned(), meta);
    }

    pub fn clear(&mut self) {
        for meta in self.cookies.values_mut() {
            meta.value.zeroize();
        }
        self.cookies.clear();
        self.cookies.shrink_to_fit();
    }
}

fn default_path(url: &url::Url) -> String {
    let p = url.path();
    if let Some(idx) = p.rfind('/') {
        p[..=idx].to_owned()
    } else {
        "/".to_owned()
    }
}

/// RFC6265 §5.1.4 path-match: exact match, or cookie-path is a prefix ending
/// in `/`, or prefix where the first non-matching char is `/`.
/// Prevents `Path=/admin` leaking to `/administrator`.
fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if let Some(rest) = request_path.strip_prefix(cookie_path) {
        return cookie_path.ends_with('/') || rest.starts_with('/');
    }
    false
}

impl Zeroize for CookieJar {
    fn zeroize(&mut self) {
        for meta in self.cookies.values_mut() {
            meta.value.zeroize();
        }
        self.cookies.clear();
        self.cookies.shrink_to_fit();
    }
}
impl Drop for CookieJar {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for CookieJar {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn path_match_rejects_sibling_prefix() {
        assert!(path_matches("/admin", "/admin"));
        assert!(path_matches("/admin/", "/admin"));
        assert!(path_matches("/admin/users", "/admin"));
        assert!(path_matches("/admin/users", "/admin/"));
        assert!(!path_matches("/administrator", "/admin"));
        assert!(!path_matches("/admin2", "/admin"));
    }

    #[test]
    fn malformed_url_sends_no_cookies_fail_closed() {
        let mut jar = CookieJar::new();
        jar.set_raw("sess", "secret");
        assert!(jar.header_value_for_url(Some("http://%zz")).is_none());
    }

    #[test]
    fn secure_cookie_not_sent_over_http() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie_with_url(
            "sess=secret; Secure",
            Some(&url::Url::parse("https://victime.com/admin").unwrap()),
        );
        assert!(
            jar.header_value_for_url(Some("http://victime.com/admin"))
                .is_none()
        );
        assert!(
            jar.header_value_for_url(Some("https://victime.com/admin"))
                .is_some()
        );
    }
}
