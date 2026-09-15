#![deny(unsafe_code)]

use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RawRequestError {
    #[error("invalid request line: {0}")]
    RequestLine(String),
    #[error("invalid header line: {0}")]
    Header(String),
    #[error("missing host")]
    MissingHost,
}

/// Parsed Burp/ZAP style raw request.
///
/// Example:
/// ```text
/// GET /search?q=1 HTTP/1.1
/// Host: example.com
/// Cookie: a=b
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RawRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub http_version: String,
}

impl RawRequest {
    /// Parse from raw string (headers + optional body).
    ///
    /// The header block and body are split on the first blank line
    /// (`\r\n\r\n` preferred, `\n\n` fallback) and the body is preserved
    /// verbatim: re-splitting it into lines and rejoining with `\n` would
    /// corrupt `multipart/form-data` boundaries (`\r\n`-delimited) and any
    /// other `\r\n`-sensitive payload.
    ///
    /// # Errors
    /// Returns an error if the request line or method is missing/malformed.
    pub fn parse(input: &str) -> Result<Self, RawRequestError> {
        // Verbatim body split first (before any line iteration).
        let (head, body) = if let Some(idx) = input.find("\r\n\r\n") {
            (&input[..idx], Some(&input[idx + 4..]))
        } else if let Some(idx) = input.find("\n\n") {
            (&input[..idx], Some(&input[idx + 2..]))
        } else {
            (input, None)
        };
        let mut lines = head.lines();
        let request_line = lines
            .next()
            .ok_or_else(|| RawRequestError::RequestLine("empty".to_owned()))?;
        // The request-target never contains a literal space (it would be
        // `%20`), so `split_whitespace` on the request line is safe.
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(RawRequestError::RequestLine(request_line.to_owned()));
        }
        let method = parts[0].to_owned();
        let path = parts[1].to_owned();
        let http_version = parts.get(2).unwrap_or(&"HTTP/1.1").to_string();

        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                // Lowercase at insertion: single canonical form, O(1) lookups
                // without per-access `eq_ignore_ascii_case` chains.
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
            } else {
                return Err(RawRequestError::Header(line.to_owned()));
            }
        }
        let body = body.filter(|b| !b.is_empty()).map(str::to_owned);
        Ok(Self {
            method,
            path,
            headers,
            body,
            http_version,
        })
    }

    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        // Keys are lowercased at insertion (see `parse`).
        self.headers.get("content-type").map(String::as_str)
    }

    #[must_use]
    pub fn is_multipart(&self) -> bool {
        self.content_type()
            .is_some_and(|ct| ct.contains("multipart/form-data"))
    }

    /// Reconstruct target URL if Host header present.
    /// Supports absolute-form request-target (e.g., `GET http://host/path HTTP/1.1`)
    /// and preserves Host:port if present.
    ///
    /// When both are present, the absolute-form URI wins (it is the complete
    /// target as sent to a proxy); the `Host` header is only used for
    /// origin-form targets. Callers that need port-aware scheme selection
    /// (e.g. `Host: x:80` → `http` first) handle it themselves.
    #[must_use]
    pub fn to_url(&self, scheme: &str) -> Option<String> {
        if self.path.starts_with("http://") || self.path.starts_with("https://") {
            return Some(self.path.clone());
        }
        let host = self.headers.get("host")?;
        let path = if self.path.starts_with('/') {
            self.path.clone()
        } else {
            format!("/{}", self.path)
        };
        Some(format!("{scheme}://{host}{path}"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_get() {
        let raw = "GET /?id=1 HTTP/1.1\nHost: example.com\nUser-Agent: test\n\n";
        let r = RawRequest::parse(raw).unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/?id=1");
        // Keys are lowercased at insertion.
        assert_eq!(r.headers.get("host").unwrap(), "example.com");
        assert_eq!(r.headers.get("user-agent").unwrap(), "test");
    }

    #[test]
    fn parses_post_with_body() {
        let raw = "POST /login HTTP/1.1\nHost: x\nContent-Type: application/x-www-form-urlencoded\n\nuser=admin&pass=1";
        let r = RawRequest::parse(raw).unwrap();
        assert_eq!(r.body.unwrap(), "user=admin&pass=1");
    }
}
