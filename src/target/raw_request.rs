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
    pub fn parse(input: &str) -> Result<Self, RawRequestError> {
        let mut lines = input.lines();
        let request_line = lines
            .next()
            .ok_or_else(|| RawRequestError::RequestLine("empty".to_owned()))?;
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(RawRequestError::RequestLine(request_line.to_owned()));
        }
        let method = parts[0].to_owned();
        let path = parts[1].to_owned();
        let http_version = parts.get(2).unwrap_or(&"HTTP/1.1").to_string();

        let mut headers = HashMap::new();
        let mut body_lines = Vec::new();
        let mut in_body = false;
        for line in lines {
            if in_body {
                body_lines.push(line);
                continue;
            }
            if line.is_empty() {
                in_body = true;
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_owned(), v.trim().to_owned());
            } else {
                return Err(RawRequestError::Header(line.to_owned()));
            }
        }
        let body = if body_lines.is_empty() {
            None
        } else {
            Some(body_lines.join("\n"))
        };
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
        self.headers
            .get("Content-Type")
            .or_else(|| self.headers.get("content-type"))
            .map(String::as_str)
    }

    #[must_use]
    pub fn is_multipart(&self) -> bool {
        self.content_type()
            .is_some_and(|ct| ct.contains("multipart/form-data"))
    }

    /// Reconstruct target URL if Host header present.
    #[must_use]
    pub fn to_url(&self, scheme: &str) -> Option<String> {
        let host = self
            .headers
            .get("Host")
            .or_else(|| self.headers.get("host"))?;
        Some(format!("{scheme}://{host}{}", self.path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get() {
        let raw = "GET /?id=1 HTTP/1.1\nHost: example.com\nUser-Agent: test\n\n";
        let r = RawRequest::parse(raw).unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/?id=1");
        assert_eq!(r.headers.get("Host").unwrap(), "example.com");
    }

    #[test]
    fn parses_post_with_body() {
        let raw = "POST /login HTTP/1.1\nHost: x\nContent-Type: application/x-www-form-urlencoded\n\nuser=admin&pass=1";
        let r = RawRequest::parse(raw).unwrap();
        assert_eq!(r.body.unwrap(), "user=admin&pass=1");
    }
}
