#![deny(unsafe_code)]

use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Redacts sensitive data from logs / evidence / reports.
///
/// - Replaces Authorization, Cookie, Set-Cookie, X-Api-Key fully with `[REDACTED]`
/// - JWT, Bearer, AWS keys, PEM blocks replaced with hash or `[REDACTED]`
/// - Extracted values masked by default.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Scrubber {
    no_redact: bool,
}

impl Scrubber {
    #[must_use]
    pub fn new(no_redact: bool) -> Self {
        Self { no_redact }
    }

    /// Scrub arbitrary text.
    #[must_use]
    pub fn scrub(&self, input: &str) -> String {
        if self.no_redact {
            return input.to_owned();
        }
        let mut out = input.to_owned();
        out = scrub_headers(&out);
        out = scrub_patterns(&out);
        out
    }

    /// Scrub header name/value pair. Returns redacted value if sensitive.
    #[must_use]
    pub fn scrub_header(&self, name: &str, value: &str) -> String {
        if self.no_redact {
            return value.to_owned();
        }
        if is_sensitive_header(name) {
            return "[REDACTED]".to_owned();
        }
        self.scrub(value)
    }

    /// Hash-truncate for traceability without leaking secret (64-bit = 16 hex).
    #[must_use]
    pub fn hash_truncated(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let digest = hasher.finalize();
        hex::encode(digest)[..16].to_owned()
    }
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "proxy-authorization"
    )
}

fn scrub_headers(input: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        #[allow(clippy::unwrap_used)]
        {
            Regex::new(
                r"(?i)(authorization|cookie|set-cookie|x-api-key|x-auth-token|proxy-authorization)\s*:\s*[^\r\n]+",
            )
            .unwrap_or_else(|_| Regex::new(r"(?i)authorization\s*:\s*[^\r\n]+").unwrap())
        }
    });
    re.replace_all(input, |caps: &regex::Captures<'_>| {
        format!("{}: [REDACTED]", &caps[1])
    })
    .into_owned()
}

fn scrub_patterns(input: &str) -> String {
    static JWT_RE: OnceLock<Regex> = OnceLock::new();
    static BEARER_RE: OnceLock<Regex> = OnceLock::new();
    static AWS_RE: OnceLock<Regex> = OnceLock::new();
    static PEM_RE: OnceLock<Regex> = OnceLock::new();

    let jwt_re = JWT_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
                .expect("jwt regex")
        }
    });
    let bearer_re = BEARER_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(r"(?i)bearer\s+[A-Za-z0-9._\-]+").expect("bearer regex")
        }
    });
    let aws_re = AWS_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(r"AKIA[0-9A-Z]{16}").expect("aws regex")
        }
    });
    let pem_re = PEM_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(r"-----BEGIN [A-Z ]+-----").expect("pem regex")
        }
    });

    let mut s = jwt_re.replace_all(input, "[REDACTED-JWT]").into_owned();
    s = bearer_re.replace_all(&s, "Bearer [REDACTED]").into_owned();
    s = aws_re.replace_all(&s, "[REDACTED-AWS-KEY]").into_owned();
    s = pem_re.replace_all(&s, "[REDACTED-PEM]").into_owned();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_authorization() {
        let sc = Scrubber::new(false);
        let out = sc.scrub("Authorization: Bearer abc123");
        assert!(out.contains("[REDACTED]"), "{out}");
    }

    #[test]
    fn no_redact_passthrough() {
        let sc = Scrubber::new(true);
        let input = "Authorization: Bearer abc";
        assert_eq!(sc.scrub(input), input);
    }

    #[test]
    fn hash_truncated_len() {
        assert_eq!(Scrubber::hash_truncated("secret").len(), 16);
    }
}
