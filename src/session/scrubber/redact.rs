use super::headers::{is_sensitive_header, scrub_headers};
use super::oob::scrub_oob;
use super::patterns::scrub_patterns;
use super::secrets::{
    scrub_form_secrets, scrub_json_secrets, scrub_query_secrets, scrub_url_userinfo,
};
use sha2::{Digest, Sha256};

/// Redacts sensitive data from logs / evidence / reports.
///
/// - Sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`,
///   `X-Auth-Token`, `Proxy-Authorization`, + `X-Access/Session/Csrf-Token`,
///   `X-Api-Secret`, `Proxy-Authenticate`, `WWW-Authenticate`, …) fully
///   replaced with `[REDACTED]`
/// - JWT, Bearer, Basic, AWS keys, PEM blocks, provider tokens (GitHub,
///   GitLab, Slack, Stripe/OpenAI-style) replaced with `[REDACTED-*]`
/// - URL userinfo (`scheme://user:pass@host`) → `scheme://[REDACTED]@`
/// - Sensitive query values (`?token=…`, `?sessionid=…`, `?password=…`, …)
///   → `key=[REDACTED]`
/// - JSON string values for sensitive keys (`"password": "…"`) →
///   `"key": "[REDACTED]"`
/// - Form/body pairs (`password=…&token=…`) → `key=[REDACTED]`
/// - OOB collaborator hosts (`oastify`, `interactsh`, `burpcollaborator`,
///   `oast.*`) + `oob_domain`/`oob_poll_url`/`collaborator` keyed values →
///   `[REDACTED-OOB]` / `key: [REDACTED]`
/// - Findings, targets and evidences are always scrubbed (unless `--no-redact`).
/// - `seed` is NOT a secret (replay determinism) and is never redacted.
/// - Extracted DB content (`--extract`/`--dump`/enumeration payoff) is shown
///   in full by design: the operator explicitly opted into exfiltration, so
///   redacting it would defeat the feature. Only its log lines use hashes.
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
        out = scrub_url_userinfo(&out);
        out = scrub_query_secrets(&out);
        out = scrub_json_secrets(&out);
        out = scrub_form_secrets(&out);
        out = scrub_patterns(&out);
        out = scrub_oob(&out);
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
