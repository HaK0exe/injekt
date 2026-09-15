#![deny(unsafe_code)]

use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

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

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "www-authenticate"
            | "authentication"
            | "cookie"
            | "cookie2"
            | "set-cookie"
            | "set-cookie2"
            | "x-api-key"
            | "x-api-token"
            | "x-api-secret"
            | "x-auth-token"
            | "x-access-token"
            | "x-session-token"
            | "x-csrf-token"
            | "x-csrftoken"
            | "api-key"
            | "api-secret"
            | "api-token"
            | "apikey"
            | "access-token"
            | "refresh-token"
            | "id-token"
            | "client-secret"
            | "session-token"
            | "csrf-token"
    )
}

fn scrub_headers(input: &str) -> String {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let re = RE.get_or_init(|| {
        // Both patterns are static; if either fails to compile, skip header
        // scrubbing for this input — never panic in prod.
        Regex::new(
            r"(?i)(authorization|proxy-authorization|proxy-authenticate|www-authenticate|authentication|cookie2?|set-cookie2?|x-api-key|x-api-token|x-api-secret|x-auth-token|x-access-token|x-session-token|x-csrf-token|x-csrftoken|api-key|api-secret|api-token|apikey|access-token|refresh-token|id-token|client-secret|session-token|csrf-token)\s*:\s*[^\r\n]+",
        )
        .or_else(|_| Regex::new(r"(?i)authorization\s*:\s*[^\r\n]+"))
        .ok()
    });
    let Some(re) = re.as_ref() else {
        return input.to_owned();
    };
    re.replace_all(input, |caps: &regex::Captures<'_>| {
        format!("{}: [REDACTED]", &caps[1])
    })
    .into_owned()
}

/// Redact URL userinfo (`scheme://user:pass@host` → `scheme://[REDACTED]@`).
/// Covers operator credentials in targets and proxy URLs with auth
/// (`socks5h://user:pass@proxy:1080`). The host itself is preserved.
fn scrub_url_userinfo(input: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(r"(?i)((?:https?|socks5h?|socks4a?|socks|ftp)://)[^/\s@]+@")
                .expect("userinfo regex")
        }
    });
    re.replace_all(input, "$1[REDACTED]@").into_owned()
}

/// Sensitive query-parameter values (`?token=…&sessionid=…`).
/// The key is preserved for triage, the value is redacted. `id`, `q`, `page`
/// and other non-sensitive params are untouched.
fn scrub_query_secrets(input: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(
                r#"(?i)([?&;](?:sessionid|phpsessid|jsessionid|aspsessionid|asp_net_sessionid|sid|sessid|session|token|access_token|accesstoken|auth_token|authtoken|api_key|api-key|api_secret|api-secret|apisecret|apikey|api_token|api-token|apitoken|x-api-key|x-api-token|x-api-secret|secret|client_secret|clientsecret|password|passwd|pwd|auth|session_token|sessiontoken|refresh_token|refreshtoken|id_token|idtoken|csrf|csrf_token|csrf-token|private_key|privatekey)=)[^&\s"'<>]+"#,
            )
            .expect("query secrets regex")
        }
    });
    re.replace_all(input, "$1[REDACTED]").into_owned()
}

/// JSON string values for sensitive keys (`"password": "hunter2"`).
/// Keeps valid JSON (`"key": "[REDACTED]"`). Numeric/bool/null values for
/// sensitive keys are redacted the same way.
fn scrub_json_secrets(input: &str) -> String {
    static STR_RE: OnceLock<Regex> = OnceLock::new();
    static RAW_RE: OnceLock<Regex> = OnceLock::new();
    let str_re = STR_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(
                r#"(?i)("(?:password|passwd|pwd|secret|client_secret|clientsecret|api_key|api-key|api_secret|api-secret|apisecret|apikey|api_token|api-token|apitoken|access_token|accesstoken|auth_token|authtoken|session_token|sessiontoken|refresh_token|refreshtoken|id_token|idtoken|token|sessionid|session|cookie|authorization|set-cookie|x-api-key|x-api-token|x-api-secret|x-auth-token|csrf|csrf_token|csrf-token|private_key|privatekey|private-key|aws_secret|aws_session_token)"\s*:\s*")[^"]*(")"#,
            )
            .expect("json str secrets regex")
        }
    });
    let raw_re = RAW_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(
                r#"(?i)("(?:password|passwd|pwd|secret|client_secret|clientsecret|api_key|api-key|api_secret|api-secret|apisecret|apikey|api_token|api-token|apitoken|access_token|accesstoken|auth_token|authtoken|session_token|sessiontoken|refresh_token|refreshtoken|id_token|idtoken|token|sessionid|session|csrf|csrf_token|csrf-token)"\s*:\s*)(-?\d+(?:\.\d+)?|true|false|null)"#,
            )
            .expect("json raw secrets regex")
        }
    });
    let s = str_re.replace_all(input, "$1[REDACTED]$2").into_owned();
    raw_re.replace_all(&s, r#"$1"[REDACTED]""#).into_owned()
}

/// Form/body pairs (`password=hunter2&token=abc`).
/// The key is preserved, the value is redacted up to the next delimiter.
fn scrub_form_secrets(input: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(
                r#"(?i)\b(password|passwd|pwd|secret|client_secret|clientsecret|api_key|api-key|api_secret|api-secret|apisecret|apikey|api_token|api-token|apitoken|x-api-key|x-api-token|x-api-secret|access_token|accesstoken|auth_token|authtoken|session_token|sessiontoken|refresh_token|refreshtoken|id_token|idtoken|token|sessionid|phpsessid|jsessionid|sid|sessid|session|auth|csrf|csrf_token|csrf-token|private_key|privatekey|private-key)\s*=\s*[^&\s,;"'<>]+"#,
            )
            .expect("form secrets regex")
        }
    });
    re.replace_all(input, |caps: &regex::Captures<'_>| {
        format!("{}=[REDACTED]", &caps[1])
    })
    .into_owned()
}

fn scrub_patterns(input: &str) -> String {
    static JWT_RE: OnceLock<Regex> = OnceLock::new();
    static BEARER_RE: OnceLock<Regex> = OnceLock::new();
    static BASIC_RE: OnceLock<Regex> = OnceLock::new();
    static AWS_RE: OnceLock<Regex> = OnceLock::new();
    static AWS_SECRET_RE: OnceLock<Regex> = OnceLock::new();
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
            // Tokens are base64url/base64: must include `+/=` or trailing chunks leak.
            Regex::new(r"(?i)bearer\s+[A-Za-z0-9._\-~+/=]+").expect("bearer regex")
        }
    });
    let basic_re = BASIC_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            // Inline `Basic base64(user:pass)` outside header lines.
            // Header lines are already fully redacted by `scrub_headers`.
            Regex::new(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}").expect("basic regex")
        }
    });
    let aws_re = AWS_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            // AKIA (long-term) + ASIA (temporary STS) + ABIA/ACCA variants.
            Regex::new(r"A(KIA|SIA|BIA|CCA)[0-9A-Z]{16}").expect("aws regex")
        }
    });
    let aws_secret_re = AWS_SECRET_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            // `aws_secret_access_key` assignments carry a 40-char base64 secret.
            Regex::new(r"(?i)\baws_secret[^A-Za-z0-9/+=]{0,10}[A-Za-z0-9/+=]{40}")
                .expect("aws secret regex")
        }
    });
    let pem_re = PEM_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            // Redact the full PEM block (header + body + footer), not just the
            // BEGIN line — otherwise the base64 body stays reconstructible.
            Regex::new(r"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----")
                .expect("pem regex")
        }
    });

    let mut s = jwt_re.replace_all(input, "[REDACTED-JWT]").into_owned();
    s = bearer_re.replace_all(&s, "Bearer [REDACTED]").into_owned();
    s = basic_re.replace_all(&s, "Basic [REDACTED]").into_owned();
    s = aws_re.replace_all(&s, "[REDACTED-AWS-KEY]").into_owned();
    s = aws_secret_re
        .replace_all(&s, "[REDACTED-AWS-SECRET]")
        .into_owned();
    s = pem_re.replace_all(&s, "[REDACTED-PEM]").into_owned();
    scrub_provider_tokens(&s)
}

/// Provider-issued tokens (split from [`scrub_patterns`] for readability).
fn scrub_provider_tokens(input: &str) -> String {
    static GITHUB_RE: OnceLock<Regex> = OnceLock::new();
    static GITLAB_RE: OnceLock<Regex> = OnceLock::new();
    static SLACK_RE: OnceLock<Regex> = OnceLock::new();
    static STRIPE_RE: OnceLock<Regex> = OnceLock::new();
    static OPENAI_RE: OnceLock<Regex> = OnceLock::new();

    let github_re = GITHUB_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(r"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{10,})")
                .expect("github regex")
        }
    });
    let gitlab_re = GITLAB_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(r"glpat-[A-Za-z0-9_\-]{10,}").expect("gitlab regex")
        }
    });
    let slack_re = SLACK_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(r"xox[bpras]-[A-Za-z0-9\-]+").expect("slack regex")
        }
    });
    let stripe_re = STRIPE_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]+").expect("stripe regex")
        }
    });
    let openai_re = OPENAI_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}").expect("openai regex")
        }
    });

    let mut s = github_re
        .replace_all(input, "[REDACTED-GITHUB-TOKEN]")
        .into_owned();
    s = gitlab_re
        .replace_all(&s, "[REDACTED-GITLAB-TOKEN]")
        .into_owned();
    s = slack_re
        .replace_all(&s, "[REDACTED-SLACK-TOKEN]")
        .into_owned();
    s = stripe_re
        .replace_all(&s, "[REDACTED-STRIPE-KEY]")
        .into_owned();
    openai_re
        .replace_all(&s, "[REDACTED-OPENAI-KEY]")
        .into_owned()
}

/// Redact OOB collaborator material (sensible per OPSEC: the collaborator
/// domain + poll tokens identify the operator infra).
///
/// - Known public OOB providers (`oastify`, `interactsh`, `burpcollaborator`,
///   `oast.live|site|fun|online`) → `[REDACTED-OOB]`. Self-hosted collaborator
///   hosts are NOT matched here on purpose (indistinguishable from a target):
///   they never enter reports in clear because payloads/bodies are hashed in
///   the trace (`reasoning/trace.rs`) and `knowledge.json` stores aggregates
///   only — the keyed patterns below still catch `oob_domain=`-style echoes.
/// - Keyed echoes (`oob_domain: …`, `oob_poll_url=…`, `collaborator…: …`) →
///   `key: [REDACTED]`.
fn scrub_oob(input: &str) -> String {
    static HOST_RE: OnceLock<Regex> = OnceLock::new();
    static KEY_RE: OnceLock<Regex> = OnceLock::new();
    let host_re = HOST_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(
                r"(?i)\b[a-z0-9.-]*(?:oastify|interactsh|burpcollaborator|oast\.(?:live|site|fun|online))[a-z0-9./?=&_~+\-]*",
            )
            .expect("oob host regex")
        }
    });
    let key_re = KEY_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(
                r"(?i)\b(oob[_-]?domain|oob[_-]?poll[_-]?url|collaborator[_-]?(?:url|domain)?)\s*[:=]\s*\S+",
            )
            .expect("oob key regex")
        }
    });
    let s = host_re.replace_all(input, "[REDACTED-OOB]").into_owned();
    key_re
        .replace_all(&s, |caps: &regex::Captures<'_>| {
            format!("{}: [REDACTED]", &caps[1])
        })
        .into_owned()
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

    #[test]
    fn scrubs_bearer_with_base64_padding() {
        let sc = Scrubber::new(false);
        let out = sc.scrub("Authorization: Bearer abc");
        assert!(out.contains("[REDACTED]"), "{out}");
        // `+/=` are valid base64 token chars — no trailing leakage.
        let out = sc.scrub("token Bearer abc+def/ghi==");
        assert!(!out.contains("+def/ghi=="), "{out}");
        assert!(out.contains("Bearer [REDACTED]"), "{out}");
    }

    #[test]
    fn scrubs_temporary_aws_keys() {
        let sc = Scrubber::new(false);
        let out = sc.scrub("key ASIAIOSFODNN7EXAMPLE");
        assert!(!out.contains("ASIAIOSFODNN7EXAMPLE"), "{out}");
    }

    #[test]
    fn scrubs_full_pem_block() {
        let sc = Scrubber::new(false);
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----";
        let out = sc.scrub(pem);
        assert!(!out.contains("MIIEvgIBADANBg"), "{out}");
        assert!(!out.contains("END PRIVATE KEY"), "{out}");
    }

    #[test]
    fn scrubs_extended_sensitive_headers() {
        let sc = Scrubber::new(false);
        for line in [
            "X-Access-Token: hunter2-value",
            "X-Session-Token: hunter2-value",
            "X-Api-Secret: hunter2-value",
            "Proxy-Authenticate: Basic hunter2-value",
            "WWW-Authenticate: Bearer hunter2-value",
        ] {
            let out = sc.scrub(line);
            assert!(!out.contains("hunter2-value"), "{line} leaked: {out}");
            assert!(out.contains("[REDACTED]"), "{line}: {out}");
        }
        assert_eq!(
            sc.scrub_header("X-Session-Token", "hunter2-value"),
            "[REDACTED]"
        );
        assert_eq!(sc.scrub_header("X-Request-Id", "req-123"), "req-123");
    }

    #[test]
    fn scrubs_url_userinfo_but_keeps_host() {
        let sc = Scrubber::new(false);
        let out = sc.scrub("target https://admin:s3cr3t-p4ss@example.com/?id=1");
        assert!(!out.contains("s3cr3t-p4ss"), "{out}");
        assert!(!out.contains("admin:s3cr3t"), "{out}");
        assert!(out.contains("example.com/?id=1"), "{out}");
        let out = sc.scrub("proxy socks5h://user:p4ss@127.0.0.1:1080");
        assert!(!out.contains("p4ss@"), "{out}");
    }

    #[test]
    fn scrubs_sensitive_query_values_but_keeps_benign_params() {
        let sc = Scrubber::new(false);
        let out = sc.scrub("https://example.com/?id=1&token=abc123XYZ&sessionid=sess-999");
        assert!(out.contains("id=1"), "benign param must survive: {out}");
        assert!(!out.contains("abc123XYZ"), "{out}");
        assert!(!out.contains("sess-999"), "{out}");
        assert!(out.contains("token=[REDACTED]"), "{out}");
    }

    #[test]
    fn scrubs_json_and_form_body_secrets() {
        let sc = Scrubber::new(false);
        let out = sc.scrub(r#"body {"password": "hunter2", "user": "admin"}"#);
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains(r#""password": "[REDACTED]""#), "{out}");
        assert!(
            out.contains("admin"),
            "non-sensitive value must survive: {out}"
        );
        let out = sc.scrub("data password=hunter2&user=admin&api_key=AK-999");
        assert!(!out.contains("hunter2"), "{out}");
        assert!(!out.contains("AK-999"), "{out}");
        assert!(out.contains("user=admin"), "{out}");
    }

    #[test]
    fn scrubs_provider_tokens_and_basic() {
        let sc = Scrubber::new(false);
        let fixture = "ghp_1234567890abcdefghij1234567890abcd glpat-1234567890abcdefg \
             xoxb-123-456-abc sk_live_abc123DEF456 sk-proj-abcDEF1234567890ABCDEF \
             Basic dXNlcjpwYXNz hunter BasicAuth";
        let out = sc.scrub(fixture);
        for secret in [
            "ghp_1234567890abcdefghij1234567890abcd",
            "glpat-1234567890abcdefg",
            "xoxb-123-456-abc",
            "sk_live_abc123DEF456",
            "sk-proj-abcDEF1234567890ABCDEF",
            "dXNlcjpwYXNz",
        ] {
            assert!(!out.contains(secret), "{secret} leaked: {out}");
        }
    }

    #[test]
    fn scrubs_extended_secret_key_variants() {
        let sc = Scrubber::new(false);
        // Previously-missed variants from the audit: hyphen/underscore/camelCase.
        for secret in [
            "X-Api-Token: hunter2-value",
            "X-Api-Secret: hunter2-value",
            "Api-Secret: hunter2-value",
            "Csrf-Token: hunter2-value",
            "https://example.com/?x-api-token=abc123&api-secret=def456&csrf-token=ghi789",
            r#"{"privateKey": "hunter2", "apiSecret": "hunter2b"}"#,
            "data apiSecret=hunter2&privateKey=hunter2b&csrf-token=hunter2c",
            "proxy socks://user:p4ss@127.0.0.1:1080",
        ] {
            let out = sc.scrub(secret);
            assert!(
                !out.contains("hunter2")
                    && !out.contains("abc123")
                    && !out.contains("def456")
                    && !out.contains("ghi789")
                    && !out.contains("p4ss@"),
                "leaked: {secret} -> {out}"
            );
        }
        // Host preserved for userinfo redact.
        let out = sc.scrub("proxy socks://user:p4ss@127.0.0.1:1080");
        assert!(out.contains("127.0.0.1"), "{out}");
    }

    #[test]
    fn scrubs_oob_collaborator_but_keeps_seed() {
        let sc = Scrubber::new(false);
        let out = sc.scrub("callback https://abc123.oastify.com/poll?token=xyz");
        assert!(!out.contains("oastify.com"), "{out}");
        assert!(out.contains("[REDACTED-OOB]"), "{out}");
        let out = sc.scrub("oob_domain: my-collab.example.net");
        assert!(!out.contains("my-collab.example.net"), "{out}");
        // Seed is NOT a secret (replay determinism) — never redacted.
        let out = sc.scrub("seed 42 seed=42");
        assert!(out.contains("42"), "seed must survive: {out}");
    }

    #[test]
    fn audit_fixture_all_renderers_inputs_are_scrubbed() {
        // v1.0-rc OPSEC audit fixture: every renderer input shape
        // (stdout/JSON/SARIF/JUnit/MD/trace/knowledge) goes through `scrub`.
        // Faux secrets must vanish; structure (keys, benign params, seed)
        // must survive.
        let sc = Scrubber::new(false);
        let fixture = "Authorization: Bearer faketoken123\n\
            Cookie: sess=fakesess999\n\
            https://op:s3cr3t@example.com/?id=1&token=faketoken123\n\
            {\"password\": \"fakehunter2\"} password=fakehunter2\n\
            ghp_fakesecret0123456789abcdefghij\n\
            https://xyz789.oastify.com/cb oob_poll_url=https://collab.local/poll/abc\n\
            seed 42 id=1";
        let out = sc.scrub(fixture);
        for secret in [
            "faketoken123",
            "fakesess999",
            "s3cr3t",
            "fakehunter2",
            "ghp_fakesecret0123456789abcdefghij",
            "xyz789.oastify.com",
            "https://collab.local/poll/abc",
        ] {
            assert!(!out.contains(secret), "{secret} leaked: {out}");
        }
        for survivor in ["id=1", "seed 42", "[REDACTED", "[REDACTED-OOB]"] {
            assert!(out.contains(survivor), "{survivor} missing: {out}");
        }
    }
}
