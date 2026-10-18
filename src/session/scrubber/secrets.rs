use regex::Regex;
use std::sync::OnceLock;

/// Redact URL userinfo (`scheme://user:pass@host` → `scheme://[REDACTED]@`).
/// Covers operator credentials in targets and proxy URLs with auth
/// (`socks5h://user:pass@proxy:1080`). The host itself is preserved.
pub(super) fn scrub_url_userinfo(input: &str) -> String {
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

/// Shared sensitive-key alternation for query/JSON/form secret scrubbing.
/// ONE list for all three renderers so a key covered in one place cannot
/// leak through another (`?authorization=…`, `"cookie":123`,
/// `private-key=…` were previously missed in query/form/RAW respectively).
const SENSITIVE_KEY_ALTERNATION: &str = "sessionid|phpsessid|jsessionid|aspsessionid|asp_net_sessionid|sid|sessid|session|token|access_token|accesstoken|auth_token|authtoken|api_key|api-key|api_secret|api-secret|apisecret|apikey|api_token|api-token|apitoken|x-api-key|x-api-token|x-api-secret|x-auth-token|secret|client_secret|clientsecret|client_id|password|passwd|pwd|auth|authorization|session_token|sessiontoken|refresh_token|refreshtoken|id_token|idtoken|csrf|csrf_token|csrf-token|private_key|privatekey|private-key|cookie|set-cookie|aws_secret|aws_session_token";

/// Sensitive query-parameter values (`?token=…&sessionid=…`).
/// The key is preserved for triage, the value is redacted. `id`, `q`, `page`
/// and other non-sensitive params are untouched.
pub(super) fn scrub_query_secrets(input: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(&format!(
                r#"(?i)([?&;](?:{SENSITIVE_KEY_ALTERNATION})=)[^&\s"'<>]+"#,
            ))
            .expect("query secrets regex")
        }
    });
    re.replace_all(input, "$1[REDACTED]").into_owned()
}

/// JSON string values for sensitive keys (`"password": "hunter2"`).
/// Keeps valid JSON (`"key": "[REDACTED]"`). Numeric/bool/null values for
/// sensitive keys are redacted the same way.
pub(super) fn scrub_json_secrets(input: &str) -> String {
    static STR_RE: OnceLock<Regex> = OnceLock::new();
    static RAW_RE: OnceLock<Regex> = OnceLock::new();
    let str_re = STR_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(&format!(
                r#"(?i)("(?:{SENSITIVE_KEY_ALTERNATION})"\s*:\s*")[^"]*(")"#,
            ))
            .expect("json str secrets regex")
        }
    });
    let raw_re = RAW_RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(&format!(
                r#"(?i)("(?:{SENSITIVE_KEY_ALTERNATION})"\s*:\s*)(-?\d+(?:\.\d+)?|true|false|null)"#,
            ))
            .expect("json raw secrets regex")
        }
    });
    let s = str_re.replace_all(input, "$1[REDACTED]$2").into_owned();
    raw_re.replace_all(&s, r#"$1"[REDACTED]""#).into_owned()
}

/// Form/body pairs (`password=hunter2&token=abc`).
/// The key is preserved, the value is redacted up to the next delimiter.
pub(super) fn scrub_form_secrets(input: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(&format!(
                r#"(?i)\b({SENSITIVE_KEY_ALTERNATION})\s*=\s*[^&\s,;"'<>]+"#,
            ))
            .expect("form secrets regex")
        }
    });
    re.replace_all(input, |caps: &regex::Captures<'_>| {
        format!("{}=[REDACTED]", &caps[1])
    })
    .into_owned()
}
