use regex::Regex;
use std::sync::OnceLock;

pub(super) fn is_sensitive_header(name: &str) -> bool {
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
            | "x-client-id"
            | "client-id"
            | "api-key"
            | "api-secret"
            | "api-token"
            | "apikey"
            | "access-token"
            | "refresh-token"
            | "id-token"
            | "client-secret"
            | "session-token"
            | "sessionid"
            | "csrf-token"
            | "token"
            | "aws-secret"
            | "private-key"
    )
}

pub(super) fn scrub_headers(input: &str) -> String {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let re = RE.get_or_init(|| {
        // Both patterns are static; if either fails to compile, skip header
        // scrubbing for this input — never panic in prod.
        Regex::new(
            r"(?i)(authorization|proxy-authorization|proxy-authenticate|www-authenticate|authentication|cookie2?|set-cookie2?|x-api-key|x-api-token|x-api-secret|x-auth-token|x-access-token|x-session-token|x-csrf-token|x-csrftoken|x-client-id|client-id|api-key|api-secret|api-token|apikey|access-token|refresh-token|id-token|client-secret|session-token|sessionid|csrf-token|token|aws-secret|private-key)\s*:\s*[^\r\n]+",
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
