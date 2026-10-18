use regex::Regex;
use std::sync::OnceLock;

pub(super) fn scrub_patterns(input: &str) -> String {
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
