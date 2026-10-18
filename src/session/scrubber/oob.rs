use regex::Regex;
use std::sync::OnceLock;

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
pub(super) fn scrub_oob(input: &str) -> String {
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
