#![deny(unsafe_code)]

//! Collaborator verification for OOB callbacks.
//!
//! The [`OobVerifier`] trait decouples detection from the collaborator
//! backend (Burp Collaborator, interactsh, self-hosted DNS/HTTP listener).
//! The engine sends OOB probes embedding a unique token, waits for the async
//! DB-side query, then polls the verifier for `<token>.<domain>`.
//!
//! OPSEC: OOB emits DNS/HTTP from the **target DB server** to third-party
//! infra. Prefer self-hosted collaborator + `--proxy socks5h://` for your
//! own traffic; the DB-side egress itself cannot be proxied by injekt.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Async verifier: returns `true` when the collaborator observed `token`.
pub trait OobVerifier: Send + Sync + core::fmt::Debug {
    /// Poll once for `token`. Implementations must be cheap and cancellable
    /// via timeout; retry loops live in the caller.
    fn verify(&self, token: &str) -> impl core::future::Future<Output = bool> + Send;
}

/// Expand `{token}` / `%TOKEN%` placeholders, else append `?token=` or
/// `/token` so one `--oob-poll-url` covers REST, query-param and path-param
/// collaborator shims.
#[must_use]
pub fn expand_poll_url(poll_url: &str, token: &str) -> String {
    if poll_url.contains("{token}") {
        return poll_url.replace("{token}", token);
    }
    if poll_url.contains("%TOKEN%") {
        return poll_url.replace("%TOKEN%", token);
    }
    if poll_url.contains('?') {
        format!("{poll_url}&token={token}")
    } else if poll_url.ends_with('/') {
        format!("{poll_url}{token}")
    } else {
        format!("{poll_url}?token={token}")
    }
}

/// Decide whether a poll response body means "token seen".
///
/// Accepts generic shims: body containing the token (case-insensitive), or
/// JSON `{"seen":true}` / non-empty `"interactions"` (interactsh-style).
#[must_use]
pub fn poll_body_means_seen(body: &str, token: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    if !token.is_empty() && lower.contains(&token.to_ascii_lowercase()) {
        return true;
    }
    let compact: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("\"seen\":true") {
        return true;
    }
    // Non-empty interactions array: "interactions":[{...}] or ["..."]
    if let Some(pos) = compact.find("\"interactions\":[") {
        let rest = &compact[pos + "\"interactions\":[".len()..];
        if let Some(end) = rest.find(']') {
            return !rest[..end].trim().is_empty();
        }
    }
    false
}

/// HTTP polling verifier for generic collaborator shims.
///
/// `poll_url` may contain `{token}`; otherwise the token is appended as
/// `?token=<token>`. `timeout_secs` bounds each HTTP round-trip.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpPollVerifier {
    /// Base poll URL (see [`expand_poll_url`]).
    pub poll_url: String,
    /// Per-request timeout in seconds.
    pub timeout_secs: u64,
}

impl HttpPollVerifier {
    #[must_use]
    pub fn new(poll_url: impl Into<String>, timeout_secs: u64) -> Self {
        Self {
            poll_url: poll_url.into(),
            timeout_secs: timeout_secs.clamp(1, 60),
        }
    }
}

impl OobVerifier for HttpPollVerifier {
    async fn verify(&self, token: &str) -> bool {
        let url = expand_poll_url(&self.poll_url, token);
        let client = reqwest::Client::builder()
            .timeout(core::time::Duration::from_secs(self.timeout_secs))
            .build();
        let client = match client {
            Ok(c) => c,
            Err(_) => return false,
        };
        let resp = tokio::time::timeout(
            core::time::Duration::from_secs(self.timeout_secs + 2),
            client.get(&url).send(),
        )
        .await;
        let body = match resp {
            Ok(Ok(r)) => r.text().await.unwrap_or_default(),
            _ => return false,
        };
        poll_body_means_seen(&body, token)
    }
}

/// In-memory verifier for tests and offline dry-runs.
///
/// Pre-register callbacks with [`mark_seen`](Self::mark_seen); `verify`
/// is a synchronous set lookup wrapped in async for trait compat.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct InMemoryVerifier {
    seen: Arc<Mutex<HashSet<String>>>,
}

impl InMemoryVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Record that the collaborator observed `token` (case-insensitive).
    pub fn mark_seen(&self, token: &str) {
        if let Ok(mut guard) = self.seen.lock() {
            guard.insert(token.to_ascii_lowercase());
        }
    }
}

impl OobVerifier for InMemoryVerifier {
    async fn verify(&self, token: &str) -> bool {
        let needle = token.to_ascii_lowercase();
        self.seen
            .lock()
            .map(|guard| guard.contains(&needle))
            .unwrap_or(false)
    }
}

/// Verifier that never confirms — used when no `--oob-poll-url` is given.
///
/// Probes are still sent (operator checks collaborator UI manually), but the
/// engine never emits a finding without evidence.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct NoopVerifier;

impl OobVerifier for NoopVerifier {
    async fn verify(&self, _token: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_verifier_roundtrip() {
        let v = InMemoryVerifier::new();
        assert!(!v.verify("oobabc123").await);
        v.mark_seen("OOBABC123");
        assert!(v.verify("oobabc123").await);
        assert!(!v.verify("other").await);
    }

    #[tokio::test]
    async fn noop_never_confirms() {
        assert!(!NoopVerifier.verify("anything").await);
    }

    #[test]
    fn poll_url_expansion() {
        assert_eq!(
            expand_poll_url("https://c.example/poll/{token}", "oob1"),
            "https://c.example/poll/oob1"
        );
        assert_eq!(
            expand_poll_url("https://c.example/poll/%TOKEN%", "oob2"),
            "https://c.example/poll/oob2"
        );
        assert_eq!(
            expand_poll_url("https://c.example/poll", "oob3"),
            "https://c.example/poll?token=oob3"
        );
        assert_eq!(
            expand_poll_url("https://c.example/poll/?a=1", "oob4"),
            "https://c.example/poll/?a=1&token=oob4"
        );
        assert_eq!(
            expand_poll_url("https://c.example/poll/", "oob5"),
            "https://c.example/poll/oob5"
        );
    }

    #[test]
    fn poll_body_heuristics() {
        assert!(poll_body_means_seen(
            "seen OOBABC123 in dns log",
            "oobabc123"
        ));
        assert!(poll_body_means_seen(r#"{"seen":true}"#, "oobzzz"));
        assert!(poll_body_means_seen(r#"{"seen": false, "x":1}"#, "oobzzz") == false);
        assert!(poll_body_means_seen(
            r#"{"interactions":[{"id":1}]}"#,
            "oobzzz"
        ));
        assert!(!poll_body_means_seen(r#"{"interactions":[]}"#, "oobzzz"));
        assert!(!poll_body_means_seen("nothing yet", "oobzzz"));
    }
}
