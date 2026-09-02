#![deny(unsafe_code)]

//! OOB (out-of-band) detection.
//!
//! OOB is definitive when the collaborator observes the callback, and
//! inconclusive otherwise: the vulnerable query runs **asynchronously** and
//! typically leaves the HTTP response unchanged (PortSwigger Academy OOB
//! labs). The detector therefore combines:
//! 1. `callback_seen` from an [`OobVerifier`](crate::techniques::oob::verifier)
//!    (DNS / HTTP interaction containing the per-probe token) — decisive.
//! 2. Response similarity to baseline — the probe should *not* produce a SQL
//!    error; an accepted-but-silent probe is a candidate, not a finding.

use crate::detection::response_diff::{diff_against_baseline, jaccard};
use crate::techniques::oob::payloads::{OobChannel, OobPayload};

/// Result of evaluating one OOB probe.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OobResult {
    /// Confirmed only when the collaborator saw the token.
    pub is_vulnerable: bool,
    /// 0.95 on callback; 0.35 accepted-but-unconfirmed; 0.15-0.2 otherwise.
    pub confidence: f64,
    /// Channel of the confirming/candidate payload.
    pub channel: OobChannel,
    /// DBMS of the payload (`None` when rejected).
    pub dbms: Option<String>,
    /// Per-probe token that triggered (or would trigger) the callback.
    pub token: String,
}

/// OOB detector bound to one collaborator base domain.
///
/// The domain itself is only used for evidence; correlation happens via the
/// per-probe `token` embedded in `<token>.<domain>`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OobDetector {
    /// Collaborator base domain (e.g. `x.oastify.com`). Kept for evidence.
    pub domain: String,
}

impl OobDetector {
    #[must_use]
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
        }
    }

    /// Evaluate one probe response.
    ///
    /// - `callback_seen=true` → vulnerable, confidence 0.95 regardless of
    ///   response body (async OOB often returns the baseline page).
    /// - `false` + SQL/OOB error in body → rejected, 0.2.
    /// - `false` + response similar to baseline → silently accepted,
    ///   candidate for manual verification, 0.35 (not vulnerable).
    /// - `false` + significant unexplained diff → likely filter/WAF, 0.15.
    #[must_use]
    pub fn evaluate_with_callback(
        &self,
        baseline_body: &str,
        candidate_body: &str,
        baseline_ms: f64,
        candidate_ms: f64,
        payload: &OobPayload,
        callback_seen: bool,
    ) -> OobResult {
        if callback_seen {
            return OobResult {
                is_vulnerable: true,
                confidence: 0.95,
                channel: payload.channel,
                dbms: Some(payload.dbms.clone()),
                token: payload.token.clone(),
            };
        }
        if contains_oob_error(candidate_body) {
            return OobResult {
                is_vulnerable: false,
                confidence: 0.2,
                channel: payload.channel,
                dbms: None,
                token: payload.token.clone(),
            };
        }
        let diff = diff_against_baseline(
            baseline_body,
            candidate_body,
            baseline_ms,
            candidate_ms,
            100.0,
        );
        let j = jaccard(baseline_body, candidate_body);
        // Silently accepted: close to baseline, no error -> plausible OOB
        // injection point awaiting collaborator confirmation.
        if diff.confidence < 0.4 && j > 0.7 {
            return OobResult {
                is_vulnerable: false,
                confidence: 0.35,
                channel: payload.channel,
                dbms: None,
                token: payload.token.clone(),
            };
        }
        OobResult {
            is_vulnerable: false,
            confidence: 0.15,
            channel: payload.channel,
            dbms: None,
            token: payload.token.clone(),
        }
    }

    /// Convenience wrapper when no collaborator polling is available.
    #[must_use]
    pub fn evaluate_without_callback(
        &self,
        baseline_body: &str,
        candidate_body: &str,
        baseline_ms: f64,
        candidate_ms: f64,
        payload: &OobPayload,
    ) -> OobResult {
        self.evaluate_with_callback(
            baseline_body,
            candidate_body,
            baseline_ms,
            candidate_ms,
            payload,
            false,
        )
    }

    /// Check whether any collaborator interaction log contains `token`
    /// (case-insensitive substring). Used to turn raw DNS/HTTP logs into
    /// `callback_seen`.
    #[must_use]
    pub fn token_seen_in_interactions(token: &str, interactions: &[String]) -> bool {
        if token.is_empty() {
            return false;
        }
        let needle = token.to_ascii_lowercase();
        interactions
            .iter()
            .any(|line| line.to_ascii_lowercase().contains(&needle))
    }
}

/// Heuristic: body reveals the OOB function was rejected by the DB.
///
/// Covers MySQL `LOAD_FILE`, Postgres `COPY/dblink`, MSSQL
/// `xp_dirtree/xp_fileexist/sp_OA*`, Oracle `UTL_INADDR/UTL_HTTP/DBMS_LDAP`,
/// plus generic SQL syntax errors mentioning those vectors.
#[must_use]
pub fn contains_oob_error(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "utl_inaddr",
        "utl_http",
        "dbms_ldap",
        "xp_dirtree",
        "xp_fileexist",
        "xp_subdirs",
        "sp_oacreate",
        "sp_oamethod",
        "dblink_connect",
        "dblink",
        "load_file",
        "copy to program",
        "pg_sleep",
        "ora-24247", // Oracle network ACL denied
        "ora-29273", // UTL_HTTP request failed
        "ora-06512", // PL/SQL call stack (often with UTL_* errors)
    ];
    MARKERS.iter().any(|m| lower.contains(m))
        && (lower.contains("error")
            || lower.contains("exception")
            || lower.contains("ora-")
            || lower.contains("sql"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::techniques::oob::payloads::{OobChannel, oob_payloads_for};

    fn fixtures() -> (OobDetector, OobPayload, String) {
        let d = OobDetector::new("collab.example.com");
        let p = oob_payloads_for(Some("mssql"), "collab.example.com", "oobabc123")
            .into_iter()
            .next()
            .unwrap_or_else(|| {
                crate::techniques::oob::payloads::OobPayload::new(
                    "probe",
                    "mssql",
                    OobChannel::Dns,
                    "oobabc123",
                    "oobabc123.collab.example.com",
                )
            });
        (d, p, "welcome normal page id=1 content".to_owned())
    }

    #[test]
    fn callback_confirms_despite_identical_body() {
        let (d, p, baseline) = fixtures();
        // Async OOB: response == baseline, but collaborator saw the token.
        let r = d.evaluate_with_callback(&baseline, &baseline, 100.0, 105.0, &p, true);
        assert!(r.is_vulnerable);
        assert!((r.confidence - 0.95).abs() < 1e-6);
        assert_eq!(r.dbms, Some(p.dbms.clone()));
        assert_eq!(r.token, p.token);
    }

    #[test]
    fn silent_accept_is_candidate_not_finding() {
        let (d, p, baseline) = fixtures();
        let r = d.evaluate_without_callback(&baseline, &baseline, 100.0, 102.0, &p);
        assert!(!r.is_vulnerable);
        assert!((r.confidence - 0.35).abs() < 1e-6);
    }

    #[test]
    fn oob_error_is_rejected() {
        let (d, p, baseline) = fixtures();
        let body = "SQL error: EXEC xp_dirtree failed — access denied";
        let r = d.evaluate_without_callback(&baseline, body, 100.0, 110.0, &p);
        assert!(!r.is_vulnerable);
        assert!(r.confidence <= 0.2);
    }

    #[test]
    fn unexplained_diff_is_not_oob() {
        let (d, p, baseline) = fixtures();
        let body = "completely different page with lots of new content and structure 12345";
        let r = d.evaluate_without_callback(&baseline, body, 100.0, 110.0, &p);
        assert!(!r.is_vulnerable);
        assert!(r.confidence <= 0.2);
    }

    #[test]
    fn token_matching_is_case_insensitive() {
        let logs = vec![
            "DNS lookup OOBABC123.collab.example.com".to_owned(),
            "unrelated.example.com".to_owned(),
        ];
        assert!(OobDetector::token_seen_in_interactions("oobabc123", &logs));
        assert!(!OobDetector::token_seen_in_interactions("oobzzz999", &logs));
        assert!(!OobDetector::token_seen_in_interactions("", &logs));
    }

    #[test]
    fn error_markers_require_error_context() {
        assert!(contains_oob_error("SQL error near UTL_INADDR"));
        assert!(contains_oob_error(
            "ORA-24247: network access denied by ACL for UTL_HTTP"
        ));
        // Bare mention without error context must not count (avoids FP on
        // pages echoing the payload).
        assert!(!contains_oob_error("welcome page utl_inaddr info"));
    }
}
