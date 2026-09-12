#![deny(unsafe_code)]

use crate::detection::response_diff::{diff_against_baseline, jaccard};
use crate::techniques::stacked::payloads::StackedPayload;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StackedResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub dbms: Option<String>,
}

#[derive(Debug, Default)]
pub struct StackedDetector;

impl StackedDetector {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Strip raw payload from body to avoid false positives from echoed input.
    fn strip_payload(body: &str, payload: &str) -> String {
        body.replace(payload, "")
    }

    /// `true` when the response merely echoes our input instead of executing
    /// it: the raw, percent-decoded (`%27`), form-decoded (`+` as space) or
    /// HTML-entity-decoded body contains the exact string we sent. A stacked
    /// marker only proves execution when it appears *without* its surrounding
    /// payload syntax (search-results pages reflecting `?q=` input are the
    /// classic false positive).
    fn is_echo(body: &str, sent_payload: &str) -> bool {
        if sent_payload.is_empty() {
            return false;
        }
        if body.contains(sent_payload) {
            return true;
        }
        // Encoded reflections: the page may echo the URL-encoded, `+`-spaced
        // or HTML-escaped form of our input instead of the raw payload.
        if percent_decode(body, false).contains(sent_payload) {
            return true;
        }
        if percent_decode(body, true).contains(sent_payload) {
            return true;
        }
        if html_decode_entities(body).contains(sent_payload) {
            return true;
        }
        // Server-side normalization echo: our encoded payload, decoded once,
        // appears verbatim in the response.
        let decoded_sent = percent_decode(sent_payload, true);
        if decoded_sent != sent_payload && body.contains(&decoded_sent) {
            return true;
        }
        false
    }

    /// Stacked queries: second statement should execute and produce visible side-effect.
    /// We probe with a tautology that changes response (e.g., `; SELECT 1 --`).
    /// Detection: response differs from baseline AND contains marker from second query.
    ///
    /// `sent_payload` is the exact (tampered) string sent on the wire — used
    /// for the reflection veto, since the page may echo it back verbatim.
    #[must_use]
    pub fn evaluate(
        &self,
        baseline_body: &str,
        candidate_body: &str,
        baseline_ms: f64,
        candidate_ms: f64,
        payload: &StackedPayload,
        sent_payload: &str,
    ) -> StackedResult {
        // Reject if marker already present in baseline (echo/false positive)
        if baseline_body.contains(&payload.marker) {
            return StackedResult {
                is_vulnerable: false,
                confidence: 0.1,
                dbms: None,
            };
        }
        // Reject reflections of our own input: the marker proves nothing when
        // the full payload syntax is echoed back.
        if Self::is_echo(candidate_body, sent_payload) {
            return StackedResult {
                is_vulnerable: false,
                confidence: 0.1,
                dbms: None,
            };
        }
        let stripped_candidate = Self::strip_payload(candidate_body, &payload.payload);
        let diff = diff_against_baseline(
            baseline_body,
            &stripped_candidate,
            baseline_ms,
            candidate_ms,
            100.0,
        );
        let j = jaccard(baseline_body, &stripped_candidate);
        let has_marker = stripped_candidate.contains(&payload.marker);
        // Stacked queries often produce subtle changes; lower thresholds than UNION.
        // Require marker + some diff + reasonable jaccard drop (j < 0.85).
        let is_vuln = has_marker && diff.confidence > 0.4 && j < 0.85;
        let confidence = if is_vuln {
            let raw = (diff.confidence * 0.5 + (1.0 - j) * 0.3 + 0.2)
                .clamp(0.0, 1.0)
                .max(0.55);
            // `generic` proves no DBMS: flag, but never look proven.
            if payload.dbms == "generic" {
                raw.min(0.6)
            } else {
                raw
            }
        } else {
            0.15
        };
        StackedResult {
            is_vulnerable: is_vuln,
            confidence,
            dbms: if is_vuln {
                Some(payload.dbms.clone())
            } else {
                None
            },
        }
    }
}

/// Minimal percent-decoder (`%XX` → byte). With `plus_as_space`, `+` decodes
/// to a space (query-string echo form). Invalid sequences are kept verbatim;
/// invalid UTF-8 becomes `U+FFFD` via lossy conversion. Never panics.
fn percent_decode(input: &str, plus_as_space: bool) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == b'%'
            && i + 3 <= bytes.len()
            && let Ok(hex) = core::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(decoded) = u8::from_str_radix(hex, 16)
        {
            out.push(decoded);
            i += 3;
            continue;
        }
        if plus_as_space && byte == b'+' {
            out.push(b' ');
        } else {
            out.push(byte);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Minimal HTML-entity decoder (same set as `matcher::strip_html` plus
/// `&#39;`/`&apos;`), `&amp;` last to avoid double-decoding `&amp;lt;`.
fn html_decode_entities(input: &str) -> String {
    input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#X27;", "'")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_mysql_stacked_select() {
        let d = StackedDetector::new();
        let baseline = "welcome page id=1";
        let injected = "welcome page id=1 stacked_marker_12345";
        let payload = StackedPayload::new(
            "; SELECT 'stacked_marker_12345' -- -",
            "mysql",
            "stacked_marker_12345",
        );
        let r = d.evaluate(
            baseline,
            injected,
            100.0,
            110.0,
            &payload,
            payload.payload.as_str(),
        );
        assert!(r.is_vulnerable);
        assert_eq!(r.dbms, Some("mysql".to_owned()));
    }

    #[test]
    fn no_false_positive_on_same_page() {
        let d = StackedDetector::new();
        let baseline = "welcome page id=1";
        let payload = StackedPayload::new("; SELECT 'marker' -- -", "mysql", "marker");
        let r = d.evaluate(
            baseline,
            baseline,
            100.0,
            102.0,
            &payload,
            payload.payload.as_str(),
        );
        assert!(!r.is_vulnerable);
    }

    #[test]
    fn requires_marker_and_diff() {
        let d = StackedDetector::new();
        let baseline = "welcome page id=1 normal content here";
        // Much more different content + marker
        let with_marker = "welcome page id=1 normal content here marker_here EXTRA DATA THAT MAKES IT DIFFERENT ENOUGH";
        let payload = StackedPayload::new("; SELECT 'marker_here' -- -", "mysql", "marker_here");
        let r = d.evaluate(
            baseline,
            with_marker,
            100.0,
            110.0,
            &payload,
            payload.payload.as_str(),
        );
        assert!(
            r.is_vulnerable,
            "should detect with marker and diff, confidence={}",
            r.confidence
        );
        assert_eq!(r.dbms, Some("mysql".to_owned()));

        let different_no_marker = "completely different page content without any marker";
        let r2 = d.evaluate(
            baseline,
            different_no_marker,
            100.0,
            105.0,
            &payload,
            payload.payload.as_str(),
        );
        assert!(
            !r2.is_vulnerable,
            "diff alone without marker should not trigger"
        );
    }

    #[test]
    fn rejects_marker_in_baseline() {
        let d = StackedDetector::new();
        let baseline = "welcome page marker_here normal content";
        let candidate = "welcome page marker_here injected content";
        let payload = StackedPayload::new("; SELECT 'marker_here' -- -", "mysql", "marker_here");
        let r = d.evaluate(
            baseline,
            candidate,
            100.0,
            110.0,
            &payload,
            payload.payload.as_str(),
        );
        assert!(!r.is_vulnerable, "marker in baseline should reject");
    }

    #[test]
    fn rejects_full_payload_echo() {
        let d = StackedDetector::new();
        let baseline = "welcome page";
        // Search-style page reflecting our input verbatim: the marker is
        // present, but so is the full payload syntax — no execution proof.
        let payload_text = "; SELECT 'found_it' -- -";
        let candidate = format!(
            "results for '{payload_text}' found_it EXTRA CONTENT THAT MAKES RESPONSE DIFFERENT"
        );
        let payload = StackedPayload::new(payload_text, "mysql", "found_it");
        let r = d.evaluate(baseline, &candidate, 100.0, 110.0, &payload, payload_text);
        assert!(
            !r.is_vulnerable,
            "reflected payload must not report, confidence={}",
            r.confidence
        );
    }

    #[test]
    fn rejects_encoded_payload_echo() {
        let d = StackedDetector::new();
        let baseline = "welcome page";
        let payload_text = "; SELECT 'found_it' -- -";
        let payload = StackedPayload::new(payload_text, "mysql", "found_it");
        // URL-encoded reflection (`%27`, `%3B`, `+` for space).
        let url_echo = "results for %3B+SELECT+%27found_it%27+--+-+ EXTRA CONTENT THAT MAKES RESPONSE DIFFERENT";
        let r = d.evaluate(baseline, url_echo, 100.0, 110.0, &payload, payload_text);
        assert!(!r.is_vulnerable, "URL-encoded echo must not report");
        // HTML-escaped reflection.
        let html_echo = "results for &#39;; SELECT &#39;found_it&#39; -- -&#39; EXTRA CONTENT THAT MAKES RESPONSE DIFFERENT";
        let r2 = d.evaluate(baseline, html_echo, 100.0, 110.0, &payload, payload_text);
        assert!(!r2.is_vulnerable, "HTML-escaped echo must not report");
    }

    #[test]
    fn generic_dbms_confidence_is_capped() {
        let d = StackedDetector::new();
        let baseline = "welcome page id=1 normal content here";
        let with_marker = "welcome page id=1 normal content here generic_marker_xyz EXTRA DATA THAT MAKES IT DIFFERENT ENOUGH";
        let payload = StackedPayload::new(
            "; SELECT 'generic_marker_xyz' -- -",
            "generic",
            "generic_marker_xyz",
        );
        let r = d.evaluate(
            baseline,
            with_marker,
            100.0,
            110.0,
            &payload,
            payload.payload.as_str(),
        );
        assert!(r.is_vulnerable);
        assert!(
            r.confidence <= 0.6,
            "generic findings must stay capped, got {}",
            r.confidence
        );
    }
}
