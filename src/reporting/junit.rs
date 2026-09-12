#![deny(unsafe_code)]

//! `JUnit` XML renderer (C7) for CI test-case ingestion.
//!
//! Each finding becomes one `<testcase>` with a `<failure>` element carrying
//! the calibrated severity, so CI dashboards fail the build on `high`/`medium`
//! without custom parsers. Every string passes through [`Scrubber`]; XML
//! metacharacters are escaped by [`escape_xml`].

use crate::session::{scrubber::Scrubber, state::Finding};
use std::fmt::Write as _;

/// Escape the five XML metacharacters plus invalid control chars.
#[must_use]
pub fn escape_xml(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 0x20 && c != '\n' && c != '\r' && c != '\t' => {
                out.push('\u{FFFD}');
            }
            c => out.push(c),
        }
    }
    out
}

/// Render `findings` as `JUnit` XML.
///
/// A clean scan (no findings) yields a single passing `scan` testcase so the
/// suite stays green-but-visible instead of empty.
#[must_use]
pub fn to_junit(target: &str, findings: &[Finding], scrubber: &Scrubber) -> String {
    let safe_target = escape_xml(&scrubber.scrub(target));
    let clean: Vec<Finding> = findings.iter().map(|f| f.scrubbed(scrubber)).collect();

    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    if clean.is_empty() {
        let _ = writeln!(
            out,
            "<testsuite name=\"injekt\" tests=\"1\" failures=\"0\" errors=\"0\" skipped=\"0\" hostname=\"{safe_target}\">\n"
        );
        out.push_str("  <testcase classname=\"injekt.scan\" name=\"no-injection\"/>");
        out.push_str("</testsuite>\n");
        return out;
    }
    // Security posture: every finding fails the build (including `low` —
    // a confirmed injection is never "passing"). `failures` therefore equals
    // the testcase count; triage by severity happens in the dashboard.
    let failures = clean.len();
    let _ = writeln!(
        out,
        "<testsuite name=\"injekt\" tests=\"{}\" failures=\"{failures}\" errors=\"0\" skipped=\"0\" hostname=\"{safe_target}\">",
        clean.len(),
    );
    for finding in &clean {
        let classname = escape_xml(&format!("injekt.{}", finding.technique));
        let name = escape_xml(&finding.parameter);
        let _ = writeln!(
            out,
            "  <testcase classname=\"{classname}\" name=\"{name}\">\n"
        );
        let message = escape_xml(&failure_message(finding));
        let body = escape_xml(&failure_body(finding));
        let _ = writeln!(out, "    <failure message=\"{message}\">{body}</failure>");
        out.push_str("  </testcase>\n");
    }
    out.push_str("</testsuite>\n");
    out
}

fn failure_message(finding: &Finding) -> String {
    format!(
        "[{}] SQL injection via {} on parameter '{}' (confidence {:.2}, fp {:.2})",
        finding.live_severity(),
        finding.technique,
        finding.parameter,
        finding.confidence,
        finding.false_positive_prob,
    )
}

fn failure_body(finding: &Finding) -> String {
    let mut body = format!(
        "target: {}\ndbms: {}\nevidence: {}\nremediation: {}",
        finding.target,
        finding.dbms.as_deref().unwrap_or("-"),
        finding.evidence,
        if finding.remediation.summary.is_empty() {
            "Use parameterized queries.".to_owned()
        } else {
            finding.remediation.summary.clone()
        },
    );
    if !finding.remediation.parameterized_example.is_empty() {
        let _ = writeln!(
            body,
            "\nfix example: {}",
            finding.remediation.parameterized_example
        );
    }
    if let Some(trace_ref) = finding.evidence_detail.trace_ref.as_deref() {
        let _ = writeln!(body, "\ntrace_ref: {trace_ref}");
    }
    if finding.waf.blocking || finding.waf.vendor.is_some() {
        let _ = writeln!(
            body,
            "\nwaf: vendor={} blocking={}",
            finding.waf.vendor.as_deref().unwrap_or("unknown"),
            finding.waf.blocking,
        );
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::state::TechniqueKind;

    #[test]
    fn escapes_xml_metacharacters() {
        assert_eq!(
            escape_xml("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&apos;"
        );
    }

    #[test]
    fn empty_scan_is_single_passing_case() {
        let out = to_junit("https://example.com/", &[], &Scrubber::new(true));
        assert!(out.contains("failures=\"0\""), "{out}");
        assert!(out.contains("no-injection"), "{out}");
    }

    #[test]
    fn finding_becomes_failure_with_severity() {
        let finding = Finding::new(
            "https://example.com/?id=1",
            "id@query",
            TechniqueKind::Boolean,
            0.95,
            "boolean true_sim=0.95",
        )
        .with_false_positive_prob(0.02);
        let out = to_junit(
            "https://example.com/?id=1",
            &[finding],
            &Scrubber::new(true),
        );
        assert!(out.contains("failures=\"1\""), "{out}");
        assert!(out.contains("[high]"), "{out}");
    }

    #[test]
    fn junit_scrubs_secrets_and_escapes() {
        let finding = Finding::new(
            "https://example.com/?id=<1>",
            "id@query",
            TechniqueKind::Error,
            0.9,
            "evidence Authorization: Bearer abc123 & <tag>",
        );
        let out = to_junit(
            "https://example.com/?id=<1>",
            &[finding],
            &Scrubber::new(false),
        );
        assert!(!out.contains("abc123"), "secret leaked in JUnit");
        assert!(!out.contains("<tag>"), "unescaped XML in JUnit: {out}");
    }
}
