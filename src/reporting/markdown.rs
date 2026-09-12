#![deny(unsafe_code)]

//! Markdown renderer (C7): human-sendable report with remediation.
//!
//! Tables carry one row per finding; each finding gets a detail section with
//! the parameterized fix example, scrubbed evidence, WAF context and trace
//! reference. Every string passes through [`Scrubber`].

use crate::session::{scrubber::Scrubber, state::Finding};
use std::fmt::Write as _;

/// Render `findings` as a Markdown report.
///
/// `request_count` and `tool_version` feed the header summary; pass `0` /
/// `""` when unknown.
#[must_use]
pub fn to_markdown(
    target: &str,
    findings: &[Finding],
    request_count: u64,
    tool_version: &str,
    scrubber: &Scrubber,
) -> String {
    let safe_target = scrubber.scrub(target);
    let clean: Vec<Finding> = findings.iter().map(|f| f.scrubbed(scrubber)).collect();
    let tool_version = scrubber.scrub(tool_version);

    let mut out = String::new();
    out.push_str("# injekt report\n\n");
    let _ = writeln!(out, "- Target: `{safe_target}`");
    let _ = writeln!(out, "- Findings: {}", clean.len());
    let _ = writeln!(out, "- Requests: {request_count}");
    if !tool_version.is_empty() {
        let _ = writeln!(out, "- Tool: injekt {tool_version}");
    }
    out.push('\n');

    if clean.is_empty() {
        out.push_str("No findings.\n");
        return out;
    }

    out.push_str("| Parameter | Technique | Severity | Confidence | FP prob | DBMS |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    for finding in &clean {
        let _ = writeln!(
            out,
            "| `{}` | {} | **{}** | {:.2} | {:.2} | {} |",
            finding.parameter,
            finding.technique,
            finding.live_severity(),
            finding.confidence,
            finding.false_positive_prob,
            finding.dbms.as_deref().unwrap_or("-"),
        );
    }
    out.push('\n');

    for (index, finding) in clean.iter().enumerate() {
        let _ = writeln!(
            out,
            "## {} — `{}` ({})\n",
            index + 1,
            finding.parameter,
            finding.technique,
        );
        let _ = writeln!(out, "- Severity: **{}**", finding.live_severity());
        let _ = writeln!(
            out,
            "- Confidence: {:.2} (false-positive probability {:.2})",
            finding.confidence, finding.false_positive_prob,
        );
        let _ = writeln!(
            out,
            "- DBMS: {}",
            finding.dbms.as_deref().unwrap_or("unknown"),
        );
        let _ = writeln!(out, "- Evidence: `{}`", finding.evidence);
        if let Some(diff) = finding.evidence_detail.diff.as_deref() {
            let _ = writeln!(out, "- Diff: `{diff}`");
        }
        if !finding.evidence_detail.hashes.is_empty() {
            let _ = writeln!(
                out,
                "- Evidence hashes: `{}`",
                finding.evidence_detail.hashes.join(", "),
            );
        }
        if let Some(trace_ref) = finding.evidence_detail.trace_ref.as_deref() {
            let _ = writeln!(out, "- Trace ref: `{trace_ref}`");
        }
        if finding.waf.blocking || finding.waf.vendor.is_some() {
            let _ = writeln!(
                out,
                "- WAF: vendor={} blocking={}",
                finding.waf.vendor.as_deref().unwrap_or("unknown"),
                finding.waf.blocking,
            );
        }
        out.push('\n');
        out.push_str("### Remediation\n\n");
        if finding.remediation.summary.is_empty() {
            out.push_str("Use parameterized queries; never concatenate input into SQL.\n");
        } else {
            out.push_str(&finding.remediation.summary);
            out.push('\n');
        }
        if !finding.remediation.parameterized_example.is_empty() {
            out.push_str("\n```\n");
            out.push_str(&finding.remediation.parameterized_example);
            out.push_str("\n```\n");
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::state::TechniqueKind;

    fn sample() -> Finding {
        Finding::new(
            "https://example.com/?id=1",
            "id@query",
            TechniqueKind::Boolean,
            0.95,
            "boolean true_sim=0.95 false_sim=0.10",
        )
        .with_false_positive_prob(0.02)
    }

    #[test]
    fn markdown_contains_table_and_remediation() {
        let out = to_markdown(
            "https://example.com/?id=1",
            &[sample()],
            42,
            "0.3.0",
            &Scrubber::new(true),
        );
        assert!(out.contains("# injekt report"), "{out}");
        assert!(out.contains("### Remediation"), "{out}");
        assert!(out.contains("parameterized"), "{out}");
        assert!(out.contains("**high**"), "{out}");
    }

    #[test]
    fn markdown_empty_scan() {
        let out = to_markdown(
            "https://example.com/",
            &[],
            7,
            "0.3.0",
            &Scrubber::new(true),
        );
        assert!(out.contains("No findings."), "{out}");
    }

    #[test]
    fn markdown_scrubs_secrets() {
        let finding = Finding::new(
            "https://example.com/?id=1",
            "id@query",
            TechniqueKind::Error,
            0.9,
            "evidence Authorization: Bearer abc123",
        );
        let out = to_markdown(
            "https://example.com/?id=1",
            &[finding],
            9,
            "0.3.0",
            &Scrubber::new(false),
        );
        assert!(!out.contains("abc123"), "secret leaked in Markdown");
    }
}
