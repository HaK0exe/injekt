#![deny(unsafe_code)]

//! SARIF 2.1.0 renderer (C7) for CI / code-scanning ingestion.
//!
//! Every string passes through [`Scrubber`]: SARIF reports are shared
//! artefacts, never debug dumps. Trace references are opaque hashes and are
//! scrubbed again for uniformity.

use crate::session::{scrubber::Scrubber, state::Finding};

/// SARIF schema URI pinned for the emitted format version.
pub const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
/// SARIF format version emitted.
pub const SARIF_VERSION: &str = "2.1.0";

/// Render `findings` as a SARIF 2.1.0 log (pretty JSON).
///
/// `tool_name` identifies the producer (`injekt` + version at call sites).
/// Output is scrubbed with `scrubber` before serialization.
#[must_use]
pub fn to_sarif(
    target: &str,
    findings: &[Finding],
    tool_name: &str,
    tool_version: &str,
    scrubber: &Scrubber,
) -> String {
    let safe_target = scrubber.scrub(target);
    let clean: Vec<Finding> = findings.iter().map(|f| f.scrubbed(scrubber)).collect();

    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for finding in &clean {
        let rule_id = rule_id_for(finding);
        if !seen.iter().any(|s| s == &rule_id) {
            seen.push(rule_id.clone());
            rules.push(serde_json::json!({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": remediation_summary(finding)},
                "fullDescription": {"text": rule_description(finding)},
                "help": {"text": remediation_help(finding)},
                "properties": {
                    "precision": "very-high",
                    "security-severity": security_severity(finding),
                },
            }));
        }
    }

    let results: Vec<serde_json::Value> = clean.iter().map(sarif_result).collect();

    let log = serde_json::json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": scrubber.scrub(tool_name),
                    "version": scrubber.scrub(tool_version),
                    "informationUri": "https://github.com/HaK0exe/injekt",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "properties": {"target": safe_target},
            }],
        }],
    });
    serde_json::to_string_pretty(&log).unwrap_or_else(|_| "{\"version\":\"2.1.0\"}".to_owned())
}

fn rule_id_for(finding: &Finding) -> String {
    format!("injekt/sqli-{}", finding.technique)
}

fn rule_description(finding: &Finding) -> String {
    format!(
        "SQL injection via {} technique (parameter '{}', confidence {:.2}, false-positive probability {:.2})",
        finding.technique, finding.parameter, finding.confidence, finding.false_positive_prob,
    )
}

fn remediation_summary(finding: &Finding) -> String {
    if finding.remediation.summary.is_empty() {
        "Use parameterized queries; never concatenate input into SQL.".to_owned()
    } else {
        finding.remediation.summary.clone()
    }
}

fn remediation_help(finding: &Finding) -> String {
    let mut help = remediation_summary(finding);
    if !finding.remediation.parameterized_example.is_empty() {
        help.push_str("\nExample fix:\n");
        help.push_str(&finding.remediation.parameterized_example);
    }
    help
}

#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn security_severity(finding: &Finding) -> String {
    // CVSS-style 0.0–10.0 score derived from the calibrated bucket, so
    // consumers that sort by `security-severity` inherit the C7 calibration.
    let score = match finding.live_severity() {
        crate::session::state::Severity::High => 9.0 + finding.confidence,
        crate::session::state::Severity::Medium => 5.0 + finding.confidence * 3.9,
        crate::session::state::Severity::Low => finding.confidence * 3.9,
    };
    format!("{:.1}", score.clamp(0.0, 10.0))
}

fn sarif_level(finding: &Finding) -> &'static str {
    match finding.live_severity() {
        crate::session::state::Severity::High => "error",
        crate::session::state::Severity::Medium => "warning",
        crate::session::state::Severity::Low => "note",
    }
}

fn sarif_result(finding: &Finding) -> serde_json::Value {
    let mut properties = serde_json::json!({
        "confidence": finding.confidence,
        "false_positive_prob": finding.false_positive_prob,
        "severity": finding.live_severity().to_string(),
        "technique": finding.technique.to_string(),
        "parameter": finding.parameter,
        "dbms": finding.dbms,
        "evidence": finding.evidence,
    });
    if let Some(diff) = finding.evidence_detail.diff.as_deref() {
        properties["diff"] = serde_json::Value::String(diff.to_owned());
    }
    if !finding.evidence_detail.hashes.is_empty() {
        properties["hashes"] = serde_json::json!(finding.evidence_detail.hashes);
    }
    if let Some(trace_ref) = finding.evidence_detail.trace_ref.as_deref() {
        properties["trace_ref"] = serde_json::Value::String(trace_ref.to_owned());
    }
    if finding.waf.blocking || finding.waf.vendor.is_some() {
        properties["waf"] = serde_json::json!({
            "vendor": finding.waf.vendor,
            "blocking": finding.waf.blocking,
        });
    }
    if !finding.remediation.summary.is_empty() {
        properties["remediation"] = serde_json::json!({
            "summary": finding.remediation.summary,
            "parameterized_example": finding.remediation.parameterized_example,
        });
    }

    serde_json::json!({
        "ruleId": rule_id_for(finding),
        "level": sarif_level(finding),
        "message": {"text": rule_description(finding)},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.target},
                "region": {
                    "startLine": 1,
                    "snippet": {"text": finding.evidence},
                },
            },
            "logicalLocations": [{
                "name": finding.parameter,
                "kind": "parameter",
            }],
        }],
        "properties": properties,
    })
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
    fn sarif_is_valid_envelope() {
        let out = to_sarif(
            "https://example.com/?id=1",
            &[sample()],
            "injekt",
            "0.3.0",
            &Scrubber::new(true),
        );
        let value: serde_json::Value =
            serde_json::from_str(&out).unwrap_or(serde_json::Value::Null);
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "injekt");
        assert_eq!(value["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            value["runs"][0]["results"][0]["ruleId"],
            "injekt/sqli-boolean"
        );
    }

    #[test]
    fn sarif_scrubs_secrets() {
        let finding = Finding::new(
            "https://example.com/?id=1",
            "id@query",
            TechniqueKind::Error,
            0.9,
            "evidence Authorization: Bearer abc123",
        );
        let out = to_sarif(
            "https://example.com/?id=1",
            &[finding],
            "injekt",
            "0.3.0",
            &Scrubber::new(false),
        );
        assert!(!out.contains("abc123"), "secret leaked in SARIF");
    }

    #[test]
    fn sarif_empty_findings_has_no_results() {
        let out = to_sarif(
            "https://example.com/",
            &[],
            "injekt",
            "0.3.0",
            &Scrubber::new(true),
        );
        let value: serde_json::Value =
            serde_json::from_str(&out).unwrap_or(serde_json::Value::Null);
        assert_eq!(
            value["runs"][0]["results"].as_array().map(Vec::len),
            Some(0)
        );
    }
}
