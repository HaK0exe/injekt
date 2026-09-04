#![deny(unsafe_code)]

use crate::session::scrubber::Scrubber;
use crate::session::state::Finding;
use owo_colors::OwoColorize;
use tabled::settings::Style;
use tabled::{Table, Tabled};

#[derive(Tabled)]
struct Row {
    #[tabled(rename = "Target")]
    target: String,
    #[tabled(rename = "Param")]
    param: String,
    #[tabled(rename = "Technique")]
    technique: String,
    #[tabled(rename = "Conf")]
    conf: String,
    #[tabled(rename = "DBMS")]
    dbms: String,
}

/// Confidence bucket: drives both the icon shown next to each finding and
/// the color of its evidence line — the score alone doesn't jump out in a
/// wall of text.
enum Severity {
    High,
    Medium,
    Low,
}

fn severity(confidence: f64) -> Severity {
    if confidence >= 0.8 {
        Severity::High
    } else if confidence >= 0.5 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

pub fn print_findings(findings: &[Finding], scrubber: &Scrubber) {
    if findings.is_empty() {
        println!("{} {}", "✓".green().bold(), "No findings.".yellow());
        return;
    }

    let high = findings
        .iter()
        .filter(|f| matches!(severity(f.confidence), Severity::High))
        .count();
    let medium = findings
        .iter()
        .filter(|f| matches!(severity(f.confidence), Severity::Medium))
        .count();
    let low = findings.len() - high - medium;

    println!(
        "{} {} across {} parameter(s)  {}",
        "⚠".red().bold(),
        format!("{} finding(s)", findings.len()).bold(),
        findings
            .iter()
            .map(|f| f.parameter.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        format!("[{high} high · {medium} medium · {low} low]").dimmed()
    );
    println!();

    let rows: Vec<Row> = findings
        .iter()
        .map(|f| {
            let sf = f.scrubbed(scrubber);
            Row {
                target: sf.target,
                param: sf.parameter,
                technique: sf.technique.to_string(),
                conf: format!("{:.2}", sf.confidence),
                dbms: sf.dbms.unwrap_or_else(|| "-".to_owned()),
            }
        })
        .collect();
    let table = Table::new(rows).with(Style::rounded()).to_string();
    println!("{}", table.bright_white());
    println!();

    for f in findings {
        let sf = f.scrubbed(scrubber);
        let (icon, label) = match severity(f.confidence) {
            Severity::High => ("●".red().to_string(), "HIGH".red().bold().to_string()),
            Severity::Medium => ("●".yellow().to_string(), "MED".yellow().bold().to_string()),
            Severity::Low => ("●".dimmed().to_string(), "LOW".dimmed().to_string()),
        };
        println!(
            "{icon} {label} {} — {}",
            sf.parameter.cyan().bold(),
            sf.evidence.dimmed()
        );
    }
}

/// Print extracted DB data (banner, tables, dump rows, …) collected during
/// the scan. Not scrubbed: this is the requested payoff of
/// `--dump`/`--banner`/`--current-user`/etc, not collateral secret leakage,
/// so it's shown in full regardless of `--no-redact`.
pub fn print_extracted(extracted: &[String]) {
    if extracted.is_empty() {
        return;
    }
    println!();
    println!(
        "{} {}",
        "⛏".bright_green().bold(),
        format!("{} extracted value(s)", extracted.len()).bold()
    );
    for e in extracted {
        println!("  {} {e}", "•".bright_green());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::state::TechniqueKind;

    fn finding_with_secret() -> Finding {
        Finding::new(
            "http://example.com/?id=1",
            "id@query",
            TechniqueKind::Boolean,
            0.9,
            "secret evidence with Authorization: Bearer abc123",
        )
    }

    #[test]
    fn print_findings_scrubs_secrets() {
        let findings = [finding_with_secret()];
        let scrubber = Scrubber::new(false);

        // Since we can't easily capture println! in unit tests without extra crates,
        // we test the scrubbed finding directly
        let sf = findings[0].scrubbed(&scrubber);
        assert!(
            !sf.evidence.contains("abc123"),
            "secret leaked in evidence: {}",
            sf.evidence
        );
        assert!(!sf.target.contains("abc123"), "secret leaked in target");
        assert!(
            !sf.parameter.contains("abc123"),
            "secret leaked in parameter"
        );
    }

    #[test]
    fn print_findings_no_redact_passthrough() {
        let findings = [finding_with_secret()];
        let scrubber = Scrubber::new(true);

        let sf = findings[0].scrubbed(&scrubber);
        assert!(
            sf.evidence.contains("abc123"),
            "no_redact should pass through"
        );
    }
}
