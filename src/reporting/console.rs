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
/// wall of text. Buckets are the C7 calibrated verdicts
/// ([`crate::reporting::verdict::severity_for`]: `high` → precision ≥ 95 %,
/// `medium` → ≥ 80 %); both confidence and false-positive probability must
/// agree before a finding is promoted.
enum Severity {
    High,
    Medium,
    Low,
}

fn severity(confidence: f64, false_positive_prob: f64) -> Severity {
    match crate::reporting::verdict::severity_for(confidence, false_positive_prob) {
        crate::session::state::Severity::High => Severity::High,
        crate::session::state::Severity::Medium => Severity::Medium,
        crate::session::state::Severity::Low => Severity::Low,
    }
}

pub fn print_findings(findings: &[Finding], scrubber: &Scrubber) {
    // Results go to stdout (pipeable); colors follow NO_COLOR/TERM=dumb
    // and stdout TTY — never force ANSI into a pipe or CI log.
    let color = crate::cli::output::console::stdout_colors_enabled();
    if findings.is_empty() {
        if color {
            println!("{} {}", "✓".green().bold(), "No findings.".yellow());
        } else {
            println!("✓ No findings.");
        }
        return;
    }

    let high = findings
        .iter()
        .filter(|f| {
            matches!(
                severity(f.confidence, f.false_positive_prob),
                Severity::High
            )
        })
        .count();
    let medium = findings
        .iter()
        .filter(|f| {
            matches!(
                severity(f.confidence, f.false_positive_prob),
                Severity::Medium
            )
        })
        .count();
    let low = findings.len() - high - medium;

    if color {
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
    } else {
        println!(
            "⚠ {} finding(s) across {} parameter(s) [{high} high · {medium} medium · {low} low]",
            findings.len(),
            findings
                .iter()
                .map(|f| f.parameter.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len(),
        );
    }
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
    if color {
        println!("{}", table.bright_white());
    } else {
        println!("{table}");
    }
    println!();

    for f in findings {
        let sf = f.scrubbed(scrubber);
        if color {
            let (icon, label) = match severity(f.confidence, f.false_positive_prob) {
                Severity::High => ("●".red().to_string(), "HIGH".red().bold().to_string()),
                Severity::Medium => ("●".yellow().to_string(), "MED".yellow().bold().to_string()),
                Severity::Low => ("●".dimmed().to_string(), "LOW".dimmed().to_string()),
            };
            println!(
                "{icon} {label} {} — {}",
                sf.parameter.cyan().bold(),
                sf.evidence.dimmed()
            );
        } else {
            let label = match severity(f.confidence, f.false_positive_prob) {
                Severity::High => "HIGH",
                Severity::Medium => "MED",
                Severity::Low => "LOW",
            };
            println!("● {label} {} — {}", sf.parameter, sf.evidence);
        }
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
    if crate::cli::output::console::stdout_colors_enabled() {
        println!(
            "{} {}",
            "⛏".bright_green().bold(),
            format!("{} extracted value(s)", extracted.len()).bold()
        );
        for e in extracted {
            println!("  {} {e}", "•".bright_green());
        }
    } else {
        println!("⛏ {} extracted value(s)", extracted.len());
        for e in extracted {
            println!("  • {e}");
        }
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
