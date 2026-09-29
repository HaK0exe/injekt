#![deny(unsafe_code)]

use crate::session::scrubber::Scrubber;
use crate::session::state::Finding;
use owo_colors::OwoColorize;
use std::time::Duration;
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

/// Pure verdict mapping: `Cancelled`/`Inconclusive` engine states never
/// surface as `CLEAN`, even with 0 findings. Unit-testable.
#[must_use]
pub fn run_status(state: &str, findings: usize) -> &'static str {
    let lowered = state.to_ascii_lowercase();
    // Cancel wins even with hits (operator interrupted the run).
    if lowered.contains("cancel") {
        "CANCELLED"
    } else if findings > 0 {
        // A hit is a hit, even on a truncated run.
        "FINDINGS"
    } else if lowered.contains("inconclusive") || lowered.contains("incomplete") {
        "INCONCLUSIVE"
    } else {
        "CLEAN"
    }
}

/// Print the compact human-facing result of one scan.
///
/// Logs remain on stderr while this summary stays with findings on stdout.
/// It reports confirmed findings only; `CLEAN` means a complete run produced
/// no finding, `INCONCLUSIVE` means the run stopped early or the oracle was
/// unusable (unstable/all-5xx baseline, budget/duration stop) — never read it
/// as "not injectable". `CANCELLED` means the operator interrupted the run.
pub fn print_run_summary(
    target: &str,
    state: &str,
    request_count: u64,
    elapsed: Duration,
    findings: usize,
    scrubber: &Scrubber,
) {
    let target = scrubber.scrub(target);
    let status = run_status(state, findings);
    let elapsed = elapsed.as_secs_f64();
    let color = crate::cli::output::console::stdout_colors_enabled();

    println!();
    if color {
        let status_text = match status {
            "CANCELLED" | "INCONCLUSIVE" => status.yellow().bold().to_string(),
            "CLEAN" => status.green().bold().to_string(),
            _ => status.red().bold().to_string(),
        };
        println!("{} {}", "◆".bright_cyan().bold(), "Scan complete".bold());
        println!("  {} {}", "Status".dimmed(), status_text);
        println!("  {} {}", "Target".dimmed(), target);
        println!("  {} {}", "Requests".dimmed(), request_count);
        println!("  {} {:.1}s", "Duration".dimmed(), elapsed);
    } else {
        println!("Scan complete");
        println!("  Status: {status}");
        println!("  Target: {target}");
        println!("  Requests: {request_count}");
        println!("  Duration: {elapsed:.1}s");
    }
    println!();
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

    #[test]
    fn interrupted_runs_never_map_to_clean() {
        // Interrupted/incomplete runs with 0 findings must not look CLEAN.
        assert_eq!(run_status("Done", 0), "CLEAN");
        assert_eq!(run_status("Done", 2), "FINDINGS");
        assert_eq!(run_status("Cancelled", 0), "CANCELLED");
        assert_eq!(run_status("Cancelled", 3), "CANCELLED");
        assert_eq!(run_status("Inconclusive", 0), "INCONCLUSIVE");
        // A hit on a truncated run still surfaces as FINDINGS.
        assert_eq!(run_status("Inconclusive", 1), "FINDINGS");
    }
}
