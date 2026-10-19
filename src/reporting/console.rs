#![deny(unsafe_code)]

use crate::cli::output::theme::Theme;
use crate::session::scrubber::Scrubber;
use crate::session::state::Finding;
use std::time::Duration;
use tabled::settings::Style;
use tabled::settings::Width;
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
    let t = Theme::for_stdout();
    if findings.is_empty() {
        println!("{} {}", t.icon_ok(), t.warning("No findings."));
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
    let params = findings
        .iter()
        .map(|f| f.parameter.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();

    println!(
        "{} {} across {} parameter(s) {}",
        t.icon_alert(),
        t.bold(format!("{} finding(s)", findings.len())),
        t.plain(params),
        t.dim(format!("[{high} high · {medium} medium · {low} low]")),
    );
    println!();

    // Group by parameter (reading an exploit attempt = read one param's
    // story end to end), confidence descending inside a group, stable on
    // ties so repeated runs keep the detection order.
    let ordered = sorted_findings(findings);

    let rows: Vec<Row> = ordered
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
    // `Width::wrap` guards narrow terminals (and `tmux` panes): without it
    // a wide target column overflows the viewport and breaks the rounded
    // frame. `keep_words` avoids splitting target/param tokens mid-word.
    let table = Table::new(rows)
        .with(Style::rounded())
        .with(Width::wrap(100).keep_words(true))
        .to_string();
    println!("{}", t.white(table));
    println!();

    for f in &ordered {
        let sf = f.scrubbed(scrubber);
        let (icon, label, bar) = match severity(f.confidence, f.false_positive_prob) {
            Severity::High => (
                t.dot_high(),
                t.danger_bold("HIGH"),
                t.danger(conf_bar(f.confidence)),
            ),
            Severity::Medium => (
                t.dot_medium(),
                t.warning_bold("MED"),
                t.warning(conf_bar(f.confidence)),
            ),
            Severity::Low => (t.dot_low(), t.dim("LOW"), t.dim(conf_bar(f.confidence))),
        };
        println!(
            "{icon} {label} {bar} {:.2} {} — {}",
            f.confidence,
            t.accent(sf.parameter),
            t.dim(truncate_evidence(&sf.evidence, EVIDENCE_MAX_COLS))
        );
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

/// Barre de confiance 5 segments `▰▰▰▰▱` (fin du plan UI P2) : lecture
/// instantanée du score sans lire le nombre. Pure — la couleur (accents de
/// sévérité) est appliquée côté `print_findings`.
#[must_use]
pub fn conf_bar(confidence: f64) -> String {
    const SEGMENTS: usize = 5;
    // Clamp saturant : un score hors [0,1] (bug futur de scoring) ne doit
    // jamais paniquer ni déborder le repeat. Le round-half-away + clamp
    // garantit `0..=SEGMENTS` — les cast f64→usize sont donc passés au
    // crible (pedantic), l'allow est scoped et justifié.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let filled = (confidence.clamp(0.0, 1.0) * SEGMENTS as f64).round() as usize;
    let filled = filled.min(SEGMENTS);
    format!("{}{}", "▰".repeat(filled), "▱".repeat(SEGMENTS - filled))
}

/// Evidence tronquée à N colonnes (wall of text obéit au viewport, clig.dev :
/// « truncate long strings »). Coupe sur un blanc si possible, jamais au
/// milieu d'un escape (les séquences ANSI vivent APRÈS, dans `Theme`).
#[must_use]
pub fn truncate_evidence(evidence: &str, max_cols: usize) -> String {
    if evidence.chars().count() <= max_cols {
        return evidence.to_owned();
    }
    let cut: String = evidence.chars().take(max_cols).collect();
    match cut.rfind(' ') {
        Some(idx) if idx > max_cols / 2 => format!("{}…", &cut[..idx]),
        _ => format!("{cut}…"),
    }
}

/// Largeur max de la ligne d'evidence (`--no-redact` peut exfiltrer des
/// dumps longs : la ligne finding reste scannable).
pub const EVIDENCE_MAX_COLS: usize = 96;

/// Ordre de lecture des findings : regroupés par paramètre (l'histoire d'un
/// param se lit d'un bloc), confiance décroissante dans le groupe, stable
/// sur les égalités (ordre de détection préservé). Pure — testable sans
/// capture stdout.
#[must_use]
pub fn sorted_findings(findings: &[Finding]) -> Vec<&Finding> {
    let mut refs: Vec<&Finding> = findings.iter().collect();
    refs.sort_by(|a, b| {
        a.parameter
            .cmp(&b.parameter)
            .then(b.confidence.total_cmp(&a.confidence))
    });
    refs
}

/// Print the compact human-facing result of one scan.
///
/// Logs remain on stderr while this summary stays with findings on stdout.
/// It reports confirmed findings only; `CLEAN` means a complete run produced
/// no finding, `INCONCLUSIVE` means the run stopped early or the oracle was
/// unusable (unstable/all-5xx baseline, budget/duration stop) — never read it
/// as "not injectable". `CANCELLED` means the operator interrupted the run.
/// `suggestion` (C14) : commande rejouable **déjà scrubbée** (elle vit dans
/// un `Diagnostic::scrubbed`), imprimée uniquement quand
/// `status == "INCONCLUSIVE"` — une run CLEAN/FINDINGS/CANCELLED n'a pas de
/// conseil de rejeu à recevoir.
/// `level` : profil `--level` effectif de la run — sert au hint CLEAN
/// ([`next_step_hint`]), `None` = hors CLI (MCP/tests, pas de hint).
// `level` : hic d'API — regrouper les stats dans une `RunStats` serait le
// vrai fix ; l'allow trace l'intention (record de rendu, pas de logique).
#[allow(clippy::too_many_arguments)]
pub fn print_run_summary(
    target: &str,
    state: &str,
    request_count: u64,
    elapsed: Duration,
    findings: usize,
    suggestion: Option<&str>,
    level: Option<u8>,
    scrubber: &Scrubber,
) {
    let target = scrubber.scrub(target);
    let status = run_status(state, findings);
    let elapsed = elapsed.as_secs_f64();
    let t = Theme::for_stdout();

    println!();
    println!("{} {}", t.icon_diamond(), t.bold("Scan complete"));
    println!("{}", t.kv("Status", t.status_pill(status)));
    println!("{}", t.kv("Target", target));
    println!("{}", t.kv("Requests", request_count));
    println!("{}", t.kv("Duration", format!("{elapsed:.1}s")));
    let rate = if elapsed > 0.0 {
        f64::from(u32::try_from(request_count).unwrap_or(u32::MAX)) / elapsed
    } else {
        0.0
    };
    println!("{}", t.kv("Rate", format!("{rate:.1} req/s")));
    if status == "INCONCLUSIVE"
        && let Some(sug) = suggestion
    {
        println!("{}", suggestion_line(sug, t.color()));
    } else if let Some(hint) = next_step_hint(status, level) {
        println!("{}", next_step_line(hint, t.color()));
    }
    println!();
}

/// C14 — ligne de conseil `→ suggestion: <cmd>` (pure, testable). La
/// commande est déjà scrubbée en amont (`Diagnostic::scrubbed`) : aucun
/// token brut ne traverse cette fonction.
#[must_use]
pub fn suggestion_line(suggestion: &str, color: bool) -> String {
    let t = Theme::new(color);
    format!("  {} {suggestion}", t.accent("→ suggestion:"))
}

/// Hint `→ suite: …` pour les statuts SANS la ligne C14 (clig.dev :
/// « suggest commands the user should run »). Pure — textes statiques, aucun
/// secret (pas de target/param injecté). `None` pour `INCONCLUSIVE` (C14
/// occupe la ligne) et pour les hints inapplicables (CLEAN au `--level 3`).
#[must_use]
pub fn next_step_hint(status: &str, level: Option<u8>) -> Option<&'static str> {
    if status == "INCONCLUSIVE" {
        return None;
    }
    match status {
        "FINDINGS" => Some(
            "confirme : --confirm (2e passe, payloads frais) · verdicts : --explain <param@location>",
        ),
        "CLEAN" if level.is_none_or(|l| l < 3) => Some(
            "élargis : --level 3 (charge ORDER BY 20 cols + headers) · oracle silencieux : --techniques time",
        ),
        "CANCELLED" => {
            Some("reprise déterministe du flux de payloads : --seed <n> (relance la même matrix)")
        }
        _ => None,
    }
}

/// Ligne `→ suite: <hint>` (même gabarit que [`suggestion_line`]).
#[must_use]
pub fn next_step_line(hint: &str, color: bool) -> String {
    let t = Theme::new(color);
    format!("  {} {hint}", t.accent("→ suite:"))
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
    let t = Theme::for_stdout();
    println!(
        "{} {}",
        t.icon_pick(),
        t.bold(format!("{} extracted value(s)", extracted.len()))
    );
    for e in extracted {
        println!("  {} {e}", t.icon_bullet());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::state::TechniqueKind;

    #[test]
    fn conf_bar_buckets_are_5_segments_and_saturate() {
        assert_eq!(conf_bar(0.0), "▱▱▱▱▱");
        assert_eq!(conf_bar(0.85), "▰▰▰▰▱");
        assert_eq!(conf_bar(1.0), "▰▰▰▰▰");
        // Hors bornes (bug de scoring futur) : saturé, jamais de panic.
        assert_eq!(conf_bar(-0.5), "▱▱▱▱▱");
        assert_eq!(conf_bar(1.5), "▰▰▰▰▰");
    }

    #[test]
    fn sorted_findings_groups_by_parameter_conf_desc() {
        let mk = |param: &str, conf: f64, evidence: &str| {
            Finding::new(
                "http://example.com/?id=1",
                param,
                TechniqueKind::Boolean,
                conf,
                evidence,
            )
        };
        let findings = [
            mk("id@query", 0.70, "e1"),
            mk("user@post", 0.90, "e2"),
            mk("id@query", 0.95, "e3"),
            mk("user@post", 0.50, "e4"),
        ];
        let ordered = sorted_findings(&findings);
        let keys: Vec<(&str, f64)> = ordered
            .iter()
            .map(|f| (f.parameter.as_str(), f.confidence))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("id@query", 0.95),
                ("id@query", 0.70),
                ("user@post", 0.90),
                ("user@post", 0.50),
            ]
        );
    }

    #[test]
    fn truncate_evidence_cuts_on_words_and_marks() {
        assert_eq!(truncate_evidence("short", 96), "short");
        let long = "word ".repeat(30);
        let cut = truncate_evidence(&long, 20);
        assert!(cut.ends_with('…'), "{cut}");
        assert!(cut.chars().count() <= 21, "{cut}");
        // Pas de blanc découpable : coupe franche à la borne (jamais mid-token).
        let no_space = "a".repeat(100);
        assert_eq!(truncate_evidence(&no_space, 40).chars().count(), 41);
    }

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

    #[test]
    fn suggestion_line_renders_verbatim_in_both_colorings() {
        // C14 : pure et fidèle — la commande scrubbée apparaît telle quelle;
        // la couleur ne doit ni casser ni recomposer le texte affiché.
        let line = suggestion_line("injekt --tamper space2comment,randomcase", true);
        assert!(line.contains("→ suggestion"), "{line}");
        assert!(
            line.contains("injekt --tamper space2comment,randomcase"),
            "{line}"
        );
        assert_eq!(
            suggestion_line("injekt --rate-limit 2", false),
            "  → suggestion: injekt --rate-limit 2"
        );
    }

    #[test]
    fn next_step_hint_matches_outcomes() {
        // clig.dev : « suggest commands the user should run » — chaque statut
        // sauf INCONCLUSIVE (la ligne C14 occupe le slot) reçoit un hint.
        assert!(next_step_hint("INCONCLUSIVE", Some(1)).is_none());
        assert_eq!(
            next_step_hint("CANCELLED", Some(1)),
            Some("reprise déterministe du flux de payloads : --seed <n> (relance la même matrix)")
        );
        assert!(next_step_hint("FINDINGS", Some(2)).is_some_and(|h| h.contains("--confirm")));
        // CLEAN à level < 3 → élargir; CLEAN au max → pas de hint (pas de
        // conseil inapplicable). `None` (MCP/tests) = toujours éligible.
        assert!(next_step_hint("CLEAN", Some(1)).is_some());
        assert!(next_step_hint("CLEAN", Some(3)).is_none());
        assert!(next_step_hint("CLEAN", None).is_some());
    }

    #[test]
    fn next_step_line_verbatim() {
        assert_eq!(
            next_step_line("élargis : --level 3", false),
            "  → suite: élargis : --level 3"
        );
    }
}
