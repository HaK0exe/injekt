#![deny(unsafe_code)]

//! Bannière de démarrage : un art tiré au sort par run, lu depuis
//! `ascii_art.txt` (racine du dépôt, embarqué via `include_str!`).
//!
//! ## Format du fichier
//!
//! Plusieurs arts séparés par des lignes de séparation : un run d'au moins
//! 4 caractères parmi `-`, `─`, `━`, `═`, `=`. La légende éventuelle après le
//! run nomme l'art *au-dessus* (style légende de schéma) :
//!
//! ```text
//! ░██     ...     ← art
//! ------------------------- block   ← fin de l'art + nom
//! ███     ...     ← art suivant
//! ```
//!
//! Un art sans légende prend le nom `art-<n>` (n = position, 1-based). Le
//! fichier est éditable à chaud : renommer une légende ou coller un nouvel
//! art n'exige aucun changement de code.
//!
//! ## Sélection
//!
//! Rotation aléatoire par défaut, une seule fois par run (`--seed` la rend
//! déterministe). `INJEKT_BANNER_ART=<nom>` épingle un art (insensible à la
//! casse), `=random` force la rotation, `=list` liste les noms disponibles
//! (les valeurs `random`/`list` sont réservées, jamais des noms d'art).
//! `--no-banner` reste prioritaire (géré dans `main.rs`).
//!
//! ## Rendu
//!
//! - Arts clairs : dégradé vertical cyan → magenta, une couleur par ligne.
//! - Art truecolor (séquences SGR déjà présentes, section `ansi`) : imprimé
//!   tel quel quand les couleurs sont actives ; strippé proprement sinon
//!   (`NO_COLOR`, `TERM=dumb`, pipe/CI/MCP).

use super::theme::{Stream, colors_for};
use owo_colors::OwoColorize as _;
use std::sync::OnceLock;

/// Tous les arts embarqués : source de vérité `ascii_art.txt` à la racine.
const ASCII_ART: &str = include_str!("../../../ascii_art.txt");

/// Un art de la bannière, extrait d'`ascii_art.txt`.
pub struct Art {
    /// Nom de sélection : légende du séparateur, sinon `art-<n>`.
    pub name: String,
    /// Lignes de l'art (fins de ligne nettoyées, bords vides retirés).
    pub lines: Vec<&'static str>,
}

impl Art {
    /// `true` si l'art porte ses propres séquences ANSI (wordmark truecolor) :
    /// à imprimer brut, jamais re-coloré par le dégradé.
    fn is_ansi(&self) -> bool {
        self.lines.iter().any(|l| l.contains('\u{1b}'))
    }
}

/// Caractères admis dans une ligne de séparation (ASCII + box-drawing).
fn is_separator_char(c: char) -> bool {
    matches!(c, '-' | '─' | '━' | '═' | '=')
}

/// Légende d'une ligne de séparation : `Some(label)` (possiblement vide) quand
/// la ligne ouvre sur au moins 4 caractères de séparation, `None` sinon.
fn separator_label(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let run = trimmed
        .chars()
        .take_while(|c| is_separator_char(*c))
        .count();
    if run < 4 {
        return None;
    }
    Some(trimmed.trim_start_matches(is_separator_char).trim())
}

/// Clôt l'art courant : bords vides retirés, fins de ligne nettoyées, nom
/// (légende ou `art-<n>`) puis pousse dans `arts`. Section vide : ignorée.
fn flush_section(lines: &mut Vec<&'static str>, label: Option<&str>, arts: &mut Vec<Art>) {
    while lines.first().is_some_and(|l| l.trim().is_empty()) {
        lines.remove(0);
    }
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }
    if lines.is_empty() {
        return;
    }
    let fallback = format!("art-{}", arts.len() + 1);
    let name = label
        .filter(|l| !l.is_empty())
        .unwrap_or(fallback.as_str())
        .to_owned();
    let trimmed = lines.iter().map(|l| l.trim_end()).collect();
    arts.push(Art {
        name,
        lines: trimmed,
    });
    lines.clear();
}

/// Parse tous les arts du fichier : chaque séparateur clôt l'art courant (sa
/// légende le nomme) ; un art final sans séparateur est accepté.
fn parse_art(source: &'static str) -> Vec<Art> {
    let mut arts: Vec<Art> = Vec::new();
    let mut current: Vec<&'static str> = Vec::new();
    for raw in source.split('\n') {
        if let Some(label) = separator_label(raw) {
            flush_section(&mut current, Some(label), &mut arts);
        } else {
            current.push(raw);
        }
    }
    flush_section(&mut current, None, &mut arts);
    arts
}

/// Arts embarqués, parsés une seule fois (fichier `include_str!`).
///
/// Invariant : jamais vide — un fichier vidé retombe sur un wordmark minimal.
pub fn sections() -> &'static [Art] {
    static SECTIONS: OnceLock<Vec<Art>> = OnceLock::new();
    SECTIONS.get_or_init(|| {
        let mut arts = parse_art(ASCII_ART);
        if arts.is_empty() {
            arts.push(Art {
                name: "fallback".to_owned(),
                lines: vec!["InJEKT"],
            });
        }
        arts
    })
}

/// Indice tiré au sort ; déterministe sous `--seed` (même flux que le reste
/// des choix non cryptographiques, [`crate::seeded_rng`]).
fn random_index(len: usize, seed: Option<u64>) -> usize {
    use rand::RngExt as _;
    if len == 0 {
        return 0;
    }
    crate::seeded_rng::make_rng(seed).random_range(0..len)
}

/// Résout la sélection : nom exact (insensible à la casse), `random`/absent =
/// rotation. `Some(warning)` quand `INJEKT_BANNER_ART` ne matche aucun nom
/// (repli rotation, jamais d'échec de run pour une option cosmétique).
fn pick(arts: &[Art], want: Option<&str>, seed: Option<u64>) -> (usize, Option<String>) {
    if let Some(name) = want
        && !name.eq_ignore_ascii_case("random")
    {
        if let Some(index) = arts.iter().position(|a| a.name.eq_ignore_ascii_case(name)) {
            return (index, None);
        }
        let available = arts
            .iter()
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return (
            random_index(arts.len(), seed),
            Some(format!(
                "unknown banner art '{name}' (available: {available}) — falling back to random"
            )),
        );
    }
    (random_index(arts.len(), seed), None)
}

/// Couleur de la ligne `i` sur `n` : dégradé cyan → magenta (interpolation
/// entière, une seule couleur par ligne pour garder l'art lisible).
fn row_color(i: usize, n: usize) -> (u8, u8, u8) {
    let den = n.saturating_sub(1).max(1);
    let num = i.min(den);
    let mix = |start: u8, end: u8| -> u8 {
        let value = usize::from(start) * (den - num) + usize::from(end) * num;
        u8::try_from(value / den).unwrap_or(start)
    };
    (mix(34, 232), mix(211, 121), mix(238, 249))
}

/// Retire les séquences d'échappement ANSI (CSI, OSC, échappements courts) :
/// l'art truecolor reste lisible sur pipe / `NO_COLOR` / `TERM=dumb`.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.next() {
            // CSI : paramètres jusqu'à l'octet final 0x40..=0x7E.
            Some('[') => {
                for next in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&next) {
                        break;
                    }
                }
            }
            // OSC : jusqu'à BEL ou ST (`ESC \`).
            Some(']') => {
                let mut prev = '\0';
                for next in chars.by_ref() {
                    if next == '\u{7}' || (prev == '\u{1b}' && next == '\\') {
                        break;
                    }
                    prev = next;
                }
            }
            // Échappement court (ESC c, ESC 7, …) : l'octet suivant est avalé.
            _ => {}
        }
    }
    out
}

/// Écrit l'art : dégradé ligne à ligne, brut si truecolor, strippé si les
/// couleurs sont coupées.
fn emit(art: &Art, colors: bool) {
    let raw_ansi = art.is_ansi();
    let n = art.lines.len();
    for (i, line) in art.lines.iter().enumerate() {
        if !colors {
            eprintln!("{}", strip_ansi(line));
        } else if raw_ansi {
            eprintln!("{line}");
        } else {
            let (r, g, b) = row_color(i, n);
            eprintln!("{}", line.truecolor(r, g, b));
        }
    }
}

/// Signature posée sous chaque art (identité = wordmark, version magenta).
fn tagline(colors: bool) {
    if !colors {
        eprintln!("by s6stem · v{}", env!("CARGO_PKG_VERSION"));
        eprintln!("zero persistence · anonymisation by design");
        return;
    }
    eprintln!(
        "{} {} {}",
        "by s6stem".bright_black(),
        "·".bright_black(),
        format!("v{}", env!("CARGO_PKG_VERSION")).bright_magenta()
    );
    eprintln!(
        "{}",
        "zero persistence · anonymisation by design".bright_black()
    );
}

/// `INJEKT_BANNER_ART=list` : noms disponibles sur stderr, un par ligne.
fn list(arts: &[Art]) {
    eprintln!("Banner art (INJEKT_BANNER_ART=<name>|random):");
    for art in arts {
        let kind = if art.is_ansi() { "ansi" } else { "plain" };
        eprintln!("  {:<10} {kind}  {} lines", art.name, art.lines.len());
    }
}

/// Bannière de démarrage : rotation d'art + signature, toujours sur stderr
/// (stdout reste propre : JSON recon, rapports `--output`, JSON-RPC MCP).
pub fn print(seed: Option<u64>) {
    let arts = sections();
    let want_env = std::env::var("INJEKT_BANNER_ART").ok();
    let want = want_env.as_deref().map(str::trim).filter(|w| !w.is_empty());

    if want.is_some_and(|w| w.eq_ignore_ascii_case("list")) {
        list(arts);
        return;
    }

    let (index, warning) = pick(arts, want, seed);
    if let Some(warning) = warning {
        eprintln!("Warning: {warning}");
    }

    // Ligne d'aération : sépare la commande tapée du logo (et le tagline du
    // résultat qui suit, via le `eprintln!()` final). Tout l'espacement vit
    // ici, jamais dans `ascii_art.txt`.
    eprintln!();
    let colors = colors_for(Stream::Stderr);
    emit(&arts[index], colors);
    tagline(colors);
    eprintln!();
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const SAMPLE: &str = "AAA\nBBB\n\n---- alpha\nCCC\n════ beta\nDDD\n\n----\nEEE\ntrailing\n";

    #[test]
    fn parses_labeled_and_unnamed_sections() {
        let arts = parse_art(SAMPLE);
        assert_eq!(
            arts.len(),
            4,
            "sections: {:?}",
            arts.iter().map(|a| &a.name).collect::<Vec<_>>()
        );
        assert_eq!(arts[0].name, "alpha");
        assert_eq!(arts[0].lines, ["AAA", "BBB"]);
        assert_eq!(arts[1].name, "beta");
        assert_eq!(arts[1].lines, ["CCC"]);
        // `----` sans légende puis section finale acceptée sans séparateur.
        assert_eq!(arts[2].name, "art-3");
        assert_eq!(arts[2].lines, ["DDD"]);
        assert_eq!(arts[3].name, "art-4");
        assert_eq!(arts[3].lines, ["EEE", "trailing"]);
    }

    #[test]
    fn blank_source_yields_no_section() {
        assert!(parse_art("").is_empty());
        assert!(parse_art("\n\n--------\n\n").is_empty());
    }

    #[test]
    fn real_art_file_exposes_rotation() {
        let arts = sections();
        assert!(arts.len() >= 4, "{} arts found", arts.len());
        assert!(arts.iter().all(|a| !a.lines.is_empty()));
        assert!(arts.iter().all(|a| !a.name.is_empty()));
        // Le wordmark truecolor doit être détecté comme tel (pas re-coloré).
        assert!(arts.iter().any(Art::is_ansi));
    }

    #[test]
    fn pick_matches_names_case_insensitively() {
        let arts = parse_art(SAMPLE);
        assert_eq!(pick(&arts, Some("BETA"), None).0, 1);
        assert!(pick(&arts, Some("beta"), None).1.is_none());
        let (idx, warning) = pick(&arts, Some("missing"), None);
        assert!(idx < arts.len());
        assert!(warning.unwrap().contains("missing"));
        // `random` = rotation, jamais un nom.
        assert!(pick(&arts, Some("random"), None).1.is_none());
    }

    #[test]
    fn rotation_is_seed_deterministic() {
        let arts = parse_art(SAMPLE);
        for seed in [1, 7, 42] {
            let a = pick(&arts, None, Some(seed)).0;
            let b = pick(&arts, None, Some(seed)).0;
            assert_eq!(a, b, "seed {seed} must be deterministic");
        }
    }

    #[test]
    fn strip_ansi_keeps_glyphs() {
        assert_eq!(strip_ansi("\u{1b}[0;97;40m█\u{1b}[0m"), "█");
        assert_eq!(strip_ansi("plain"), "plain");
        assert_eq!(strip_ansi("\u{1b}]0;title\u{7}text"), "text");
        let ansi_art = sections().iter().find(|a| a.is_ansi()).expect("ansi art");
        let plain: Vec<String> = ansi_art.lines.iter().map(|l| strip_ansi(l)).collect();
        assert!(plain.iter().all(|l| !l.contains('\u{1b}')));
        assert!(plain.iter().any(|l| l.contains('█')));
    }

    #[test]
    fn gradient_spans_cyan_to_magenta() {
        assert_eq!(row_color(0, 3), (34, 211, 238));
        assert_eq!(row_color(2, 3), (232, 121, 249));
        // Une seule ligne (ou zéro) : couleur de départ, jamais de division nulle.
        assert_eq!(row_color(0, 1), (34, 211, 238));
        assert_eq!(row_color(0, 0), (34, 211, 238));
    }
}
