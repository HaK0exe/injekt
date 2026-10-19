#![deny(unsafe_code)]

//! Palette & gating couleur — source de vérité unique pour toute la sortie
//! terminal (stdout résultats, stderr logs).
//!
//! ## Gating (convention repo)
//!
//! Couleurs désactivées quand `NO_COLOR` est présent (toute valeur),
//! `TERM=dumb`, `CLICOLOR=0`, ou quand le stream visé n'est pas un TTY
//! (pipe/CI/MCP). `CLICOLOR_FORCE` non vide et ≠ `0` force la couleur même
//! pipé (golden tests colorés, captures CI) — prioritaire sur `NO_COLOR`
//! (convention `CLICOLOR_FORCE`).
//!
//! ## [`Theme`]
//!
//! Construit une fois par point de sortie ([`Theme::for_stdout`] /
//! [`Theme::for_stderr`]), puis chaque site d'appel remplace son
//! `if color { … } else { … }` par un appel stylé (`theme.bold(…)`,
//! `theme.icon_ok()`, …) : la branche plain/colorée vit ici, plus nulle part.
//! Les logs et les résultats sont testés **séparément** (clig.dev : stdout
//! pipé vers un consommateur n'empêche pas des logs stderr colorés).

use std::fmt::Display;
use std::io::IsTerminal as _;

use owo_colors::OwoColorize as _;

/// Icônes partagées (Unicode single-codepoint, largeur 1 sauf `⛏`).
pub mod icon {
    /// Succès / check OK (doctor, "No findings").
    pub const OK: &str = "✓";
    /// Avertissement (doctor, résumé bulk à findings).
    pub const WARN: &str = "!";
    /// Échec (doctor).
    pub const ERR: &str = "✗";
    /// Findings (bullets de sévérité).
    pub const DOT: &str = "●";
    /// En-tête "findings found".
    pub const ALERT: &str = "⚠";
    /// En-tête "Scan complete".
    pub const DIAMOND: &str = "◆";
    /// Données extraites (`--dump`/`--banner`/…).
    pub const PICK: &str = "⛏";
    /// Item de liste.
    pub const BULLET: &str = "•";
    /// En-tête bulk.
    pub const PLAY: &str = "▶";
}

/// Stream visé par le gating couleur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// Résultats (pipeables) — `--json`, tables, résumé.
    Stdout,
    /// Logs / progress bars / banner.
    Stderr,
}

/// `true` si les séquences ANSI sont admises sur `stream`.
#[must_use]
pub fn colors_for(stream: Stream) -> bool {
    // CLICOLOR_FORCE non vide ≠ "0" : force même pipé (prioritaire, convention
    // CLICOLOR_FORCE) — c'est la porte d'entrée des tests golden colorés.
    if std::env::var("CLICOLOR_FORCE").is_ok_and(|force| !force.is_empty() && force != "0") {
        return true;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var("TERM").is_ok_and(|v| v == "dumb") {
        return false;
    }
    if std::env::var("CLICOLOR").is_ok_and(|v| v == "0") {
        return false;
    }
    match stream {
        Stream::Stdout => std::io::stdout().is_terminal(),
        Stream::Stderr => std::io::stderr().is_terminal(),
    }
}

/// Palette stylée : chaque méthode rend le texte coloré quand actif, brut sinon.
///
/// Une instance par point de sortie (le gating stdout et stderr peuvent
/// différer quand stdout est pipé). Coût : une allocation `String` par appel —
/// négligeable pour une sortie CLI, et c'est le prix d'une API sans branche
/// `if color` chez l'appelant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    color: bool,
}

impl Theme {
    /// Gating sur stdout (résultats).
    #[must_use]
    pub fn for_stdout() -> Self {
        Self::new(colors_for(Stream::Stdout))
    }

    /// Gating sur stderr (logs, banner).
    #[must_use]
    pub fn for_stderr() -> Self {
        Self::new(colors_for(Stream::Stderr))
    }

    /// Gating explicite (tests, cas forcé).
    #[must_use]
    pub fn new(color: bool) -> Self {
        Self { color }
    }

    /// Gating effectif de cette instance.
    #[must_use]
    pub fn color(&self) -> bool {
        self.color
    }

    // -- styles texte --------------------------------------------------------

    /// Vert (succès).
    #[must_use]
    pub fn ok(&self, text: impl Display) -> String {
        self.paint(text, |s| format!("{}", s.green()))
    }

    /// Vert gras.
    #[must_use]
    pub fn ok_bold(&self, text: impl Display) -> String {
        self.paint(text, |s| format!("{}", s.green().bold()))
    }

    /// Jaune (avertissement).
    #[must_use]
    pub fn warning(&self, text: impl Display) -> String {
        self.paint(text, |s| format!("{}", s.yellow()))
    }

    /// Jaune gras.
    #[must_use]
    pub fn warning_bold(&self, text: impl Display) -> String {
        self.paint(text, |s| format!("{}", s.yellow().bold()))
    }

    /// Rouge (danger).
    #[must_use]
    pub fn danger(&self, text: impl Display) -> String {
        self.paint(text, |s| format!("{}", s.red()))
    }

    /// Rouge gras.
    #[must_use]
    pub fn danger_bold(&self, text: impl Display) -> String {
        self.paint(text, |s| format!("{}", s.red().bold()))
    }

    /// Cyan gras (accents : paramètre, suggestion).
    #[must_use]
    pub fn accent(&self, text: impl Display) -> String {
        self.paint(text, |s| format!("{}", s.cyan().bold()))
    }

    /// Bright cyan gras (titres doctor, labels `info`).
    #[must_use]
    pub fn accent_bright(&self, text: impl Display) -> String {
        self.paint(text, |s| format!("{}", s.bright_cyan().bold()))
    }

    /// Atténué (evidence, crochets de stats, clés kv).
    #[must_use]
    pub fn dim(&self, text: impl Display) -> String {
        self.paint(text, |s| format!("{}", s.dimmed()))
    }

    /// Gris (timestamps logs, tagline).
    #[must_use]
    pub fn gray(&self, text: impl Display) -> String {
        self.paint(text, |s| format!("{}", s.bright_black()))
    }

    /// Gras.
    #[must_use]
    pub fn bold(&self, text: impl Display) -> String {
        self.paint(text, |s| format!("{}", s.bold()))
    }

    /// Bright white (tableau findings).
    #[must_use]
    pub fn white(&self, text: impl Display) -> String {
        self.paint(text, |s| format!("{}", s.bright_white()))
    }

    /// Identité — symétrie d'appel quand un site conditionne uniquement le style.
    #[must_use]
    pub fn plain(&self, text: impl Display) -> String {
        text.to_string()
    }

    // -- icônes stylées ------------------------------------------------------

    /// `✓` vert gras.
    #[must_use]
    pub fn icon_ok(&self) -> String {
        self.ok_bold(icon::OK)
    }

    /// `!` jaune gras.
    #[must_use]
    pub fn icon_warn(&self) -> String {
        self.warning_bold(icon::WARN)
    }

    /// `✗` rouge gras.
    #[must_use]
    pub fn icon_err(&self) -> String {
        self.danger_bold(icon::ERR)
    }

    /// `⚠` rouge gras.
    #[must_use]
    pub fn icon_alert(&self) -> String {
        self.danger_bold(icon::ALERT)
    }

    /// `●` rouge (finding HIGH).
    #[must_use]
    pub fn dot_high(&self) -> String {
        self.danger(icon::DOT)
    }

    /// `●` jaune (finding MEDIUM).
    #[must_use]
    pub fn dot_medium(&self) -> String {
        self.warning(icon::DOT)
    }

    /// `●` atténué (finding LOW).
    #[must_use]
    pub fn dot_low(&self) -> String {
        self.dim(icon::DOT)
    }

    /// `◆` bright cyan gras (en-tête résumé).
    #[must_use]
    pub fn icon_diamond(&self) -> String {
        self.paint(icon::DIAMOND, |s| format!("{}", s.bright_cyan().bold()))
    }

    /// `⛏` bright green gras (données extraites).
    #[must_use]
    pub fn icon_pick(&self) -> String {
        self.paint(icon::PICK, |s| format!("{}", s.bright_green().bold()))
    }

    /// `•` bright green (item extrait).
    #[must_use]
    pub fn icon_bullet(&self) -> String {
        self.paint(icon::BULLET, |s| format!("{}", s.bright_green()))
    }

    // -- compositions --------------------------------------------------------

    /// Ligne clé-valeur indentée : `  Key: value` (clé atténuée, deux-points
    /// dans les deux rendus — contrat grep-able, cf. `suggestion_line`).
    #[must_use]
    pub fn kv(&self, key: &str, value: impl Display) -> String {
        format!("  {}: {value}", self.dim(key))
    }

    /// Statut de run coloré : `CLEAN` vert, `CANCELLED`/`INCONCLUSIVE` jaune,
    /// `FINDINGS` rouge (mapping [`crate::reporting::console::run_status`]).
    #[must_use]
    pub fn status_pill(&self, status: &str) -> String {
        match status {
            "CANCELLED" | "INCONCLUSIVE" => self.warning_bold(status),
            "CLEAN" => self.ok_bold(status),
            _ => self.danger_bold(status),
        }
    }

    // -- interne -------------------------------------------------------------

    fn paint(self, text: impl Display, styled: impl FnOnce(String) -> String) -> String {
        if self.color {
            styled(text.to_string())
        } else {
            text.to_string()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn plain_theme_strips_all_ansi() {
        let t = Theme::new(false);
        assert_eq!(t.ok("x"), "x");
        assert_eq!(t.bold("x"), "x");
        assert_eq!(t.icon_ok(), icon::OK);
        assert_eq!(t.icon_err(), icon::ERR);
        assert_eq!(t.dot_high(), icon::DOT);
        assert_eq!(t.kv("Key", 42), "  Key: 42");
        assert_eq!(t.status_pill("CLEAN"), "CLEAN");
        assert_eq!(t.plain("x"), "x");
    }

    #[test]
    fn colored_theme_emits_ansi() {
        let t = Theme::new(true);
        assert!(t.ok("x").contains('\u{1b}'));
        assert!(t.bold("x").contains('\u{1b}'));
        assert!(t.icon_ok().contains('\u{1b}'));
        assert!(t.status_pill("CLEAN").contains('\u{1b}'));
        // kv garde la clé stylée mais la valeur brute.
        assert!(t.kv("Key", 42).contains("42"));
    }

    #[test]
    fn status_pill_mapping_matches_run_status() {
        let plain = Theme::new(false);
        assert_eq!(plain.status_pill("FINDINGS"), "FINDINGS");
        assert_eq!(plain.status_pill("CANCELLED"), "CANCELLED");
        assert_eq!(plain.status_pill("INCONCLUSIVE"), "INCONCLUSIVE");
        assert_eq!(plain.status_pill("CLEAN"), "CLEAN");
    }
}
