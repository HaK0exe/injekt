#![deny(unsafe_code)]

//! Progress bars & vue pipeline (stderr, indicatif) — construction partagée
//! pour toute la sortie live.
//!
//! ## Contrat TTY / OPSEC
//!
//! Tout est **hidden** quand stderr n'est pas un TTY (MCP stdio, pipes, CI) :
//! stdout JSON-RPC reste propre, zéro spam, zéro steady-tick CPU. Les
//! templates colorés suivent le même gating que les logs
//! ([`crate::cli::output::theme::colors_for`]) et `--quiet` coupe tout.
//!
//! ## [`PipelineView`]
//!
//! Vue cargo-style du pipeline : chaque phase terminée laisse une ligne
//! `✓ label · résumé` empilée ([`PipelineView::done_phase`]), la barre de
//! détection se greffe dessous ([`PipelineView::attach`]) pendant qu'elle
//! vit. Les spinners transitoires (baseline, context) restent locaux aux
//! phases et s'effacent (`finish_and_clear`) — ils n'empilent rien.

use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};

use super::theme::{colors_for, Stream};

/// Refresh rate plafonné : les redraws indicatif coûtent du CPU et brassent
/// le terminal (OPSEC : moins de churn visuel) — 8 Hz reste fluide.
const DRAW_HZ: u8 = 8;

/// Barre de progression partagée (detection, recon bulk) : spinner + barre +
/// compteur + elapsed + ETA + message. Hidden hors TTY.
#[must_use]
pub fn bar(len: u64, msg: &str) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let color = colors_for(Stream::Stderr);
    let template = if color {
        "{spinner:.cyan} {bar:40.cyan/blue} {pos}/{len} {elapsed} eta {eta} {msg}"
    } else {
        "{spinner} {bar:40} {pos}/{len} {elapsed} eta {eta} {msg}"
    };
    let pb = ProgressBar::with_draw_target(len, ProgressDrawTarget::stderr_with_hz(DRAW_HZ));
    pb.set_style(
        ProgressStyle::with_template(template)
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("━╸─"),
    );
    pb.set_message(msg.to_owned());
    pb
}

/// Spinner transitoire de phase (baseline) : `{spinner} {msg} {elapsed}`.
/// Hidden hors TTY. La phase appelle `finish_and_clear()` à la fin.
#[must_use]
pub fn spinner(msg: &str) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let color = colors_for(Stream::Stderr);
    let template = if color {
        "{spinner:.cyan} {msg} {elapsed:.3}s"
    } else {
        "{spinner} {msg} {elapsed:.3}s"
    };
    let pb = ProgressBar::with_draw_target(0, ProgressDrawTarget::stderr_with_hz(DRAW_HZ));
    pb.set_style(
        ProgressStyle::with_template(template).unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    pb.set_message(msg.to_owned());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Vue pipeline : lignes `✓ phase · résumé` empilées + greffe de la barre
/// de détection. Une instance par run, créée dans `run_internal`.
///
/// `enabled = false` (stderr non-TTY ou `--quiet`) : toutes les opérations
/// sont des no-op sur des barres hidden — le code appelant est identique.
#[derive(Debug, Clone)]
pub struct PipelineView {
    multi: MultiProgress,
    enabled: bool,
}

impl PipelineView {
    /// Vue active si stderr est un TTY et que `quiet` est faux.
    #[must_use]
    pub fn new(quiet: bool) -> Self {
        Self {
            multi: MultiProgress::new(),
            enabled: !quiet && std::io::stderr().is_terminal(),
        }
    }

    /// Vue tout-hidden (tests, MCP).
    #[must_use]
    pub fn hidden() -> Self {
        Self {
            multi: MultiProgress::new(),
            enabled: false,
        }
    }

    /// Laisse une ligne persistante `✓ label · summary` (phase terminée).
    pub fn done_phase(&self, label: &str, summary: &str) {
        if !self.enabled {
            return;
        }
        let t = super::theme::Theme::for_stderr();
        let rendered = format!(
            "{} {}",
            t.ok_bold(format!("✓ {label}")),
            t.dim(format!("· {summary}"))
        );
        let pb = self.multi.add(ProgressBar::with_draw_target(
            1,
            ProgressDrawTarget::stderr_with_hz(DRAW_HZ),
        ));
        pb.set_style(
            ProgressStyle::with_template("{msg}").unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        pb.finish_with_message(rendered);
    }

    /// Ouvre une ligne de phase transitoire (spinner). `PhaseLine::clear()`
    /// l'efface à la fin de la phase.
    #[must_use]
    pub fn phase(&self, msg: &str) -> PhaseLine {
        if !self.enabled {
            return PhaseLine {
                pb: ProgressBar::hidden(),
            };
        }
        PhaseLine {
            pb: self.multi.add(spinner(msg)),
        }
    }

    /// Greffe une barre existante (detection) sous les lignes déjà posées.
    #[must_use]
    pub fn attach(&self, pb: ProgressBar) -> ProgressBar {
        if !self.enabled {
            return pb; // déjà hidden par son constructeur
        }
        self.multi.add(pb)
    }
}

/// Une ligne de phase transitoire ouverte par [`PipelineView::phase`].
pub struct PhaseLine {
    pb: ProgressBar,
}

impl PhaseLine {
    /// Efface la ligne (phase transitoire terminée, détail dans les logs).
    pub fn clear(&self) {
        self.pb.finish_and_clear();
    }

    /// Fige la ligne avec `✓ <summary>` (phase à garder visible).
    pub fn done(&self, summary: &str) {
        self.pb.finish_with_message(format!("✓ {summary}"));
    }

    /// Met à jour le message courant (phase en cours).
    pub fn set_message(&self, msg: &str) {
        self.pb.set_message(msg.to_owned());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn hidden_view_is_noop() {
        let view = PipelineView::hidden();
        view.done_phase("baseline", "3 · 1.2s"); // no-op, ne panique pas
        let line = view.phase("x");
        assert!(line.pb.is_hidden());
        line.clear();
        line.done("y");
        line.set_message("z");
        assert!(view.attach(bar(10, "x")).is_hidden());
    }

    #[test]
    fn quiet_view_is_hidden() {
        let view = PipelineView::new(true);
        view.done_phase("baseline", "x"); // no-op
        assert!(view.phase("x").pb.is_hidden());
    }

    #[test]
    fn builders_hidden_off_tty() {
        // Le harnais de test capture stderr (non-TTY) : contrat pipe/CI/MCP.
        // Avec `--nocapture` sur un vrai TTY, les barres sont réelles —
        // on n'affirme alors que la non-panique.
        if !std::io::stderr().is_terminal() {
            assert!(bar(10, "x").is_hidden());
            assert!(spinner("x").is_hidden());
        }
    }
}
