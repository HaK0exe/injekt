#![deny(unsafe_code)]

//! Couleurs de l'aide CLI (`--help` / `-h` / erreurs clap).
//!
//! Palette calée sur l'identité du banner ([`crate::cli::output::console::banner`] :
//! wordmark cyan, version magenta) : en-têtes de sections cyan gras, flags et
//! sous-commandes vert gras, placeholders (`<TARGET>`, `<PROFILE>`) magenta,
//! erreurs rouge vif. Propagée aux sous-commandes par clap
//! (`Command::styles` : "propagated to all child subcommands", donc un seul
//! point de réglage sur [`crate::cli::args::Cli`]).
//!
//! Respecte `NO_COLOR` / `TERM=dumb` / `CLICOLOR=0` / sortie pipée : c'est
//! `anstream` (feature `color` de clap) qui coupe les séquences ANSI, pas ce
//! module — aucun test golden n'est impacté (`tests/golden/cli-flags.txt` ne
//! collecte que les noms de flags).

use clap::builder::styling::{AnsiColor, Styles};

/// Palette vive pour toute l'aide clap (courte, longue, erreurs).
pub const CLI_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Cyan.on_default().bold())
    .usage(AnsiColor::BrightCyan.on_default().bold())
    .literal(AnsiColor::Green.on_default().bold())
    .placeholder(AnsiColor::Magenta.on_default())
    .error(AnsiColor::BrightRed.on_default().bold())
    .valid(AnsiColor::Green.on_default())
    .invalid(AnsiColor::Yellow.on_default());
