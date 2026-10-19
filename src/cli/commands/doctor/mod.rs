#![deny(unsafe_code)]

//! C15 — `injekt doctor` : santé de la config **LOCALE** — jamais la cible,
//! jamais le réseau (OPSEC : 0 socket TCP, 0 fetch). Chaque check est une
//! fonction pure `fn check_*(…) -> CheckResult` (`level` + une seule ligne)
//! testée sans réseau ; les valeurs viennent des résolutions existantes
//! (`Cli::effective_*_with`, precedence CLI > env > config > profil >
//! défauts — logique jamais dupliquée) et des métadonnées fichier (existe +
//! lisible via `fs::metadata`, pas de read complet).
//!
//! Wiring : early-branch dans `main` AVANT l'init tracing et le banner
//! (stdout pur, pas de `SqlMapStyle`) — miroir du serveur MCP.
//!
//! Différence volontaire vs runtime : un `./injekt.toml` cassé est
//! silencieusement ignoré par `file_config::load` (warn + défauts) — le
//! doctor le remonte en `Fail` : tuer la classe d'erreurs de config
//! silencieuse est sa raison d'être.

use crate::cli::args::Cli;
use crate::cli::output::theme::Theme;
use crate::session::scrubber::Scrubber;
use std::process::ExitCode;

pub use self::cadence::{check_cadence, parse_jitter_pair};
pub use self::config::{ConfigResolution, check_config};
pub use self::ingest::{SourceItem, SourceState, check_ingestion, collect_ingestion_sources};
pub use self::proxy::check_proxy;
mod cadence;
mod config;
mod ingest;
mod proxy;
use self::config::resolve_config;

// ---------------------------------------------------------------------------
// Types de sortie
// ---------------------------------------------------------------------------

/// Verdict d'un check : `Ok` (vert), `Warn` (jaune, n'opère pas l'exit) ou
/// `Fail` (rouge — une seule variante bascule l'exit 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckLevel {
    Ok,
    Warn,
    Fail,
}

/// Un check = un niveau + une ligne unique, préfixée par son nom
/// (`config: …`, `proxy: …`, `cadence: …`, `ingestion: …`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CheckResult {
    pub level: CheckLevel,
    pub line: String,
}

impl CheckResult {
    #[must_use]
    pub fn ok<T: Into<String>>(line: T) -> Self {
        Self {
            level: CheckLevel::Ok,
            line: line.into(),
        }
    }

    #[must_use]
    pub fn warn<T: Into<String>>(line: T) -> Self {
        Self {
            level: CheckLevel::Warn,
            line: line.into(),
        }
    }

    #[must_use]
    pub fn fail<T: Into<String>>(line: T) -> Self {
        Self {
            level: CheckLevel::Fail,
            line: line.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Entrée : rendu stdout pur + exit code
// ---------------------------------------------------------------------------

/// Symbole `✓ / ! / ✗` ; couleur selon le gating stdout (`NO_COLOR`,
/// `TERM=dumb`, `CLICOLOR=0`, stdout non-TTY désactivent — la convention
/// repo, pas d'équivalent `INJEKT_NO_COLOR` inventé).
pub(super) fn symbol(level: CheckLevel, colors: bool) -> String {
    let t = Theme::new(colors);
    match level {
        CheckLevel::Ok => t.icon_ok(),
        CheckLevel::Warn => t.icon_warn(),
        CheckLevel::Fail => t.icon_err(),
    }
}

/// Run des 4 checks (config locale only) — rendu `✓/!/✗` une ligne par
/// check, puis `ExitCode` : 0 sans `✗`, 1 avec (mapping `main`, comme
/// `NoTarget` → 2 pour l'usage). Toute sortie passe par le `Scrubber`
/// (mêmes règles que le reste du CLI ; `--no-redact` respecté comme
/// ailleurs — les lignes doctor n'écho jamais un proxy brut en premier
/// lieu : userinfo déjà redirigé côté `check_proxy`).
///
/// Aucune requête réseau, aucun fetch, aucune écriture disque ; le seul IO
/// est la lecture du TOML et les `metadata` de sources ingestion.
///
/// # Errors
/// Jamais en pratique aujourd'hui (les échecs IO sont convertis en `Fail`
/// dans les checks) — la signature `Result` permet le wiring early-branch
/// identique à `mcp::server::run_mcp` dans `main`.
#[allow(clippy::unused_async)] // cohérence du wiring early-branch (await) dans main
pub async fn run(cli: &Cli) -> anyhow::Result<ExitCode> {
    let snap = cli.resolve_snapshot();

    let config = check_config(
        &resolve_config(cli.config.as_deref()),
        snap.profile,
        cli.effective_threads_with(&snap),
    );
    let proxy = check_proxy(cli.effective_proxy_with(&snap).as_deref());
    // Explicitité : CLI/env (clap remplit les champs) ou clé du TOML — la
    // precedence effective est celle des helpers `*_with(&snap)`, jamais
    // ré-implémentée ici.
    let cadence = check_cadence(
        cli.effective_rate_limit_with(&snap),
        cli.http.rate_limit.is_some() || snap.file.rate_limit.is_some(),
        &cli.effective_jitter_with(&snap),
        cli.http.jitter.is_some() || snap.file.jitter.is_some(),
        snap.profile,
    );
    let ingestion = check_ingestion(&collect_ingestion_sources(cli));

    let checks = [config, proxy, cadence, ingestion];
    let theme = Theme::for_stdout();
    let scrubber = Scrubber::new(cli.output_opts.no_redact);

    let title = "injekt doctor — vérifications de la config locale (0 requête, 0 socket)";
    println!("{}", theme.accent_bright(title));
    for c in &checks {
        println!(
            "{} {}",
            symbol(c.level, theme.color()),
            scrubber.scrub(&c.line)
        );
    }

    let failed = checks.iter().any(|c| c.level == CheckLevel::Fail);
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests;
