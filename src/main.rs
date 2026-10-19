#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::todo)]

use clap::{CommandFactory, FromArgMatches};
use injekt::cli::{
    args::{Cli, Commands},
    commands::dispatch,
};
use std::process::ExitCode;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        // Un chemin peut désormais porter un code d'exit dédié (C15 :
        // `doctor` → 0 sans `✗`, 1 avec `✗` ; C16 : erreur d'usage
        // `NoTarget`/`TargetConflict` → 2) ; les autres restent `()`.
        Ok(code) => code,
        Err(e) => {
            let usage = e.chain().any(|c| {
                c.downcast_ref::<injekt::error::InjektError>()
                    .is_some_and(|e| {
                        matches!(
                            e,
                            injekt::error::InjektError::NoTarget
                                | injekt::error::InjektError::TargetConflict { .. }
                        )
                    })
            });
            eprintln!("Error: {e:#}");
            if usage {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

/// C16 — `-u/--target` **tapé** sur la ligne de commande, pour distinguer
/// l'env `INJEKT_TARGET` (les deux parse dans `TargetOpts::target`). clap
/// expose la source du root arg au niveau top-level quelle que soit la
/// profondeur (flag tapé après une sous-commande aussi), donc la
/// vérification top-level suffit. `None`/`EnvVariable`/défaut ⇒ `false`.
fn cli_typed_target(matches: &clap::ArgMatches) -> bool {
    matches
        .value_source("target")
        .is_some_and(|s| matches!(s, clap::parser::ValueSource::CommandLine))
}

async fn run() -> anyhow::Result<ExitCode> {
    // C16 : parse via matches (`Cli::command().get_matches_from` +
    // `from_arg_matches`) — même comportement d'erreur que `Cli::parse`
    // (clap sort lui-même : usage 2, help/version 0) mais permet de
    // distinguer `-u/--target` tapé de l'env (`cli_typed_target`).
    let matches = Cli::command().get_matches_from(std::env::args_os());
    let mut cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };
    cli.cli_typed_target = cli_typed_target(&matches);
    // C14 : capture de l'argv original (nom du binaire exclu) pour le patch
    // de suggestion `INCONCLUSIVE`. `args_os` + `to_string_lossy` (aucun
    // panique possible : un argv non-UTF8 échoue déjà dans `Cli::parse`) ;
    // RAM-only — remonté dans `EngineConfig::argv` (`Zeroizing`, Debug
    // masqué), aucune persistance.
    cli.captured_argv = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if matches!(cli.command, Some(Commands::Doctor(_))) {
        // C15 : `doctor` = stdout pur (aucune ligne tracing, pas de banner)
        // — early-branch avant l'init tracing, comme le serveur MCP.
        return injekt::cli::commands::doctor::run(&cli).await;
    }
    if matches!(cli.command, Some(Commands::Mcp(_))) {
        return injekt::mcp::server::run_mcp()
            .await
            .map(|()| ExitCode::SUCCESS);
    }
    let filter = if cli.quiet {
        "warn"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };
    fmt()
        .event_format(injekt::cli::output::console::SqlmapStyle)
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .init();
    if !cli.no_banner && !cli.quiet {
        injekt::cli::output::banner::print(cli.detection.seed);
    }
    let cancel = CancellationToken::new();
    let c = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::warn!("Ctrl+C received — graceful shutdown");
            c.cancel();
        }
    });
    dispatch(cli, cancel).await.map(|()| ExitCode::SUCCESS)
}
