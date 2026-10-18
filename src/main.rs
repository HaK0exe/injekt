#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::todo)]

use clap::Parser as _;
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
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let usage = e.chain().any(|c| {
                matches!(
                    c.downcast_ref::<injekt::error::InjektError>(),
                    Some(injekt::error::InjektError::NoTarget)
                )
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

async fn run() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    // C14 : capture de l'argv original (nom du binaire exclu) pour le patch
    // de suggestion `INCONCLUSIVE`. `args_os` + `to_string_lossy` (aucun
    // panique possible : un argv non-UTF8 échoue déjà dans `Cli::parse`) ;
    // RAM-only — remonté dans `EngineConfig::argv` (`Zeroizing`, Debug
    // masqué), aucune persistance.
    cli.captured_argv = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if matches!(cli.command, Some(Commands::Mcp(_))) {
        return injekt::mcp::server::run_mcp().await;
    }
    let filter = if cli.verbose { "debug" } else { "info" };
    fmt()
        .event_format(injekt::cli::output::console::SqlmapStyle)
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .init();
    if !cli.no_banner {
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
    dispatch(cli, cancel).await
}
