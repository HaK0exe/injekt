#![deny(unsafe_code)]
#![allow(clippy::pedantic)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use clap::Parser as _;
use injekt::cli::{
    args::{Cli, Commands},
    commands,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose { "debug" } else { "info" };
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .init();

    let cancel = CancellationToken::new();
    let c = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::warn!("Ctrl+C received — graceful shutdown");
            c.cancel();
        }
    });

    match &cli.command {
        Some(Commands::Scan(_)) => {
            commands::scan::run(cli, cancel).await?;
        }
        Some(Commands::Replay(_)) => {
            commands::replay::run(cli).await?;
        }
        Some(Commands::Info(_)) => {
            commands::info::run();
        }
        Some(_) => {
            eprintln!("Unknown command");
            std::process::exit(2);
        }
        None => {
            if cli.effective_target().is_some() {
                commands::scan::run(cli, cancel).await?;
            } else {
                eprintln!("No target provided. Use --target <URL> or `injekt scan --target <URL>`");
                std::process::exit(2);
            }
        }
    }

    Ok(())
}
