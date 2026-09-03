#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::todo)]

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

    // MCP mode branches off before any stdout tracing is installed:
    // on stdio transport, stdout is the JSON-RPC channel.
    if matches!(cli.command, Some(Commands::Mcp(_))) {
        return injekt::mcp::server::run_mcp().await;
    }

    let filter = if cli.verbose { "debug" } else { "info" };
    fmt()
        .event_format(injekt::cli::output::console::SqlmapStyle)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .init();

    if !cli.no_banner {
        injekt::cli::output::console::banner();
    }

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
        Some(Commands::Recon(_)) => {
            commands::recon::run(cli, cancel).await?;
        }
        Some(Commands::Replay(_)) => {
            commands::replay::run(cli)?;
        }
        Some(Commands::Info(_)) => {
            commands::info::run();
        }
        // `Mcp` is handled before tracing init above (stdout must stay pure
        // JSON-RPC); no second branch here.
        Some(_) => {
            eprintln!("Unknown command");
            std::process::exit(2);
        }
        None => {
            if cli.bulk_file.is_some() || cli.effective_target().is_some() {
                commands::scan::run(cli, cancel).await?;
            } else {
                eprintln!("No target provided. Use --target <URL> or `injekt scan --target <URL>`");
                std::process::exit(2);
            }
        }
    }

    Ok(())
}
