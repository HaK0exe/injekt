#![deny(unsafe_code)]
pub mod auto;
pub mod bulk;
pub mod common;
pub mod info;
pub mod recon;
pub mod replay;
pub mod scaffold;
pub mod scan;

use crate::cli::args::{Cli, Commands};
use tokio_util::sync::CancellationToken;

/// Unified command dispatch (P3): exhaustive match, no `dyn`.
/// `Mcp` is normally branched before tracing in `main` (stdout JSON-RPC
/// pur); the arm below is a defensive fallback for direct callers.
///
/// # Errors
/// Returns an error when the selected subcommand fails.
pub async fn dispatch(cli: Cli, cancel: CancellationToken) -> anyhow::Result<()> {
    match &cli.command {
        Some(Commands::Scan(args)) => {
            common::warn_scan_explicit();
            scan::run(&cli, args, cancel).await
        }
        Some(Commands::Auto(args)) => auto::run(&cli, args, cancel).await,
        Some(Commands::Init(args)) => {
            let force = cli.output_opts.force;
            scaffold::run_init(args, force)
        }
        Some(Commands::Completions(args)) => scaffold::run_completions(&cli, args),
        Some(Commands::Man(_)) => {
            scaffold::run_man();
            Ok(())
        }
        Some(Commands::Recon(args)) => recon::run(&cli, args, cancel).await,
        Some(Commands::Replay(args)) => replay::run(args, &cli.output_opts),
        Some(Commands::Info(_)) => {
            info::run();
            Ok(())
        }
        Some(Commands::Mcp(_)) => crate::mcp::server::run_mcp().await,
        None => fallback_bare_or_auto(&cli, cancel).await,
    }
}

/// Bare-mode fallback (no subcommand): bulk sources, explicit target or
/// `--dry-run` reuse the `scan` pipeline; otherwise return [`crate::error::InjektError::NoTarget`]
/// (mapped to exit code 2 by `main`, no network touched). Bulk stays
/// auto-detected, never a subcommand.
///
/// # Errors
/// Returns an error when the scan pipeline fails, or when no target was
/// provided (`NoTarget` usage error).
pub async fn fallback_bare_or_auto(cli: &Cli, cancel: CancellationToken) -> anyhow::Result<()> {
    if common::is_bulk(cli) || cli.effective_target().is_some() || cli.output_opts.dry_run {
        let args = crate::cli::args::ScanArgs { target: None };
        scan::run(cli, &args, cancel).await
    } else {
        Err(crate::error::InjektError::NoTarget.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[tokio::test]
    async fn bare_without_target_returns_notarget_usage_error() {
        // No `process::exit(2)`: library returns a typed error, `main`
        // maps it to exit code 2.
        let cli = Cli::try_parse_from(["injekt"]).expect("parse bare cli");
        let err = fallback_bare_or_auto(&cli, CancellationToken::new())
            .await
            .expect_err("must err without target");
        let is_usage = err.chain().any(|c| {
            matches!(
                c.downcast_ref::<crate::error::InjektError>(),
                Some(crate::error::InjektError::NoTarget)
            )
        });
        assert!(is_usage, "expected NoTarget, got {err:#}");
    }
}
