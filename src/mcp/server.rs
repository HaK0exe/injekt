#![deny(unsafe_code)]

use crate::mcp::tools::InjektServer;
use anyhow::Result;
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::{EnvFilter, fmt};

/// Run the MCP server over stdio transport.
///
/// tracing goes to stderr only: stdout is the MCP JSON-RPC transport and any
/// stray write there would corrupt the protocol.
///
/// # Errors
/// Returns an error if the stdio transport fails to start or the service loop errors.
pub async fn run_mcp() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let service = InjektServer::new().serve(stdio()).await?;
    service.waiting().await?;

    Ok(())
}
