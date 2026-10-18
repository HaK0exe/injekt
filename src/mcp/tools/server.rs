use rmcp::{
    ServerHandler,
    model::{Implementation, ServerCapabilities, ServerConfig},
    tool_handler,
};

#[derive(Debug, Clone)]
pub struct InjektServer {
    pub(super) cancel: tokio_util::sync::CancellationToken,
}

impl Default for InjektServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_handler]
// `#[tool_handler]` (rmcp) generates async trait methods regardless of whether
// each one awaits; signature isn't ours to change.
#[allow(clippy::unused_async_trait_impl)]
impl ServerHandler for InjektServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "injekt",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "injekt MCP server — SQL injection detection tools. \
                 Only use scan / recon_crawl / recon_scan against systems you are authorized to test. \
                 All tools return structured JSON.",
            )
    }
}
