#![deny(unsafe_code)]

use crate::{
    cli::args::{Cli, Commands, ReconArgs, ReconCommands, ReconCrawlArgs, ReconScanArgs, ScanArgs},
    cli::commands::{info, recon, scan},
};
use rmcp::{
    ErrorData, ServerHandler,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct InjektServer {
    cancel: tokio_util::sync::CancellationToken,
}

impl Default for InjektServer {
    fn default() -> Self {
        Self::new()
    }
}

impl InjektServer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cancel: tokio_util::sync::CancellationToken::new(),
        }
    }

    /// Validate an MCP `output` path: relative-only, no parent traversal.
    /// MCP agents must not overwrite arbitrary files; absolute paths and
    /// `..` are rejected with `invalid_params`. Writes use 0o600 on Unix.
    fn validate_output_path(path: &str) -> Result<std::path::PathBuf, ErrorData> {
        use std::path::Component;
        let p = std::path::Path::new(path);
        if path.is_empty() {
            return Err(ErrorData::invalid_params("output path is empty", None));
        }
        if p.is_absolute() {
            return Err(ErrorData::invalid_params(
                "output must be a relative path (absolute paths rejected in MCP mode)",
                None,
            ));
        }
        if p.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(ErrorData::invalid_params(
                "output must not contain '..' (path traversal rejected)",
                None,
            ));
        }
        Ok(p.to_path_buf())
    }

    /// Opt-in disk write for MCP `output` param (already-scrubbed JSON).
    fn write_output_file(path: &std::path::Path, json: &str) -> Result<(), ErrorData> {
        use std::io::Write as _;
        tracing::warn!(
            path=%path.display(),
            "MCP output requested — opt-in disk write (sensitive report, 0o600)"
        );
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(path)
            .map_err(|e| ErrorData::internal_error(format!("output write failed: {e}"), None))?;
        file.write_all(json.as_bytes())
            .map_err(|e| ErrorData::internal_error(format!("output write failed: {e}"), None))?;
        file.write_all(b"\n")
            .map_err(|e| ErrorData::internal_error(format!("output write failed: {e}"), None))?;
        file.sync_all()
            .map_err(|e| ErrorData::internal_error(format!("output write failed: {e}"), None))?;
        Ok(())
    }

    fn warn_no_redact(no_redact: bool) {
        if no_redact {
            tracing::warn!(
                "no_redact=true in MCP mode — redaction disabled, output may contain secrets (local debugging only)"
            );
        }
    }

    /// Base CLI with safe defaults; each tool overrides the relevant fields.
    /// Note: `raw_file` / `marker` / `method` / `import` / `replay` are
    /// intentionally not exposed via MCP (see docs/MCP.md); Burp raw bodies
    /// and marker modes stay CLI-only to keep the stdio surface minimal.
    fn base_cli() -> Cli {
        Cli {
            command: None,
            target: None,
            bulk_file: None,
            method: None,
            headers: Vec::new(),
            cookies: None,
            proxy: None,
            threads: 5,
            timeout: 30,
            retries: 3,
            delay: 500,
            techniques: Vec::new(),
            params: Vec::new(),
            data: None,
            prefix: None,
            suffix: None,
            safe_chars: None,
            skip_urlencode: false,
            string: None,
            not_string: None,
            code: None,
            text_only: false,
            fetch_using: None,
            dbms: None,
            extract: false,
            dbs: false,
            tables: false,
            columns: false,
            dump: false,
            banner: false,
            current_user: false,
            current_db: false,
            hostname: false,
            db: None,
            table: None,
            column: None,
            start: None,
            stop: None,
            count: false,
            output: None,
            rate_limit: None,
            jitter: None,
            marker: None,
            oob_domain: None,
            oob_poll_url: None,
            oob_wait_secs: 5,
            tamper: Vec::new(),
            hpp: false,
            chunked: false,
            export_encrypted: None,
            import: None,
            no_redact: false,
            allow_private: false,
            raw_file: None,
            verbose: false,
            level: Some(1),
            confirm: false,
            ignore_codes: Vec::new(),
            no_banner: true,
        }
    }

    fn build_scan_cli(params: ScanParams) -> Cli {
        let mut cli = Self::base_cli();
        cli.command = Some(Commands::Scan(ScanArgs {
            target: Some(params.target),
        }));
        if let Some(v) = params.threads {
            cli.threads = v;
        }
        if let Some(v) = params.techniques {
            cli.techniques = v;
        }
        if let Some(v) = params.params {
            cli.params = v;
        }
        cli.data = params.data;
        cli.prefix = params.prefix;
        cli.suffix = params.suffix;
        cli.safe_chars = params.safe_chars;
        cli.skip_urlencode = params.skip_urlencode.unwrap_or(false);
        cli.string = params.string;
        cli.not_string = params.not_string;
        cli.code = params.code;
        cli.text_only = params.text_only.unwrap_or(false);
        cli.fetch_using = params.fetch_using;
        if let Some(v) = params.tamper {
            cli.tamper = v;
        }
        cli.proxy = params.proxy;
        cli.rate_limit = params.rate_limit;
        cli.jitter = params.jitter;
        if let Some(v) = params.headers {
            cli.headers = v;
        }
        cli.cookies = params.cookies;
        cli.dbms = params.dbms;
        cli.extract = params.extract.unwrap_or(false);
        cli.dbs = params.dbs.unwrap_or(false);
        cli.tables = params.tables.unwrap_or(false);
        cli.columns = params.columns.unwrap_or(false);
        cli.dump = params.dump.unwrap_or(false);
        cli.banner = params.banner.unwrap_or(false);
        cli.current_user = params.current_user.unwrap_or(false);
        cli.current_db = params.current_db.unwrap_or(false);
        cli.hostname = params.hostname.unwrap_or(false);
        cli.db = params.db;
        cli.table = params.table;
        cli.column = params.column;
        cli.start = params.start;
        cli.stop = params.stop;
        cli.count = params.count.unwrap_or(false);
        cli.output = params.output;
        cli.oob_domain = params.oob_domain;
        cli.oob_poll_url = params.oob_poll_url;
        if let Some(v) = params.oob_wait_secs {
            cli.oob_wait_secs = v;
        }
        cli.hpp = params.hpp.unwrap_or(false);
        cli.chunked = params.chunked.unwrap_or(false);
        cli.allow_private = params.allow_private.unwrap_or(false);
        cli.no_redact = params.no_redact.unwrap_or(false);
        cli
    }

    fn apply_common_network_opts(
        cli: &mut Cli,
        proxy: Option<String>,
        rate_limit: Option<f64>,
        jitter: Option<String>,
        headers: Option<Vec<String>>,
        cookies: Option<String>,
        allow_private: Option<bool>,
    ) {
        cli.proxy = proxy;
        cli.rate_limit = rate_limit;
        cli.jitter = jitter;
        if let Some(v) = headers {
            cli.headers = v;
        }
        cli.cookies = cookies;
        cli.allow_private = allow_private.unwrap_or(false);
    }

    fn build_recon_crawl(params: ReconCrawlParams) -> (Cli, ReconCrawlArgs) {
        let args = ReconCrawlArgs {
            target: params.target,
            depth: params.depth.unwrap_or(2),
            max_pages: params.max_pages.unwrap_or(100),
            include_subdomains: params.include_subdomains.unwrap_or(false),
            ignore_robots: params.ignore_robots.unwrap_or(false),
        };
        let mut cli = Self::base_cli();
        cli.command = Some(Commands::Recon(ReconArgs {
            command: ReconCommands::Crawl(args.clone()),
        }));
        if let Some(v) = params.threads {
            cli.threads = v;
        }
        Self::apply_common_network_opts(
            &mut cli,
            params.proxy,
            params.rate_limit,
            params.jitter,
            params.headers,
            params.cookies,
            params.allow_private,
        );
        (cli, args)
    }

    fn build_recon_scan(params: ReconScanParams) -> (Cli, ReconScanArgs) {
        let args = ReconScanArgs {
            crawl: ReconCrawlArgs {
                target: params.target,
                depth: params.depth.unwrap_or(2),
                max_pages: params.max_pages.unwrap_or(100),
                include_subdomains: params.include_subdomains.unwrap_or(false),
                ignore_robots: params.ignore_robots.unwrap_or(false),
            },
            auto_enumerate: params.auto_enumerate.unwrap_or(false),
        };
        let mut cli = Self::base_cli();
        cli.command = Some(Commands::Recon(ReconArgs {
            command: ReconCommands::Scan(args.clone()),
        }));
        if let Some(v) = params.threads {
            cli.threads = v;
        }
        if let Some(v) = params.techniques {
            cli.techniques = v;
        }
        if let Some(v) = params.params {
            cli.params = v;
        }
        cli.data = params.data;
        cli.prefix = params.prefix;
        cli.suffix = params.suffix;
        cli.safe_chars = params.safe_chars;
        cli.skip_urlencode = params.skip_urlencode.unwrap_or(false);
        cli.string = params.string;
        cli.not_string = params.not_string;
        cli.code = params.code;
        cli.text_only = params.text_only.unwrap_or(false);
        cli.fetch_using = params.fetch_using;
        if let Some(v) = params.tamper {
            cli.tamper = v;
        }
        cli.dbms = params.dbms;
        cli.extract = params.extract.unwrap_or(false);
        cli.dbs = params.dbs.unwrap_or(false);
        cli.tables = params.tables.unwrap_or(false);
        cli.columns = params.columns.unwrap_or(false);
        cli.dump = params.dump.unwrap_or(false);
        cli.banner = params.banner.unwrap_or(false);
        cli.current_user = params.current_user.unwrap_or(false);
        cli.current_db = params.current_db.unwrap_or(false);
        cli.hostname = params.hostname.unwrap_or(false);
        cli.db = params.db;
        cli.table = params.table;
        cli.column = params.column;
        cli.start = params.start;
        cli.stop = params.stop;
        cli.count = params.count.unwrap_or(false);
        cli.output = params.output;
        cli.oob_domain = params.oob_domain;
        cli.oob_poll_url = params.oob_poll_url;
        if let Some(v) = params.oob_wait_secs {
            cli.oob_wait_secs = v;
        }
        cli.hpp = params.hpp.unwrap_or(false);
        cli.chunked = params.chunked.unwrap_or(false);
        cli.no_redact = params.no_redact.unwrap_or(false);
        Self::apply_common_network_opts(
            &mut cli,
            params.proxy,
            params.rate_limit,
            params.jitter,
            params.headers,
            params.cookies,
            params.allow_private,
        );
        (cli, args)
    }
}

#[tool_router]
impl InjektServer {
    #[tool(
        description = "Scan a target URL for SQL injection vulnerabilities. Only use against systems you are authorized to test."
    )]
    async fn scan(
        &self,
        Parameters(params): Parameters<ScanParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // MCP mode never writes encrypted exports (no TTY for passphrase prompt).
        if params.export_encrypted.is_some() {
            return Err(ErrorData::invalid_params(
                "export_encrypted is not supported in MCP mode (no TTY for passphrase); scan results are returned inline as JSON",
                None,
            ));
        }
        let cli = Self::build_scan_cli(params);
        Self::warn_no_redact(cli.no_redact);
        // `run_scan` returns an already-scrubbed `JsonReport` (see
        // `cli::commands::scan`), so inline JSON never carries raw secrets.
        let result = scan::run_scan(&cli, self.cancel.clone())
            .await
            .map_err(|e| ErrorData::internal_error(format!("scan failed: {e}"), None))?;

        let json = serde_json::to_value(&result.report)
            .map_err(|e| ErrorData::internal_error(format!("serialization failed: {e}"), None))?;

        if let Some(out) = &cli.output {
            let path = Self::validate_output_path(out)?;
            let pretty = serde_json::to_string_pretty(&result.report).map_err(|e| {
                ErrorData::internal_error(format!("serialization failed: {e}"), None)
            })?;
            Self::write_output_file(&path, &pretty)?;
        }

        Ok(CallToolResult::success(vec![ContentBlock::json(json)?]))
    }

    #[tool(
        description = "Crawl a target to discover parameters without testing them. Only use against systems you are authorized to test."
    )]
    async fn recon_crawl(
        &self,
        Parameters(params): Parameters<ReconCrawlParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let (cli, args) = Self::build_recon_crawl(params);
        let result = recon::run_crawl(&cli, self.cancel.clone(), &args)
            .await
            .map_err(|e| ErrorData::internal_error(format!("recon crawl failed: {e}"), None))?;

        let json = serde_json::to_value(&result.report)
            .map_err(|e| ErrorData::internal_error(format!("serialization failed: {e}"), None))?;

        Ok(CallToolResult::success(vec![ContentBlock::json(json)?]))
    }

    #[tool(
        description = "Crawl a target and scan each discovered parameter for SQL injection. Only use against systems you are authorized to test."
    )]
    async fn recon_scan(
        &self,
        Parameters(params): Parameters<ReconScanParams>,
    ) -> Result<CallToolResult, ErrorData> {
        if params.export_encrypted.is_some() {
            return Err(ErrorData::invalid_params(
                "export_encrypted is not supported in MCP mode (no TTY for passphrase); results are returned inline as JSON",
                None,
            ));
        }
        let (cli, args) = Self::build_recon_scan(params);
        Self::warn_no_redact(cli.no_redact);
        let result = recon::run_scan(&cli, self.cancel.clone(), &args)
            .await
            .map_err(|e| ErrorData::internal_error(format!("recon scan failed: {e}"), None))?;

        let json = serde_json::to_value(&result)
            .map_err(|e| ErrorData::internal_error(format!("serialization failed: {e}"), None))?;

        if let Some(out) = &cli.output {
            let path = Self::validate_output_path(out)?;
            let pretty = serde_json::to_string_pretty(&result).map_err(|e| {
                ErrorData::internal_error(format!("serialization failed: {e}"), None)
            })?;
            Self::write_output_file(&path, &pretty)?;
        }

        Ok(CallToolResult::success(vec![ContentBlock::json(json)?]))
    }

    #[tool(
        description = "Get information about injekt capabilities, techniques, tampers and supported databases."
    )]
    async fn info(
        &self,
        Parameters(InfoParams {}): Parameters<InfoParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = info::info();
        let json = serde_json::to_value(&result)
            .map_err(|e| ErrorData::internal_error(format!("serialization failed: {e}"), None))?;

        Ok(CallToolResult::success(vec![ContentBlock::json(json)?]))
    }
}

#[tool_handler]
// `#[tool_handler]` (rmcp) generates async trait methods regardless of whether
// each one awaits; signature isn't ours to change.
#[allow(clippy::unused_async_trait_impl)]
impl ServerHandler for InjektServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
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

/// Parameters for the scan tool (mirrors the CLI flags).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ScanParams {
    /// Target URL to scan (e.g. <https://example.com/?id=1>)
    pub target: String,
    /// Number of concurrent threads (default: 5)
    pub threads: Option<usize>,
    /// Techniques to use: boolean, time, error, union, stacked, oob, all (default: all)
    pub techniques: Option<Vec<String>>,
    /// Test only these parameters (e.g. `["id"]` or `["body:user"]`)
    pub params: Option<Vec<String>>,
    /// POST body to test (e.g. "id=1&user=admin")
    pub data: Option<String>,
    /// Payload prefix prepended after tampers (e.g. "')")
    pub prefix: Option<String>,
    /// Payload suffix appended after tampers (e.g. "-- -")
    pub suffix: Option<String>,
    /// Extra chars exempted from percent-encoding (e.g. "(),")
    pub safe_chars: Option<String>,
    /// Send payloads without URL-encoding (use with care)
    pub skip_urlencode: Option<bool>,
    /// Response body must contain this substring, otherwise veto finding
    pub string: Option<String>,
    /// Response body must NOT contain this substring, otherwise veto finding
    pub not_string: Option<String>,
    /// Response status must equal this code, otherwise veto finding
    pub code: Option<u16>,
    /// Strip HTML tags/entities before matching and detection
    pub text_only: Option<bool>,
    /// Force fetch oracle: direct, boolean or time
    pub fetch_using: Option<String>,
    /// WAF tamper scripts: space2comment, randomcase, versionedcomment, charencode, doubleurlencode, hexencode, unicodeencode, overlongutf8, space2tab, space2newline, space2randomblank, betweencomment
    pub tamper: Option<Vec<String>>,
    /// Proxy URL (use socks5h:// for remote DNS, socks5:// is rejected)
    pub proxy: Option<String>,
    /// Request rate limit (requests per second)
    pub rate_limit: Option<f64>,
    /// Jitter as "mean,std" (e.g. "0.1,0.05")
    pub jitter: Option<String>,
    /// Request timeout in seconds (default: 30)
    pub timeout: Option<u64>,
    /// Max retries for failed requests (default: 3)
    pub retries: Option<usize>,
    /// Base retry delay in milliseconds (default: 500)
    pub delay: Option<u64>,
    /// Custom headers as ["Name: value", ...]
    pub headers: Option<Vec<String>>,
    /// Cookie header value
    pub cookies: Option<String>,
    /// Force specific DBMS: mysql, postgres, mssql, oracle
    pub dbms: Option<String>,
    /// Enable data extraction (opt-in)
    pub extract: Option<bool>,
    /// Enumerate databases
    pub dbs: Option<bool>,
    /// Enumerate tables
    pub tables: Option<bool>,
    /// Enumerate columns
    pub columns: Option<bool>,
    /// Dump table data
    pub dump: Option<bool>,
    /// Retrieve DBMS banner/version (identity enumeration)
    pub banner: Option<bool>,
    /// Retrieve current database user (identity enumeration)
    pub current_user: Option<bool>,
    /// Retrieve current database name (identity enumeration)
    pub current_db: Option<bool>,
    /// Retrieve server hostname (identity enumeration)
    pub hostname: Option<bool>,
    /// Specific database name
    pub db: Option<String>,
    /// Specific table name
    pub table: Option<String>,
    /// Specific column name
    pub column: Option<String>,
    /// Start row offset for dumping
    pub start: Option<usize>,
    /// Stop row offset for dumping
    pub stop: Option<usize>,
    /// Only count rows
    pub count: Option<bool>,
    /// Write JSON report to this file path (opt-in disk write, MCP-only:
    /// relative path without '..', 0o600 on Unix)
    pub output: Option<String>,
    /// Encrypted session export path — NOT supported in MCP mode, will error
    pub export_encrypted: Option<String>,
    /// OOB collaborator base domain (opt-in, requires operator infra)
    pub oob_domain: Option<String>,
    /// Collaborator poll URL (may contain {token}); without it OOB probes are never auto-confirmed
    pub oob_poll_url: Option<String>,
    /// Seconds to wait for the async DB-side OOB query (default: 5)
    pub oob_wait_secs: Option<u64>,
    /// HTTP Parameter Pollution: duplicate param (?id=1&id=PAYLOAD)
    pub hpp: Option<bool>,
    /// Chunked transfer-encoding for body injections
    pub chunked: Option<bool>,
    /// Allow private/loopback targets (lab only, default: false)
    pub allow_private: Option<bool>,
    /// Disable redaction in output (local debugging only)
    pub no_redact: Option<bool>,
}

/// Parameters for the `recon_crawl` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReconCrawlParams {
    /// Target URL or bare host to crawl
    pub target: String,
    /// Crawl depth (default: 2, max: 16)
    pub depth: Option<usize>,
    /// Maximum pages to crawl (default: 100, max: 100000)
    pub max_pages: Option<usize>,
    /// Include subdomains
    pub include_subdomains: Option<bool>,
    /// Ignore robots.txt
    pub ignore_robots: Option<bool>,
    /// Number of concurrent threads (default: 5)
    pub threads: Option<usize>,
    /// Proxy URL (use socks5h:// for remote DNS)
    pub proxy: Option<String>,
    /// Request rate limit (requests per second)
    pub rate_limit: Option<f64>,
    /// Jitter as "mean,std"
    pub jitter: Option<String>,
    /// Request timeout in seconds (default: 30)
    pub timeout: Option<u64>,
    /// Max retries for failed requests (default: 3)
    pub retries: Option<usize>,
    /// Base retry delay in milliseconds (default: 500)
    pub delay: Option<u64>,
    /// Custom headers as ["Name: value", ...]
    pub headers: Option<Vec<String>>,
    /// Cookie header value
    pub cookies: Option<String>,
    /// Allow private/loopback targets (lab only, default: false)
    pub allow_private: Option<bool>,
}

/// Parameters for the `recon_scan` tool (crawl + test discovered parameters).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReconScanParams {
    /// Target URL or bare host to crawl and scan
    pub target: String,
    /// Crawl depth (default: 2, max: 16)
    pub depth: Option<usize>,
    /// Maximum pages to crawl (default: 100, max: 100000)
    pub max_pages: Option<usize>,
    /// Include subdomains
    pub include_subdomains: Option<bool>,
    /// Ignore robots.txt
    pub ignore_robots: Option<bool>,
    /// Auto-enumerate databases/tables after finding injection
    pub auto_enumerate: Option<bool>,
    /// Number of concurrent threads (default: 5)
    pub threads: Option<usize>,
    /// Techniques to use: boolean, time, error, union, stacked, oob, all
    pub techniques: Option<Vec<String>>,
    /// Test only these parameters
    pub params: Option<Vec<String>>,
    /// POST body to test
    pub data: Option<String>,
    /// Payload prefix prepended after tampers
    pub prefix: Option<String>,
    /// Payload suffix appended after tampers
    pub suffix: Option<String>,
    /// Extra chars exempted from percent-encoding
    pub safe_chars: Option<String>,
    /// Send payloads without URL-encoding
    pub skip_urlencode: Option<bool>,
    /// Response body must contain this substring, otherwise veto finding
    pub string: Option<String>,
    /// Response body must NOT contain this substring, otherwise veto finding
    pub not_string: Option<String>,
    /// Response status must equal this code, otherwise veto finding
    pub code: Option<u16>,
    /// Strip HTML tags/entities before matching and detection
    pub text_only: Option<bool>,
    /// Force fetch oracle: direct, boolean or time
    pub fetch_using: Option<String>,
    /// WAF tamper scripts
    pub tamper: Option<Vec<String>>,
    /// Proxy URL (use socks5h:// for remote DNS)
    pub proxy: Option<String>,
    /// Request rate limit (requests per second)
    pub rate_limit: Option<f64>,
    /// Jitter as "mean,std"
    pub jitter: Option<String>,
    /// Request timeout in seconds (default: 30)
    pub timeout: Option<u64>,
    /// Max retries for failed requests (default: 3)
    pub retries: Option<usize>,
    /// Base retry delay in milliseconds (default: 500)
    pub delay: Option<u64>,
    /// Custom headers as ["Name: value", ...]
    pub headers: Option<Vec<String>>,
    /// Cookie header value
    pub cookies: Option<String>,
    /// Force specific DBMS: mysql, postgres, mssql, oracle
    pub dbms: Option<String>,
    /// Enable data extraction (opt-in)
    pub extract: Option<bool>,
    /// Enumerate databases
    pub dbs: Option<bool>,
    /// Enumerate tables
    pub tables: Option<bool>,
    /// Enumerate columns
    pub columns: Option<bool>,
    /// Dump table data
    pub dump: Option<bool>,
    /// Retrieve DBMS banner/version (identity enumeration)
    pub banner: Option<bool>,
    /// Retrieve current database user (identity enumeration)
    pub current_user: Option<bool>,
    /// Retrieve current database name (identity enumeration)
    pub current_db: Option<bool>,
    /// Retrieve server hostname (identity enumeration)
    pub hostname: Option<bool>,
    /// Specific database name
    pub db: Option<String>,
    /// Specific table name
    pub table: Option<String>,
    /// Specific column name
    pub column: Option<String>,
    /// Start row offset for dumping
    pub start: Option<usize>,
    /// Stop row offset for dumping
    pub stop: Option<usize>,
    /// Only count rows
    pub count: Option<bool>,
    /// Write JSON report to this file path (opt-in disk write, MCP-only:
    /// relative path without '..', 0o600 on Unix)
    pub output: Option<String>,
    /// Encrypted session export path — NOT supported in MCP mode, will error
    pub export_encrypted: Option<String>,
    /// OOB collaborator base domain (opt-in)
    pub oob_domain: Option<String>,
    /// Collaborator poll URL (may contain {token})
    pub oob_poll_url: Option<String>,
    /// Seconds to wait for the async DB-side OOB query (default: 5)
    pub oob_wait_secs: Option<u64>,
    /// HTTP Parameter Pollution
    pub hpp: Option<bool>,
    /// Chunked transfer-encoding for body injections
    pub chunked: Option<bool>,
    /// Allow private/loopback targets (lab only, default: false)
    pub allow_private: Option<bool>,
    /// Disable redaction in output (local debugging only)
    pub no_redact: Option<bool>,
}

/// Parameters for the info tool (no parameters).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct InfoParams {}
