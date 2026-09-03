#![deny(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use secrecy::SecretString;

#[derive(Debug, Clone, ValueEnum)]
#[non_exhaustive]
pub enum TechniqueOpt {
    Boolean,
    Time,
    Error,
    Union,
    Stacked,
    Oob,
    Json,
    All,
}

#[derive(Parser, Debug)]
#[command(name="injekt", version, about="Modern SQLi detection — zero persistence, anonymisation by design", long_about=None)]
#[non_exhaustive]
// Each bool is an independent CLI flag (clap derive); a state-machine/enum
// refactor would break the flat --flag command-line surface.
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Target URL (e.g. <https://example.com/?id=1>)
    #[arg(long, short = 'u', global = true)]
    pub target: Option<String>,

    /// Bulk scan: file with one target per line (`#` comments skipped, max 1000).
    /// Conflicts with --target/--raw-file; per-target errors are recorded, loop continues.
    #[arg(long = "bulk-file", short = 'm', global = true)]
    pub bulk_file: Option<String>,

    #[arg(long, global = true)]
    pub method: Option<String>,

    #[arg(long, global = true, value_delimiter = ',')]
    pub headers: Vec<String>,

    #[arg(long, global = true)]
    pub cookies: Option<String>,

    #[arg(long, global = true)]
    pub proxy: Option<String>,

    #[arg(long, global = true, default_value_t = 5)]
    pub threads: usize,

    /// Request timeout in seconds (mandatory for HTTP client build)
    #[arg(long, global = true, default_value_t = 30)]
    pub timeout: u64,

    /// Max retries for failed requests (default 3)
    #[arg(long, global = true, default_value_t = 3)]
    pub retries: usize,

    /// Base retry delay in milliseconds (default 500)
    #[arg(long, global = true, default_value_t = 500)]
    pub delay: u64,

    #[arg(long, global = true, value_delimiter = ',')]
    pub techniques: Vec<String>,

    /// Test only these parameters (e.g. -p id or -p body:user,cookie:PHPSESSID)
    #[arg(short = 'p', long = "params", global = true, value_delimiter = ',')]
    pub params: Vec<String>,

    /// POST body to test (e.g. "id=1&user=admin") — alternative to --raw-file
    #[arg(long, global = true)]
    pub data: Option<String>,

    /// Payload prefix prepended after tampers (e.g. "')")
    #[arg(long, global = true)]
    pub prefix: Option<String>,

    /// Payload suffix appended after tampers (e.g. "-- -")
    #[arg(long, global = true)]
    pub suffix: Option<String>,

    /// Extra chars exempted from percent-encoding (e.g. "(),")
    #[arg(long, global = true)]
    pub safe_chars: Option<String>,

    /// Send payloads without URL-encoding (use with care)
    #[arg(long, global = true)]
    pub skip_urlencode: bool,

    /// Force fetch oracle: direct, boolean or time (narrows techniques)
    #[arg(long, global = true, value_parser = ["direct", "boolean", "time"])]
    pub fetch_using: Option<String>,

    #[arg(long, global = true)]
    pub dbms: Option<String>,

    #[arg(long, global = true)]
    pub extract: bool,

    /// Enumeration flags
    #[arg(long, global = true)]
    pub dbs: bool,
    #[arg(long, global = true)]
    pub tables: bool,
    #[arg(long, global = true)]
    pub columns: bool,
    #[arg(long, global = true)]
    pub dump: bool,
    #[arg(long, short = 'b', global = true)]
    pub banner: bool,
    #[arg(long, global = true)]
    pub current_user: bool,
    #[arg(long, global = true)]
    pub current_db: bool,
    #[arg(long, global = true)]
    pub hostname: bool,
    #[arg(long, global = true)]
    pub db: Option<String>,
    #[arg(long, global = true)]
    pub table: Option<String>,
    #[arg(long, global = true)]
    pub column: Option<String>,
    #[arg(long, global = true)]
    pub start: Option<usize>,
    #[arg(long, global = true)]
    pub stop: Option<usize>,
    #[arg(long, global = true)]
    pub count: bool,

    #[arg(long, global = true)]
    pub output: Option<String>,

    #[arg(long, global = true)]
    pub rate_limit: Option<f64>,

    #[arg(long, global = true)]
    pub jitter: Option<String>,

    #[arg(long, global = true)]
    pub marker: Option<String>,

    /// Response body must contain this substring, otherwise veto finding
    #[arg(long, global = true)]
    pub string: Option<String>,

    /// Response body must NOT contain this substring, otherwise veto finding
    #[arg(long, global = true)]
    pub not_string: Option<String>,

    /// Response status must equal this code, otherwise veto finding
    #[arg(long, global = true)]
    pub code: Option<u16>,

    /// Strip HTML tags/entities before matching and detection
    #[arg(long, global = true)]
    pub text_only: bool,

    /// Aggressiveness level 1-5 (default 1): L1 is the historical payload
    /// budget, L2 doubles it, L3+ tries every payload and widens ORDER BY
    /// enumeration. Absent = current behaviour, byte-identical.
    #[arg(long, global = true, value_parser = clap::value_parser!(u8).range(1..=5))]
    pub level: Option<u8>,

    /// Strict second-pass confirmation (opt-in): after detection, replay each
    /// finding's technique for that single parameter against a fresh session
    /// and keep only re-confirmed findings (OOB skipped: async collaborator
    /// evidence is not replayable). Roughly doubles request cost.
    #[arg(long, global = true)]
    pub confirm: bool,

    /// HTTP status codes treated as negative probes during detection
    /// (e.g. --ignore-code 429,503): an ignored response never yields a
    /// finding. Baseline collection (incl. WAF detection) runs before this
    /// filter and is never ignored.
    #[arg(long = "ignore-code", global = true, value_delimiter = ',')]
    pub ignore_codes: Vec<u16>,

    /// OOB collaborator base domain (e.g. x.oastify.com) — enables techniques/oob DNS/HTTP probes (OPT-IN, requires operator infra)
    #[arg(long, global = true)]
    pub oob_domain: Option<String>,

    /// Generic collaborator poll URL for OOB confirmation (may contain {token}); without it, OOB probes are sent but never auto-confirmed
    #[arg(long, global = true)]
    pub oob_poll_url: Option<String>,

    /// Seconds to wait for the async DB-side OOB query before polling the collaborator
    #[arg(long, global = true, default_value_t = 5)]
    pub oob_wait_secs: u64,

    /// WAF tamper scripts (comma-separated): space2comment,randomcase,versionedcomment,charencode,doubleurlencode,hexencode,unicodeencode,overlongutf8,space2tab,space2newline,space2randomblank,betweencomment
    #[arg(long, global = true, value_delimiter = ',')]
    pub tamper: Vec<String>,

    /// HTTP Parameter Pollution: duplicate param (?id=1&id=PAYLOAD) for Query/Body — WAFs inspecting only first occurrence are bypassed
    #[arg(long, global = true)]
    pub hpp: bool,

    /// Chunked transfer: send Body injections with Transfer-Encoding: chunked (streamed) to bypass content-length inspection
    #[arg(long, global = true)]
    pub chunked: bool,

    #[arg(long, global = true)]
    pub export_encrypted: Option<String>,

    #[arg(long, global = true)]
    pub import: Option<String>,

    #[arg(long, global = true)]
    pub no_redact: bool,

    #[arg(long, global = true)]
    pub allow_private: bool,

    /// Raw HTTP request file (Burp/ZAP) — alternative to --target
    #[arg(long, global = true)]
    pub raw_file: Option<String>,

    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// Suppress the startup banner (written to stderr; stdout stays clean either way)
    #[arg(long, global = true)]
    pub no_banner: bool,
}

#[derive(Subcommand, Debug)]
#[non_exhaustive]
pub enum Commands {
    Scan(ScanArgs),
    Recon(ReconArgs),
    Replay(ReplayArgs),
    Info(InfoArgs),
    /// Run as an MCP server over stdio (for Claude Code, Codex, `OpenCode`, Cursor, VS Code).
    Mcp(McpArgs),
}

#[derive(Parser, Debug)]
#[non_exhaustive]
pub struct ReconArgs {
    #[command(subcommand)]
    pub command: ReconCommands,
}

#[derive(Subcommand, Debug)]
#[non_exhaustive]
pub enum ReconCommands {
    /// Crawl a target and print discovered parameters without testing them.
    Crawl(ReconCrawlArgs),
    /// Crawl a target, then test each discovered parameter.
    Scan(ReconScanArgs),
    /// Import candidates previously exported as JSON.
    Import(ReconImportArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct ReconCrawlArgs {
    #[arg(long)]
    pub target: String,
    #[arg(long, default_value_t = 2)]
    pub depth: usize,
    #[arg(long, default_value_t = 100)]
    pub max_pages: usize,
    #[arg(long)]
    pub include_subdomains: bool,
    #[arg(long)]
    pub ignore_robots: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct ReconScanArgs {
    #[command(flatten)]
    pub crawl: ReconCrawlArgs,
    #[arg(long)]
    pub auto_enumerate: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct ReconImportArgs {
    #[arg(long)]
    pub file: String,
    #[arg(long)]
    pub test: bool,
    #[arg(long)]
    pub enumerate: bool,
}

#[derive(Parser, Debug)]
#[non_exhaustive]
pub struct ScanArgs {
    #[arg(long)]
    pub target: Option<String>,
}

#[derive(Parser, Debug)]
#[non_exhaustive]
pub struct ReplayArgs {
    #[arg(long)]
    pub file: String,
}

#[derive(Parser, Debug)]
#[non_exhaustive]
pub struct InfoArgs {}

#[derive(Parser, Debug)]
#[non_exhaustive]
pub struct McpArgs {}

impl Cli {
    #[must_use]
    pub fn cookies_secret(&self) -> Option<SecretString> {
        self.cookies.clone().map(SecretString::from)
    }

    /// Assemble [`PayloadOpts`] from CLI flags. Unknown `--fetch-using`
    /// values fall back to `Direct` (clap constrains choices anyway).
    #[must_use]
    pub fn payload_opts(&self) -> crate::techniques::payload_opts::PayloadOpts {
        use crate::techniques::payload_opts::FetchUsing;
        let fetch_using = match self.fetch_using.as_deref() {
            Some("boolean") => FetchUsing::Boolean,
            Some("time") => FetchUsing::Time,
            _ => FetchUsing::Direct,
        };
        crate::techniques::payload_opts::PayloadOpts {
            prefix: self.prefix.clone(),
            suffix: self.suffix.clone(),
            safe_chars: self.safe_chars.clone().unwrap_or_default(),
            skip_urlencode: self.skip_urlencode,
            fetch_using,
        }
    }

    /// Assemble [`MatcherConfig`](crate::detection::matcher::MatcherConfig)
    /// from CLI flags (`--string`, `--not-string`, `--code`, `--text-only`).
    #[must_use]
    pub fn matcher_config(&self) -> crate::detection::matcher::MatcherConfig {
        crate::detection::matcher::MatcherConfig {
            string: self.string.clone(),
            not_string: self.not_string.clone(),
            code: self.code,
            text_only: self.text_only,
        }
    }

    /// Assemble tuning config from CLI flags (`--level`, `--confirm`, `--ignore-code`).
    #[must_use]
    pub fn tuning_config(&self) -> (u8, bool, Vec<u16>) {
        (
            self.level.unwrap_or(1).clamp(1, 5),
            self.confirm,
            self.ignore_codes.clone(),
        )
    }

    #[must_use]
    pub fn effective_target(&self) -> Option<String> {
        if let Some(raw) = &self.raw_file {
            let content = match std::fs::read_to_string(raw) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error=%e, path=%raw, "failed to read raw file");
                    return None;
                }
            };
            let req = match crate::target::raw_request::RawRequest::parse(&content) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error=%e, path=%raw, "failed to parse raw file");
                    return None;
                }
            };
            if let Some(url) = req.to_url("https").or_else(|| req.to_url("http")) {
                return Some(url);
            }
            tracing::warn!(path=%raw, "raw request missing Host header or invalid path");
            return None;
        }
        self.target.clone().or_else(|| match &self.command {
            Some(Commands::Scan(a)) => a.target.clone(),
            _ => None,
        })
    }

    #[must_use]
    pub fn raw_request(&self) -> Option<crate::target::raw_request::RawRequest> {
        let path = self.raw_file.as_ref()?;
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error=%e, path=%path, "failed to read raw file");
                return None;
            }
        };
        match crate::target::raw_request::RawRequest::parse(&content) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(error=%e, path=%path, "failed to parse raw file");
                None
            }
        }
    }
}
