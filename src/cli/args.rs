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
    All,
}

#[derive(Parser, Debug)]
#[command(name="injekt", version, about="Modern SQLi detection — zero persistence, anonymisation by design", long_about=None)]
#[non_exhaustive]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Target URL (e.g. <https://example.com/?id=1>)
    #[arg(long, short = 'u', global = true)]
    pub target: Option<String>,

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

    #[arg(long, global = true, value_delimiter = ',')]
    pub techniques: Vec<String>,

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
}

#[derive(Subcommand, Debug)]
#[non_exhaustive]
pub enum Commands {
    Scan(ScanArgs),
    Recon(ReconArgs),
    Replay(ReplayArgs),
    Info(InfoArgs),
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

impl Cli {
    #[must_use]
    pub fn cookies_secret(&self) -> Option<SecretString> {
        self.cookies.clone().map(SecretString::from)
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
