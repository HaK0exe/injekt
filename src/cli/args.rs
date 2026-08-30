#![deny(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use secrecy::SecretString;

#[derive(Debug, Clone, ValueEnum)]
#[non_exhaustive]
pub enum TechniqueOpt {
    Boolean,
    Time,
    Error,
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

    #[arg(long, global = true)]
    pub output: Option<String>,

    #[arg(long, global = true)]
    pub rate_limit: Option<f64>,

    #[arg(long, global = true)]
    pub jitter: Option<String>,

    #[arg(long, global = true)]
    pub marker: Option<String>,

    #[arg(long, global = true)]
    pub export_encrypted: Option<String>,

    #[arg(long, global = true)]
    pub import: Option<String>,

    #[arg(long, global = true)]
    pub no_redact: bool,

    #[arg(long, global = true)]
    pub allow_private: bool,

    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
#[non_exhaustive]
pub enum Commands {
    Scan(ScanArgs),
    Replay(ReplayArgs),
    Info(InfoArgs),
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
        self.target.clone().or_else(|| match &self.command {
            Some(Commands::Scan(a)) => a.target.clone(),
            _ => None,
        })
    }
}
