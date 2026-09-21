#![deny(unsafe_code)]

use clap::Args;

/// Data enumeration (opt-in extraction once a finding is confirmed).
#[derive(Debug, Clone, Args)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
pub struct EnumOpts {
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub extract: bool,

    /// Enumeration flags
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub dbs: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub tables: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub columns: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub dump: bool,
    #[arg(long, short = 'b', global = true, help_heading = "Enumeration")]
    pub banner: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub current_user: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub current_db: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub hostname: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub db: Option<String>,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub table: Option<String>,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub column: Option<String>,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub start: Option<usize>,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub stop: Option<usize>,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub count: bool,
}
