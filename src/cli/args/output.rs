#![deny(unsafe_code)]

use clap::{Args, ValueEnum};

/// Report serialization selected by `--format` (C7 intelligent reporting).
/// Controls `--output` file content (and `--bulk-file` aggregated reports);
/// console output is unchanged. Default is `json` (historical behaviour).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum ReportFormat {
    /// Historical `JsonReport` schema (extended with C7 calibrated fields).
    #[default]
    Json,
    /// SARIF 2.1.0 for CI code-scanning ingestion.
    Sarif,
    /// `JUnit` XML for CI test-case dashboards.
    Junit,
    /// Human-sendable Markdown with remediation.
    Md,
}

impl core::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Sarif => write!(f, "sarif"),
            Self::Junit => write!(f, "junit"),
            Self::Md => write!(f, "md"),
        }
    }
}

impl ReportFormat {
    /// C16 — strict name form (`json|sarif|junit|md`) for the config-TOML
    /// `format` key. clap parses the CLI/env spellings itself (with its own
    /// `invalid value` usage error); only the file key is resolved here.
    /// Case-insensitive; unknown names yield `None` (the caller warns once,
    /// like the unknown-profile path).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "sarif" => Some(Self::Sarif),
            "junit" => Some(Self::Junit),
            "md" => Some(Self::Md),
            _ => None,
        }
    }
}

/// Output / reporting (files, formats, dry-run, redaction).
#[derive(Debug, Clone, Args)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
pub struct OutputOpts {
    #[arg(long, global = true, help_heading = "Output")]
    pub output: Option<String>,

    /// Report serialization for `--output` files: `json` (effective default,
    /// historical `JsonReport` schema + C7 calibrated fields), `sarif`
    /// (2.1.0, CI code-scanning), `junit` (CI test cases), `md`
    /// (human-sendable with remediation). Console output is unchanged. All
    /// formats are scrubbed.
    ///
    /// C16 — `Option` (no clap default): effective resolution in
    /// `Cli::effective_format` is `--format`/`INJEKT_FORMAT` (this field,
    /// parsed by clap for both sources) > `--output` file extension
    /// (`*.sarif` → sarif, `*.json` → json, `*.junit`/`*.xml` → junit,
    /// `*.md`/`*.markdown` → md; unknown extensions never infer) > config
    /// TOML `format` key > `json`. Explicit-vs-extension conflict warns
    /// once and keeps the explicit value.
    #[arg(
        long,
        global = true,
        value_enum,
        env = "INJEKT_FORMAT",
        help_heading = "Output"
    )]
    pub format: Option<ReportFormat>,

    /// Dry run: resolve config + targets and print the execution plan
    /// without sending any network request (OPSEC-safe).
    #[arg(long, global = true, help_heading = "Output")]
    pub dry_run: bool,

    #[arg(long, global = true, help_heading = "Output")]
    pub no_redact: bool,

    /// One-line reasoning verdict for a finding (`--explain id@query`):
    /// prints `TRUE≈baseline 0.91, FALSE≠baseline 0.22, 3/3, waf=none,
    /// 14 req, seed 42` after the scan (or from `replay --file`).
    /// No extra requests; reads the RAM-only trace + evidence.
    #[arg(long, global = true, env = "INJEKT_EXPLAIN", help_heading = "Output")]
    pub explain: Option<String>,

    #[arg(long, global = true, help_heading = "Output")]
    pub export_encrypted: Option<String>,

    /// Legacy flag: `scan --import` is rejected (use `replay --file` to
    /// inspect an encrypted export, `recon import --file` for candidates).
    #[arg(long, global = true, help_heading = "Output")]
    pub import: Option<String>,

    /// Allow overwriting existing `--output` files and absolute/`..` output
    /// paths (explicit opt-in, OPSEC-sensitive: reports may contain secrets).
    #[arg(long, global = true, help_heading = "Output")]
    pub force: bool,
}
