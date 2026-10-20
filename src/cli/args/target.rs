#![deny(unsafe_code)]

use clap::Args;

/// Target selection. Bulk ingestion (`--bulk-file`, `--raw-dir`, `--stdin`,
/// `--openapi-file`, `--sitemap-file`, `collect_targets`) is additive;
/// single-scan (`positional`, `--target` / `scan --target` / `--raw-file`)
/// is exclusive — documented precedence (C16): `--raw-file` > positional >
/// `-u/--target` (CLI then env `INJEKT_TARGET`) > `scan --target` alias;
/// see `Cli::effective_target` (a positional + CLI-typed `--target` that
/// disagree is a usage error via `validate_target_conflict`).
#[derive(Clone, Args)]
#[non_exhaustive]
pub struct TargetOpts {
    /// Target URL (e.g. <https://example.com/?id=1>)
    #[arg(
        long,
        short = 'u',
        global = true,
        env = "INJEKT_TARGET",
        help_heading = "Target"
    )]
    pub target: Option<String>,

    /// Bulk scan: file with one target per line (`#` comments skipped, max 1000).
    /// Conflicts with --target/--raw-file; per-target errors are recorded, loop continues.
    #[arg(
        long = "bulk-file",
        short = 'm',
        global = true,
        help_heading = "Target"
    )]
    pub bulk_file: Option<String>,

    /// Raw HTTP request file (Burp/ZAP) — alternative to --target
    #[arg(long, global = true, help_heading = "Target")]
    pub raw_file: Option<String>,

    /// C17 — unified ingestion (merges `--bulk-file`, `--stdin`,
    /// `--openapi-file`, `--sitemap-file`, `--raw-dir`; those stay
    /// functional 2 releases). Auto-detection (frozen grammar):
    /// `-` → stdin; existing directory → raw-dir; `.json/.yaml/.yml`
    /// containing an `openapi` key → openapi; `.xml` with a `<urlset>`
    /// root → sitemap; otherwise TXT target list (`#` comments).
    /// Additive like the legacy modes (dedup handles overlaps).
    #[arg(
        long,
        global = true,
        help_heading = "Target",
        value_name = "PATH|-|DIR"
    )]
    pub input: Option<String>,

    /// Directory of raw HTTP request files (Burp/ZAP exports, `*.txt`):
    /// every parseable file becomes a target (multi-raw ingestion).
    #[arg(long, global = true, help_heading = "Target")]
    pub raw_dir: Option<String>,

    /// Read bulk targets from stdin (one per line, same format as --bulk-file).
    /// `--bulk-file -` is accepted as an alias for `--stdin`.
    #[arg(long, global = true, help_heading = "Target")]
    pub stdin: bool,

    /// `OpenAPI` 3.x document (JSON) to harvest targets from
    /// (`servers` + `paths` query parameters).
    #[arg(long, global = true, help_heading = "Target")]
    pub openapi_file: Option<String>,

    /// Sitemap XML file (urlset) to harvest targets from (`<loc>` entries).
    #[arg(long, global = true, help_heading = "Target")]
    pub sitemap_file: Option<String>,
}

// Manual `Debug` for `TargetOpts` so `--target` (which may carry
// `?token=` / `user:pass@` secrets) is scrubbed, never printed raw.
impl core::fmt::Debug for TargetOpts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let scrub = crate::session::scrubber::Scrubber::new(false);
        let scrubbed_opt = |v: &Option<String>| v.as_ref().map(|s| scrub.scrub(s));
        f.debug_struct("TargetOpts")
            .field("target", &scrubbed_opt(&self.target))
            .field("bulk_file", &self.bulk_file)
            .field("raw_file", &self.raw_file)
            .field("raw_dir", &self.raw_dir)
            .field("stdin", &self.stdin)
            .field("openapi_file", &self.openapi_file)
            .field("sitemap_file", &self.sitemap_file)
            .finish_non_exhaustive()
    }
}
