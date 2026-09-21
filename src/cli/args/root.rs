#![deny(unsafe_code)]

use super::{
    detection::DetectionOpts, enumeration::EnumOpts, evasion::EvasionOpts, http::HttpOpts,
    output::OutputOpts, target::TargetOpts,
};
use crate::cli::profile::Profile;
use crate::cli::styles::CLI_STYLES;
use clap::{Parser, Subcommand};

#[derive(Parser, Clone)]
#[command(name="injekt", version, about="Modern SQLi detection — zero persistence, anonymisation by design", long_about=None, styles = CLI_STYLES)]
#[non_exhaustive]
// Each bool is an independent CLI flag (clap derive); a state-machine/enum
// refactor would break the flat --flag command-line surface.
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Scan preset: quick, balanced, stealth or aggressive. Sets defaults for
    /// --threads/--rate-limit/--jitter/--timeout/--retries/--delay/--level/--techniques.
    /// Any explicit flag, INJEKT_* env var or config file value wins over the preset.
    /// Absent = historical behaviour (same as balanced).
    #[arg(long, global = true, value_enum, env = "INJEKT_PROFILE")]
    pub profile: Option<Profile>,

    /// TOML config file (e.g. --config ./injekt.toml). When absent, ./injekt.toml
    /// then ~/.config/injekt/config.toml are tried. Missing file = defaults.
    /// Precedence: CLI flag > env > config file > --profile > built-in defaults.
    #[arg(long, global = true, env = "INJEKT_CONFIG")]
    pub config: Option<String>,

    #[command(flatten)]
    pub target_opts: TargetOpts,

    #[command(flatten)]
    pub http: HttpOpts,

    #[command(flatten)]
    pub detection: DetectionOpts,

    #[command(flatten)]
    pub evasion: EvasionOpts,

    #[command(flatten)]
    pub enumeration: EnumOpts,

    #[command(flatten)]
    pub output_opts: OutputOpts,

    /// Explicit opt-in to replay `--cookies`/`--headers` across multiple
    /// origins in bulk/import runs. Without it, a multi-origin run carrying
    /// auth secrets fails closed instead of spraying sessions.
    #[arg(long = "allow-secret-reuse", global = true)]
    pub allow_secret_reuse: bool,

    /// C13 Knowledge Engine opt-in (défaut OFF = RAM-only, 0 lecture/écriture,
    /// boost 1.0 neutre byte-identique). Activé : lecture au boot de
    /// `~/.cache/injekt/knowledge.json` (ou `--knowledge-path` /
    /// `INJEKT_KNOWLEDGE_PATH`), boost `1+alpha` borné `[0.5,1.5]` puis clamp
    /// scheduler `[0.5,2.0]`, écriture post-run (fusion, fsync, perms 0600).
    /// Agrégats anonymes `(technique, dbms, contexte)` uniquement — jamais de
    /// cible/param/seed/secret persisté.
    #[arg(
        long,
        global = true,
        env = "INJEKT_ALLOW_KNOWLEDGE",
        help_heading = "Output",
        hide_short_help = true
    )]
    pub allow_knowledge: bool,

    /// Chemin du store knowledge (défaut `~/.cache/injekt/knowledge.json`).
    /// Inutilisé quand `--allow-knowledge` est absent (aucune IO).
    #[arg(
        long,
        global = true,
        env = "INJEKT_KNOWLEDGE_PATH",
        help_heading = "Output",
        hide_short_help = true
    )]
    pub knowledge_path: Option<String>,

    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// Suppress the startup banner (written to stderr; stdout stays clean either way)
    #[arg(long, global = true)]
    pub no_banner: bool,
}

// Manual `Debug` for `Cli`: secrets stay in `SecretString` / scrubbed output
// only — redaction itself lives in the per-group impls above
// (`TargetOpts` / `HttpOpts` / `DetectionOpts` / `EvasionOpts`).
impl core::fmt::Debug for Cli {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cli")
            .field("command", &self.command)
            .field("profile", &self.profile)
            .field("config", &self.config)
            .field("target_opts", &self.target_opts)
            .field("http", &self.http)
            .field("detection", &self.detection)
            .field("evasion", &self.evasion)
            .field("enumeration", &self.enumeration)
            .field("output_opts", &self.output_opts)
            .field("allow_secret_reuse", &self.allow_secret_reuse)
            .field("allow_knowledge", &self.allow_knowledge)
            .field("knowledge_path", &self.knowledge_path)
            .field("verbose", &self.verbose)
            .field("no_banner", &self.no_banner)
            .finish_non_exhaustive()
    }
}

#[derive(Subcommand, Debug, Clone)]
#[non_exhaustive]
pub enum Commands {
    Scan(ScanArgs),
    Recon(ReconArgs),
    Replay(ReplayArgs),
    Info(InfoArgs),
    /// One-command pipeline: ingestion -> scan -> escalation -> enumeration.
    Auto(AutoArgs),
    /// Scaffold helpers: generate a starter `injekt.toml`.
    #[command(hide = true)]
    Init(InitArgs),
    /// Print shell completions (`bash|zsh|fish|powershell|elvish`).
    #[command(hide = true)]
    Completions(CompletionsArgs),
    /// Print a man page (roff) to stdout.
    #[command(hide = true)]
    Man(ManArgs),
    /// Run as an MCP server over stdio (for Claude Code, Codex, `OpenCode`, Cursor, VS Code).
    #[command(hide = true)]
    Mcp(McpArgs),
}

#[derive(Parser, Debug, Clone)]
#[non_exhaustive]
pub struct ReconArgs {
    #[command(subcommand)]
    pub command: ReconCommands,
}

#[derive(Subcommand, Debug, Clone)]
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
    /// Cap on how many pages of the same shape (path pattern + query param
    /// names) are fetched — guards against pagination/listing/calendar traps
    /// burning the whole --max-pages budget on redundant instances.
    #[arg(long, default_value_t = 3)]
    pub max_per_template: usize,
    /// Cap on the total discovered parameters kept: listing/gallery/proxy
    /// families otherwise queue hundreds of near-identical candidates that
    /// burn scan budget. Redundant sink shapes are dropped first.
    #[arg(long, default_value_t = 500)]
    pub max_candidates: usize,
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

#[derive(Parser, Debug, Clone)]
#[non_exhaustive]
pub struct ScanArgs {
    #[arg(
        long,
        hide_short_help = true,
        help = "Alias historique de --target global (-u), préférer bare injekt --target"
    )]
    pub target: Option<String>,
}

#[derive(Parser, Debug, Clone)]
#[non_exhaustive]
pub struct ReplayArgs {
    #[arg(long)]
    pub file: String,
}

#[derive(Parser, Debug, Clone)]
#[non_exhaustive]
pub struct InfoArgs {}

#[derive(Parser, Debug, Clone)]
#[non_exhaustive]
pub struct AutoArgs {
    /// Target URL or bare host. A bare host (no `://`) implies `--with-recon`.
    #[arg(
        long,
        hide_short_help = true,
        help = "Alias historique de --target global (-u), préférer bare injekt --target"
    )]
    pub target: Option<String>,
    /// Crawl before scanning (discovers params, then tests each candidate).
    #[arg(long)]
    pub with_recon: bool,
    /// Crawl depth for the recon phase (implies `--with-recon` when > 0 and target is a host).
    #[arg(long, default_value_t = 2)]
    pub depth: usize,
    /// Max pages for the recon phase.
    #[arg(long, default_value_t = 100)]
    pub max_pages: usize,
    /// Disable the automatic level/tamper escalation loop (single pass only).
    #[arg(long)]
    pub no_escalate: bool,
    /// Enumerate (`--dbs`-style flags) once a finding is confirmed.
    #[arg(long)]
    pub auto_enumerate: bool,
}

#[derive(Parser, Debug, Clone)]
#[non_exhaustive]
pub struct InitArgs {
    /// Destination path for the generated config.
    #[arg(long, default_value = "./injekt.toml")]
    pub path: String,
    /// Preset to seed the file with (`quick|balanced|stealth|aggressive`).
    #[arg(long, default_value = "balanced")]
    pub preset: String,
    // Note: overwrite uses the global `--force` (`Cli::force`), not a
    // subcommand-local flag, so `injekt init --force` keeps working via the
    // global arg without a clap duplicate.
}

#[derive(Parser, Debug, Clone)]
#[non_exhaustive]
pub struct CompletionsArgs {
    /// Shell to generate completions for.
    #[arg(value_parser = ["bash", "zsh", "fish", "powershell", "elvish"])]
    pub shell: String,
}

#[derive(Parser, Debug, Clone)]
#[non_exhaustive]
pub struct ManArgs {}

#[derive(Parser, Debug, Clone)]
#[non_exhaustive]
pub struct McpArgs {}
