#![deny(unsafe_code)]

use crate::cli::profile::Profile;
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

    /// Target URL (e.g. <https://example.com/?id=1>)
    #[arg(long, short = 'u', global = true, env = "INJEKT_TARGET")]
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

    #[arg(long, global = true, env = "INJEKT_PROXY")]
    pub proxy: Option<String>,

    /// Concurrency [default: 5, profiles/config may override; explicit flag wins]
    #[arg(long, global = true, env = "INJEKT_THREADS")]
    pub threads: Option<usize>,

    /// Request timeout in seconds [default: 30]
    #[arg(long, global = true, env = "INJEKT_TIMEOUT")]
    pub timeout: Option<u64>,

    /// Max retries for failed requests [default: 3]
    #[arg(long, global = true, env = "INJEKT_RETRIES")]
    pub retries: Option<usize>,

    /// Base retry delay in milliseconds [default: 500]
    #[arg(long, global = true, env = "INJEKT_DELAY")]
    pub delay: Option<u64>,

    #[arg(long, global = true, value_delimiter = ',', env = "INJEKT_TECHNIQUES")]
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

    #[arg(long, global = true, env = "INJEKT_DBMS")]
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

    #[arg(long, global = true, env = "INJEKT_RATE_LIMIT")]
    pub rate_limit: Option<f64>,

    #[arg(long, global = true, env = "INJEKT_JITTER")]
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
    /// `--profile aggressive` defaults to 3 unless overridden.
    #[arg(long, global = true, value_parser = clap::value_parser!(u8).range(1..=5), env = "INJEKT_LEVEL")]
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
    #[arg(long, global = true, env = "INJEKT_OOB_DOMAIN")]
    pub oob_domain: Option<String>,

    /// Generic collaborator poll URL for OOB confirmation (may contain {token}); without it, OOB probes are sent but never auto-confirmed
    #[arg(long, global = true, env = "INJEKT_OOB_POLL_URL")]
    pub oob_poll_url: Option<String>,

    /// Seconds to wait for the async DB-side OOB query before polling the collaborator [default: 5]
    #[arg(long, global = true, env = "INJEKT_OOB_WAIT_SECS")]
    pub oob_wait_secs: Option<u64>,

    /// WAF tamper scripts (comma-separated): space2comment,space2plus,randomcase,versionedcomment,charencode,doubleurlencode,hexencode,unicodeencode,overlongutf8,space2tab,space2newline,space2randomblank,betweencomment
    #[arg(long, global = true, value_delimiter = ',', env = "INJEKT_TAMPER")]
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

    /// Directory of raw HTTP request files (Burp/ZAP exports, `*.txt`):
    /// every parseable file becomes a target (multi-raw ingestion).
    #[arg(long, global = true)]
    pub raw_dir: Option<String>,

    /// Read bulk targets from stdin (one per line, same format as --bulk-file).
    /// `--bulk-file -` is accepted as an alias for `--stdin`.
    #[arg(long, global = true)]
    pub stdin: bool,

    /// `OpenAPI` 3.x document (JSON) to harvest targets from
    /// (`servers` + `paths` query parameters).
    #[arg(long, global = true)]
    pub openapi_file: Option<String>,

    /// Sitemap XML file (urlset) to harvest targets from (`<loc>` entries).
    #[arg(long, global = true)]
    pub sitemap_file: Option<String>,

    /// Dry run: resolve config + targets and print the execution plan
    /// without sending any network request (OPSEC-safe).
    #[arg(long, global = true)]
    pub dry_run: bool,

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
    /// One-command pipeline: ingestion -> scan -> escalation -> enumeration.
    Auto(AutoArgs),
    /// Scaffold helpers: generate a starter `injekt.toml`.
    Init(InitArgs),
    /// Print shell completions (`bash|zsh|fish|powershell|elvish`).
    Completions(CompletionsArgs),
    /// Print a man page (roff) to stdout.
    Man(ManArgs),
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
    /// Cap on how many pages of the same shape (path pattern + query param
    /// names) are fetched — guards against pagination/listing/calendar traps
    /// burning the whole --max-pages budget on redundant instances.
    #[arg(long, default_value_t = 3)]
    pub max_per_template: usize,
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
    #[arg(long)]
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
    /// Overwrite an existing file.
    #[arg(long)]
    pub force: bool,
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

impl Cli {
    #[must_use]
    pub fn cookies_secret(&self) -> Option<SecretString> {
        self.cookies.clone().map(SecretString::from)
    }

    /// Load the config file snapshot for this invocation.
    /// Explicit `--config` errors are logged and ignored here (the scan
    /// entry points surface them); auto-discovered files never fail.
    fn file_snapshot(&self) -> crate::cli::file_config::FileConfig {
        match crate::cli::file_config::load(self.config.as_deref()) {
            Ok(Some((path, cfg))) => {
                tracing::debug!(path=%path.display(), "config file loaded");
                cfg
            }
            Ok(None) => crate::cli::file_config::FileConfig::default(),
            Err(e) => {
                tracing::warn!(error=%e, "invalid --config file, ignoring");
                crate::cli::file_config::FileConfig::default()
            }
        }
    }

    /// Active preset: explicit `--profile` (or `INJEKT_PROFILE`) wins over the
    /// `profile` key from the config file. Unknown file profile names warn.
    #[must_use]
    pub fn active_profile(&self) -> Option<Profile> {
        if let Some(p) = self.profile {
            return Some(p);
        }
        let file = self.file_snapshot();
        if file.profile.is_some() {
            let resolved = file.file_profile();
            if resolved.is_none() {
                tracing::warn!(
                    profile=?file.profile,
                    available=?Profile::all_names(),
                    "unknown profile in config file, ignoring"
                );
            }
            return resolved;
        }
        None
    }

    /// Effective concurrency. Precedence: CLI/env > config file > profile > 5.
    #[must_use]
    pub fn effective_threads(&self) -> usize {
        if let Some(v) = self.threads {
            return v;
        }
        let file = self.file_snapshot();
        if let Some(v) = file.threads {
            return v;
        }
        self.active_profile().map_or(5, Profile::threads)
    }

    /// Effective request timeout (seconds). Precedence: CLI/env > file > profile > 30.
    #[must_use]
    pub fn effective_timeout(&self) -> u64 {
        if let Some(v) = self.timeout {
            return v;
        }
        let file = self.file_snapshot();
        if let Some(v) = file.timeout {
            return v;
        }
        self.active_profile().map_or(30, Profile::timeout_secs)
    }

    /// Effective retry count. Precedence: CLI/env > file > profile > 3.
    #[must_use]
    pub fn effective_retries(&self) -> usize {
        if let Some(v) = self.retries {
            return v;
        }
        let file = self.file_snapshot();
        if let Some(v) = file.retries {
            return v;
        }
        self.active_profile().map_or(3, Profile::retries)
    }

    /// Effective retry base delay (ms). Precedence: CLI/env > file > profile > 500.
    #[must_use]
    pub fn effective_delay(&self) -> u64 {
        if let Some(v) = self.delay {
            return v;
        }
        let file = self.file_snapshot();
        if let Some(v) = file.delay {
            return v;
        }
        self.active_profile().map_or(500, Profile::delay_ms)
    }

    /// Effective rate limit (req/s). Always enforced; no unlimited mode.
    /// Precedence: CLI/env > file > profile > 10.0.
    #[must_use]
    pub fn effective_rate_limit(&self) -> f64 {
        if let Some(v) = self.rate_limit {
            return v;
        }
        let file = self.file_snapshot();
        if let Some(v) = file.rate_limit {
            return v;
        }
        self.active_profile().map_or(10.0, Profile::rate_limit_rps)
    }

    /// Effective jitter `"mean_ms,std_ms"`. Precedence: CLI/env > file > profile > `"750,250"`.
    #[must_use]
    pub fn effective_jitter(&self) -> String {
        if let Some(v) = self.jitter.clone() {
            return v;
        }
        let file = self.file_snapshot();
        if let Some(v) = file.jitter.clone() {
            return v;
        }
        self.active_profile()
            .map_or_else(|| "750,250".to_owned(), |p| p.jitter().to_owned())
    }

    /// Effective aggressiveness level 1-5. Precedence: CLI/env > file > profile > 1.
    #[must_use]
    pub fn effective_level(&self) -> u8 {
        if let Some(v) = self.level {
            return v.clamp(1, 5);
        }
        let file = self.file_snapshot();
        if let Some(v) = file.level {
            return v.clamp(1, 5);
        }
        self.active_profile().map_or(1, Profile::level)
    }

    /// Effective technique list. Non-empty CLI `--techniques` always wins
    /// (explicit, non-breaking); then config file; then profile; then `["all"]`.
    #[must_use]
    pub fn effective_techniques(&self) -> Vec<String> {
        if !self.techniques.is_empty() {
            return self.techniques.clone();
        }
        let file = self.file_snapshot();
        if let Some(v) = file.techniques.clone()
            && !v.is_empty()
        {
            return v;
        }
        self.active_profile()
            .map_or_else(|| vec!["all".to_owned()], Profile::techniques)
    }

    /// Effective proxy URL. Precedence: CLI/env > config file. Profiles never
    /// set a proxy (OPSEC: explicit opt-in only).
    #[must_use]
    pub fn effective_proxy(&self) -> Option<String> {
        if let Some(v) = self.proxy.clone() {
            return Some(v);
        }
        self.file_snapshot().proxy.clone()
    }

    /// Effective OOB wait (seconds). Precedence: CLI/env > file > 5.
    /// Profiles never change it (collaborator timing is operator-specific).
    #[must_use]
    pub fn effective_oob_wait_secs(&self) -> u64 {
        if let Some(v) = self.oob_wait_secs {
            return v;
        }
        self.file_snapshot().oob_wait_secs.unwrap_or(5)
    }

    /// Fail fast on an explicit `--config` path that cannot be read or parsed.
    /// Auto-discovered files never fail (they warn in [`Self::file_snapshot`]).
    ///
    /// # Errors
    /// Returns an error describing the invalid explicit config file.
    pub fn validate_explicit_config(&self) -> Result<(), String> {
        let Some(path) = self.config.as_deref() else {
            return Ok(());
        };
        match std::fs::read_to_string(path) {
            Ok(content) => crate::cli::file_config::FileConfig::parse(&content)
                .map(|_| ())
                .map_err(|e| format!("invalid config file {path}: {e}")),
            Err(e) => Err(format!("cannot read config file {path}: {e}")),
        }
    }

    /// One-line summary of the active preset/config for `tracing::info!` logs.
    /// Keeps startup output readable without dumping every resolved knob.
    #[must_use]
    pub fn resolution_summary(&self) -> String {
        let profile = self.active_profile().map_or_else(
            || "none".to_owned(),
            |p| format!("{p:?}").to_ascii_lowercase(),
        );
        let config = self.config.clone().unwrap_or_else(|| "auto".to_owned());
        format!(
            "profile={profile} config={config} threads={} rate={} jitter={} level={}",
            self.effective_threads(),
            self.effective_rate_limit(),
            self.effective_jitter(),
            self.effective_level(),
        )
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
            self.effective_level(),
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

    /// Same resolution as [`Self::effective_target`], but propagates raw-file
    /// read/parse failures as errors instead of silently returning `None`
    /// (prevents a malformed `--raw` file from being mistaken for "no
    /// target").
    ///
    /// # Errors
    /// Returns an error if `--raw` is set but the file cannot be read,
    /// fails to parse as a raw HTTP request, or lacks a usable Host header.
    pub fn try_effective_target(&self) -> anyhow::Result<Option<String>> {
        if let Some(raw) = &self.raw_file {
            let content = std::fs::read_to_string(raw)
                .map_err(|e| anyhow::anyhow!("failed to read raw file '{raw}': {e}"))?;
            let req = crate::target::raw_request::RawRequest::parse(&content)
                .map_err(|e| anyhow::anyhow!("failed to parse raw file '{raw}': {e}"))?;
            if let Some(url) = req.to_url("https").or_else(|| req.to_url("http")) {
                return Ok(Some(url));
            }
            anyhow::bail!("raw request in '{raw}' missing Host header or invalid path");
        }
        Ok(self.target.clone().or_else(|| match &self.command {
            Some(Commands::Scan(a)) => a.target.clone(),
            _ => None,
        }))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::cli::profile::Profile;

    fn blank_cli() -> Cli {
        Cli {
            command: None,
            profile: None,
            // Point at a path that never exists so auto-discovered files
            // (`./injekt.toml`, `~/.config/...`) still apply, but the
            // explicit slot never shadows them in these unit tests.
            config: Some("/nonexistent-injekt-test-config-9f3a.toml".to_owned()),
            target: None,
            bulk_file: None,
            method: None,
            headers: Vec::new(),
            cookies: None,
            proxy: None,
            threads: None,
            timeout: None,
            retries: None,
            delay: None,
            techniques: Vec::new(),
            params: Vec::new(),
            data: None,
            prefix: None,
            suffix: None,
            safe_chars: None,
            skip_urlencode: false,
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
            string: None,
            not_string: None,
            code: None,
            text_only: false,
            level: None,
            confirm: false,
            ignore_codes: Vec::new(),
            oob_domain: None,
            oob_poll_url: None,
            oob_wait_secs: None,
            tamper: Vec::new(),
            hpp: false,
            chunked: false,
            export_encrypted: None,
            import: None,
            no_redact: false,
            allow_private: false,
            raw_file: None,
            raw_dir: None,
            stdin: false,
            openapi_file: None,
            sitemap_file: None,
            dry_run: false,
            verbose: false,
            no_banner: true,
        }
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn defaults_are_historical_without_profile() {
        let cli = blank_cli();
        assert_eq!(cli.effective_threads(), 5);
        assert_eq!(cli.effective_timeout(), 30);
        assert_eq!(cli.effective_retries(), 3);
        assert_eq!(cli.effective_delay(), 500);
        assert_eq!(cli.effective_rate_limit(), 10.0);
        assert_eq!(cli.effective_jitter(), "750,250");
        assert_eq!(cli.effective_level(), 1);
        assert_eq!(cli.effective_techniques(), vec!["all".to_owned()]);
        assert_eq!(cli.effective_oob_wait_secs(), 5);
        assert_eq!(cli.effective_proxy(), None);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn stealth_profile_defaults() {
        let mut cli = blank_cli();
        cli.profile = Some(Profile::Stealth);
        assert_eq!(cli.effective_threads(), 2);
        assert_eq!(cli.effective_rate_limit(), 3.0);
        assert_eq!(cli.effective_level(), 1);
        assert_eq!(
            cli.effective_techniques(),
            vec!["boolean".to_owned(), "error".to_owned()]
        );
    }

    #[test]
    fn explicit_cli_wins_over_profile() {
        let mut cli = blank_cli();
        cli.profile = Some(Profile::Stealth);
        cli.threads = Some(9);
        cli.level = Some(3);
        cli.techniques = vec!["union".to_owned()];
        assert_eq!(cli.effective_threads(), 9);
        assert_eq!(cli.effective_level(), 3);
        assert_eq!(cli.effective_techniques(), vec!["union".to_owned()]);
    }

    #[test]
    fn config_file_wins_over_profile() {
        use std::io::Write as _;
        let mut path = std::env::temp_dir();
        path.push(format!("injekt-test-{}.toml", std::process::id()));
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "profile = \"stealth\"\nthreads = 3\n").unwrap();
        drop(file);
        let mut cli = blank_cli();
        cli.config = Some(path.to_string_lossy().into_owned());
        // File says stealth + threads 3: threads from file, techniques from profile.
        assert_eq!(cli.effective_threads(), 3);
        assert_eq!(
            cli.effective_techniques(),
            vec!["boolean".to_owned(), "error".to_owned()]
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn explicit_config_validation_rejects_missing_file() {
        let mut cli = blank_cli();
        cli.config = Some("/nonexistent-injekt-test-config-9f3a.toml".to_owned());
        assert!(cli.validate_explicit_config().is_err());
        cli.config = None;
        assert!(cli.validate_explicit_config().is_ok());
    }
}
