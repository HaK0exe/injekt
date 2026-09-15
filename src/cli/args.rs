#![deny(unsafe_code)]

use crate::cli::profile::Profile;
use clap::{Parser, Subcommand, ValueEnum};
use secrecy::SecretString;

/// Upper bound for `--max-duration` (24h, 86400s). Rejects absurd values at
/// parse time so [`crate::engine::orchestrator::BudgetConfig::detection_deadline`]
/// `checked_add` can never overflow from user input (overflow beforehand
/// silently became `None` = unlimited).
pub const MAX_DURATION_SECS: u64 = 86_400;
/// Upper bound for `--request-budget` (1M requests). Rejects absurd values at
/// parse time; the A1 evasion ceiling (~1032 req live) stays far below it.
pub const MAX_REQUEST_BUDGET: usize = 1_000_000;

/// Parse `--max-duration` / `INJEKT_MAX_DURATION`: `0..=86400` seconds.
/// `0` trips immediately (early-break path, tested); absent = unlimited.
fn parse_max_duration_secs(s: &str) -> Result<u64, String> {
    let v: u64 = s
        .trim()
        .parse()
        .map_err(|_| format!("invalid --max-duration '{s}': expected 0..={MAX_DURATION_SECS}"))?;
    if v > MAX_DURATION_SECS {
        return Err(format!(
            "invalid --max-duration '{v}': max is {MAX_DURATION_SECS}s (24h)"
        ));
    }
    Ok(v)
}

/// Parse `--request-budget` / `INJEKT_REQUEST_BUDGET`: `0..=1000000` requests.
/// `0` trips immediately (cooperative stop, tested); absent = unlimited.
fn parse_request_budget(s: &str) -> Result<usize, String> {
    let v: usize = s.trim().parse().map_err(|_| {
        format!("invalid --request-budget '{s}': expected 0..={MAX_REQUEST_BUDGET}")
    })?;
    if v > MAX_REQUEST_BUDGET {
        return Err(format!(
            "invalid --request-budget '{v}': max is {MAX_REQUEST_BUDGET}"
        ));
    }
    Ok(v)
}

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
    Nosql,
    All,
}

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

#[derive(Parser, Clone)]
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

    /// Report serialization for `--output` files: `json` (default, historical
    /// `JsonReport` schema + C7 calibrated fields), `sarif` (2.1.0, CI
    /// code-scanning), `junit` (CI test cases), `md` (human-sendable with
    /// remediation). Console output is unchanged. All formats are scrubbed.
    #[arg(
        long,
        global = true,
        value_enum,
        default_value = "json",
        env = "INJEKT_FORMAT"
    )]
    pub format: ReportFormat,

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

    /// Global detection time budget in seconds (`--max-duration 120`, range
    /// `0..=86400`, OPT-IN).
    /// SCOPE: detection phase only — the clock starts in `run_detection`,
    /// AFTER baseline + context (baseline/context/fingerprint/enumeration are
    /// NOT covered; `--max-duration` never bounds the total run).
    /// `None` (default) = unlimited, historical behaviour byte-identical.
    /// OPT-IN hors profils/config-file: `--profile` and `injekt.toml` never
    /// set it; only `--max-duration N` / `INJEKT_MAX_DURATION` enables the
    /// cooperative stop. Values above 86400s (24h) are rejected at parse time.
    /// When set, the per-parameter detection loop breaks early once the
    /// shared detection clock exceeds it (warn + clean `Done`, no new
    /// findings invented).
    #[arg(long = "max-duration", global = true, env = "INJEKT_MAX_DURATION", value_parser = parse_max_duration_secs)]
    pub max_duration: Option<u64>,

    /// Global request budget for a run (`--request-budget 25`, range
    /// `0..=1000000`, OPT-IN).
    /// `None` (default) = unlimited, historical behaviour byte-identical
    /// (A1 evasion needs ~1032 req live: never cap by default).
    /// OPT-IN hors profils/config-file: `--profile` and `injekt.toml` never
    /// set it; only `--request-budget N` / `INJEKT_REQUEST_BUDGET` enables
    /// the cooperative global stop. Values above 1000000 are rejected.
    /// When set, detection stops cooperatively once the shared
    /// `SessionState::request_count` reaches it: current technique finishes,
    /// no new technique starts (warn + clean `Done`, never an error, never
    /// a new finding). Per-parameter [`RequestBudget`] is seeded with the
    /// same value for scheduler visibility (`budget_total`), so the
    /// authoritative global check lives in the orchestrator (concurrent
    /// params may overshoot by one technique each).
    #[arg(long = "request-budget", global = true, env = "INJEKT_REQUEST_BUDGET", value_parser = parse_request_budget)]
    pub request_budget: Option<usize>,

    /// Strict second-pass confirmation (C6 real): re-sondes every confirmed
    /// finding with fresh payloads + derived seed after detection (OOB
    /// excluded, ~2x requests worst-case, documented). Never creates new
    /// findings — only drops those that fail re-validation. In-detection
    /// 3-trial confirmation still applies regardless of this flag.
    #[arg(long, global = true)]
    pub confirm: bool,

    /// Disable the C5-tardif mini-mutation second-pass (escape hatch).
    /// Default is mutation ON but strictly scoped: only on already-confirmed
    /// findings, only from the `--confirm` second-pass, ≤4 variants / ≤8
    /// requests per finding, seeded, traced (`mutation:<famille>`), silent
    /// failure (the original finding is kept). No mutation ever runs in
    /// first-pass detection or on unconfirmed targets.
    #[arg(long = "no-mutation", global = true)]
    pub no_mutation: bool,

    /// One-line reasoning verdict for a finding (`--explain id@query`):
    /// prints `TRUE≈baseline 0.91, FALSE≠baseline 0.22, 3/3, waf=none,
    /// 14 req, seed 42` after the scan (or from `replay --file`).
    /// No extra requests; reads the RAM-only trace + evidence.
    #[arg(long, global = true, env = "INJEKT_EXPLAIN")]
    pub explain: Option<String>,

    /// Deterministic run seed, recorded in the JSON report (`seed`) for
    /// reproducibility (C1 metrology). Seeds all non-cryptographic RNG
    /// (tamper scripts, request jitter, UA rotation, retry backoff): runs
    /// with the same seed are deterministic. Crypto randomness (export
    /// salt/nonce) always stays on OS randomness and ignores this seed.
    #[arg(long, global = true, env = "INJEKT_SEED")]
    pub seed: Option<u64>,

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

    /// WAF tamper scripts (comma-separated): space2comment,space2plus,randomcase,versionedcomment,versionedmorekeywords,charencode,doubleurlencode,hexencode,unicodeencode,overlongutf8,space2tab,space2newline,space2randomblank,space2dash,space2mssqlblank,betweencomment,randomcomments,equaltolike,space2paren,versionedfuzz,jsonunicodeescape,numericobfuscate,linecomment,base64encode (opt-in: breaks boolean differentials). Presets: cloudflare-generic (=randomcase,space2comment,versionedmorekeywords), aggressive (=randomcase,space2paren,versionedfuzz,equaltolike)
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

    /// Legacy flag: `scan --import` is rejected (use `replay --file` to
    /// inspect an encrypted export, `recon import --file` for candidates).
    #[arg(long, global = true)]
    pub import: Option<String>,

    #[arg(long, global = true)]
    pub no_redact: bool,

    #[arg(long, global = true)]
    pub allow_private: bool,

    /// C13 Knowledge Engine opt-in (défaut OFF = RAM-only, 0 lecture/écriture,
    /// boost 1.0 neutre byte-identique). Activé : lecture au boot de
    /// `~/.cache/injekt/knowledge.json` (ou `--knowledge-path` /
    /// `INJEKT_KNOWLEDGE_PATH`), boost `1+alpha` borné `[0.5,1.5]` puis clamp
    /// scheduler `[0.5,2.0]`, écriture post-run (fusion, fsync, perms 0600).
    /// Agrégats anonymes `(technique, dbms, contexte)` uniquement — jamais de
    /// cible/param/seed/secret persisté.
    #[arg(long, global = true, env = "INJEKT_ALLOW_KNOWLEDGE")]
    pub allow_knowledge: bool,

    /// Chemin du store knowledge (défaut `~/.cache/injekt/knowledge.json`).
    /// Inutilisé quand `--allow-knowledge` est absent (aucune IO).
    #[arg(long, global = true, env = "INJEKT_KNOWLEDGE_PATH")]
    pub knowledge_path: Option<String>,

    /// Second-order actif borné (Option B, lab only, même-origine) : stocke
    /// un marqueur bénin `u+8hex` (payload `'<marker>'` style union, jamais
    /// de RCE/stacked) puis revisite `--second-order-revisit-url` (ex:
    /// `/admin`, max 2 GET séquentiels). OFF par défaut = 0 requête extra,
    /// chemin byte-identique.
    #[arg(long = "second-order", global = true, env = "INJEKT_SECOND_ORDER")]
    pub second_order: bool,

    /// URL de revisit second-order : chemin même-origine (ex: `/admin`) ou
    /// URL absolue même-origine que la cible. Schéma/host/port différent =
    /// erreur. Requis quand `--second-order` est actif.
    #[arg(long, global = true, env = "INJEKT_SECOND_ORDER_REVISIT_URL")]
    pub second_order_revisit_url: Option<String>,

    /// Nombre max de params Body/Query/Header stockés en second-order [default: 8, range 1..=32].
    /// 1 store + max 2 revisits GET par param, séquentiel, `RequestClass::Default`.
    /// Les headers exotiques (User-Agent/X-Forwarded-For/Referer, souvent loggés
    /// en base) sont couverts comme les Body/Query.
    #[arg(
        long,
        global = true,
        default_value_t = 8,
        value_parser = clap::value_parser!(u8).range(1..=32),
        env = "INJEKT_SECOND_ORDER_MAX_STORES"
    )]
    pub second_order_max_stores: u8,

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

    /// Allow overwriting existing `--output` files and absolute/`..` output
    /// paths (explicit opt-in, OPSEC-sensitive: reports may contain secrets).
    #[arg(long, global = true)]
    pub force: bool,
}

// Manual `Debug` so `--cookies` / `--proxy` / `--headers` / `--oob-poll-url`
// never appear in logs, panics or `tracing` records (OPSEC: secrets stay in
// `SecretString` / scrubbed output only). `--target` / `--data` may carry
// `?token=` / `password=` / `user:pass@` secrets and `oob_domain` identifies
// operator infra — all three are scrubbed, not printed raw.
impl core::fmt::Debug for Cli {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let redacted_opt = |v: &Option<String>| v.as_ref().map(|_| "[REDACTED]".to_owned());
        let redacted_headers: Vec<&str> = self.headers.iter().map(|_| "[REDACTED]").collect();
        let scrub = crate::session::scrubber::Scrubber::new(false);
        let scrubbed_opt = |v: &Option<String>| v.as_ref().map(|s| scrub.scrub(s));
        f.debug_struct("Cli")
            .field("command", &self.command)
            .field("profile", &self.profile)
            .field("config", &self.config)
            .field("target", &scrubbed_opt(&self.target))
            .field("bulk_file", &self.bulk_file)
            .field("method", &self.method)
            .field("headers", &redacted_headers)
            .field("cookies", &redacted_opt(&self.cookies))
            .field("proxy", &redacted_opt(&self.proxy))
            .field("threads", &self.threads)
            .field("timeout", &self.timeout)
            .field("retries", &self.retries)
            .field("delay", &self.delay)
            .field("techniques", &self.techniques)
            .field("params", &self.params)
            .field("data", &scrubbed_opt(&self.data))
            .field("prefix", &self.prefix)
            .field("suffix", &self.suffix)
            .field("safe_chars", &self.safe_chars)
            .field("skip_urlencode", &self.skip_urlencode)
            .field("fetch_using", &self.fetch_using)
            .field("dbms", &self.dbms)
            .field("extract", &self.extract)
            .field("dbs", &self.dbs)
            .field("tables", &self.tables)
            .field("columns", &self.columns)
            .field("dump", &self.dump)
            .field("banner", &self.banner)
            .field("current_user", &self.current_user)
            .field("current_db", &self.current_db)
            .field("hostname", &self.hostname)
            .field("db", &self.db)
            .field("table", &self.table)
            .field("column", &self.column)
            .field("start", &self.start)
            .field("stop", &self.stop)
            .field("count", &self.count)
            .field("output", &self.output)
            .field("format", &self.format)
            .field("rate_limit", &self.rate_limit)
            .field("jitter", &self.jitter)
            .field("marker", &self.marker)
            .field("string", &self.string)
            .field("not_string", &self.not_string)
            .field("code", &self.code)
            .field("text_only", &self.text_only)
            .field("level", &self.level)
            .field("max_duration", &self.max_duration)
            .field("request_budget", &self.request_budget)
            .field("confirm", &self.confirm)
            .field("no_mutation", &self.no_mutation)
            .field("explain", &self.explain)
            .field("seed", &self.seed)
            .field("ignore_codes", &self.ignore_codes)
            .field("oob_domain", &scrubbed_opt(&self.oob_domain))
            .field("oob_poll_url", &redacted_opt(&self.oob_poll_url))
            .field("oob_wait_secs", &self.oob_wait_secs)
            .field("tamper", &self.tamper)
            .field("hpp", &self.hpp)
            .field("chunked", &self.chunked)
            .field("export_encrypted", &self.export_encrypted)
            .field("import", &self.import)
            .field("no_redact", &self.no_redact)
            .field("allow_private", &self.allow_private)
            .field("allow_knowledge", &self.allow_knowledge)
            .field("knowledge_path", &self.knowledge_path)
            .field("second_order", &self.second_order)
            .field(
                "second_order_revisit_url",
                &scrubbed_opt(&self.second_order_revisit_url),
            )
            .field("second_order_max_stores", &self.second_order_max_stores)
            .field("raw_file", &self.raw_file)
            .field("raw_dir", &self.raw_dir)
            .field("stdin", &self.stdin)
            .field("openapi_file", &self.openapi_file)
            .field("sitemap_file", &self.sitemap_file)
            .field("dry_run", &self.dry_run)
            .field("verbose", &self.verbose)
            .field("no_banner", &self.no_banner)
            .field("force", &self.force)
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
    Init(InitArgs),
    /// Print shell completions (`bash|zsh|fish|powershell|elvish`).
    Completions(CompletionsArgs),
    /// Print a man page (roff) to stdout.
    Man(ManArgs),
    /// Run as an MCP server over stdio (for Claude Code, Codex, `OpenCode`, Cursor, VS Code).
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
    /// Clamped to `>= 1`: `--threads 0` would make `buffer_unordered(0)`
    /// stall forever (self-DoS).
    #[must_use]
    pub fn effective_threads(&self) -> usize {
        if let Some(v) = self.threads {
            return v.max(1);
        }
        let file = self.file_snapshot();
        if let Some(v) = file.threads {
            return v.max(1);
        }
        self.active_profile().map_or(5, Profile::threads).max(1)
    }

    /// Effective request timeout (seconds). Precedence: CLI/env > file > profile > 30.
    /// Clamped to `>= 1`: `--timeout 0` would time out every request.
    #[must_use]
    pub fn effective_timeout(&self) -> u64 {
        if let Some(v) = self.timeout {
            return v.max(1);
        }
        let file = self.file_snapshot();
        if let Some(v) = file.timeout {
            return v.max(1);
        }
        self.active_profile()
            .map_or(30, Profile::timeout_secs)
            .max(1)
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

    /// Effective deterministic seed. Precedence: CLI/env > file.
    /// Profiles never set a seed (reproducibility is explicit opt-in).
    #[must_use]
    pub fn effective_seed(&self) -> Option<u64> {
        if let Some(v) = self.seed {
            return Some(v);
        }
        self.file_snapshot().seed
    }

    /// Effective global detection time budget in seconds (Phase 3).
    /// `None` (default) = unlimited, historical behaviour byte-identical.
    /// Profiles / config file never set it (explicit opt-in only).
    #[must_use]
    pub const fn effective_max_duration(&self) -> Option<u64> {
        self.max_duration
    }

    /// Effective global request budget (CODE calibration).
    /// `None` (default) = unlimited, historical behaviour byte-identical.
    /// Profiles / config file never set it (explicit opt-in only, like
    /// `--max-duration`): only `--request-budget N` / `INJEKT_REQUEST_BUDGET`
    /// enables the cooperative global stop.
    #[must_use]
    pub const fn effective_request_budget(&self) -> Option<usize> {
        self.request_budget
    }

    /// C13 opt-in gate: `false` par défaut → RAM-only, aucune IO knowledge,
    /// boost neutre `1.0` (chemin byte-identique au sans-knowledge).
    #[must_use]
    pub const fn knowledge_enabled(&self) -> bool {
        self.allow_knowledge
    }

    /// Borne effective second-order `1..=32` (clap garantit déjà la range ;
    /// clamp défensif pour les constructions manuelles). Défaut 8.
    #[must_use]
    pub const fn effective_second_order_max_stores(&self) -> usize {
        let v = self.second_order_max_stores as usize;
        if v < 1 {
            1
        } else if v > 32 {
            32
        } else {
            v
        }
    }

    /// Chemin effectif du store (`--knowledge-path` > `INJEKT_KNOWLEDGE_PATH` >
    /// `~/.cache/injekt/knowledge.json`). Non résolu / non touché quand OFF.
    #[must_use]
    pub fn effective_knowledge_path(&self) -> std::path::PathBuf {
        crate::reasoning::knowledge::resolve_knowledge_path(self.knowledge_path.as_deref())
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

    /// Fused raw request: `--raw-file` base + `--method` / `--headers` /
    /// `--cookies` / `--data` overlays. CLI flags win over the file; the file
    /// wins over `--data` (with a warning when both carry a body).
    #[must_use]
    pub fn merged_raw_request(&self) -> Option<crate::target::raw_request::RawRequest> {
        let mut base = self.raw_request();
        // `--data` alone becomes a synthetic POST raw (same path as raw-file).
        if base.is_none()
            && let Some(data) = self.data.as_deref()
        {
            let trimmed = data.trim();
            if !trimmed.is_empty() {
                base = crate::engine::orchestrator::synthetic_raw_from_data(trimmed);
            }
        }
        // `--headers`/`--cookies` alone (no file, no `--data`) still need a
        // raw to fuse into, otherwise cookie/header params are never
        // discovered and the flags only ride along passively.
        if base.is_none()
            && (!self.headers.is_empty()
                || self
                    .cookies
                    .as_deref()
                    .is_some_and(|c| !c.trim().is_empty()))
        {
            base = Some(crate::target::raw_request::RawRequest {
                method: "GET".to_owned(),
                path: "/".to_owned(),
                headers: std::collections::HashMap::new(),
                body: None,
                http_version: "HTTP/1.1".to_owned(),
            });
        }
        let mut req = base?;
        // `--method` overrides the file method (validated later; uppercased here).
        if let Some(m) = self.method.as_deref() {
            let m = m.trim();
            if !m.is_empty() {
                req.method = m.to_ascii_uppercase();
            }
        }
        // `--headers "Name: value"` override / extend the file headers
        // (keys are lowercased, matching `RawRequest::parse` canonical form).
        for h in &self.headers {
            let Some((name, value)) = h.split_once(':') else {
                continue;
            };
            let key = name.trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            req.headers.insert(key, value.trim().to_owned());
        }
        // `--cookies` merges with the file `Cookie` header (`; `-joined),
        // preserving both the Burp session and the CLI session.
        if let Some(cookies) = self.cookies.as_deref() {
            let cookies = cookies.trim();
            if !cookies.is_empty() {
                let merged = match req.headers.get("cookie") {
                    Some(existing) if !existing.trim().is_empty() => {
                        format!("{}; {cookies}", existing.trim())
                    }
                    _ => cookies.to_owned(),
                };
                req.headers.insert("cookie".to_owned(), merged);
            }
        }
        // `--data` fills an empty body only; a file body always wins.
        if let Some(data) = self.data.as_deref() {
            let trimmed = data.trim();
            let file_has_body = req.body.as_deref().is_some_and(|b| !b.trim().is_empty());
            if !trimmed.is_empty() && !file_has_body {
                req.body = Some(trimmed.to_owned());
                if !req.headers.contains_key("content-type") {
                    let kind = crate::target::structured::sniff_kind(None, trimmed);
                    let ct = match kind {
                        crate::target::structured::StructuredKind::Json => "application/json",
                        crate::target::structured::StructuredKind::Xml => "application/xml",
                        _ => "application/x-www-form-urlencoded",
                    };
                    req.headers.insert("content-type".to_owned(), ct.to_owned());
                }
            }
        }
        Some(req)
    }

    /// `true` when the proxy performs remote DNS (`socks5h://`): local
    /// DNS-time SSRF resolution must be skipped (no local leak, no false
    /// `.onion` failure). Lexical + IP-literal checks still apply.
    #[must_use]
    pub fn uses_remote_dns(&self) -> bool {
        self.effective_proxy()
            .is_some_and(|p| p.to_ascii_lowercase().starts_with("socks5h://"))
    }

    /// Normalized `--dbms` hint (`mysql|postgres|mssql|oracle|sqlite`) or `None`
    /// when absent/unknown (unknown warns, falls back to auto-fingerprint).
    #[must_use]
    pub fn normalized_dbms_hint(&self) -> Option<String> {
        let raw = self.dbms.as_deref()?;
        let v = raw.trim().to_ascii_lowercase();
        // Accept common aliases.
        let norm = match v.as_str() {
            "mysql" | "mariadb" | "my" => "mysql",
            "postgres" | "postgresql" | "pg" | "pgsql" => "postgres",
            "mssql" | "sqlserver" | "sql-server" | "tsql" => "mssql",
            "oracle" | "ora" => "oracle",
            "sqlite" => "sqlite",
            _ => {
                tracing::warn!(dbms=%raw, "unknown --dbms, ignoring (auto-fingerprint)");
                return None;
            }
        };
        Some(norm.to_owned())
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
            format: ReportFormat::Json,
            rate_limit: None,
            jitter: None,
            marker: None,
            string: None,
            not_string: None,
            code: None,
            text_only: false,
            level: None,
            max_duration: None,
            request_budget: None,
            confirm: false,
            no_mutation: false,
            explain: None,
            seed: None,
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
            allow_knowledge: false,
            knowledge_path: None,
            second_order: false,
            second_order_revisit_url: None,
            second_order_max_stores: 8,
            raw_file: None,
            raw_dir: None,
            stdin: false,
            openapi_file: None,
            sitemap_file: None,
            dry_run: false,
            verbose: false,
            no_banner: true,
            force: false,
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
    fn seed_defaults_to_none_and_ignores_profile() {
        let cli = blank_cli();
        assert_eq!(cli.effective_seed(), None);
        let mut cli = blank_cli();
        cli.profile = Some(Profile::Stealth);
        assert_eq!(cli.effective_seed(), None);
    }

    #[test]
    fn seed_cli_wins_over_file() {
        use std::io::Write as _;
        let mut path = std::env::temp_dir();
        path.push(format!("injekt-test-seed-{}.toml", std::process::id()));
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "seed = 42\n").unwrap();
        drop(file);
        let mut cli = blank_cli();
        cli.config = Some(path.to_string_lossy().into_owned());
        assert_eq!(cli.effective_seed(), Some(42));
        cli.seed = Some(7);
        assert_eq!(cli.effective_seed(), Some(7));
        std::fs::remove_file(&path).unwrap();
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

    #[test]
    fn max_duration_defaults_to_none_byte_identical() {
        // Phase 3: default None = unlimited, historical behaviour.
        let cli = blank_cli();
        assert_eq!(cli.effective_max_duration(), None);
        let mut cli = blank_cli();
        cli.max_duration = Some(120);
        assert_eq!(cli.effective_max_duration(), Some(120));
    }

    #[test]
    fn max_duration_parses_from_cli() {
        use clap::Parser as _;
        let cli =
            Cli::try_parse_from(["injekt", "--max-duration", "60"]).unwrap_or_else(|_| blank_cli());
        assert_eq!(cli.effective_max_duration(), Some(60));
        let cli_default = Cli::try_parse_from(["injekt"]).unwrap_or_else(|_| blank_cli());
        // Explicit config slot may shadow auto-discovery in this harness;
        // the flag itself must be None when absent.
        assert!(
            cli_default.max_duration.is_none(),
            "default --max-duration must be None"
        );
    }

    #[test]
    fn request_budget_defaults_to_none_byte_identical() {
        // CODE calibration: default None = unlimited, historical behaviour
        // (A1 evasion ~1032 req live must never trip a default cap).
        let cli = blank_cli();
        assert_eq!(cli.effective_request_budget(), None);
        let mut cli = blank_cli();
        cli.request_budget = Some(25);
        assert_eq!(cli.effective_request_budget(), Some(25));
    }

    #[test]
    fn request_budget_parses_from_cli() {
        use clap::Parser as _;
        let cli = Cli::try_parse_from(["injekt", "--request-budget", "25"])
            .unwrap_or_else(|_| blank_cli());
        assert_eq!(cli.effective_request_budget(), Some(25));
        let cli_default = Cli::try_parse_from(["injekt"]).unwrap_or_else(|_| blank_cli());
        assert!(
            cli_default.request_budget.is_none(),
            "default --request-budget must be None"
        );
    }

    #[test]
    fn budget_parsers_reject_absurd_values() {
        // PR20: absurd CLI values are rejected at parse time (no silent
        // `checked_add` overflow → unlimited, no unbounded request flood).
        assert_eq!(super::parse_max_duration_secs("0"), Ok(0));
        assert_eq!(super::parse_max_duration_secs("86400"), Ok(86_400));
        assert!(super::parse_max_duration_secs("86401").is_err());
        assert!(super::parse_max_duration_secs("99999999").is_err());
        assert!(super::parse_max_duration_secs("nope").is_err());
        assert_eq!(super::parse_request_budget("0"), Ok(0));
        assert_eq!(super::parse_request_budget("1000000"), Ok(1_000_000));
        assert!(super::parse_request_budget("1000001").is_err());
        assert!(super::parse_request_budget("nope").is_err());
    }

    #[test]
    fn dbms_hint_normalizes_sqlite_and_aliases() {
        // P0-3: `--dbms sqlite` must survive normalization (was: rejected as
        // unknown, silently falling back to auto-fingerprint).
        let mut cli = blank_cli();
        cli.dbms = Some("sqlite".to_owned());
        assert_eq!(cli.normalized_dbms_hint().as_deref(), Some("sqlite"));
        cli.dbms = Some("  SQLITE ".to_owned());
        assert_eq!(cli.normalized_dbms_hint().as_deref(), Some("sqlite"));
        cli.dbms = Some("pg".to_owned());
        assert_eq!(cli.normalized_dbms_hint().as_deref(), Some("postgres"));
        cli.dbms = Some("nope".to_owned());
        assert_eq!(cli.normalized_dbms_hint(), None);
        let cli = blank_cli();
        assert_eq!(cli.normalized_dbms_hint(), None);
    }

    #[test]
    fn budget_flags_reject_absurd_cli_values() {
        // End-to-end through clap (flags + env share the same value_parser).
        use clap::Parser as _;
        assert!(Cli::try_parse_from(["injekt", "--max-duration", "99999999"]).is_err());
        assert!(Cli::try_parse_from(["injekt", "--request-budget", "99999999"]).is_err());
        assert_eq!(
            Cli::try_parse_from(["injekt", "--max-duration", "120"])
                .unwrap_or_else(|_| blank_cli())
                .effective_max_duration(),
            Some(120)
        );
    }
}
