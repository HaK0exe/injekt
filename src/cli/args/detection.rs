#![deny(unsafe_code)]

use clap::{Args, ValueEnum};

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
pub(crate) fn parse_max_duration_secs(s: &str) -> Result<u64, String> {
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
pub(crate) fn parse_request_budget(s: &str) -> Result<usize, String> {
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

/// Detection scope and tuning (threads, techniques, budgets, matchers, OOB).
#[derive(Clone, Args)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
pub struct DetectionOpts {
    /// Concurrency [default: 5, profiles/config may override; explicit flag wins]
    #[arg(
        long,
        global = true,
        env = "INJEKT_THREADS",
        help_heading = "Detection"
    )]
    pub threads: Option<usize>,

    /// Aggressiveness level 1-5 (default 1): L1 is the historical payload
    /// budget, L2 doubles it, L3+ tries every payload and widens ORDER BY
    /// enumeration. Absent = current behaviour, byte-identical.
    /// `--profile aggressive` defaults to 3 unless overridden.
    #[arg(long, global = true, value_parser = clap::value_parser!(u8).range(1..=5), env = "INJEKT_LEVEL", help_heading = "Detection")]
    pub level: Option<u8>,

    #[arg(
        long,
        global = true,
        value_delimiter = ',',
        env = "INJEKT_TECHNIQUES",
        help_heading = "Detection"
    )]
    pub techniques: Vec<String>,

    /// WAF tamper scripts (comma-separated): space2comment,space2plus,randomcase,versionedcomment,versionedmorekeywords,charencode,doubleurlencode,hexencode,unicodeencode,overlongutf8,space2tab,space2newline,space2randomblank,space2dash,space2mssqlblank,betweencomment,randomcomments,equaltolike,space2paren,versionedfuzz,jsonunicodeescape,numericobfuscate,linecomment,base64encode (opt-in: breaks boolean differentials). Presets: cloudflare-generic (=randomcase,space2comment,versionedmorekeywords), aggressive (=randomcase,space2paren,versionedfuzz,equaltolike)
    #[arg(
        long,
        global = true,
        value_delimiter = ',',
        env = "INJEKT_TAMPER",
        help_heading = "Detection"
    )]
    pub tamper: Vec<String>,

    /// Test only these parameters (e.g. -p id or -p body:user,cookie:PHPSESSID)
    #[arg(
        short = 'p',
        long = "params",
        global = true,
        value_delimiter = ',',
        help_heading = "Detection"
    )]
    pub params: Vec<String>,

    /// POST body to test (e.g. "id=1&user=admin") — alternative to --raw-file
    #[arg(long, global = true, help_heading = "Detection")]
    pub data: Option<String>,

    /// Force fetch oracle: direct, boolean or time (narrows techniques)
    #[arg(long, global = true, value_parser = ["direct", "boolean", "time"], help_heading = "Detection", hide_short_help = true)]
    pub fetch_using: Option<String>,

    #[arg(long, global = true, env = "INJEKT_DBMS", help_heading = "Detection")]
    pub dbms: Option<String>,

    #[arg(long, global = true, help_heading = "Detection")]
    pub marker: Option<String>,

    /// Response body must contain this substring, otherwise veto finding
    #[arg(long, global = true, help_heading = "Detection")]
    pub string: Option<String>,

    /// Response body must NOT contain this substring, otherwise veto finding
    #[arg(long, global = true, help_heading = "Detection")]
    pub not_string: Option<String>,

    /// Response status must equal this code, otherwise veto finding
    #[arg(long, global = true, help_heading = "Detection")]
    pub code: Option<u16>,

    /// Strip HTML tags/entities before matching and detection
    #[arg(long, global = true, help_heading = "Detection")]
    pub text_only: bool,

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
    #[arg(long = "max-duration", global = true, env = "INJEKT_MAX_DURATION", value_parser = parse_max_duration_secs, help_heading = "Detection")]
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
    #[arg(long = "request-budget", global = true, env = "INJEKT_REQUEST_BUDGET", value_parser = parse_request_budget, help_heading = "Detection")]
    pub request_budget: Option<usize>,

    /// Strict second-pass confirmation (C6 real): re-sondes every confirmed
    /// finding with fresh payloads + derived seed after detection (OOB
    /// excluded, ~2x requests worst-case, documented). Never creates new
    /// findings — only drops those that fail re-validation. In-detection
    /// 3-trial confirmation still applies regardless of this flag.
    #[arg(long, global = true, help_heading = "Detection")]
    pub confirm: bool,

    /// Deterministic run seed, recorded in the JSON report (`seed`) for
    /// reproducibility (C1 metrology). Seeds all non-cryptographic RNG
    /// (tamper scripts, request jitter, UA rotation, retry backoff): runs
    /// with the same seed are deterministic. Crypto randomness (export
    /// salt/nonce) always stays on OS randomness and ignores this seed.
    #[arg(long, global = true, env = "INJEKT_SEED", help_heading = "Detection")]
    pub seed: Option<u64>,

    /// HTTP status codes treated as negative probes during detection
    /// (e.g. --ignore-code 429,503): an ignored response never yields a
    /// finding. Baseline collection (incl. WAF detection) runs before this
    /// filter and is never ignored.
    #[arg(
        long = "ignore-code",
        global = true,
        value_delimiter = ',',
        help_heading = "Detection"
    )]
    pub ignore_codes: Vec<u16>,

    /// OOB collaborator base domain (e.g. x.oastify.com) — enables techniques/oob DNS/HTTP probes (OPT-IN, requires operator infra)
    #[arg(
        long,
        global = true,
        env = "INJEKT_OOB_DOMAIN",
        help_heading = "Detection",
        hide_short_help = true
    )]
    pub oob_domain: Option<String>,

    /// Generic collaborator poll URL for OOB confirmation (may contain {token}); without it, OOB probes are sent but never auto-confirmed
    #[arg(
        long,
        global = true,
        env = "INJEKT_OOB_POLL_URL",
        requires = "oob_domain",
        help_heading = "Detection",
        hide_short_help = true
    )]
    pub oob_poll_url: Option<String>,

    /// Seconds to wait for the async DB-side OOB query before polling the collaborator [default: 5]
    #[arg(
        long,
        global = true,
        env = "INJEKT_OOB_WAIT_SECS",
        requires = "oob_domain",
        help_heading = "Detection",
        hide_short_help = true
    )]
    pub oob_wait_secs: Option<u64>,

    /// Opt-in AI suggestion second-pass: after a finding-less run blocked by
    /// WAF (`403/406/429`), app-filter (`400` streak) or dropped `--confirm`,
    /// ask an external LLM for up to `--ai-max-suggestions` boolean TRUE/FALSE
    /// pairs, validate them locally, then re-probe (bounded, silent on failure).
    /// OFF by default = 0 LLM call, historical behaviour byte-identical.
    /// Sends abstract signals only (context summary, DBMS belief, WAF vendor,
    /// payload skeletons) — never cookies/headers/target body/extracted data.
    #[arg(
        long = "ai-suggest",
        global = true,
        env = "INJEKT_AI_SUGGEST",
        help_heading = "Detection",
        hide_short_help = true
    )]
    pub ai_suggest: bool,

    /// LLM provider wire format for `--ai-suggest`: `openai` (Chat Completions)
    /// or `anthropic` (Messages). Required when `--ai-suggest` is set.
    #[arg(
        long = "ai-provider",
        global = true,
        env = "INJEKT_AI_PROVIDER",
        value_parser = ["openai", "anthropic"],
        requires = "ai_suggest",
        help_heading = "Detection",
        hide_short_help = true
    )]
    pub ai_provider: Option<String>,

    /// LLM endpoint URL for `--ai-suggest` (e.g. `http://localhost:11434/v1/chat/completions`
    /// for an OpenAI-compatible local gateway, or `https://api.anthropic.com/v1/messages`).
    /// Required when `--ai-suggest` is set. Prefer a local endpoint (OPSEC).
    #[arg(
        long = "ai-endpoint",
        global = true,
        env = "INJEKT_AI_ENDPOINT",
        requires = "ai_suggest",
        help_heading = "Detection",
        hide_short_help = true
    )]
    pub ai_endpoint: Option<String>,

    /// LLM model name for `--ai-suggest` (e.g. `llama3.1:8b`, `claude-sonnet-4-5`).
    /// Required when `--ai-suggest` is set.
    #[arg(
        long = "ai-model",
        global = true,
        env = "INJEKT_AI_MODEL",
        requires = "ai_suggest",
        help_heading = "Detection",
        hide_short_help = true
    )]
    pub ai_model: Option<String>,

    /// LLM API key for `--ai-suggest` (env `INJEKT_AI_API_KEY` preferred; never
    /// put secrets in config files). Optional: local gateways often need none.
    /// Fully redacted in logs and `Debug`.
    #[arg(
        long = "ai-api-key",
        global = true,
        env = "INJEKT_AI_API_KEY",
        requires = "ai_suggest",
        help_heading = "Detection",
        hide_short_help = true
    )]
    pub ai_api_key: Option<String>,

    /// Max LLM-suggested TRUE/FALSE pairs to re-probe per parameter [default: 3, range 1..=5].
    /// 1 pair = 2 requests, so the default costs at most 6 requests per parameter.
    #[arg(
        long = "ai-max-suggestions",
        global = true,
        default_value_t = 3,
        value_parser = clap::value_parser!(u8).range(1..=5),
        env = "INJEKT_AI_MAX_SUGGESTIONS",
        help_heading = "Detection",
        hide_short_help = true
    )]
    pub ai_max_suggestions: u8,

    /// HTTP timeout in seconds for LLM provider calls [default: 30].
    #[arg(
        long = "ai-timeout",
        global = true,
        default_value_t = 30,
        env = "INJEKT_AI_TIMEOUT",
        help_heading = "Detection",
        hide_short_help = true
    )]
    pub ai_timeout: u64,

    /// Payload generation mode (Track A grammar, deterministic + seeded):
    /// `off` = historical lists only (default, byte-identical),
    /// `conservative` = historical first, then core-predicate pairs
    /// (`EqInt`/`EqStr`/`Like`/`In`/`Between` × fences/logics) up to
    /// `--max-generated`, `aggressive` = whole historical list plus all
    /// predicates (core + `Rlike`/`CaseWhen`/`Div`/`Xor`/`ChrFunc`,
    /// dialect-aware). Generated pairs are deduped against history
    /// (zero redundant requests) and flow through the unchanged tamper /
    /// evaluation / budget pipeline.
    #[arg(
        long = "generative",
        global = true,
        env = "INJEKT_GENERATIVE",
        value_parser = ["off", "conservative", "aggressive"],
        help_heading = "Detection",
        hide_short_help = true
    )]
    pub generative: Option<String>,

    /// Max generated pairs per parameter and technique [default: 4, range 0..=32].
    /// `0` disables generation even when `--generative` is set. 32 covers the
    /// max cyclic gap between spaceless shapes for any seed rotation.
    #[arg(
        long = "max-generated",
        global = true,
        default_value_t = 4,
        value_parser = clap::value_parser!(u8).range(0..=32),
        env = "INJEKT_MAX_GENERATED",
        help_heading = "Detection",
        hide_short_help = true
    )]
    pub max_generated: u8,
}

// Manual `Debug` for `DetectionOpts`: `--data` may carry `password=` secrets
// and `oob_domain` identifies operator infra — both scrubbed, not raw;
// `--oob-poll-url` and `--ai-api-key` are fully redacted; `--ai-endpoint`
// is scrubbed (may embed userinfo/secrets in query).
impl core::fmt::Debug for DetectionOpts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let redacted_opt = |v: &Option<String>| v.as_ref().map(|_| "[REDACTED]".to_owned());
        let scrub = crate::session::scrubber::Scrubber::new(false);
        let scrubbed_opt = |v: &Option<String>| v.as_ref().map(|s| scrub.scrub(s));
        f.debug_struct("DetectionOpts")
            .field("threads", &self.threads)
            .field("level", &self.level)
            .field("techniques", &self.techniques)
            .field("tamper", &self.tamper)
            .field("params", &self.params)
            .field("data", &scrubbed_opt(&self.data))
            .field("fetch_using", &self.fetch_using)
            .field("dbms", &self.dbms)
            .field("marker", &self.marker)
            .field("string", &self.string)
            .field("not_string", &self.not_string)
            .field("code", &self.code)
            .field("text_only", &self.text_only)
            .field("max_duration", &self.max_duration)
            .field("request_budget", &self.request_budget)
            .field("confirm", &self.confirm)
            .field("seed", &self.seed)
            .field("ignore_codes", &self.ignore_codes)
            .field("oob_domain", &scrubbed_opt(&self.oob_domain))
            .field("oob_poll_url", &redacted_opt(&self.oob_poll_url))
            .field("oob_wait_secs", &self.oob_wait_secs)
            .field("ai_suggest", &self.ai_suggest)
            .field("ai_provider", &self.ai_provider)
            .field("ai_endpoint", &scrubbed_opt(&self.ai_endpoint))
            .field("ai_model", &self.ai_model)
            .field("ai_api_key", &redacted_opt(&self.ai_api_key))
            .field("ai_max_suggestions", &self.ai_max_suggestions)
            .field("ai_timeout", &self.ai_timeout)
            .field("generative", &self.generative)
            .field("max_generated", &self.max_generated)
            .finish_non_exhaustive()
    }
}
