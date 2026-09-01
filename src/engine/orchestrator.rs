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
            techniques: vec!["boolean".to_owned(), "time".to_owned(), "error".to_owned()],
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
        let params = if marker_set.has_any() {
            // Marker mode: create synthetic params for each marker type
            let mut v = Vec::new();
            if marker_set.asterisk {
                v.push(TargetParameter::new(
                    "marker_asterisk",
                    ParameterLocation::Query,
                    "*",
                ));
            }
            if marker_set.section {
                v.push(TargetParameter::new(
                    "marker_section",
                    ParameterLocation::Query,
                    "§",
                ));
            }
            if marker_set.double_brace {
                v.push(TargetParameter::new(
                    "marker_brace",
                    ParameterLocation::Query,
                    "{{}}",
                ));
            }
            if v.is_empty() {
                crate::target::parameters::collect_from_url_query(&target)
            } else {
                v
            }
        } else {
            crate::target::parameters::collect_from_url_query(&target)
        };
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
        let marker_set_clone = marker_set;

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
                    pb2.inc(1);
                }
            })
            .buffer_unordered(concurrency);

        stream.collect::<Vec<()>>().await;
        pb2.finish_with_message("detection done");
        current = EngineState::Fingerprint;
        info!(state=?current, "phase fingerprint");

        // Fingerprint (simplified): if any finding, try to label dbms via error pattern
        {
            let st = self.state.read().await;
            for f in st.findings().to_vec() {
                let _ = f; // already captured; fingerprint would refine dbms here
            }
        }

        if self.config.extract {
            current = EngineState::Extraction;
            info!(state=?current, "phase extraction — inference");
            // extraction would happen here via ExtractionEngine, storing SecretString zeroized after report
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
    if marker_set.asterisk && s.contains('*') {
        s = s.replace('*', payload);
        return s;
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
            let true_url =
                inject_param_or_marker(target, target_str, param, &p.true_payload, marker_set);
            let false_url =
                inject_param_or_marker(target, target_str, param, &p.false_payload, marker_set);
            let (true_body, true_ms) =
                fetch_body_and_time_spec(client, true_url, state, cancel).await;
            let (false_body, false_ms) =
                fetch_body_and_time_spec(client, false_url, state, cancel).await;
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
        let url = inject_param_or_marker(target, target_str, param, &p.payload, marker_set);
        let (body, _ms) = fetch_body_and_time_spec(client, url, state, cancel).await;
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
    let url = inject_param_or_marker(target, target_str, param, &payload.payload, marker_set);
    let (_body, ms) = fetch_body_and_time_spec(client, url, state, cancel).await;
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
