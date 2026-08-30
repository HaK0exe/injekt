#![deny(unsafe_code)]

use crate::{
    detection::baseline,
    http::client::HttpClient,
    session::{
        scrubber::Scrubber,
        state::{Finding, SessionState, TechniqueKind},
    },
    target::{parameters::TargetParameter, url::TargetUrl},
    techniques::{
        boolean::{detector::BooleanDetector, payloads::boolean_payloads_for},
        error::detector::ErrorDetector,
        time::{detector::TimeDetector, payloads::time_payload_for},
    },
};
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
            let resp = self.client.get_with_retry(target.as_str().to_owned()).await;
            let elapsed = start.elapsed();
            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    let body = r.bytes().await.unwrap_or_default().to_vec();
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

        // Detection per parameter, bounded concurrency
        let params = crate::target::parameters::collect_from_url_query(&target);
        let to_test: Vec<TargetParameter> = if params.is_empty() {
            // fallback: test single synthetic param "id"
            vec![crate::target::parameters::TargetParameter::new(
                "id",
                crate::target::parameters::ParameterLocation::Query,
                "1",
            )]
        } else {
            params
        };

        let pb2 = ProgressBar::new(to_test.len() as u64);
        pb2.set_style(
            ProgressStyle::default_bar()
                .template("{bar:40} {pos}/{len} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_bar()),
        );

        for param in &to_test {
            if self.cancel.is_cancelled() {
                break;
            }
            pb2.set_message(format!("testing {}", param.name));
            // boolean
            if self
                .config
                .techniques
                .iter()
                .any(|t| t == "boolean" || t == "all")
            {
                self.test_boolean(&target, param, &baseline).await;
            }
            // error
            if self
                .config
                .techniques
                .iter()
                .any(|t| t == "error" || t == "all")
            {
                self.test_error(&target, param).await;
            }
            // time
            if self
                .config
                .techniques
                .iter()
                .any(|t| t == "time" || t == "all")
            {
                self.test_time(&target, param, &baseline).await;
            }
            pb2.inc(1);
        }
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

            let baseline_body = ""; // we use empty as we already sampled; real would use baseline body hash
            let res = detector.evaluate(
                baseline_body,
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
