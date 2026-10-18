#![deny(unsafe_code)]

use crate::{
    http::client::{HttpClient, RequestSpec},
    session::state::{Finding, SessionState, TechniqueKind},
    target::raw_request::RawRequest,
    techniques::{
        json::payloads::{JsonPayload, graphql_probes_for},
        payload_opts::PayloadOpts,
    },
};
use http::Method;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::techniques::graphql::detector::GraphqlDetector;
use crate::techniques::technique::{Technique, TechniqueCtx};
use futures::future::BoxFuture;

pub(crate) struct GraphqlTechnique;

impl Technique for GraphqlTechnique {
    fn kind(&self) -> TechniqueKind {
        TechniqueKind::Graphql
    }

    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn probe<'a>(&'a self, ctx: &'a TechniqueCtx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let client = ctx.client;
            let state = ctx.state;
            let cancel = ctx.cancel;
            let target_str = ctx.target_str;
            let raw = ctx.raw;
            let baseline = ctx.baseline;
            let matcher = ctx.matcher;
            let ignore_codes = ctx.ignore_codes;

            let probes: Vec<JsonPayload> = graphql_probes_for(None);
            let Some(p) = probes.first() else {
                return;
            };
            let true_payload = p.true_payload.clone();
            let false_payload = p.false_payload.clone();
            let error_payload = p.error_payload.clone();

            let detector = GraphqlDetector::new();
            let baseline_body = matcher.pre_process(&baseline.representative_body_str());

            // Boolean differential (3 trials)
            let mut trials: Vec<crate::detection::confirmation::Trial> = Vec::with_capacity(3);
            let mut last_true = String::new();
            let mut last_false = String::new();
            let mut last_t_status: u16 = 0;
            let mut last_f_status: u16 = 0;
            for _ in 0..3 {
                if cancel.is_cancelled() {
                    break;
                }
                let (true_raw, true_ms, true_status) =
                    send_graphql(client, state, cancel, target_str, raw, &true_payload).await;
                let true_body = matcher.pre_process(&true_raw);
                let (false_raw, false_ms, false_status) =
                    send_graphql(client, state, cancel, target_str, raw, &false_payload).await;
                let false_body = matcher.pre_process(&false_raw);

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
                if ignore_codes.contains(&true_status) || ignore_codes.contains(&false_status) {
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
                let res = detector.evaluate_boolean_with_match_ratio(
                    &baseline_body,
                    &true_body,
                    &false_body,
                    baseline.mean_ms,
                    true_ms,
                    false_ms,
                    baseline.match_ratio(),
                );
                let (t_conf, f_conf) = if res.noise_vetoed {
                    (0.5, 0.5)
                } else {
                    (res.true_similarity, res.false_similarity)
                };
                trials.push(crate::detection::confirmation::Trial {
                    true_conf: t_conf,
                    false_conf: f_conf,
                });
                last_true = true_body;
                last_false = false_body;
                last_t_status = true_status;
                last_f_status = false_status;
            }

            let (conf, _inverted) = crate::detection::confirmation::confirm_either(&trials);
            if conf.confirmed
                && matcher.gate_boolean(&last_true, &last_false, last_t_status, last_f_status)
                    != Some(false)
            {
                let (agg_true, agg_false) = crate::detection::confirmation::aggregate_sims(&trials);
                let finding = Finding::new(
                    ctx.target.as_str(),
                    ctx.param.key(),
                    TechniqueKind::Graphql,
                    conf.score,
                    format!(
                        "graphql channel=boolean true_sim={:.2} false_sim={:.2} trials={}/3",
                        agg_true, agg_false, conf.trials
                    ),
                )
                .with_false_positive_prob(conf.false_positive_prob)
                .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                state.write().await.push_finding(finding);
                debug!(param = ctx.param.key(), "graphql boolean finding");
                return;
            }

            // Error channel
            let (raw_body, _ms, status) =
                send_graphql(client, state, cancel, target_str, raw, &error_payload).await;
            let body = matcher.pre_process(&raw_body);
            if !ignore_codes.contains(&status) {
                let r = detector.evaluate_error(&body);
                if r.is_vulnerable {
                    let finding = Finding::new(
                        ctx.target.as_str(),
                        ctx.param.key(),
                        TechniqueKind::Graphql,
                        r.confidence,
                        format!("graphql channel=error pattern={:?}", r.matched_pattern),
                    )
                    .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                    state.write().await.push_finding(finding);
                    debug!(param = ctx.param.key(), "graphql error finding");
                }
            }
            let _ = (baseline_body, ctx, p);
        })
    }
}

async fn send_graphql(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target_str: &str,
    raw: Option<&RawRequest>,
    body: &str,
) -> (String, f64, u16) {
    use std::time::Instant;
    let method = raw
        .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
        .unwrap_or(Method::POST);
    let mut headers = http::HeaderMap::new();
    if let Ok(v) = http::HeaderValue::from_str("application/json") {
        headers.insert(http::header::CONTENT_TYPE, v);
    }
    if let Ok(v) = http::HeaderValue::from_str("application/json") {
        headers.insert(http::header::ACCEPT, v);
    }
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
    let spec = RequestSpec {
        method,
        url: target_str.to_owned(),
        headers,
        body: Some(body.to_owned().into()),
    };
    let start = Instant::now();
    let resp = client.send_with_retry(spec, cancel).await;
    {
        let mut st = state.write().await;
        st.increment_requests();
    }
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match client.read_body_string_with_timeout(r).await {
                Ok(body) => (body, elapsed, status),
                Err(_) => (String::new(), elapsed, 0),
            }
        }
        Err(_) => (String::new(), elapsed, 0),
    }
}

#[allow(dead_code)]
fn _use_payload_opts(_: &PayloadOpts) {}
