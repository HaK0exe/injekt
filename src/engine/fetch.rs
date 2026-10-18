#![deny(unsafe_code)]

//! Probe fetch layer (P1): bounded + cancellable HTTP fetches for detection
//! probes. Extracted verbatim from `orchestrator.rs`; no behaviour change.

use crate::{
    http::{
        client::{HttpClient, RequestSpec},
        timeouts::RequestClass,
    },
    session::state::SessionState,
    target::{
        injection::{ProbeOpts, build_injection_spec_with_raw},
        markers::MarkerSet,
        parameters::TargetParameter,
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::payload_opts::PayloadOpts,
};
use http::Method;
use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::warn;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_for_payload(
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
pub(crate) async fn fetch_for_payload_with_class(
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
    // Unrepresentable injection (header/cookie value rejected): no request
    // is sent, so the trial is skipped without scoring (status 0) and
    // without counting a request. The builder already warned.
    let Some(spec) = build_injection_spec_with_raw(
        target, target_str, param, payload, marker_set, raw, opts, popts,
    ) else {
        return (String::new(), 0.0, 0);
    };
    let start = Instant::now();
    let resp = client.send_with_retry_for_class(spec, class, cancel).await;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    {
        let mut st = state.write().await;
        st.increment_requests();
        // WAF footprint par param (live) : `403`/`406`/`429` sur une sonde =
        // blocage probable. Mémorisé pour le trigger `--ai-suggest`
        // (post-échec) ; distinct des compteurs `detectability` absorbés en
        // fin de run depuis le client HTTP.
        if let Ok(r) = resp.as_ref()
            && matches!(r.status().as_u16(), 403 | 406 | 429)
        {
            st.note_waf_hit(&param.key());
        }
    }
    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            // Bounded + cancellable body read: Ctrl+C pendant un body drip
            // sort immédiatement au lieu de bloquer jusqu'au timeout de classe.
            // Bounded body read: a transport error (`Timeout`, reset) returns
            // status 0 so callers skip scoring instead of treating `""` as a
            // dissimilar body (similarity ~0 / confidence 0.75 false positive).
            let body_res = tokio::select! {
                biased;
                () = cancel.cancelled() => None,
                res = client.read_body_string_for_class(r, class) => Some(res),
            };
            match body_res {
                Some(Ok(body)) => (body, elapsed, status),
                Some(Err(e)) => {
                    warn!(error=%e, "probe body read failed, skipping score");
                    (String::new(), elapsed, 0)
                }
                // Cancelled mid-read: status 0 = skipped, never scored.
                None => (String::new(), elapsed, 0),
            }
        }
        Err(e) => {
            warn!(error=%e, "probe request failed, skipping score");
            (String::new(), elapsed, 0)
        }
    }
}

#[allow(dead_code)]
pub(crate) async fn fetch_body_and_time_spec(
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
