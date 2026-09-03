#![deny(unsafe_code)]

use crate::{
    detection::baseline,
    error::InjektError,
    http::client::HttpClient,
    session::state::{Finding, SessionState, TechniqueKind},
    target::{
        markers::MarkerSet,
        parameters::TargetParameter,
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
            verifier::OobVerifier as _,
        },
        payload_opts::{PayloadOpts, build_final_payload},
        request_tamper::{hpp_query_url, should_apply_chunked},
        stacked::{detector::StackedDetector, payloads::stacked_payloads_for},
        tamper::{Tamper, tamper_transformation_sets},
        time::{detector::TimeDetector, payloads::time_payload_for},
        union::{detector::UnionDetector, payloads::union_payloads_for},
    },
};
use http::Method;
use std::{collections::HashMap, io::IsTerminal as _, sync::Arc, time::{Duration, Instant}};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use indicatif::ProgressBar;

/// Context shared across all detection probes for a single parameter.
#[derive(Clone)]
#[non_exhaustive]
pub struct ProbeCtx {
    pub client: HttpClient,
    pub state: Arc<RwLock<SessionState>>,
    pub cancel: CancellationToken,
    pub target: TargetUrl,
    pub target_str: String,
    pub baseline: baseline::Baseline,
    pub marker_set: MarkerSet,
    pub raw_request: Option<RawRequest>,
    pub tampers: Arc<Vec<Tamper>>,
    pub opts: super::ProbeOpts,
    pub popts: PayloadOpts,
    pub matcher: crate::detection::matcher::MatcherConfig,
    pub level: u8,
    pub ignore_codes: Vec<u16>,
}

impl ProbeCtx {
    /// Build a `RequestSpec` for injecting `payload` into `param`.
    pub fn build_spec(&self, param: &TargetParameter, payload: &str) -> crate::http::client::RequestSpec {
        build_injection_spec_with_raw(
            &self.target,
            &self.target_str,
            param,
            payload,
            &self.marker_set,
            self.raw_request.as_ref(),
            self.opts,
            &self.popts,
        )
    }
}

/// Run all enabled detection techniques for a single parameter.
pub async fn run_detection(ctx: &ProbeCtx, param: &TargetParameter) {
    if ctx.cancel.is_cancelled() {
        return;
    }
    let tamper_sets = tamper_transformation_sets(&ctx.tampers);

    // Boolean with confirmation (3 trials)
    if ctx.config_techniques().iter().any(|t| t == "boolean" || t == "all") {
        test_boolean_bounded(ctx, param, &tamper_sets).await;
    }
    if ctx.config_techniques().iter().any(|t| t == "error" || t == "all") {
        test_error_bounded(ctx, param, &tamper_sets).await;
    }
    if ctx.config_techniques().iter().any(|t| t == "time" || t == "all") {
        test_time_bounded(ctx, param, &tamper_sets).await;
    }
    if ctx.config_techniques().iter().any(|t| t == "union" || t == "all") {
        test_union_bounded(ctx, param, &tamper_sets).await;
    }
    if ctx.config_techniques().iter().any(|t| t == "stacked" || t == "all") {
        test_stacked_bounded(ctx, param, &tamper_sets).await;
    }
    if ctx.config_techniques().iter().any(|t| t == "json" || t == "all") {
        test_json_bounded(ctx, param, &tamper_sets).await;
    }
    if ctx.config_techniques().iter().any(|t| t == "oob" || t == "all") {
        test_oob_bounded(ctx, param, &tamper_sets).await;
    }
}

impl ProbeCtx {
    fn config_techniques(&self) -> &Vec<String> {
        // This is a workaround; in practice we'd pass techniques from EngineConfig
        // For now, assume the caller sets up the context with the right techniques
        // We'll add a techniques field to ProbeCtx if needed
        static EMPTY: Vec<String> = Vec::new();
        &EMPTY
    }
}

// We'll move the actual test functions below. For the run_detection to work,
// we need to pass techniques. Let's add techniques to ProbeCtx.