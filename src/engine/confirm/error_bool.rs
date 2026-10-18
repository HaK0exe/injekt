use crate::detection::baseline;
use crate::engine::fetch::fetch_for_payload_with_class;
use crate::http::{client::HttpClient, timeouts::RequestClass};
use crate::session::state::SessionState;
use crate::target::{
    injection::{ProbeOpts, is_ignored},
    markers::MarkerSet,
    parameters::TargetParameter,
    raw_request::RawRequest,
    url::TargetUrl,
};
use crate::techniques::{
    boolean::{detector::BooleanDetector, payloads::boolean_payloads_for},
    payload_opts::{PayloadOpts, build_final_payload_with_rng},
    tamper::Tamper,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// Outcome of the lightweight error→boolean confirmation probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorBoolConfirm {
    Confirmed,
    Denied,
    Inconclusive,
    Skipped,
}

impl ErrorBoolConfirm {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "true",
            Self::Denied => "false",
            Self::Inconclusive => "inconclusive",
            Self::Skipped => "skipped",
        }
    }
}

pub(crate) struct ErrorBoolOutcome {
    pub(crate) verdict: ErrorBoolConfirm,
    pub(crate) true_sim: f64,
    pub(crate) false_sim: f64,
}

/// Lightweight confirmation for error hits without an extracted fragment
/// (confidence 0.75): one boolean TRUE/FALSE pair (+2 requests) on the same
/// parameter, reusing the error-hit tamper set filtered to boolean-safe
/// tampers. Returns `Skipped` without any request when the boolean technique
/// is disabled, `Inconclusive` on transport failure/cancel (never scores
/// `""`), `Denied` on a clean differential or matcher veto.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn confirm_error_with_boolean(
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
    let true_body = matcher.pre_process(&baseline.strip_dynamic_content(&true_raw));
    let false_body = matcher.pre_process(&baseline.strip_dynamic_content(&false_raw));
    let res = BooleanDetector::new().evaluate_with_match_ratio(
        baseline_body,
        &true_body,
        &false_body,
        baseline.mean_ms,
        true_ms,
        false_ms,
        baseline.match_ratio(),
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
