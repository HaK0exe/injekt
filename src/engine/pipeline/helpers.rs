//! Private helpers of the `engine::pipeline` run machine (P5 split):
//! `PipelineCtx` handle bundle plus `absorb_detectability`,
//! `build_raw_request`, `effective_marker_set` and `select_params`.
use crate::http::client::HttpClient;
use crate::session::state::SessionState;
use crate::target::{
    injection::{filter_params, synthetic_raw_from_data},
    markers::MarkerSet,
    parameters::{ParameterLocation, TargetParameter},
    raw_request::RawRequest,
    url::TargetUrl,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::engine::config::EngineConfig;

/// Bundled handles for a single pipeline run — keeps `run_internal`'s
/// argument list short (was 9 params, now 3).
pub(crate) struct PipelineCtx<'a> {
    pub client: &'a crate::http::client::HttpClient,
    pub state: &'a std::sync::Arc<tokio::sync::RwLock<crate::session::state::SessionState>>,
    pub cancel: &'a tokio_util::sync::CancellationToken,
    pub config: &'a crate::engine::config::EngineConfig,
    pub scrubber: &'a crate::session::scrubber::Scrubber,
    pub baseline_cache: Option<&'a std::sync::Arc<crate::recon::BaselineCache>>,
    pub shared_client: bool,
}

/// Drain the [`HttpClient`] throttle counters into the run's
/// detectability counters (C10, bench Annexe A). Take-semantics: each run
/// is absorbed exactly once, even if the client is reused across runs.
/// Skipped when the client is shared across concurrent engines
/// ([`Engine::with_shared_client`](crate::engine::Engine::with_shared_client)): the `swap(0)` would be attributed
/// to whichever engine finishes first, so the owner drains once at the
/// end of the whole run instead.
pub(super) async fn absorb_detectability(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    shared_client: bool,
) {
    if shared_client {
        return;
    }
    let (c403, c429) = client.take_detectability_counts();
    if c403 != 0 || c429 != 0 {
        state.write().await.add_detectability(c403, c429);
    }
}

/// Fused raw request: `EngineConfig::raw_request` (`--raw-file` + CLI
/// overlays) wins, then the recon-candidate synthetic, then `--data`.
/// A bare `--method` without any body is carried as a method-only raw so
/// baseline + injection preserve it instead of falling back to `GET`.
pub(super) fn build_raw_request(
    config: &EngineConfig,
    candidate: Option<&crate::recon::ParameterCandidate>,
) -> Option<RawRequest> {
    if let Some(mut raw) = config.raw_request.clone() {
        if let Some(m) = config.net.method_override.as_deref() {
            let m = m.trim();
            if !m.is_empty() {
                raw.method = m.to_ascii_uppercase();
            }
        }
        return Some(raw);
    }
    let cli_raw_request = candidate.map(crate::recon::ParameterCandidate::raw_request);
    if let Some(mut raw) = cli_raw_request {
        if let Some(m) = config.net.method_override.as_deref() {
            let m = m.trim();
            if !m.is_empty() {
                raw.method = m.to_ascii_uppercase();
            }
        }
        if config.post_data.is_some() {
            warn!("--raw-file and --data both set — raw request wins, --data ignored");
        }
        return Some(raw);
    }
    if let Some(data) = config.post_data.as_deref() {
        let raw = synthetic_raw_from_data(data);
        if raw.is_none() && !data.is_empty() {
            warn!("--data is blank — scanning without a body");
        }
        if let Some(mut raw) = raw {
            if let Some(m) = config.net.method_override.as_deref() {
                let m = m.trim();
                if !m.is_empty() {
                    raw.method = m.to_ascii_uppercase();
                }
            }
            return Some(raw);
        }
    }
    // Bare `--method` (e.g. `--method POST --target <url>`): method carrier.
    if let Some(m) = config.net.method_override.as_deref() {
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
fn effective_marker_set(config: &EngineConfig, target_str: &str) -> MarkerSet {
    let mut set = MarkerSet::detect(target_str);
    if let Some(m) = config.marker.as_deref() {
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

/// Builds the marker-synthetic + real parameter list to test, applying
/// `-p` filtering (skipped when a recon `candidate_param` is already fixed).
///
/// Emplacements exotiques (`User-Agent` / `Referer` / `X-Forwarded-For` /
/// `X-Real-IP`, souvent loggés en base sans sanitisation → second-order
/// via header) : ajoutés comme synthétiques à partir du `--level 2`
/// quand absents des params déjà collectés. L1 reste byte-identique
/// (aucune requête extra par défaut, même philosophie que sqlmap qui ne
/// teste UA/Referer qu'à haut niveau).
pub(super) fn select_params(
    config: &EngineConfig,
    target_str: &str,
    target: &TargetUrl,
    raw_request: Option<&RawRequest>,
    candidate_param: Option<&TargetParameter>,
) -> (MarkerSet, Vec<TargetParameter>) {
    let marker_set = effective_marker_set(config, target_str);
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
    if config.budget.level >= 2 && candidate_param.is_none() {
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
    if candidate_param.is_none() && !config.test_params.is_empty() {
        let before = to_test.len();
        to_test = filter_params(to_test, &config.test_params);
        if to_test.is_empty() {
            warn!(
                filter=?config.test_params,
                before,
                "parameter filter matched 0 params — nothing to test"
            );
        } else {
            info!(filter=?config.test_params, before, after=%to_test.len(), "parameter filter applied");
        }
    }
    (marker_set, to_test)
}
