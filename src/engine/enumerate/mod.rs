#![deny(unsafe_code)]

//! Boolean-blind enumeration field extraction (P1).
//! Extracted verbatim from `orchestrator.rs`; no behaviour change.

use super::{
    config::{BudgetConfig, EngineConfig, dbms_hint_kind},
    confirm::{first_finding_param, is_confirmed_finding},
};
use crate::{
    detection::baseline,
    http::client::HttpClient,
    session::{
        scrubber::Scrubber,
        state::{Finding, SessionState},
    },
    target::{injection::ProbeOpts, markers::MarkerSet, raw_request::RawRequest, url::TargetUrl},
    techniques::tamper::Tamper,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

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

mod field;

use self::field::extract_enum_field;
