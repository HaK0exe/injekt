#![deny(unsafe_code)]

//! Unified `EngineConfig` builder shared by `scan`, `recon` and `auto`.
//!
//! Pure factorisation: no CLI flag, network behaviour or default changes.
//! `scan`/`auto` use [`EnumGate::Passthrough`], `recon` uses
//! [`EnumGate::Strict`] (warns when identity/enumeration flags are set
//! without `--auto-enumerate` and gates them, historical `recon` behaviour).

use crate::{cli::args::Cli, engine::orchestrator::EngineConfig};

/// Enumeration gating mode.
///
/// * `Passthrough` — `scan`/`auto` behaviour: enumeration flags pass through
///   untouched, no warning.
/// * `Strict(enumerate)` — `recon` behaviour: when `enumerate` is `false`,
///   identity/enumeration flags are ignored with a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumGate {
    Passthrough,
    Strict(bool),
}

/// Build engine config from CLI detection/enumeration options.
/// Resolution honours `--profile` / config file / `INJEKT_*` via `Cli::effective_*`:
/// explicit flags always win, presets only fill gaps (non-breaking).
#[allow(clippy::too_many_lines)]
// unified scan+recon builder: one struct literal per EngineConfig section, split would reintroduce drift.
#[must_use]
pub fn build_engine_config(cli: &Cli, enum_gate: EnumGate) -> EngineConfig {
    let tampers = if cli.detection.tamper.is_empty() {
        Vec::new()
    } else {
        crate::techniques::tamper::parse_tamper_list(Some(&cli.detection.tamper.join(",")))
    };
    let (enumerate, strict) = match enum_gate {
        EnumGate::Passthrough => (true, false),
        EnumGate::Strict(e) => (e, true),
    };
    if strict
        && !enumerate
        && (cli.enumeration.dbs
            || cli.enumeration.tables
            || cli.enumeration.columns
            || cli.enumeration.dump
            || cli.enumeration.banner
            || cli.enumeration.current_user
            || cli.enumeration.current_db
            || cli.enumeration.hostname
            || cli.enumeration.count)
    {
        tracing::warn!(
            "identity/enumeration flags (--banner/--current-user/--current-db/--hostname/--dbs/--tables/--columns/--dump/--count) require --auto-enumerate for recon scan; ignoring them"
        );
    }
    // C13 : lecture au boot uniquement sur opt-in explicite. OFF (`None`) =
    // aucune IO, boost 1.0 neutre, chemin byte-identique au sans-knowledge.
    let knowledge = crate::reasoning::knowledge::load_if_enabled(
        cli.knowledge_enabled(),
        cli.knowledge_path.as_deref(),
    );
    if let Some(ks) = knowledge.as_ref() {
        tracing::debug!(
            entries = ks.len(),
            enabled = true,
            "knowledge loaded (opt-in)"
        );
    }
    EngineConfig {
        budget: crate::engine::orchestrator::BudgetConfig {
            threads: cli.effective_threads(),
            level: cli.effective_level(),
            request_budget: cli.effective_request_budget(),
            max_duration_secs: cli.effective_max_duration(),
        },
        evasion: crate::engine::orchestrator::EvasionConfig {
            payload_opts: cli.payload_opts(),
            tampers,
            hpp: cli.evasion.hpp,
            chunked: cli.evasion.chunked,
        },
        net: crate::engine::orchestrator::NetConfig {
            allow_private: cli.http.allow_private,
            remote_dns: cli.uses_remote_dns(),
            ignore_codes: cli.detection.ignore_codes.clone(),
            method_override: cli.http.method.clone(),
        },
        oob: crate::engine::orchestrator::OobConfig {
            oob_domain: cli.detection.oob_domain.clone(),
            oob_poll_url: cli.detection.oob_poll_url.clone(),
            oob_wait_secs: cli.effective_oob_wait_secs(),
        },
        enumeration: crate::engine::orchestrator::EnumConfig {
            extract: cli.enumeration.extract,
            dbs: enumerate && cli.enumeration.dbs,
            tables: enumerate && cli.enumeration.tables,
            columns: enumerate && cli.enumeration.columns,
            dump: enumerate && cli.enumeration.dump,
            banner: enumerate && cli.enumeration.banner,
            current_user: enumerate && cli.enumeration.current_user,
            current_db: enumerate && cli.enumeration.current_db,
            hostname: enumerate && cli.enumeration.hostname,
            db: cli.enumeration.db.clone(),
            table: cli.enumeration.table.clone(),
            column: cli.enumeration.column.clone(),
            start: cli.enumeration.start,
            stop: cli.enumeration.stop,
            count: enumerate && cli.enumeration.count,
        },
        techniques: if !cli.detection.techniques.is_empty() {
            cli.detection.techniques.clone()
        } else if cli
            .detection
            .fetch_using
            .as_deref()
            .is_some_and(|v| v == "boolean" || v == "time")
        {
            // --fetch-using narrows the default technique set (explicit --techniques wins,
            // otherwise explicit --fetch-using wins over config file / profile defaults).
            match cli.detection.fetch_using.as_deref() {
                Some("boolean") => vec!["boolean".to_owned()],
                Some("time") => vec!["time".to_owned()],
                _ => cli.effective_techniques(),
            }
        } else {
            cli.effective_techniques()
        },
        test_params: cli.detection.params.clone(),
        post_data: cli.detection.data.clone(),
        matcher: cli.matcher_config(),
        confirm: cli.detection.confirm,
        no_mutation: cli.evasion.no_mutation,
        seed: cli.effective_seed(),
        explain: cli.output_opts.explain.clone(),
        no_redact: cli.output_opts.no_redact,
        dbms_hint: cli.normalized_dbms_hint(),
        marker: cli.detection.marker.clone(),
        raw_request: cli.merged_raw_request(),
        knowledge,
        second_order: crate::engine::orchestrator::SecondOrderConfig {
            enabled: cli.evasion.second_order,
            revisit_url: cli.evasion.second_order_revisit_url.clone(),
            max_stores: cli.effective_second_order_max_stores(),
            ..crate::engine::orchestrator::SecondOrderConfig::default()
        },
    }
}
