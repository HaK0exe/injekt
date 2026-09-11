#![deny(unsafe_code)]

use crate::{
    cli::args::Cli,
    cli::client_builder::build_client,
    cli::output::file::write_output_file_async,
    engine::orchestrator::{Engine, EngineConfig},
    reporting::{console, json::JsonReport, render::render_report},
    session::scrubber::Scrubber,
};
use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// Result of a scan operation containing all findings and metadata.
#[derive(Debug)]
pub struct ScanResult {
    pub report: JsonReport,
    pub engine_state: crate::engine::orchestrator::EngineState,
    pub target: String,
    pub config: EngineConfig,
    pub state_handle: Arc<tokio::sync::RwLock<crate::session::state::SessionState>>,
}

/// Build engine config from CLI detection/enumeration options.
/// Resolution honours `--profile` / config file / `INJEKT_*` via `Cli::effective_*`:
/// explicit flags always win, presets only fill gaps (non-breaking).
pub(crate) fn engine_config(cli: &Cli) -> EngineConfig {
    let tampers = if cli.tamper.is_empty() {
        Vec::new()
    } else {
        crate::techniques::tamper::parse_tamper_list(Some(&cli.tamper.join(",")))
    };
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
            request_budget: None,
        },
        evasion: crate::engine::orchestrator::EvasionConfig {
            payload_opts: cli.payload_opts(),
            tampers,
            hpp: cli.hpp,
            chunked: cli.chunked,
        },
        net: crate::engine::orchestrator::NetConfig {
            allow_private: cli.allow_private,
            remote_dns: cli.uses_remote_dns(),
            ignore_codes: cli.ignore_codes.clone(),
            method_override: cli.method.clone(),
        },
        oob: crate::engine::orchestrator::OobConfig {
            oob_domain: cli.oob_domain.clone(),
            oob_poll_url: cli.oob_poll_url.clone(),
            oob_wait_secs: cli.effective_oob_wait_secs(),
        },
        enumeration: crate::engine::orchestrator::EnumConfig {
            extract: cli.extract,
            dbs: cli.dbs,
            tables: cli.tables,
            columns: cli.columns,
            dump: cli.dump,
            banner: cli.banner,
            current_user: cli.current_user,
            current_db: cli.current_db,
            hostname: cli.hostname,
            db: cli.db.clone(),
            table: cli.table.clone(),
            column: cli.column.clone(),
            start: cli.start,
            stop: cli.stop,
            count: cli.count,
        },
        techniques: if !cli.techniques.is_empty() {
            cli.techniques.clone()
        } else if cli
            .fetch_using
            .as_deref()
            .is_some_and(|v| v == "boolean" || v == "time")
        {
            // --fetch-using narrows the default technique set (explicit --techniques wins,
            // otherwise explicit --fetch-using wins over config file / profile defaults).
            match cli.fetch_using.as_deref() {
                Some("boolean") => vec!["boolean".to_owned()],
                Some("time") => vec!["time".to_owned()],
                _ => cli.effective_techniques(),
            }
        } else {
            cli.effective_techniques()
        },
        test_params: cli.params.clone(),
        post_data: cli.data.clone(),
        matcher: cli.matcher_config(),
        confirm: cli.confirm,
        no_mutation: cli.no_mutation,
        seed: cli.effective_seed(),
        explain: cli.explain.clone(),
        no_redact: cli.no_redact,
        dbms_hint: cli.normalized_dbms_hint(),
        marker: cli.marker.clone(),
        raw_request: cli.merged_raw_request(),
        knowledge,
        second_order: crate::engine::orchestrator::SecondOrderConfig {
            enabled: cli.second_order,
            revisit_url: cli.second_order_revisit_url.clone(),
            max_stores: cli.effective_second_order_max_stores(),
            ..crate::engine::orchestrator::SecondOrderConfig::default()
        },
    }
}

/// Run a scan and return structured results without printing to stdout.
/// This is the core logic reusable by both CLI and MCP server.
///
/// # Errors
/// Returns an error if no target is given, the HTTP client fails to build,
/// or the scan engine fails.
pub async fn run_scan(cli: &Cli, cancel: CancellationToken) -> Result<ScanResult> {
    if let Err(e) = cli.validate_explicit_config() {
        return Err(crate::error::InjektError::Other(e.into()).into());
    }
    // `--import` is not a scan-resume flag: session resume lives in
    // `replay --file` (decrypt + summary) and `recon import --file`.
    // Fail fast instead of silently ignoring it.
    if let Some(path) = cli.import.as_deref() {
        return Err(crate::error::InjektError::Other(
            format!(
                "--import '{path}' is not supported for scan; use `replay --file <export.enc>` to inspect an encrypted export or `recon import --file <crawl.json> --test` for candidates"
            )
            .into(),
        )
        .into());
    }
    info!(resolution=%cli.resolution_summary(), "scan config resolved");
    let target = cli
        .effective_target()
        .ok_or_else(|| crate::error::InjektError::Other("target required".into()))?;

    let client = build_client(cli, cli.allow_private)?;
    let cfg = engine_config(cli);

    let engine = Engine::new(cfg.clone(), client, cancel.clone());
    let state = engine.run(&target).await?;

    // Reporting
    let handle = engine.state_handle();
    let s = handle.read().await;
    let findings = s.findings().to_vec();
    let extracted = s.extracted_exposed();
    let count = s.request_count();
    let detectability = s.detectability();
    drop(s);

    let scrubber = Scrubber::new(cfg.no_redact);
    let meta = crate::reporting::json::ReportMeta::current(
        cfg.seed,
        cli.active_profile()
            .map(|p| format!("{p:?}").to_ascii_lowercase()),
        cfg.techniques.clone(),
        cfg.budget.level,
        cfg.evasion
            .tampers
            .iter()
            .map(|t| t.name().to_owned())
            .collect(),
    );
    let report = JsonReport::new(target.clone(), findings, vec![], extracted, count, meta)
        .with_detectability(detectability)
        .scrubbed(&scrubber);

    // C13 post-run (opt-in uniquement) : fusion des compteurs anonymes puis
    // écriture (`fsync`, perms 0600). OFF = aucune IO. Le delta ne contient
    // que `(technique, dbms, generic, succès?, req)` — jamais de cible,
    // param, seed, evidence ou secret.
    if cli.knowledge_enabled() {
        let mut delta = crate::reasoning::knowledge::KnowledgeStore::empty();
        crate::reasoning::knowledge::learn_from_run(
            &mut delta,
            &report.findings,
            &cfg.techniques,
            cfg.dbms_hint.as_deref(),
            count,
        );
        match crate::reasoning::knowledge::save_delta_if_enabled(
            &delta,
            true,
            cli.knowledge_path.as_deref(),
        ) {
            Ok(true) => tracing::info!(
                path = %scrubber.scrub(&cli.effective_knowledge_path().display().to_string()),
                entries = delta.len(),
                "knowledge updated (opt-in, aggregates only)"
            ),
            Ok(false) => {}
            Err(e) => warn!(error=%e, "knowledge save failed (run results kept in RAM)"),
        }
    }

    Ok(ScanResult {
        report,
        engine_state: state,
        target,
        config: cfg,
        state_handle: handle,
    })
}

/// Bulk CLI entry point (`-m/--bulk-file` + `--stdin` / `--openapi-file` /
/// `--sitemap-file` / `--raw-dir`): sequential multi-target scan.
async fn run_bulk_cli(cli: &Cli, cancel: CancellationToken) -> Result<()> {
    if cli.bulk_file.is_some() && cli.effective_target().is_some() {
        return Err(crate::error::InjektError::Other(
            "--bulk-file conflicts with --target/--raw-file (one mode at a time)".into(),
        )
        .into());
    }
    if cli.export_encrypted.is_some() {
        return Err(crate::error::InjektError::Other(
            "--export-encrypted is not supported with --bulk-file (use --output for the aggregated report)".into(),
        )
        .into());
    }
    if cli.cookies.is_some() {
        warn!("--cookies combined with --bulk-file replays the same cookies on every target");
    }
    if cli.headers.iter().any(|h| {
        h.split_once(':')
            .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("authorization"))
    }) {
        warn!("Authorization header combined with --bulk-file is replayed on every target");
    }
    let targets = crate::target::ingest::collect_targets(cli, None)?;
    // Fail fast on broken network config; per-target rebuilds stay fresh
    // (CookieJar/RateLimiter isolation).
    build_client(cli, cli.allow_private)?;
    let cfg = engine_config(cli);
    let scrubber = Scrubber::new(cfg.no_redact);
    info!(count = targets.len(), "bulk scan start");
    let report = super::bulk::run_bulk(
        targets,
        &cfg,
        || build_client(cli, cli.allow_private),
        &cancel,
        &scrubber,
    )
    .await;
    for r in &report.per_target {
        println!("=== [{}] ===", scrubber.scrub(&r.target));
        console::print_findings(&r.findings, &scrubber);
    }
    report.print_summary(&scrubber);
    // C13 bulk (opt-in) : un seul delta agrégé sur tous les findings du run.
    if cli.knowledge_enabled() {
        let findings: Vec<crate::session::state::Finding> = report
            .per_target
            .iter()
            .flat_map(|r| r.findings.clone())
            .collect();
        let mut delta = crate::reasoning::knowledge::KnowledgeStore::empty();
        crate::reasoning::knowledge::learn_from_run(
            &mut delta,
            &findings,
            &cfg.techniques,
            cfg.dbms_hint.as_deref(),
            report.request_count_total,
        );
        if let Err(e) = crate::reasoning::knowledge::save_delta_if_enabled(
            &delta,
            true,
            cli.knowledge_path.as_deref(),
        ) {
            warn!(error=%e, "knowledge save failed (run results kept in RAM)");
        }
    }
    if let Some(out) = &cli.output {
        let body = if matches!(cli.format, crate::cli::args::ReportFormat::Json) {
            serde_json::to_string_pretty(&report.to_json(&scrubber))?
        } else {
            // SARIF/JUnit/Markdown aggregate every per-target finding into
            // one CI-ready document (bulk has no single target URL).
            let findings: Vec<crate::session::state::Finding> = report
                .per_target
                .iter()
                .flat_map(|r| r.findings.clone())
                .collect();
            let aggregated = JsonReport::new(
                format!(
                    "bulk ({} ok / {} total)",
                    report.targets_ok, report.targets_total
                ),
                findings,
                vec![],
                vec![],
                report.request_count_total,
                crate::reporting::json::ReportMeta::default(),
            );
            render_report(&aggregated, cli.format, &scrubber)
        };
        write_output_file_async(out, &body, cli.force, &scrubber.scrub(out)).await?;
        info!(path=%scrubber.scrub(out), format=%cli.format.to_string(), "bulk report written (0o600, no overwrite unless --force)");
    }
    Ok(())
}

/// `true` when any multi-target ingestion source is set.
#[must_use]
pub fn has_ingestion_sources(cli: &Cli) -> bool {
    cli.bulk_file.is_some()
        || cli.stdin
        || cli.openapi_file.is_some()
        || cli.sitemap_file.is_some()
        || cli.raw_dir.is_some()
}

/// Print the offline execution plan without sending any request (C11).
/// 0 requête: no `HttpClient` is built, no `send` is called — lexical URL
/// parse + passive context + scheduler scores only.
fn dry_run(cli: &Cli) {
    println!("dry-run: scan plan (no request sent)");
    println!("  resolution: {}", cli.resolution_summary());
    let cfg = engine_config(cli);
    // `collect_targets` is lexical-only (parse + dedup, no DNS/HTTP).
    let targets = match crate::target::ingest::collect_targets(cli, None) {
        Ok(t) => t,
        Err(e) => {
            // Fall back to the single effective target so `--target` typos
            // still show a plan attempt instead of an empty run.
            let single = cli.effective_target().into_iter().collect::<Vec<_>>();
            if single.is_empty() {
                println!("  targets: 0 ({e})");
                return;
            }
            single
        }
    };
    if targets.is_empty() {
        println!("  targets: 0 (no valid target)");
        return;
    }
    println!("  targets: {}", targets.len());
    for target in targets.iter().take(20) {
        let scrubber = Scrubber::new(cli.no_redact);
        match crate::cli::plan::build_plan(target, &cfg) {
            Ok(plan) => {
                print!(
                    "{}",
                    crate::cli::plan::render_human(
                        &plan.scrubbed(&scrubber),
                        &cli.resolution_summary(),
                        true
                    )
                );
            }
            Err(e) => {
                println!("    - {}: plan failed: {e}", scrubber.scrub(target));
            }
        }
    }
    if targets.len() > 20 {
        println!("    … ({} more)", targets.len() - 20);
    }
    // C13 : priors knowledge affichés en dry-run (0 requête, OPSEC-safe,
    // scrubbé : agrégats seuls, aucun identifiant).
    {
        let scrubber = Scrubber::new(cli.no_redact);
        if cli.knowledge_enabled() {
            let path = cli.effective_knowledge_path();
            let loaded = cfg
                .knowledge
                .as_ref()
                .map_or(0, crate::reasoning::knowledge::KnowledgeStore::len);
            println!(
                "  knowledge: ON path={} entries={} (boost 1+alpha [0.5,1.5] -> clamp [0.5,2.0])",
                scrubber.scrub(&path.display().to_string()),
                loaded
            );
            if let Some(ks) = cfg.knowledge.as_ref() {
                for tech in [
                    "boolean", "error", "union", "time", "stacked", "oob", "json", "nosql",
                ] {
                    if let Some(kind) = crate::reasoning::knowledge::parse_technique(tech) {
                        let b = ks.boost_for(kind, "unknown", "generic");
                        println!("    prior {tech}: boost={b:.2}");
                    }
                }
            }
        } else {
            println!("  knowledge: OFF (RAM-only, boost 1.0 neutre)");
        }
    }
    println!("  0 requête envoyée (HttpClient.send jamais appelé)");
}

/// Original CLI entry point — prints to stdout/stderr.
///
/// # Errors
/// Returns an error if the scan (or bulk scan) fails, or the output report
/// can't be written to disk.
pub async fn run(cli: Cli, cancel: CancellationToken) -> Result<()> {
    if cli.dry_run {
        dry_run(&cli);
        return Ok(());
    }
    if has_ingestion_sources(&cli) {
        return run_bulk_cli(&cli, cancel).await;
    }
    let result = run_scan(&cli, cancel).await?;

    let scrubber = Scrubber::new(result.config.no_redact);
    // Canonical human summary is the orchestrator `scan done` line (findings
    // per technique, req, 403/429, `--explain` hint). Keep this at `debug!`
    // so TTY output shows exactly one summary, not two.
    debug!(
        target=%scrubber.scrub(&result.target),
        state=?result.engine_state,
        "scan finished"
    );

    console::print_findings(&result.report.findings, &scrubber);
    console::print_extracted(&result.report.extracted);

    // `--explain <param>`: one-line reasoning verdict to stdout (in addition
    // to the orchestrator `info!` log above). Reads findings + RAM-only trace.
    if let Some(wanted) = cli.explain.as_deref() {
        let st = result.state_handle.read().await;
        match st.explain(wanted) {
            Some(line) => println!("explain {wanted}: {line}"),
            None => println!("explain {wanted}: no finding matches"),
        }
    }

    if let Some(out) = &cli.output {
        let body = render_report(&result.report, cli.format, &scrubber);
        // Secure write: 0o600, create_new (no overwrite unless --force),
        // relative-only + canonicalized parent (see `output::file`).
        write_output_file_async(out, &body, cli.force, &scrubber.scrub(out)).await?;
        info!(path=%scrubber.scrub(out), format=%cli.format.to_string(), "report written (0o600, no overwrite unless --force)");
    }

    if let Some(path) = &cli.export_encrypted {
        let scrubbed_path = Scrubber::new(result.config.no_redact).scrub(path);
        warn!(path=%scrubbed_path, "export chiffré demandé — artefact sensible");
        // Secure passphrase prompt (rpassword) with fallback to env for CI
        let pass = if let Ok(env_pass) = std::env::var("INJEKT_PASSPHRASE") {
            if env_pass.len() < 12 {
                return Err(crate::error::InjektError::Other(
                    "INJEKT_PASSPHRASE trop courte (min 12)".into(),
                )
                .into());
            }
            secrecy::SecretString::from(env_pass)
        } else {
            let p1 = Zeroizing::new(
                tokio::task::spawn_blocking(|| {
                    rpassword::prompt_password("Passphrase export (min 12 chars): ")
                })
                .await
                .map_err(|e| {
                    anyhow::Error::from(crate::error::InjektError::Other(
                        format!("tty read task failed: {e}").into(),
                    ))
                })?
                .map_err(|e| {
                    anyhow::Error::from(crate::error::InjektError::Other(
                        format!("tty read: {e}").into(),
                    ))
                })?,
            );
            if p1.len() < 12 {
                return Err(crate::error::InjektError::Other(
                    "passphrase trop courte (min 12)".into(),
                )
                .into());
            }
            let p2 = Zeroizing::new(
                tokio::task::spawn_blocking(|| {
                    rpassword::prompt_password("Confirmer passphrase: ")
                })
                .await
                .map_err(|e| {
                    anyhow::Error::from(crate::error::InjektError::Other(
                        format!("tty read task failed: {e}").into(),
                    ))
                })?
                .map_err(|e| {
                    anyhow::Error::from(crate::error::InjektError::Other(
                        format!("tty read: {e}").into(),
                    ))
                })?,
            );
            if p1.as_str() != p2.as_str() {
                return Err(crate::error::InjektError::Other("passphrases mismatch".into()).into());
            }
            secrecy::SecretString::from(p1.as_str().to_owned())
        };
        if let Err(e) = crate::session::export::EncryptedExport::encrypt_to_file(
            &*result.state_handle.read().await,
            &pass,
            path,
        ) {
            // Fail the command: a silent warning + exit 0 would pretend the
            // sensitive artefact exists while nothing was written.
            return Err(crate::error::InjektError::Other(
                format!("export failed for '{scrubbed_path}': {e}").into(),
            )
            .into());
        }
        info!(path=%scrubbed_path, "export chiffré écrit (0o600, v2 argon2id)");
    }

    Ok(())
}
