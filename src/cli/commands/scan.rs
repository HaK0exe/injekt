#![deny(unsafe_code)]

use crate::{
    cli::args::Cli,
    cli::client_builder::build_client,
    engine::orchestrator::{Engine, EngineConfig},
    reporting::{console, json::JsonReport},
    session::scrubber::Scrubber,
};
use anyhow::Result;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
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
    EngineConfig {
        threads: cli.effective_threads(),
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
        payload_opts: cli.payload_opts(),
        matcher: cli.matcher_config(),
        tampers,
        level: cli.effective_level(),
        confirm: cli.confirm,
        ignore_codes: cli.ignore_codes.clone(),
        oob_domain: cli.oob_domain.clone(),
        oob_poll_url: cli.oob_poll_url.clone(),
        oob_wait_secs: cli.effective_oob_wait_secs(),
        hpp: cli.hpp,
        chunked: cli.chunked,
        allow_private: cli.allow_private,
        no_redact: cli.no_redact,
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
    let count = s.request_count();
    drop(s);

    let scrubber = Scrubber::new(cfg.no_redact);
    let report = JsonReport::new(target.clone(), findings, vec![], count).scrubbed(&scrubber);

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
    if let Some(out) = &cli.output {
        let json = serde_json::to_string_pretty(&report.to_json(&scrubber))?;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(out).await?;
        file.write_all(json.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.sync_all().await?;
        info!(path=%scrubber.scrub(out), "bulk json report written (0o600)");
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

/// Print the execution plan without sending any request.
fn dry_run(cli: &Cli) {
    let scrubber = Scrubber::new(cli.no_redact);
    println!("dry-run: scan plan (no request sent)");
    println!("  resolution: {}", cli.resolution_summary());
    let targets = crate::target::ingest::collect_targets(cli, None)
        .unwrap_or_else(|_| cli.effective_target().map(|t| vec![t]).unwrap_or_default());
    if targets.is_empty() {
        println!("  targets: 0 (no valid target)");
    } else {
        println!("  targets: {}", targets.len());
        for target in targets.iter().take(20) {
            println!("    - {}", scrubber.scrub(target));
        }
        if targets.len() > 20 {
            println!("    … ({} more)", targets.len() - 20);
        }
    }
    let cfg = engine_config(cli);
    println!(
        "  techniques: {} level={} threads={}",
        if cfg.techniques.is_empty() {
            "all".to_owned()
        } else {
            cfg.techniques.join(",")
        },
        cfg.level,
        cfg.threads
    );
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
    info!(
        target=%scrubber.scrub(&result.target),
        state=?result.engine_state,
        "scan finished"
    );

    console::print_findings(&result.report.findings, &scrubber);

    if let Some(out) = &cli.output {
        let json = result.report.to_json(&scrubber);
        // Write with 0o600 perms on Unix (sensitive report)
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(out).await?;
        file.write_all(json.as_bytes()).await?;
        file.sync_all().await?;
        info!(path=%scrubber.scrub(out), "json report written (0o600)");
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
            warn!(error=%e, "export failed");
        } else {
            info!(path=%scrubbed_path, "export chiffré écrit (0o600, v2 argon2id)");
        }
    }

    Ok(())
}
