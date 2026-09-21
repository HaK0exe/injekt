#![deny(unsafe_code)]

//! Shared helpers for CLI command dispatch (P3).
//!
//! Pure factorisation: no flag, network or default changes.
//! * [`is_bulk`] — multi-target ingestion predicate (bulk/stdin/openapi/
//!   sitemap/raw-dir only, no `effective_target` / `dry_run`).
//! * [`resolve_targets`] — thin wrapper over `collect_targets`.
//! * [`write_report_async`] — single `--output` writer (always
//!   `write_output_file_async`; callers build `body` via `render_report`
//!   for `JsonReport` or `to_string_pretty` for recon envelopes).
//! * [`guard_bulk`] — fail-closed cross-origin secret gate + opt-in warn.
//! * [`warn_scan_explicit`] / [`warn_recon_scan`] — centralised soft-
//!   deprecation warnings.

use crate::cli::args::Cli;

/// `true` when any multi-target ingestion source is set.
///
/// Bulk-only: `--bulk-file` / `--stdin` / `--openapi-file` / `--sitemap-file`
/// / `--raw-dir`. `effective_target` and `dry_run` are intentionally excluded
/// (handled by `fallback_bare_or_auto`).
#[must_use]
pub fn is_bulk(cli: &Cli) -> bool {
    cli.target_opts.bulk_file.is_some()
        || cli.target_opts.stdin
        || cli.target_opts.openapi_file.is_some()
        || cli.target_opts.sitemap_file.is_some()
        || cli.target_opts.raw_dir.is_some()
}

/// Thin wrapper over [`crate::target::ingest::collect_targets`].
///
/// # Errors
/// Returns an error when ingestion files cannot be read/parsed, or when no
/// valid target remains after filtering.
///
/// Conseils.js : fichier — fonction, pas de blabla.
pub fn resolve_targets(cli: &Cli, extra: Option<&str>) -> anyhow::Result<Vec<String>> {
    crate::target::ingest::collect_targets(cli, extra)
}

/// Single `--output` writer: always `write_output_file_async` (0o600,
/// no overwrite unless `force`). `body` must already be rendered
/// (`render_report` for `JsonReport`, `to_string_pretty` for recon
/// envelopes). `None` path = no-op (caller owns stdout console output).
///
/// # Errors
/// Returns an error when validation fails, the payload is too large, or the
/// write/sync fails.
pub async fn write_report_async(
    path: Option<&str>,
    body: &str,
    force: bool,
    scrubbed: &str,
) -> anyhow::Result<()> {
    if let Some(out) = path {
        crate::cli::output::file::write_output_file_async(out, body, force, scrubbed).await
    } else {
        Ok(())
    }
}

/// Generic JSON emitter for recon envelopes (`CrawlReport`,
/// `DiscoveryReport`, candidates): pretty JSON to stdout, or via
/// [`write_report_async`] (always async file write) when `path` is set.
///
/// # Errors
/// Returns an error when serialization or the file write fails.
pub async fn emit_json_async<T: serde::Serialize>(
    value: &T,
    path: Option<&str>,
    no_redact: bool,
    force: bool,
) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    if let Some(out) = path {
        let scrubber = crate::session::scrubber::Scrubber::new(no_redact);
        write_report_async(Some(out), &json, force, &scrubber.scrub(out)).await
    } else {
        println!("{json}");
        Ok(())
    }
}

/// Fail-closed gate against cross-origin secret replay + explicit opt-in
/// warning. Single-origin runs always pass.
///
/// # Errors
/// Returns an error when auth secrets would be sprayed across origins
/// without `--allow-secret-reuse`.
pub fn guard_bulk(cli: &Cli, targets: &[String]) -> anyhow::Result<()> {
    cli.check_secret_reuse(targets)?;
    if cli.allow_secret_reuse && cli.has_auth_secrets() {
        tracing::warn!(
            "--allow-secret-reuse: replaying --cookies/--headers across multiple origins"
        );
    }
    Ok(())
}

/// Soft-deprecation warning for the explicit `scan` subcommand.
/// Bare `injekt --target <URL>` shares the scan entry point and stays the
/// recommended path, so it must not warn (warn lives in `dispatch`, not in
/// `scan::run`).
pub fn warn_scan_explicit() {
    tracing::warn!(
        "The 'scan' subcommand is deprecated. Use bare 'injekt --target <URL>' or 'injekt auto' instead — behaviour is identical."
    );
}

/// Soft-deprecation warning for `recon scan` (thin alias over
/// `auto --with-recon`).
pub fn warn_recon_scan() {
    tracing::warn!(
        "The 'recon scan' subcommand is deprecated. Use 'injekt auto --with-recon' instead — behaviour is identical."
    );
}
