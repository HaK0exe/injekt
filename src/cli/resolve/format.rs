#![deny(unsafe_code)]

//! C16 — `--format` resolution: explicit CLI/env > `--output` extension >
//! config-TOML `format` key > default `json`.
//!
//! The extension inference applies only when neither `--format` nor
//! `INJEKT_FORMAT` is set (clap parses both sources into the same
//! `OutputOpts::format` field, `Some` ⇒ explicit). Unknown extensions
//! (`.yaml`, no extension, …) never infer and never warn — silent
//! `json`/config default.

use crate::cli::args::{Cli, ReportFormat};

/// Infer a report format from the `--output` file extension. Returns `None`
/// for unknown extensions (including no extension at all, non-UTF8 names and
/// dotfiles) — silently, so the caller falls through to config / default.
#[must_use]
pub fn infer_from_extension(output: Option<&str>) -> Option<ReportFormat> {
    let path = output?;
    let ext = std::path::Path::new(path).extension()?.to_str()?;
    match ext.to_ascii_lowercase().as_str() {
        "json" => Some(ReportFormat::Json),
        "sarif" => Some(ReportFormat::Sarif),
        "junit" | "xml" => Some(ReportFormat::Junit),
        "md" | "markdown" => Some(ReportFormat::Md),
        _ => None,
    }
}

impl Cli {
    /// Effective report format (C16). Precedence: CLI `--format` / env
    /// `INJEKT_FORMAT` (both land in [`crate::cli::args::OutputOpts::format`])
    /// > `--output` extension > config-TOML `format` key > default `json`.
    ///
    /// An explicit value contradicting a DIFFERENT extension-derived one is
    /// warned exactly once per invocation (the explicit value wins).
    #[must_use]
    pub fn effective_format(&self) -> ReportFormat {
        if let Some(explicit) = self.output_opts.format {
            self.warn_explicit_extension_conflict(explicit);
            return explicit;
        }
        if let Some(inferred) = infer_from_extension(self.output_opts.output.as_deref()) {
            return inferred;
        }
        let file = self.file_snapshot();
        if let Some(fmt) = file.file_format() {
            return fmt;
        }
        if file.format.is_some() {
            tracing::warn!(
                format = file.format.as_deref().unwrap_or(""),
                "unknown `format` key in config file, ignoring (expected json|sarif|junit|md)"
            );
        }
        ReportFormat::Json
    }

    /// One warning max per invocation (shared across `Cli` clones via
    /// `format_conflict_warned`) when the explicit `--format` disagrees with
    /// the `--output` extension. Equal values and absent extensions stay
    /// silent. Message scrubbed (paths may sit under token-bearing names).
    fn warn_explicit_extension_conflict(&self, explicit: ReportFormat) {
        let Some(inferred) = infer_from_extension(self.output_opts.output.as_deref()) else {
            return;
        };
        if inferred == explicit {
            return;
        }
        if self
            .format_conflict_warned
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        let scrubber = crate::session::scrubber::Scrubber::new(self.output_opts.no_redact);
        tracing::warn!(
            path = %scrubber
                .scrub(self.output_opts.output.as_deref().unwrap_or("")),
            explicit = %explicit,
            inferred = %inferred,
            "--format {explicit} disagrees with the --output extension ({inferred}) — explicit --format wins"
        );
    }
}
