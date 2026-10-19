//! Explicit `--config` validation + target-source consistency + operator-facing resolution summary.

use crate::cli::args::Cli;

impl Cli {
    /// C16 — usage error when the positional target (`injekt <URL>` /
    /// `injekt auto <URL|HOST>`) and a CLI-typed `-u/--target` disagree.
    /// Equal values are accepted silently (zero-break for
    /// `injekt <URL> -u <URL>` round-trips). An env-sourced `INJEKT_TARGET`
    /// is below the positional in the documented precedence, so it never
    /// conflicts — `cli_typed_target` (set in `main` from clap
    /// `ValueSource::CommandLine`) gates the check. No network, no side
    /// effect.
    ///
    /// # Errors
    /// Returns [`crate::error::InjektError::TargetConflict`] (mapped to exit
    /// code 2 by `main`, like `NoTarget`).
    pub fn validate_target_conflict(&self) -> Result<(), crate::error::InjektError> {
        if !self.cli_typed_target {
            return Ok(());
        }
        let Some(position) = self.positional_target() else {
            return Ok(());
        };
        let Some(flag) = self.target_opts.target.as_deref() else {
            return Ok(());
        };
        if flag != position {
            return Err(crate::error::InjektError::TargetConflict {
                positional: position.to_owned(),
                target: flag.to_owned(),
            });
        }
        Ok(())
    }

    /// Fail fast on an explicit `--config` path that cannot be read or parsed.
    /// Auto-discovered files never fail (they warn in `Self::file_snapshot`).
    ///
    /// # Errors
    /// Returns an error describing the invalid explicit config file.
    pub fn validate_explicit_config(&self) -> Result<(), String> {
        let Some(path) = self.config.as_deref() else {
            return Ok(());
        };
        match std::fs::read_to_string(path) {
            Ok(content) => crate::cli::file_config::FileConfig::parse(&content)
                .map(|_| ())
                .map_err(|e| format!("invalid config file {path}: {e}")),
            Err(e) => Err(format!("cannot read config file {path}: {e}")),
        }
    }

    /// One-line summary of the active preset/config for `tracing::info!` logs.
    /// Keeps startup output readable without dumping every resolved knob.
    #[must_use]
    pub fn resolution_summary(&self) -> String {
        let profile = self.active_profile().map_or_else(
            || "none".to_owned(),
            |p| format!("{p:?}").to_ascii_lowercase(),
        );
        let config = self.config.clone().unwrap_or_else(|| "auto".to_owned());
        format!(
            "profile={profile} config={config} threads={} rate={} jitter={} level={}",
            self.effective_threads(),
            self.effective_rate_limit(),
            self.effective_jitter(),
            self.effective_level(),
        )
    }
}
