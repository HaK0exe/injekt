//! Single-load config snapshot (P0/P3): the TOML file is read at
//! most once per process, then every `*_with` helper resolves from it.

use crate::cli::args::Cli;
use crate::cli::profile::Profile;

/// Single-load snapshot for one CLI invocation (P0).
/// Loads the TOML config file **once** plus the active profile, then all
/// `*_with` helpers below resolve from it with zero extra I/O.
/// Hot paths (`build_engine_config`, `build_client`) must use
/// [`Cli::resolve_snapshot`] + `*_with` instead of the legacy `effective_*`
/// (which each re-`load()` for backward compatibility).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ResolvedSnapshot {
    pub file: crate::cli::file_config::FileConfig,
    pub profile: Option<Profile>,
}

impl Cli {
    /// Load config file + active profile exactly once.
    #[must_use]
    pub fn resolve_snapshot(&self) -> ResolvedSnapshot {
        let file = self.file_snapshot();
        let profile = if let Some(p) = self.profile {
            Some(p)
        } else if file.profile.is_some() {
            let resolved = file.file_profile();
            if resolved.is_none() {
                tracing::warn!(
                    profile=?file.profile,
                    available=?Profile::all_names(),
                    "unknown profile in config file, ignoring"
                );
            }
            resolved
        } else {
            None
        };
        ResolvedSnapshot { file, profile }
    }

    #[must_use]
    pub fn effective_threads_with(&self, snap: &ResolvedSnapshot) -> usize {
        if let Some(v) = self.detection.threads {
            return v.max(1);
        }
        if let Some(v) = snap.file.threads {
            return v.max(1);
        }
        snap.profile.map_or(5, Profile::threads).max(1)
    }

    #[must_use]
    pub fn effective_timeout_with(&self, snap: &ResolvedSnapshot) -> u64 {
        if let Some(v) = self.http.timeout {
            return v.max(1);
        }
        if let Some(v) = snap.file.timeout {
            return v.max(1);
        }
        snap.profile.map_or(30, Profile::timeout_secs).max(1)
    }

    #[must_use]
    pub fn effective_retries_with(&self, snap: &ResolvedSnapshot) -> usize {
        if let Some(v) = self.http.retries {
            return v;
        }
        if let Some(v) = snap.file.retries {
            return v;
        }
        snap.profile.map_or(3, Profile::retries)
    }

    #[must_use]
    pub fn effective_delay_with(&self, snap: &ResolvedSnapshot) -> u64 {
        if let Some(v) = self.http.delay {
            return v;
        }
        if let Some(v) = snap.file.delay {
            return v;
        }
        snap.profile.map_or(500, Profile::delay_ms)
    }

    #[must_use]
    pub fn effective_rate_limit_with(&self, snap: &ResolvedSnapshot) -> f64 {
        if let Some(v) = self.http.rate_limit {
            return v;
        }
        if let Some(v) = snap.file.rate_limit {
            return v;
        }
        snap.profile.map_or(10.0, Profile::rate_limit_rps)
    }

    #[must_use]
    pub fn effective_jitter_with(&self, snap: &ResolvedSnapshot) -> String {
        if let Some(v) = self.http.jitter.clone() {
            return v;
        }
        if let Some(v) = snap.file.jitter.clone() {
            return v;
        }
        snap.profile
            .map_or_else(|| "750,250".to_owned(), |p| p.jitter().to_owned())
    }

    #[must_use]
    pub fn effective_level_with(&self, snap: &ResolvedSnapshot) -> u8 {
        if let Some(v) = self.detection.level {
            return v.clamp(1, 5);
        }
        if let Some(v) = snap.file.level {
            return v.clamp(1, 5);
        }
        snap.profile.map_or(1, Profile::level).clamp(1, 5)
    }

    #[must_use]
    pub fn effective_seed_with(&self, snap: &ResolvedSnapshot) -> Option<u64> {
        if self.detection.seed.is_some() {
            return self.detection.seed;
        }
        snap.file.seed
    }

    #[must_use]
    pub fn effective_techniques_with(&self, snap: &ResolvedSnapshot) -> Vec<String> {
        if !self.detection.techniques.is_empty() {
            return self.detection.techniques.clone();
        }
        if let Some(v) = snap.file.techniques.clone()
            && !v.is_empty()
        {
            return v;
        }
        snap.profile
            .map_or_else(|| vec!["all".to_owned()], Profile::techniques)
    }

    #[must_use]
    pub fn effective_proxy_with(&self, snap: &ResolvedSnapshot) -> Option<String> {
        if let Some(v) = self.http.proxy.clone() {
            return Some(v);
        }
        snap.file.proxy.clone()
    }

    #[must_use]
    pub fn effective_oob_wait_secs_with(&self, snap: &ResolvedSnapshot) -> u64 {
        if let Some(v) = self.detection.oob_wait_secs {
            return v;
        }
        snap.file.oob_wait_secs.unwrap_or(5)
    }

    /// Load the config file snapshot for this invocation.
    /// Memoised per [`Cli`] instance: the first call reads the TOML once, every
    /// later call clones the cached value (`Arc<OnceLock>` also covers clones
    /// of the parsed `Cli`).
    /// Explicit `--config` errors are logged and ignored here (the scan
    /// entry points surface them); auto-discovered files never fail.
    pub(super) fn file_snapshot(&self) -> crate::cli::file_config::FileConfig {
        self.file_cache
            .get_or_init(
                || match crate::cli::file_config::load(self.config.as_deref()) {
                    Ok(Some((path, cfg))) => {
                        tracing::debug!(path=%path.display(), "config file loaded");
                        cfg
                    }
                    Ok(None) => crate::cli::file_config::FileConfig::default(),
                    Err(e) => {
                        tracing::warn!(error=%e, "invalid --config file, ignoring");
                        crate::cli::file_config::FileConfig::default()
                    }
                },
            )
            .clone()
    }

    /// Active preset: explicit `--profile` (or `INJEKT_PROFILE`) wins over the
    /// `profile` key from the config file. Unknown file profile names warn.
    #[must_use]
    pub fn active_profile(&self) -> Option<Profile> {
        if let Some(p) = self.profile {
            return Some(p);
        }
        let file = self.file_snapshot();
        if file.profile.is_some() {
            let resolved = file.file_profile();
            if resolved.is_none() {
                tracing::warn!(
                    profile=?file.profile,
                    available=?Profile::all_names(),
                    "unknown profile in config file, ignoring"
                );
            }
            return resolved;
        }
        None
    }
}
