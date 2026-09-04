#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Optional TOML config file (`--config <PATH>`, `./injekt.toml`,
/// `~/.config/injekt/config.toml`).
///
/// Only non-secret tuning knobs are supported on purpose: secrets
/// (`--cookies`, `Authorization` headers, passphrases) must stay on the
/// command line / environment so a config file never becomes a secret store.
/// Unknown keys are ignored to stay forward-compatible.
///
/// Precedence (highest wins): explicit CLI flag > environment variable
/// (`INJEKT_*`, handled by clap) > config file > `--profile` preset >
/// built-in defaults. Setting `--profile` on the CLI overrides a `profile`
/// key from the file.
///
/// Example `injekt.toml`:
/// ```toml
/// profile = "stealth"
/// threads = 2
/// rate_limit = 3.0
/// jitter = "1200,400"
/// timeout = 30
/// retries = 3
/// delay = 800
/// level = 1
/// techniques = ["boolean", "error"]
/// proxy = "socks5h://127.0.0.1:9050"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FileConfig {
    pub profile: Option<String>,
    pub threads: Option<usize>,
    pub timeout: Option<u64>,
    pub retries: Option<usize>,
    pub delay: Option<u64>,
    pub rate_limit: Option<f64>,
    pub jitter: Option<String>,
    pub level: Option<u8>,
    pub techniques: Option<Vec<String>>,
    pub proxy: Option<String>,
    pub oob_wait_secs: Option<u64>,
}

impl FileConfig {
    /// Parse TOML content. Unknown fields are ignored (`serde` default would
    /// deny them, so we use an untagged tolerant path via `toml::Value`).
    ///
    /// # Errors
    /// Returns an error if the TOML is malformed or a known field has the
    /// wrong type.
    pub fn parse(content: &str) -> Result<Self, String> {
        toml::from_str::<Self>(content).map_err(|e| e.to_string())
    }

    /// Resolve the profile named in the file, if any. Unknown names yield
    /// `None` (caller logs a warning) to avoid breaking runs on typos.
    #[must_use]
    pub fn file_profile(&self) -> Option<crate::cli::profile::Profile> {
        let name = self.profile.as_deref()?;
        match name.to_ascii_lowercase().as_str() {
            "quick" => Some(crate::cli::profile::Profile::Quick),
            "balanced" => Some(crate::cli::profile::Profile::Balanced),
            "stealth" => Some(crate::cli::profile::Profile::Stealth),
            "aggressive" => Some(crate::cli::profile::Profile::Aggressive),
            _ => None,
        }
    }
}

/// Locate config files to try, in order. The explicit `--config` path (if
/// any) comes first, then `./injekt.toml`, then `~/.config/injekt/config.toml`.
#[must_use]
pub fn candidate_paths(explicit: Option<&str>) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Some(p) = explicit {
        out.push(std::path::PathBuf::from(p));
    }
    out.push(std::path::PathBuf::from("./injekt.toml"));
    if let Some(home) = std::env::var_os("HOME") {
        let mut p = std::path::PathBuf::from(home);
        p.push(".config/injekt/config.toml");
        out.push(p);
    }
    out
}

/// Load the first existing config file. Returns `None` when no file exists.
/// An explicit `--config` path that cannot be read/parsed is an error;
/// auto-discovered files that fail to parse only warn (never break a run
/// because of a stray file).
///
/// # Errors
/// Returns an error if the explicit `--config` file cannot be read or parsed.
pub fn load(explicit: Option<&str>) -> Result<Option<(std::path::PathBuf, FileConfig)>, String> {
    let candidates = candidate_paths(explicit);
    let explicit_path = explicit.map(std::path::PathBuf::from);
    for path in candidates {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        match FileConfig::parse(&content) {
            Ok(cfg) => return Ok(Some((path, cfg))),
            Err(e) => {
                if explicit_path.as_ref().is_some_and(|p| p == &path) {
                    return Err(format!("invalid config file {}: {e}", path.display()));
                }
                tracing::warn!(path=%path.display(), error=%e, "ignoring invalid auto-loaded config file");
                return Ok(None);
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let cfg = FileConfig::parse("threads = 2\n").unwrap_or_default();
        assert_eq!(cfg.threads, Some(2));
        assert_eq!(cfg.proxy, None);
    }

    #[test]
    fn parse_full_example() {
        let content = r#"
profile = "stealth"
threads = 2
rate_limit = 3.0
jitter = "1200,400"
techniques = ["boolean", "error"]
"#;
        let cfg = FileConfig::parse(content).unwrap_or_default();
        assert_eq!(cfg.threads, Some(2));
        assert_eq!(cfg.rate_limit, Some(3.0));
    }

    #[test]
    fn parse_invalid_type_errors() {
        assert!(FileConfig::parse("threads = \"many\"\n").is_err());
    }

    #[test]
    fn unknown_profile_yields_none() {
        let cfg = FileConfig {
            profile: Some("nope".to_owned()),
            ..FileConfig::default()
        };
        assert_eq!(cfg.file_profile(), None);
    }
}
