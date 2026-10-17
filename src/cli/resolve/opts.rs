//! Engine option builders (`PayloadOpts`, matcher, tuning tuple).

use crate::cli::args::Cli;

impl Cli {
    /// Assemble [`PayloadOpts`] from CLI flags. Unknown `--fetch-using`
    /// values warn + fall back to `Direct` (clap constrains choices anyway;
    /// manual/MCP constructions hit this path).
    #[must_use]
    pub fn payload_opts(&self) -> crate::techniques::payload_opts::PayloadOpts {
        use crate::techniques::payload_opts::FetchUsing;
        let fetch_using = match self.detection.fetch_using.as_deref() {
            Some("boolean") => FetchUsing::Boolean,
            Some("time") => FetchUsing::Time,
            Some("direct" | "") | None => FetchUsing::Direct,
            Some(other) => {
                tracing::warn!(value = %other, "unknown --fetch-using, falling back to direct");
                FetchUsing::Direct
            }
        };
        crate::techniques::payload_opts::PayloadOpts {
            prefix: self.evasion.prefix.clone(),
            suffix: self.evasion.suffix.clone(),
            safe_chars: self.evasion.safe_chars.clone().unwrap_or_default(),
            skip_urlencode: self.evasion.skip_urlencode,
            fetch_using,
        }
    }

    /// Assemble [`MatcherConfig`](crate::detection::matcher::MatcherConfig)
    /// from CLI flags (`--string`, `--not-string`, `--code`, `--text-only`).
    #[must_use]
    pub fn matcher_config(&self) -> crate::detection::matcher::MatcherConfig {
        crate::detection::matcher::MatcherConfig {
            string: self.detection.string.clone(),
            not_string: self.detection.not_string.clone(),
            code: self.detection.code,
            text_only: self.detection.text_only,
        }
    }

    /// Assemble tuning config from CLI flags (`--level`, `--confirm`, `--ignore-code`).
    #[must_use]
    pub fn tuning_config(&self) -> (u8, bool, Vec<u16>) {
        (
            self.effective_level(),
            self.detection.confirm,
            self.detection.ignore_codes.clone(),
        )
    }
}
