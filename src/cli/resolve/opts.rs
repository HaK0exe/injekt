//! Engine option builders (`PayloadOpts`, matcher, tuning tuple).

use regex::Regex;

use crate::cli::args::Cli;

impl Cli {
    /// Assemble [`crate::techniques::payload_opts::PayloadOpts`] from CLI flags. Unknown `--fetch-using`
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

    /// Compile a `body~RE` pattern once into the resolver-built config
    /// (validated at parse; a failure here is only reachable through a
    /// programmatic path — Centralisation of the double-checked compile).
    fn push_compiled(pattern: &str, compiled: &mut Vec<Regex>, src: &mut Vec<String>) {
        match Regex::new(pattern) {
            Ok(re) => {
                compiled.push(re);
                src.push(pattern.to_owned());
            }
            Err(e) => {
                tracing::warn!(
                    "--match/--veto regex invalid (validated at parse — unreachable): {e}"
                );
            }
        }
    }

    /// Assemble [`MatcherConfig`](crate::detection::matcher::MatcherConfig)
    /// from CLI flags (`--string`, `--not-string`, `--code`, `--text-only`;
    /// plus the C17 `--match`/`--veto` expressions mapped exactly per the
    /// frozen grammar). Legacy flags are read first, then exprs — the
    /// LAST expr processed wins on the single-`Option` fields
    /// (`code`/`string`/`not_string`), list fields append
    /// (`veto_codes`, the compiled regex lists). Regexes are compiled
    /// ONCE here: `matches()` (per-response hot path) never recompiles.
    ///
    /// The `warn!` on a compile failure covers only a programmatic
    /// construction (MCP builder fills no expr); CLI exprs are validated
    /// at parse (usage exit 2), a double failure is unreachable.
    #[must_use]
    pub fn matcher_config(&self) -> crate::detection::matcher::MatcherConfig {
        use crate::cli::args::detection::MatchExprKind;
        let mut cfg = crate::detection::matcher::MatcherConfig {
            string: self.detection.string.clone(),
            not_string: self.detection.not_string.clone(),
            code: self.detection.code,
            text_only: self.detection.text_only,
            ..crate::detection::matcher::MatcherConfig::default()
        };
        for kind in &self.detection.match_expr {
            match kind {
                MatchExprKind::StatusEq(status) => cfg.code = Some(*status),
                MatchExprKind::StatusNe(status) => cfg.veto_codes.push(*status),
                MatchExprKind::BodyContains(text) => cfg.string = Some(text.clone()),
                MatchExprKind::BodyRegex(pattern) => {
                    Self::push_compiled(pattern, &mut cfg.match_regex, &mut cfg.match_regex_src);
                }
            }
        }
        for kind in &self.detection.veto_expr {
            match kind {
                MatchExprKind::StatusEq(status) => cfg.veto_codes.push(*status),
                MatchExprKind::StatusNe(status) => cfg.code = Some(*status),
                MatchExprKind::BodyContains(text) => cfg.not_string = Some(text.clone()),
                MatchExprKind::BodyRegex(pattern) => {
                    Self::push_compiled(pattern, &mut cfg.veto_regex, &mut cfg.veto_regex_src);
                }
            }
        }
        cfg
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
