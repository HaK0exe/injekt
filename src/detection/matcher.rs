#![deny(unsafe_code)]

//! Custom response matchers (`--string`, `--not-string`, `--code`,
//! `--text-only`; plus the C17 `--match`/`--veto` expression forms —
//! same `MatcherConfig`, richer grammar).
//!
//! [`MatcherConfig`] is a lightweight veto gate evaluated *before* the
//! statistical detector: it can only reject a candidate (`Some(false)`)
//! or abstain (`None`) and let the detector decide. It never confirms
//! a finding on its own.

use regex::Regex;

/// User-supplied matching constraints for response gating.
///
/// All string comparisons are case-sensitive. The caller is expected to
/// pre-process the body via [`MatcherConfig::pre_process`] (handles
/// `--text-only`) before calling [`MatcherConfig::matches`].
///
/// C17 — `--match EXPR`/`--veto EXPR` (frozen grammar:
/// `status==N`, `status!=N`, `body=CONTENU`, `body~RE`) map onto this
/// struct exactly:
/// * `--match status==N` ⇔ `code` (must equal) — same field, expr ordering
///   validated at parse;
/// * `--veto status!=N` ⇔ `code` too (must equal, inverted wording);
/// * `--veto status==N` ⇒ `veto_codes` (no legacy equivalent);
/// * `--match body=…` ⇔ `string`, `--veto body=…` ⇔ `not_string`;
/// * `body~RE` ⇒ the compiled regex lists below (no legacy equivalent).
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct MatcherConfig {
    /// Response body must contain this substring, otherwise veto.
    pub string: Option<String>,
    /// Response body must NOT contain this substring, otherwise veto.
    pub not_string: Option<String>,
    /// Response status must equal this code, otherwise veto.
    pub code: Option<u16>,
    /// Strip HTML tags/entities before matching.
    pub text_only: bool,
    /// C17 — compiled `--match body~RE` expressions (disjunction: any
    /// hit satisfies the gate). Compiled ONCE in the resolver — this
    /// hot path (per response) must never recompile a regex; sources
    /// kept in `*_src` for evidence/debugging only.
    pub match_regex: Vec<Regex>,
    /// C17 — source patterns of [`MatcherConfig::match_regex`].
    pub match_regex_src: Vec<String>,
    /// C17 — compiled `--veto body~RE` expressions: any hit vetoes.
    pub veto_regex: Vec<Regex>,
    /// C17 — source patterns of [`MatcherConfig::veto_regex`].
    pub veto_regex_src: Vec<String>,
    /// C17 — `--veto status==N`: veto when the status equals one of these.
    pub veto_codes: Vec<u16>,
}

impl MatcherConfig {
    /// Returns `true` when at least one constraint is set.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.string.is_some()
            || self.not_string.is_some()
            || self.code.is_some()
            || self.text_only
            || !self.match_regex.is_empty()
            || !self.veto_regex.is_empty()
            || !self.veto_codes.is_empty()
    }

    /// Pre-process a response body according to the config.
    ///
    /// When `text_only` is set, HTML tags are stripped via [`strip_html`];
    /// otherwise the body is returned unchanged.
    #[must_use]
    pub fn pre_process(&self, body: &str) -> String {
        if self.text_only {
            strip_html(body)
        } else {
            body.to_owned()
        }
    }

    /// Evaluate a (pre-processed) body + status pair.
    ///
    /// Order matters (first veto wins):
    /// 1. `code` mismatch → `Some(false)`
    /// 2. C17 `veto_codes` hit (status equal) → `Some(false)`
    /// 3. `not_string` contained → `Some(false)`
    /// 4. C17 any `veto_regex` hit → `Some(false)`
    /// 5. valid-page conditions — when at least one is requested
    ///    (`string` XOR the C17 `match` list): no legacy `string` hit AND
    ///    no regex hit ⇒ `Some(false)`.
    ///
    /// Otherwise returns `None` (no verdict, let the detector decide).
    #[must_use]
    pub fn matches(&self, body: &str, status: u16) -> Option<bool> {
        if let Some(expected) = self.code
            && status != expected
        {
            return Some(false);
        }
        if self.veto_codes.contains(&status) {
            return Some(false);
        }
        if let Some(needle) = self.not_string.as_deref()
            && body.contains(needle)
        {
            return Some(false);
        }
        if self.veto_regex.iter().any(|re| re.is_match(body)) {
            return Some(false);
        }
        // Valid-page conditions (require-style): satisfied = abstain.
        if self.string.is_some() || !self.match_regex.is_empty() {
            let covered = self.string.as_deref().is_some_and(|n| body.contains(n))
                || self.match_regex.iter().any(|re| re.is_match(body));
            if !covered {
                return Some(false);
            }
        }
        None
    }

    /// Veto gate for boolean-based (TRUE/FALSE) checks.
    ///
    /// Differential semantics: `--string`/`--code`/`--not-string` describe the
    /// valid page, and a boolean oracle *by design* makes one branch differ
    /// (e.g. `--string welcome`: TRUE contains it, FALSE legitimately does
    /// not). Veto only when *both* branches violate [`Self::matches`]
    /// (neither looks like a valid page); when at least one branch satisfies
    /// the matcher, abstain (`None`) and let the detector decide.
    #[must_use]
    pub fn gate_boolean(
        &self,
        true_body: &str,
        false_body: &str,
        t_status: u16,
        f_status: u16,
    ) -> Option<bool> {
        let true_violates = self.matches(true_body, t_status) == Some(false);
        let false_violates = self.matches(false_body, f_status) == Some(false);
        if true_violates && false_violates {
            return Some(false);
        }
        None
    }

    /// Short evidence fragment describing the active matcher.
    ///
    /// Returns an empty string when the matcher is inactive. Each value is
    /// truncated to 24 characters so evidence stays compact.
    #[must_use]
    pub fn evidence_suffix(&self) -> String {
        if !self.is_active() {
            return String::new();
        }
        let string = self
            .string
            .as_deref()
            .map_or_else(|| "-".to_owned(), truncate24);
        let not_string = self
            .not_string
            .as_deref()
            .map_or_else(|| "-".to_owned(), truncate24);
        let code = self
            .code
            .map_or_else(|| "-".to_owned(), |c| truncate24(&c.to_string()));
        // C17 — regex sources rendered as a `|`-join (per-expr truncated).
        let display_list = |srcs: &[String]| -> String {
            if srcs.is_empty() {
                "-".to_owned()
            } else {
                srcs.iter()
                    .map(|s| truncate24(s))
                    .collect::<Vec<_>>()
                    .join("|")
            }
        };
        let veto_codes = if self.veto_codes.is_empty() {
            "-".to_owned()
        } else {
            self.veto_codes
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join("|")
        };
        format!(
            " matcher=string:{string},not-string:{not_string},code:{code},\
             re-match:{},re-veto:{},status-veto:{veto_codes},text-only:{}",
            display_list(&self.match_regex_src),
            display_list(&self.veto_regex_src),
            self.text_only
        )
    }
}

/// Truncate a string to at most 24 characters (char-safe, never panics).
fn truncate24(value: &str) -> String {
    if value.chars().count() > 24 {
        value.chars().take(24).collect()
    } else {
        value.to_owned()
    }
}

/// Strip HTML tags and decode a small set of entities.
///
/// - Removes anything between `<` and the next `>` (simple char-by-char
///   state machine, no regex, so no catastrophic backtracking).
/// - An unclosed `<` is emitted literally with its remainder (no data loss:
///   `a < b` stays `a < b`, so baseline comparison is not skewed).
/// - Decodes `&lt;`, `&gt;`, `&quot;`, `&#x27;`, then `&amp;` last to
///   avoid double-decoding `&amp;lt;` into `<`.
/// - Collapses all whitespace runs into single spaces (and trims).
/// - Unknown entities (e.g. `&unknown;`) are left untouched.
/// - Never panics, even on malformed or non-ASCII input.
#[must_use]
pub fn strip_html(body: &str) -> String {
    let mut without_tags = String::with_capacity(body.len());
    let mut in_tag = false;
    let mut tag_buf = String::new();
    for c in body.chars() {
        if in_tag {
            if c == '>' {
                in_tag = false;
                tag_buf.clear();
            } else {
                // `<` inside a tag is kept in the buffer: if the tag never
                // closes, the whole remainder flushes literally (no loss).
                tag_buf.push(c);
            }
        } else if c == '<' {
            in_tag = true;
            tag_buf.clear();
        } else {
            without_tags.push(c);
        }
    }
    if in_tag {
        without_tags.push('<');
        without_tags.push_str(&tag_buf);
    }
    let decoded = without_tags
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&amp;", "&");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn active_string_config() -> MatcherConfig {
        MatcherConfig {
            string: Some("welcome".to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn inactive_by_default() {
        let cfg = MatcherConfig::default();
        assert!(!cfg.is_active());
        assert!(cfg.matches("anything", 200).is_none());
        assert_eq!(cfg.evidence_suffix(), "");
    }

    #[test]
    fn is_active_when_any_field_set() {
        let code_only = MatcherConfig {
            code: Some(200),
            ..Default::default()
        };
        assert!(code_only.is_active());

        let text_only = MatcherConfig {
            text_only: true,
            ..Default::default()
        };
        assert!(text_only.is_active());

        assert!(active_string_config().is_active());
    }

    #[test]
    fn matches_code_veto() {
        let cfg = MatcherConfig {
            code: Some(200),
            ..Default::default()
        };
        assert_eq!(cfg.matches("hello", 404), Some(false));
        assert!(cfg.matches("hello", 200).is_none());
    }

    #[test]
    fn matches_string_veto() {
        let cfg = active_string_config();
        assert_eq!(cfg.matches("goodbye", 200), Some(false));
        assert!(cfg.matches("welcome back", 200).is_none());
    }

    #[test]
    fn matches_not_string_veto() {
        let cfg = MatcherConfig {
            not_string: Some("error".to_owned()),
            ..Default::default()
        };
        assert_eq!(cfg.matches("an error occurred", 200), Some(false));
        assert!(cfg.matches("all good", 200).is_none());
    }

    #[test]
    fn matches_case_sensitive() {
        let cfg = active_string_config();
        // "Welcome" != "welcome": veto expected.
        assert_eq!(cfg.matches("Welcome back", 200), Some(false));
    }

    #[test]
    fn matches_code_veto_wins_over_string() {
        let cfg = MatcherConfig {
            string: Some("welcome".to_owned()),
            code: Some(200),
            ..Default::default()
        };
        // Body satisfies `string` but status violates `code` → veto.
        assert_eq!(cfg.matches("welcome", 500), Some(false));
        // Both satisfied → abstain.
        assert!(cfg.matches("welcome", 200).is_none());
    }

    #[test]
    fn matches_pass_through_none_when_satisfied() {
        let cfg = MatcherConfig {
            string: Some("ok".to_owned()),
            not_string: Some("fatal".to_owned()),
            code: Some(200),
            ..Default::default()
        };
        assert!(cfg.matches("ok response", 200).is_none());
    }

    #[test]
    fn gate_boolean_pass_through() {
        let cfg = active_string_config();
        assert!(
            cfg.gate_boolean("welcome true", "welcome false", 200, 200)
                .is_none()
        );
    }

    #[test]
    fn gate_boolean_veto_true_branch() {
        let cfg = active_string_config();
        // Differential oracle: only the TRUE branch must satisfy `--string`;
        // a FALSE branch that differs is the signal, not a veto.
        assert!(
            cfg.gate_boolean("goodbye", "welcome false", 200, 200)
                .is_none()
        );
        // Veto only when BOTH branches violate the matcher.
        assert_eq!(
            cfg.gate_boolean("goodbye", "goodbye", 200, 200),
            Some(false)
        );
    }

    #[test]
    fn gate_boolean_veto_false_branch() {
        let cfg = active_string_config();
        assert!(
            cfg.gate_boolean("welcome true", "goodbye", 200, 200)
                .is_none()
        );
        assert_eq!(
            cfg.gate_boolean("goodbye", "goodbye", 200, 200),
            Some(false)
        );
    }

    #[test]
    fn gate_boolean_veto_on_status() {
        let cfg = MatcherConfig {
            code: Some(200),
            ..Default::default()
        };
        // Single-branch code differentials (TRUE 200 / FALSE 500) are the
        // oracle signal — veto only when both miss.
        assert!(cfg.gate_boolean("a", "b", 200, 500).is_none());
        assert_eq!(cfg.gate_boolean("a", "b", 500, 500), Some(false));
        assert!(cfg.gate_boolean("a", "b", 200, 200).is_none());
    }

    #[test]
    fn gate_boolean_inactive_never_vetoes() {
        let cfg = MatcherConfig::default();
        assert!(cfg.gate_boolean("a", "b", 200, 500).is_none());
    }

    #[test]
    fn pre_process_passthrough_without_text_only() {
        let cfg = MatcherConfig::default();
        let body = "<p>hi</p>";
        assert_eq!(cfg.pre_process(body), body);
    }

    #[test]
    fn pre_process_strips_when_text_only() {
        let cfg = MatcherConfig {
            text_only: true,
            ..Default::default()
        };
        assert_eq!(cfg.pre_process("<p>hi</p>"), "hi");
    }

    #[test]
    fn strip_html_removes_tags_keeps_text() {
        assert_eq!(strip_html("<p>hello <b>world</b></p>"), "hello world");
        assert_eq!(strip_html("no tags here"), "no tags here");
        assert_eq!(strip_html(""), "");
    }

    #[test]
    fn strip_html_decodes_entities() {
        assert_eq!(
            strip_html("&lt;tag&gt; &amp; &quot;q&quot; &#x27;s&#x27;"),
            "<tag> & \"q\" 's'"
        );
        // Single decode only: &amp;lt; → &lt;, not <.
        assert_eq!(strip_html("&amp;lt;"), "&lt;");
    }

    #[test]
    fn strip_html_collapses_whitespace() {
        assert_eq!(strip_html("a   b\n\t c"), "a b c");
        assert_eq!(strip_html("  <p>  hi  </p>  "), "hi");
    }

    #[test]
    fn strip_html_no_panic_on_malformed() {
        // Unclosed `<` is kept literally (no data loss for baseline compare).
        assert_eq!(strip_html("<a <b"), "<a <b");
        assert_eq!(strip_html("<unclosed"), "<unclosed");
        assert_eq!(strip_html("a < b"), "a < b");
        assert_eq!(strip_html("a > b"), "a > b");
        assert_eq!(strip_html("&unknown; stays"), "&unknown; stays");
        assert_eq!(strip_html("<<<>>>"), ">>");
    }

    #[test]
    fn strip_html_unicode_safe() {
        assert_eq!(strip_html("<p>héllo 🌍</p>"), "héllo 🌍");
        assert_eq!(strip_html("日本語 <b>テスト</b> &amp;"), "日本語 テスト &");
        // Lone angle brackets / emoji must not panic, remainder kept.
        assert_eq!(strip_html("<🦀 <b"), "<🦀 <b");
    }

    #[test]
    fn evidence_suffix_empty_when_inactive() {
        let cfg = MatcherConfig::default();
        assert_eq!(cfg.evidence_suffix(), "");
    }

    #[test]
    fn evidence_suffix_describes_active_matcher() {
        let cfg = MatcherConfig {
            string: Some("welcome".to_owned()),
            code: Some(200),
            text_only: true,
            ..Default::default()
        };
        let suffix = cfg.evidence_suffix();
        assert!(suffix.starts_with(" matcher="));
        assert!(suffix.contains("string:welcome"));
        assert!(suffix.contains("code:200"));
        assert!(suffix.contains("text-only:true"));
    }

    #[test]
    fn evidence_suffix_truncates_long_values() {
        let long = "abcdefghijklmnopqrstuvwxyz0123456789";
        let cfg = MatcherConfig {
            string: Some(long.to_owned()),
            ..Default::default()
        };
        let suffix = cfg.evidence_suffix();
        // 24-char truncation of the alphabet prefix.
        assert!(suffix.contains("string:abcdefghijklmnopqrstuvwx"));
        assert!(!suffix.contains(long));
    }

    // ------------------------------------------------------------------
    // C17 — expression gates (`--match`/`--veto`)
    // ------------------------------------------------------------------

    fn regex_cfg(match_src: &[&str], veto_src: &[&str], veto_codes: &[u16]) -> MatcherConfig {
        MatcherConfig {
            match_regex: match_src.iter().map(|s| Regex::new(s).unwrap()).collect(),
            match_regex_src: match_src.iter().map(|s| (*s).to_owned()).collect(),
            veto_regex: veto_src.iter().map(|s| Regex::new(s).unwrap()).collect(),
            veto_regex_src: veto_src.iter().map(|s| (*s).to_owned()).collect(),
            veto_codes: veto_codes.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn regex_match_passes_on_hit_abstains() {
        let cfg = regex_cfg(&["wel.*come", "^canvas[[:alnum:]]+$"], &[], &[]);
        // Any hit satisfies the valid-page condition → abstain.
        assert!(cfg.matches("a welcome page", 200).is_none());
        assert!(cfg.matches("canvas123", 200).is_none());
        assert_eq!(
            cfg.matches("nothing relevant", 200),
            Some(false),
            "aucun hit sur les deux regex ⇒ veto"
        );
    }

    #[test]
    fn regex_veto_on_hit_vetoes() {
        let cfg = regex_cfg(&[], &["maintenance|waf"], &[]);
        assert_eq!(
            cfg.matches("under maintenance", 200),
            Some(false),
            "veto regex hit ⇒ Some(false)"
        );
        assert!(
            cfg.matches("all good", 200).is_none(),
            "pas de hit veto ⇒ abstension"
        );
    }

    #[test]
    fn status_veto_codes_veto_on_equal() {
        let cfg = regex_cfg(&[], &[], &[503, 429]);
        assert_eq!(cfg.matches("ok", 503), Some(false));
        assert_eq!(cfg.matches("ok", 429), Some(false));
        assert!(cfg.matches("ok", 200).is_none());
    }

    #[test]
    fn veto_wins_over_match_on_combined() {
        // Ordre veto-first : une réponse satisfaisant `--match` mais
        // relevant d'un veto explicite reste vetée (pas d'absurde abstain).
        let cfg_status = MatcherConfig {
            string: Some("welcome".to_owned()),
            veto_codes: vec![410],
            ..Default::default()
        };
        assert_eq!(
            cfg_status.matches("welcome", 410),
            Some(false),
            "veto status : prioritaire sur --match"
        );
        let cfg_body = MatcherConfig {
            not_string: Some("fatal".to_owned()),
            string: Some("welcome".to_owned()),
            ..Default::default()
        };
        assert_eq!(cfg_body.matches("welcome fatal", 200), Some(false));
        assert!(cfg_body.matches("welcome ok", 200).is_none());
    }

    #[test]
    fn is_active_with_expression_fields() {
        assert!(regex_cfg(&["a"], &[], &[]).is_active());
        assert!(regex_cfg(&[], &["b"], &[]).is_active());
        assert!(regex_cfg(&[], &[], &[200]).is_active());
        assert!(!regex_cfg(&[], &[], &[]).is_active());
    }

    #[test]
    fn evidence_suffix_lists_c17_expressions() {
        let cfg = regex_cfg(&["a.*b", "cde"], &["veto"], &[410]);
        let suffix = cfg.evidence_suffix();
        assert!(suffix.contains("re-match:a.*b|cde"), "{suffix}");
        assert!(suffix.contains("re-veto:veto"), "{suffix}");
        assert!(suffix.contains("status-veto:410"), "{suffix}");
    }
}
