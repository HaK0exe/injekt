#![deny(unsafe_code)]

//! Custom response matchers (`--string`, `--not-string`, `--code`, `--text-only`).
//!
//! [`MatcherConfig`] is a lightweight veto gate evaluated *before* the
//! statistical detector: it can only reject a candidate (`Some(false)`)
//! or abstain (`None`) and let the detector decide. It never confirms
//! a finding on its own.

/// User-supplied matching constraints for response gating.
///
/// All string comparisons are case-sensitive. The caller is expected to
/// pre-process the body via [`MatcherConfig::pre_process`] (handles
/// `--text-only`) before calling [`MatcherConfig::matches`].
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
}

impl MatcherConfig {
    /// Returns `true` when at least one constraint is set.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.string.is_some() || self.not_string.is_some() || self.code.is_some() || self.text_only
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
    /// 2. `not_string` contained → `Some(false)`
    /// 3. `string` missing → `Some(false)`
    ///
    /// Otherwise returns `None` (no verdict, let the detector decide).
    #[must_use]
    pub fn matches(&self, body: &str, status: u16) -> Option<bool> {
        if let Some(expected) = self.code
            && status != expected
        {
            return Some(false);
        }
        if let Some(needle) = self.not_string.as_deref()
            && body.contains(needle)
        {
            return Some(false);
        }
        if let Some(needle) = self.string.as_deref()
            && !body.contains(needle)
        {
            return Some(false);
        }
        None
    }

    /// Veto gate for boolean-based (TRUE/FALSE) checks.
    ///
    /// Returns `Some(false)` when either branch violates [`Self::matches`],
    /// otherwise `None` (no verdict).
    #[must_use]
    pub fn gate_boolean(
        &self,
        true_body: &str,
        false_body: &str,
        t_status: u16,
        f_status: u16,
    ) -> Option<bool> {
        if self.matches(true_body, t_status) == Some(false) {
            return Some(false);
        }
        if self.matches(false_body, f_status) == Some(false) {
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
        format!(
            " matcher=string:{string},not-string:{not_string},code:{code},text-only:{}",
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
/// - An unclosed `<` discards the remainder (no panic).
/// - Decodes `&lt;`, `&gt;`, `&quot;`, `&#x27;`, then `&amp;` last to
///   avoid double-decoding `&amp;lt;` into `<`.
/// - Collapses all whitespace runs into single spaces (and trims).
/// - Unknown entities (e.g. `&unknown;`) are left untouched.
/// - Never panics, even on malformed or non-ASCII input.
#[must_use]
pub fn strip_html(body: &str) -> String {
    let mut without_tags = String::with_capacity(body.len());
    let mut in_tag = false;
    for c in body.chars() {
        if in_tag {
            if c == '>' {
                in_tag = false;
            }
        } else if c == '<' {
            in_tag = true;
        } else {
            without_tags.push(c);
        }
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
        assert_eq!(
            cfg.gate_boolean("goodbye", "welcome false", 200, 200),
            Some(false)
        );
    }

    #[test]
    fn gate_boolean_veto_false_branch() {
        let cfg = active_string_config();
        assert_eq!(
            cfg.gate_boolean("welcome true", "goodbye", 200, 200),
            Some(false)
        );
    }

    #[test]
    fn gate_boolean_veto_on_status() {
        let cfg = MatcherConfig {
            code: Some(200),
            ..Default::default()
        };
        assert_eq!(cfg.gate_boolean("a", "b", 200, 500), Some(false));
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
        assert_eq!(strip_html("<a <b"), "");
        assert_eq!(strip_html("<unclosed"), "");
        assert_eq!(strip_html("a > b"), "a > b");
        assert_eq!(strip_html("&unknown; stays"), "&unknown; stays");
        assert_eq!(strip_html("<<<>>>"), ">>");
    }

    #[test]
    fn strip_html_unicode_safe() {
        assert_eq!(strip_html("<p>héllo 🌍</p>"), "héllo 🌍");
        assert_eq!(strip_html("日本語 <b>テスト</b> &amp;"), "日本語 テスト &");
        // Lone angle brackets / emoji must not panic.
        assert_eq!(strip_html("<🦀 <b"), "");
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
}
