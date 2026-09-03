#![deny(unsafe_code)]

//! Payload assembly options: prefix/suffix wrapping, safe-char encoding control,
//! and fetch-mode hint.
//!
//! Normative assembly order is defined by [`build_final_payload`]:
//! `apply_tampers(base, tampers)` first, then `prefix + tampered + suffix`.
//! Percent-encoding happens at the injection point (see
//! [`encode_with_safe_chars`]), never inside [`build_final_payload`].

use super::tamper::{Tamper, apply_tampers};
use std::fmt::Write as _;

/// How an extracted value is fetched (oracle hint, no behaviour by itself).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FetchUsing {
    /// Direct (in-band) fetch.
    #[default]
    Direct,
    /// Boolean-based inference.
    Boolean,
    /// Time-based inference.
    Time,
}

/// Prefix/suffix wrapping plus encoding controls for payload assembly.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct PayloadOpts {
    /// String prepended before the (tampered) base payload.
    pub prefix: Option<String>,
    /// String appended after the (tampered) base payload.
    pub suffix: Option<String>,
    /// Extra chars exempted from percent-encoding in [`encode_with_safe_chars`].
    pub safe_chars: String,
    /// When `true`, [`encode_with_safe_chars`] returns its input unchanged.
    pub skip_urlencode: bool,
    /// Fetch-mode hint.
    pub fetch_using: FetchUsing,
}

impl PayloadOpts {
    /// Returns `true` when any option deviates from the inactive default
    /// (no prefix/suffix, empty `safe_chars`, `skip_urlencode == false`,
    /// `fetch_using == Direct`).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.prefix.is_some()
            || self.suffix.is_some()
            || !self.safe_chars.is_empty()
            || self.skip_urlencode
            || !matches!(self.fetch_using, FetchUsing::Direct)
    }

    /// Short evidence suffix, e.g. `" prefix=') suffix=-- -"`, or `""` when
    /// inactive. Prefix/suffix values are truncated to 24 chars each.
    #[must_use]
    pub fn evidence_suffix(&self) -> String {
        if !self.is_active() {
            return String::new();
        }
        let prefix = truncate_24(self.prefix.as_deref().unwrap_or(""));
        let suffix = truncate_24(self.suffix.as_deref().unwrap_or(""));
        format!(" prefix={prefix} suffix={suffix}")
    }
}

/// Assemble the final payload: `apply_tampers(base, tampers)` first,
/// then `prefix + tampered + suffix`.
///
/// URL-encoding is deliberately *not* applied here; it happens at the
/// injection point via [`encode_with_safe_chars`].
#[must_use]
pub fn build_final_payload(base: &str, tampers: &[Tamper], opts: &PayloadOpts) -> String {
    let tampered = apply_tampers(base, tampers);
    let prefix = opts.prefix.as_deref().unwrap_or("");
    let suffix = opts.suffix.as_deref().unwrap_or("");
    let mut out = String::with_capacity(prefix.len() + tampered.len() + suffix.len());
    out.push_str(prefix);
    out.push_str(&tampered);
    out.push_str(suffix);
    out
}

/// Percent-encode `s`, leaving `[A-Za-z0-9-_.~]` plus every char of `safe`
/// untouched. All other chars are encoded byte by byte over their UTF-8
/// representation as `%XX` (uppercase hex).
///
/// When `skip` is `true`, `s` is returned unchanged. Never panics.
#[must_use]
pub fn encode_with_safe_chars(s: &str, safe: &[char], skip: bool) -> String {
    if skip {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        if c.is_ascii_alphanumeric()
            || c == '-'
            || c == '_'
            || c == '.'
            || c == '~'
            || safe.contains(&c)
        {
            out.push(c);
        } else {
            let mut buf = [0_u8; 4];
            let encoded = c.encode_utf8(&mut buf);
            for b in encoded.bytes() {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Truncate to at most 24 chars (never splits UTF-8, never panics).
fn truncate_24(s: &str) -> String {
    s.chars().take(24).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::techniques::tamper::Tamper;

    fn opts_with(prefix: &str, suffix: &str) -> PayloadOpts {
        PayloadOpts {
            prefix: Some(prefix.to_owned()),
            suffix: Some(suffix.to_owned()),
            safe_chars: String::new(),
            skip_urlencode: false,
            fetch_using: FetchUsing::Direct,
        }
    }

    #[test]
    fn order_is_tamper_then_prefix_suffix() {
        let tampers = [Tamper::Space2Comment];
        let opts = opts_with("')", "-- -");
        let base = "' OR 1=1";
        let tampered = apply_tampers(base, &tampers);
        let got = build_final_payload(base, &tampers, &opts);
        let expected = format!("'){tampered}-- -");
        assert_eq!(got, expected);
        assert!(got.starts_with("')"));
        assert!(got.ends_with("-- -"));
        assert!(got.contains(&tampered));
    }

    #[test]
    fn build_without_opts_equals_apply_tampers() {
        let tampers = [Tamper::Space2Comment, Tamper::Space2Plus];
        let opts = PayloadOpts::default();
        let base = "' OR 1=1";
        assert_eq!(
            build_final_payload(base, &tampers, &opts),
            apply_tampers(base, &tampers)
        );
        assert_eq!(
            build_final_payload(base, &[], &opts),
            apply_tampers(base, &[])
        );
        assert_eq!(build_final_payload(base, &[], &opts), base);
    }

    #[test]
    fn encode_skip_is_identity() {
        let s = "' OR 1=1 &";
        assert_eq!(encode_with_safe_chars(s, &[], true), s);
        assert_eq!(encode_with_safe_chars(s, &['\'', ' ', '&'], true), s);
    }

    #[test]
    fn encode_specials_when_not_skipped() {
        let out = encode_with_safe_chars("' &", &[], false);
        assert!(!out.contains('\''));
        assert!(!out.contains(' '));
        assert!(!out.contains('&'));
        assert!(out.contains("%27"));
        assert!(out.contains("%20"));
        assert!(out.contains("%26"));
        assert_eq!(out, "%27%20%26");
    }

    #[test]
    fn encode_safe_chars_preserved() {
        let out = encode_with_safe_chars("' '&", &['\''], false);
        assert!(out.contains('\''));
        assert!(!out.contains("%27"));
        assert!(out.contains("%20"));
        assert!(out.contains("%26"));
    }

    #[test]
    fn encode_unreserved_never_encoded() {
        let s = "AZaz09~-._";
        assert_eq!(encode_with_safe_chars(s, &[], false), s);
    }

    #[test]
    fn encode_multibyte_per_utf8_byte() {
        assert_eq!(encode_with_safe_chars("é", &[], false), "%C3%A9");
        assert_eq!(encode_with_safe_chars("aéb", &[], false), "a%C3%A9b");
    }

    #[test]
    fn encode_empty_is_empty() {
        assert_eq!(encode_with_safe_chars("", &[], false), "");
        assert_eq!(encode_with_safe_chars("", &['\''], true), "");
    }

    #[test]
    fn evidence_empty_when_inactive() {
        let opts = PayloadOpts::default();
        assert!(!opts.is_active());
        assert_eq!(opts.evidence_suffix(), "");
    }

    #[test]
    fn evidence_non_empty_when_prefix_set() {
        let opts = PayloadOpts {
            prefix: Some("')".to_owned()),
            ..PayloadOpts::default()
        };
        assert!(opts.is_active());
        let suffix = opts.evidence_suffix();
        assert!(!suffix.is_empty());
        assert!(suffix.contains("prefix="));
    }

    #[test]
    fn evidence_truncates_long_values() {
        let long = "abcdefghijklmnopqrstuvwxyz0123456789";
        assert!(long.chars().count() > 24);
        let opts = PayloadOpts {
            prefix: Some(long.to_owned()),
            ..PayloadOpts::default()
        };
        let suffix = opts.evidence_suffix();
        let truncated: String = long.chars().take(24).collect();
        assert!(suffix.contains(&truncated));
        assert!(!suffix.contains(long));
    }

    #[test]
    fn fetch_using_default_is_direct() {
        assert_eq!(FetchUsing::default(), FetchUsing::Direct);
        assert_eq!(PayloadOpts::default().fetch_using, FetchUsing::Direct);
    }
}
