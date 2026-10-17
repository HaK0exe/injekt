//! Encoding tampers: percent char-encode, overlong UTF-8, JSON-unicode escapes.

use std::fmt::Write as _;

use super::space::split_trailing_comment;

pub(super) fn char_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '~' {
            out.push(c);
        } else {
            let _ = write!(out, "%{b:02x}");
        }
    }
    out
}

pub(super) fn overlong_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 6);
    // Char loop (was byte loop): overlong 2-byte form is only defined for
    // ASCII bytes < 0x80. Non-ASCII chars pass through untouched instead of
    // being mangled byte-by-byte (`0x80 | b` is a no-op for b >= 0x80).
    for c in input.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if c.is_ascii() {
            // overlong 2-byte UTF-8: 0xC0 | (b>>6), 0x80 | (b & 0x3F)
            // for ASCII b < 0x80, first byte is always 0xC0, second is 0x80|b
            let b = c as u8;
            let b1 = 0xC0u8;
            let b2 = 0x80u8 | b;
            let _ = write!(out, "%{b1:02x}%{b2:02x}");
        } else {
            out.push(c);
        }
    }
    out
}

/// JSON-unicode escapes for WAF-visible chars, applied to the body only
/// (trailing `-- ...`/`#...` terminator preserved verbatim).
///
/// NOT boolean-safe: escaping `'`/`"` removes the quote the injection relies
/// on, so both TRUE and FALSE branches go inert (equally false) even though
/// the transformed strings stay `a != b`. Boolean detectors must skip it
/// (see [`Tamper::is_boolean_safe`]); string-level `assert_ne!` alone cannot
/// catch this semantic collapse.
pub(super) fn apply_json_unicode_escape(payload: &str) -> String {
    let (body, tail) = split_trailing_comment(payload);
    let mut out = String::with_capacity(body.len() + 16);
    for ch in body.chars() {
        match ch {
            '"' => out.push_str("\\u0022"),
            '\'' => out.push_str("\\u0027"),
            ' ' => out.push_str("\\u0020"),
            '/' => out.push_str("\\u002f"),
            _ => out.push(ch),
        }
    }
    out.push_str(tail);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::techniques::tamper::Tamper;

    #[test]
    fn charencode_encodes_space_and_quote() {
        let out = Tamper::CharEncode.apply("' OR 1=1");
        // ' -> %27, space -> %20, = -> %3d
        assert!(out.contains("%27"), "got {out}");
        assert!(out.contains("%20"));
        assert!(!out.contains(' '));
        assert!(!out.contains('\''));
    }

    #[test]
    fn doubleencode_encodes_percent() {
        let out = Tamper::DoubleEncode.apply("'");
        // ' -> %27 -> %2527 (since % -> %25)
        assert_eq!(out, "%2527");
    }

    #[test]
    fn hexencode_full() {
        let out = Tamper::HexEncode.apply("AB");
        assert_eq!(out, "%41%42");
    }

    #[test]
    fn unicodeencode_full() {
        let out = Tamper::UnicodeEncode.apply("A");
        assert_eq!(out, "%u0041");
    }

    #[test]
    fn overlong_encodes_slash() {
        let out = Tamper::OverlongUtf8.apply("/");
        // / 0x2f -> %c0%af
        assert_eq!(out, "%c0%af");
        let out2 = Tamper::OverlongUtf8.apply("a/b");
        assert!(out2.contains("%c0%af"), "got {out2}");
        assert!(out2.starts_with('a'));
    }

    #[test]
    fn base64_roundtrips() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let out = Tamper::Base64Encode.apply("' OR 1=1 -- -");
        assert_eq!(
            STANDARD
                .decode(&out)
                .map(|b| String::from_utf8_lossy(&b).into_owned()),
            Ok("' OR 1=1 -- -".to_owned())
        );
    }

    #[test]
    fn base64encode_roundtrips() {
        let payload = "' OR 1=1 -- -";
        let out = Tamper::Base64Encode.apply(payload);
        assert_eq!(out, "JyBPUiAxPTEgLS0gLQ==");
        assert!(!Tamper::Base64Encode.is_boolean_safe());
    }

    #[test]
    fn double_encode_degrades_trailing_comment_needs_double_decode() {
        // Documente l'exigence double-décodage serveur : après simple
        // décodage, `-- -` ne revient pas (reste `%20`), donc le terminateur
        // casse sans 2e passe. Verrouille la non-régression.
        let out = Tamper::DoubleEncode.apply("' OR 1=1 -- -");
        assert!(out.contains("%2520"), "got {out}");
        assert!(!out.contains(' '), "got {out}");
    }

    #[test]
    fn jsonunicodeescape_replaces_waf_visible_chars() {
        let out = Tamper::JsonUnicodeEscape.apply("' OR 1=1 -- -");
        assert!(out.ends_with("-- -"), "terminator preserved: {out}");
        let body = out.split("--").next().unwrap_or("");
        assert!(!body.contains('\''), "got {out}");
        assert!(!body.contains('"'), "got {out}");
        assert!(!body.contains(' '), "got {out}");
        assert!(!body.contains('/'), "got {out}");
        assert!(out.contains("\\u0027"), "got {out}");
        assert!(out.contains("\\u0020"), "got {out}");
        assert!(out.contains("1=1"), "digits survive: {out}");
        // slash escaping
        let slash = Tamper::JsonUnicodeEscape.apply("a/b");
        assert_eq!(slash, "a\\u002fb");
        // roundtrip: decoding restores the body
        let decoded = body
            .replace("\\u0022", "\"")
            .replace("\\u0027", "'")
            .replace("\\u0020", " ")
            .replace("\\u002f", "/");
        assert_eq!(decoded, "' OR 1=1 ");
    }

    #[test]
    fn jsonunicodeescape_deterministic_across_seeds() {
        use crate::seeded_rng::make_rng;
        let mut a = make_rng(Some(1));
        let mut b = make_rng(Some(2));
        assert_eq!(
            Tamper::JsonUnicodeEscape.apply_with_rng("' OR 'a'='a' -- -", &mut a),
            Tamper::JsonUnicodeEscape.apply_with_rng("' OR 'a'='a' -- -", &mut b)
        );
    }
}
