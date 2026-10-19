#![deny(unsafe_code)]

//! WAF evasion tampers (P4 split): the `Tamper` enum + `apply` dispatch in
//! this file, with helpers by family — `space`, `keywords`, `encoding`,
//! `numeric`, `signatures` — and the pipelines (`registry`, `pipeline`).
//! Composition via [`apply_tampers`] allows stacking (e.g.
//! `space2comment,randomcase`).

use std::fmt::Write as _;

use encoding::{apply_json_unicode_escape, char_encode, overlong_encode};
use keywords::{
    apply_between_comment, apply_versioned_comment, apply_versioned_fuzz,
    apply_versioned_more_keywords,
};
use numeric::apply_numeric_obfuscate;
use signatures::{apply_equal_to_like, apply_linecomment};
use space::{apply_space2paren, split_trailing_comment};

mod encoding;
mod keywords;
mod numeric;
mod pipeline;
mod registry;
mod signatures;
mod space;

pub use pipeline::{
    apply_tampers, apply_tampers_with_rng, boolean_safe_transformation_sets, expand_with_tampers,
    expand_with_tampers_with_rng, tamper_transformation_sets,
};
pub use registry::parse_tamper_list;

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
    pub fn apply_with_rng(&self, payload: &str, rng: &mut impl rand::RngExt) -> String {
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

/// Comma-joined tamper names for finding evidence (`none` when the set is
/// empty) — shared by every technique's `scan.rs`.
pub(crate) fn tamper_label(trans: &[Tamper]) -> String {
    if trans.is_empty() {
        "none".to_owned()
    } else {
        trans.iter().map(Tamper::name).collect::<Vec<_>>().join(",")
    }
}
