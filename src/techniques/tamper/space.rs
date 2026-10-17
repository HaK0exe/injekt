//! Space-substitution helpers: trailing line-comment split and
//! `space2paren` (`' OR 1=1` → `'OR(1=1)`).

/// Split `(body, trailing line comment)` so space-substituting tampers keep
/// `-- ...` / `#...` terminators intact (`--/**/-` is not a comment).
/// Only the LAST `--` (followed by whitespace/end) or `#` counts, so `--`
/// inside string literals earlier in the payload is left alone.
pub(super) fn split_trailing_comment(payload: &str) -> (&str, &str) {
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

/// Space → parenthesis separator (`' OR 1=1` → `'OR(1=1)`).
///
/// Deterministic (no RNG): every `' '` in the body is either dropped (no
/// separator needed — at least one side is an operator/quote/paren, or a
/// `digit→letter` boundary like `1 AND` which lexes apart, except `e`/`E`
/// which would start scientific notation) or replaced with `(` (alnum–alnum
/// gaps like `OR 1` that would otherwise merge into one token). Inserted
/// `(` are balanced by appending `)` before the trailing line-comment
/// terminator (preserved verbatim via [`split_trailing_comment`]).
pub(super) fn apply_space2paren(payload: &str) -> String {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::techniques::tamper::Tamper;

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
    fn space2newline_only_replaces_inter_token_spaces() {
        // `U\nNION` intra-mot ne doit jamais être produit : seuls les `' '`
        // inter-tokens sont remplacés, pas de split dans le mot-clé.
        let out = Tamper::Space2Newline.apply("UNION");
        assert_eq!(out, "UNION");
        let spaced = Tamper::Space2Newline.apply("' UNION SELECT 1 -- -");
        assert!(!spaced.contains(' '), "got {spaced}");
        assert!(spaced.contains("%0a"), "got {spaced}");
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
}
