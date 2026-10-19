//! Tamper pipelines: ordered chaining, bounded expansion,
//! transformation sets (boolean-safe variant drops non-differential tampers).

use super::Tamper;

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
    rng: &mut impl rand::RngExt,
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
    rng: &mut impl rand::RngExt,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::techniques::tamper::Tamper;

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
}
