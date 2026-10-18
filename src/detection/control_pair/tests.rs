use super::control::{CONTROL_VALUE_MAX, CONTROL_VALUE_MIN, find_int_comparison};
use super::*;
use crate::detection::response_diff::{
    PageSimilarity, classify_page_similarity, diff_against_baseline, jaccard,
};
use crate::techniques::boolean::detector::{
    DIFF_SIGMA_MS, DIFFERENT_CONFIDENCE_MIN, SIMILAR_CONFIDENCE_MAX,
};

/// Corps de référence : page stable vs page sans résultat.
const BASELINE: &str = "welcome to the shop product listing page id 1 normal";
const DIFFERENT: &str = "no results found";
/// Variante quasi identique de [`BASELINE`] (un token en plus) : Jaccard
/// `10/11 ≈ 0.91`, dans la bande apprise (`m = 0.9`) sans franchir
/// `UPPER_RATIO_BOUND` — exerce la rescousse par plancher appris, pas par
/// la borne haute.
const NEAR_BASELINE: &str = "welcome to the shop product listing page id 1 normal extra";

/// Décompose la comparaison repérée d'un payload en
/// `(préfixe, lhs, rhs, suffixe)`.
fn split(payload: &str, want_equal: bool) -> (String, u64, u64, String) {
    let (range, lhs, rhs) = find_int_comparison(payload, want_equal).expect("comparison");
    (
        payload[..range.start].to_owned(),
        lhs,
        rhs,
        payload[range.end..].to_owned(),
    )
}

#[test]
fn derives_random_arithmetic_only_inside_comparison() {
    let pair =
        derive_control_pair("' AND 1=1 -- -", "' AND 1=2 -- -", Some(7)).expect("pair derivable");
    let (t_prefix, t_lhs, t_rhs, t_suffix) = split(&pair.must_true, true);
    assert_eq!(t_prefix, "' AND ");
    assert_eq!(t_suffix, " -- -");
    assert_eq!(t_lhs, t_rhs, "côté vrai : r=r réflexif");
    assert!((CONTROL_VALUE_MIN..=CONTROL_VALUE_MAX).contains(&t_lhs));
    let (f_prefix, f_lhs, f_rhs, f_suffix) = split(&pair.must_false, false);
    assert_eq!(f_prefix, "' AND ");
    assert_eq!(f_suffix, " -- -");
    assert_ne!(f_lhs, f_rhs, "côté faux : r1=r2 inégal");
    assert!((CONTROL_VALUE_MIN..=CONTROL_VALUE_MAX).contains(&f_lhs));
    assert!((CONTROL_VALUE_MIN..=CONTROL_VALUE_MAX).contains(&f_rhs));
    // Les payloads d'origine doivent réellement changer (sinon le contrôle
    // rejouerait la paire confirmée et ne testerait rien).
    assert_ne!(pair.must_true, "' AND 1=1 -- -");
    assert_ne!(pair.must_false, "' AND 1=2 -- -");
    assert_ne!(pair.must_true, pair.must_false);
}

#[test]
fn other_digits_survive_untouched() {
    let pair = derive_control_pair("' AND 1=1 LIMIT 7 -- -", "' AND 1=2 LIMIT 7 -- -", Some(3))
        .expect("pair derivable");
    assert!(pair.must_true.starts_with("' AND "), "{}", pair.must_true);
    assert!(
        pair.must_true.ends_with(" LIMIT 7 -- -"),
        "{}",
        pair.must_true
    );
    assert!(
        pair.must_false.ends_with(" LIMIT 7 -- -"),
        "{}",
        pair.must_false
    );
    // Le `1` d'origine du côté vrai a bien été remplacé (valeur ≠ 1).
    let (_, lhs, _, _) = split(&pair.must_true, true);
    assert_ne!(lhs, 1);
}

#[test]
fn none_without_arithmetic() {
    for (t, f) in [
        // String comparisons: no integer arithmetic to derive from.
        ("' OR 'a'='a -- -", "' OR 'a'='b -- -"),
        ("'\"())) OR '1'='1' -- -", "'\"())) OR '1'='2' -- -"),
        // JSON / NoSQL shapes: values are quoted, never a bare `\d+=\d+`.
        (
            "' OR JSON_EXTRACT('{\"k\":1}', '$.k')=1 -- -",
            "' OR '{\"k\":1}'->>'$.k'='1' -- -",
        ),
        ("{\"$gt\": \"\"}", "{\"$lt\": \"\"}"),
        ("", ""),
        // Un seul côté exploitable ⇒ None (pas de contrôle partiel).
        ("' AND 1=1 -- -", "' AND 1=1 -- -"),
        ("1=2", "1=2"),
    ] {
        assert!(
            derive_control_pair(t, f, Some(1)).is_none(),
            "aucun contrôle attendu pour {t} / {f}"
        );
    }
}

#[test]
fn seeded_derivation_is_deterministic() {
    let a = derive_control_pair("' AND 1=1 -- -", "' AND 1=2 -- -", Some(1234)).expect("a");
    let b = derive_control_pair("' AND 1=1 -- -", "' AND 1=2 -- -", Some(1234)).expect("b");
    assert_eq!(a, b, "même seed ⇒ mêmes payloads de contrôle");
    let c = derive_control_pair("' AND 1=1 -- -", "' AND 1=2 -- -", Some(4321)).expect("c");
    assert_ne!(a, c, "seeds différents ⇒ valeurs différentes");
}

#[test]
fn weird_inputs_never_panic() {
    for (t, f) in [
        ("=", "="),
        ("1=", "1=2"),
        ("=1", "=1"),
        ("é=é", "é=é"),
        (
            "99999999999999999999999999=1",
            "99999999999999999999999999=2",
        ),
        ("\n\t=\t\n", "\n\t=\t\n"),
        ("1=1=1", "1=2=2"),
    ] {
        let _ = derive_control_pair(t, f, None);
        let _ = derive_control_pair(t, f, Some(0));
    }
    // Espaces autour du `=` : motif repéré quand même.
    let spaced =
        derive_control_pair("' AND 1 = 1 -- -", "' AND 1 = 2 -- -", Some(1)).expect("spaced");
    assert!(spaced.must_true.contains('='), "{}", spaced.must_true);
    // Comparaisons enchaînées : seule la première est remplacée.
    let chained = derive_control_pair("1=1=1", "1=2=2", Some(1)).expect("chained");
    let (range, lhs, rhs) = find_int_comparison(&chained.must_true, true).expect("reparse");
    assert_eq!(range, 0..9, "r=r fait 9 octets dans 1=1=1 → RRRR=RRRR=1");
    assert_eq!(lhs, rhs);
    assert!(chained.must_true.ends_with("=1"), "{}", chained.must_true);
}

#[test]
fn verdict_normal_direction() {
    // r=r ≈ baseline et r1=r2 ≠ baseline → cohérent.
    assert_eq!(
        control_verdict(BASELINE, BASELINE, DIFFERENT, 100.0, 105.0, 102.0, false),
        ControlVerdict::Keep
    );
    // r=r s'éloigne de la baseline → contredit.
    assert_eq!(
        control_verdict(BASELINE, DIFFERENT, DIFFERENT, 100.0, 105.0, 102.0, false),
        ControlVerdict::Veto
    );
    // r1=r2 confondu avec la baseline (page qui ne réagit plus) → contredit.
    assert_eq!(
        control_verdict(BASELINE, BASELINE, BASELINE, 100.0, 105.0, 102.0, false),
        ControlVerdict::Veto
    );
}

#[test]
fn verdict_inverted_direction() {
    // Découverte inversée : c'est r1=r2 qui doit rester baseline-like.
    assert_eq!(
        control_verdict(BASELINE, DIFFERENT, BASELINE, 100.0, 105.0, 102.0, true),
        ControlVerdict::Keep
    );
    assert_eq!(
        control_verdict(BASELINE, BASELINE, DIFFERENT, 100.0, 105.0, 102.0, true),
        ControlVerdict::Veto
    );
    assert_eq!(
        control_verdict(BASELINE, BASELINE, BASELINE, 100.0, 105.0, 102.0, true),
        ControlVerdict::Veto
    );
}

#[test]
fn verdict_neutral_on_transport_or_degenerate_baseline() {
    // Corps vides (défaillance transport) : jamais de veto, quel que soit
    // le sens.
    for inverted in [false, true] {
        assert_eq!(
            control_verdict(BASELINE, "", "", 100.0, 0.0, 0.0, inverted),
            ControlVerdict::Neutral
        );
        assert_eq!(
            control_verdict(BASELINE, DIFFERENT, "", 100.0, 105.0, 0.0, inverted),
            ControlVerdict::Neutral
        );
        assert_eq!(
            control_verdict("", DIFFERENT, BASELINE, 100.0, 105.0, 102.0, inverted),
            ControlVerdict::Neutral
        );
    }
}

#[test]
fn none_matches_legacy_control_verdict() {
    // `match_ratio = None` doit rester bit-à-bit l'ancien verdict sur
    // plusieurs entrées (directions, zones grises, gardes d'entrée).
    let cases = [
        (BASELINE, BASELINE, DIFFERENT, 100.0, 105.0, 102.0, false),
        (BASELINE, DIFFERENT, DIFFERENT, 100.0, 105.0, 102.0, false),
        (BASELINE, BASELINE, BASELINE, 100.0, 105.0, 102.0, false),
        (
            BASELINE,
            NEAR_BASELINE,
            DIFFERENT,
            100.0,
            600.0,
            100.0,
            false,
        ),
        (BASELINE, DIFFERENT, BASELINE, 100.0, 105.0, 102.0, true),
        (BASELINE, BASELINE, DIFFERENT, 100.0, 105.0, 102.0, true),
        (BASELINE, DIFFERENT, BASELINE, 100.0, 100.0, 600.0, true),
        (BASELINE, "", "", 100.0, 0.0, 0.0, false),
        ("", DIFFERENT, BASELINE, 100.0, 105.0, 102.0, true),
    ];
    for (b, t, f, b_ms, t_ms, f_ms, inv) in cases {
        assert_eq!(
            control_verdict(b, t, f, b_ms, t_ms, f_ms, inv),
            control_verdict_with_match_ratio(b, t, f, b_ms, t_ms, f_ms, inv, None),
            "None doit rester legacy ({b:?}/{t:?}/{f:?}/{inv})"
        );
    }
}

#[test]
fn match_ratio_floor_rescues_same_side_from_veto() {
    // Côté `same` : contenu identique à la baseline mais timing très
    // différent (+500 ms > 2·DIFF_SIGMA_MS) ⇒ confiance 0.65 > 0.6.
    let same_ms = 600.0;
    let same_conf =
        diff_against_baseline(BASELINE, BASELINE, 100.0, same_ms, DIFF_SIGMA_MS).confidence;
    assert!(
        same_conf > DIFFERENT_CONFIDENCE_MIN,
        "le timing seul doit pousser la confiance au-dessus de 0.6, got {same_conf}"
    );
    // Sans plancher : veto legacy (le côté same s'éloigne par confiance).
    assert_eq!(
        control_verdict_with_match_ratio(
            BASELINE, BASELINE, DIFFERENT, 100.0, same_ms, 100.0, false, None,
        ),
        ControlVerdict::Veto
    );
    // Avec plancher appris (m ≈ 0.9, jaccard 1.0 → Same) : rescousse.
    assert_eq!(
        control_verdict_with_match_ratio(
            BASELINE,
            BASELINE,
            DIFFERENT,
            100.0,
            same_ms,
            100.0,
            false,
            Some(0.9),
        ),
        ControlVerdict::Keep
    );
    // Bande apprise réellement exercée : contenu quasi identique
    // (jaccard 10/11 ≈ 0.91, sous UPPER_RATIO_BOUND), c'est bien
    // `m - DIFF_TOLERANCE` qui classe Same.
    assert_eq!(
        classify_page_similarity(jaccard(BASELINE, NEAR_BASELINE), Some(0.9)),
        PageSimilarity::Same
    );
    assert_eq!(
        control_verdict_with_match_ratio(
            BASELINE,
            NEAR_BASELINE,
            DIFFERENT,
            100.0,
            same_ms,
            100.0,
            false,
            Some(0.9),
        ),
        ControlVerdict::Keep
    );
    assert_eq!(
        control_verdict_with_match_ratio(
            BASELINE,
            NEAR_BASELINE,
            DIFFERENT,
            100.0,
            same_ms,
            100.0,
            false,
            None,
        ),
        ControlVerdict::Veto
    );
    // Un Keep legacy ne peut jamais être dégradé par le plancher.
    assert_eq!(
        control_verdict_with_match_ratio(
            BASELINE,
            BASELINE,
            DIFFERENT,
            100.0,
            105.0,
            102.0,
            false,
            Some(0.9),
        ),
        ControlVerdict::Keep
    );
}

#[test]
fn match_ratio_floor_never_rescues_other_side() {
    // Le côté `other` reste sur les barres fixes : un contrôle « faux »
    // (ou « vrai » en sens inversé) confondu avec la baseline → veto,
    // avec ET sans plancher.
    for match_ratio in [None, Some(0.9)] {
        assert_eq!(
            control_verdict_with_match_ratio(
                BASELINE,
                BASELINE,
                BASELINE,
                100.0,
                105.0,
                102.0,
                false,
                match_ratio,
            ),
            ControlVerdict::Veto,
            "other baseline-like → veto ({match_ratio:?})"
        );
        assert_eq!(
            control_verdict_with_match_ratio(
                BASELINE,
                BASELINE,
                DIFFERENT,
                100.0,
                105.0,
                102.0,
                true,
                match_ratio,
            ),
            ControlVerdict::Veto,
            "other baseline-like en sens inversé → veto ({match_ratio:?})"
        );
    }
}

#[test]
fn match_ratio_floor_inactive_in_gray_zone() {
    // Similarité dans la zone grise (10/11 ≈ 0.91 < UPPER_RATIO_BOUND) :
    // sans plancher exploitable, la classification reste `Undetermined`
    // → comportement legacy, aucune rescousse.
    assert_eq!(
        classify_page_similarity(jaccard(BASELINE, NEAR_BASELINE), Some(f64::NAN)),
        PageSimilarity::Undetermined
    );
    for match_ratio in [None, Some(f64::NAN), Some(f64::INFINITY)] {
        assert_eq!(
            control_verdict_with_match_ratio(
                BASELINE,
                NEAR_BASELINE,
                DIFFERENT,
                100.0,
                600.0,
                100.0,
                false,
                match_ratio,
            ),
            ControlVerdict::Veto,
            "zone grise → legacy ({match_ratio:?})"
        );
    }
}

#[test]
fn match_ratio_floor_rescues_inverted_same_side() {
    // Sens inversé : c'est `ctl_false_body` (`r1=r2`) qui est
    // baseline-like ; même rescousse quand son timing s'éloigne.
    assert_eq!(
        control_verdict_with_match_ratio(
            BASELINE, DIFFERENT, BASELINE, 100.0, 100.0, 600.0, true, None,
        ),
        ControlVerdict::Veto,
        "legacy : côté same inversé à confiance 0.65 → veto"
    );
    assert_eq!(
        control_verdict_with_match_ratio(
            BASELINE,
            DIFFERENT,
            BASELINE,
            100.0,
            100.0,
            600.0,
            true,
            Some(0.9),
        ),
        ControlVerdict::Keep,
        "plancher : même rescousse en sens inversé"
    );
}

#[test]
fn calibration_shared_with_boolean_detector() {
    // Source de vérité unique : les seuils viennent de `BooleanDetector`.
    assert!((SIMILAR_CONFIDENCE_MAX - 0.4).abs() < f64::EPSILON);
    assert!((DIFFERENT_CONFIDENCE_MIN - 0.6).abs() < f64::EPSILON);
    assert!((DIFF_SIGMA_MS - 100.0).abs() < f64::EPSILON);
}
