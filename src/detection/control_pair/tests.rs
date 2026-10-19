use super::control::{CONTROL_VALUE_MAX, CONTROL_VALUE_MIN, find_int_comparison};
use super::*;
use crate::detection::response_diff::{PageSimilarity, classify_page_similarity, jaccard};
use crate::techniques::boolean::detector::{DIFFERENT_CONFIDENCE_MIN, SIMILAR_CONFIDENCE_MAX};

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
        control_verdict(BASELINE, BASELINE, DIFFERENT, false),
        ControlVerdict::Keep
    );
    // r=r s'éloigne de la baseline → contredit.
    assert_eq!(
        control_verdict(BASELINE, DIFFERENT, DIFFERENT, false),
        ControlVerdict::Veto
    );
    // r1=r2 confondu avec la baseline (page qui ne réagit plus) → contredit.
    assert_eq!(
        control_verdict(BASELINE, BASELINE, BASELINE, false),
        ControlVerdict::Veto
    );
}

#[test]
fn verdict_inverted_direction() {
    // Découverte inversée : c'est r1=r2 qui doit rester baseline-like.
    assert_eq!(
        control_verdict(BASELINE, DIFFERENT, BASELINE, true),
        ControlVerdict::Keep
    );
    assert_eq!(
        control_verdict(BASELINE, BASELINE, DIFFERENT, true),
        ControlVerdict::Veto
    );
    assert_eq!(
        control_verdict(BASELINE, BASELINE, BASELINE, true),
        ControlVerdict::Veto
    );
}

#[test]
fn verdict_neutral_on_transport_or_degenerate_baseline() {
    // Corps vides (défaillance transport) : jamais de veto, quel que soit
    // le sens.
    for inverted in [false, true] {
        assert_eq!(
            control_verdict(BASELINE, "", "", inverted),
            ControlVerdict::Neutral
        );
        assert_eq!(
            control_verdict(BASELINE, DIFFERENT, "", inverted),
            ControlVerdict::Neutral
        );
        assert_eq!(
            control_verdict("", DIFFERENT, BASELINE, inverted),
            ControlVerdict::Neutral
        );
    }
}

/// Enveloppe A1-shaped : contrôle « vrai » identique à la baseline, contrôle
/// « faux » amputé d'un petit bloc de contenu. Le Jaccard sépare nettement
/// (10/22 ≈ 0.4545 < 0.5) alors que la métrique historique
/// (0.7·char + 0.3·Jaccard + timing) lisait « s'y confond » et sabordait
/// l'oracle confirmé 3/3 du lab bench A1. La gap-classe du verdict par-trial
/// ([`crate::detection::confirmation::confirm`]) s'applique ici à l'identique.
#[test]
fn envelope_gap_clause_keeps_true_oracle() {
    // 10 tokens partagés + 12 étrangers : J = 10/22 ≈ 0.4545, sous la borne
    // gap-clause (0.5) au-dessus du seuil fixe « confondu » (0.6 en J).
    let sliced =
        format!("{BASELINE} alpha beta gamma delta epsilon zeta eta theta iota kappa lambda");
    let j = jaccard(BASELINE, &sliced);
    assert!(
        (0.4..0.5).contains(&j),
        "la jambe false doit rester dans la bande enveloppe (0.40..0.50), got {j}"
    );
    assert_eq!(
        control_verdict(BASELINE, BASELINE, &sliced, false),
        ControlVerdict::Keep
    );
}

/// Zone grise enveloppe : J ≈ 0.556 — ni « écarté » (barre 0.5), ni gap
/// franc (0.444 < 0.5) → le veto reste fail-open (neutral).
#[test]
fn envelope_gray_zone_stays_neutral() {
    let partial = format!("{BASELINE} alpha beta gamma delta epsilon zeta eta theta");
    let j = jaccard(BASELINE, &partial);
    assert!(
        (0.5..0.6).contains(&j),
        "zone grise attendue (0.50..0.60), got {j}"
    );
    assert_eq!(
        control_verdict(BASELINE, BASELINE, &partial, false),
        ControlVerdict::Neutral
    );
    // Dans la même bande, la réflexion du contrôle (page qui échoit
    // l'entrée sans logique) reste différenciable : J=1.0 → veto.
    assert_eq!(
        control_verdict(BASELINE, BASELINE, BASELINE, false),
        ControlVerdict::Veto
    );
}

/// Corps dans la bande médiane : 7 tokens partagés + 3 étrangers,
/// J = 7/13 ≈ 0.538 — ni baseline-like (barre 0.6), ni franchement
/// contradictoire (barre 0.4).
const MID_SAME: &str = "welcome to the shop product listing page red blue green";

#[test]
fn match_ratio_floor_rescues_same_side() {
    // Sans plancher : mid-band → zone grise, neutre (fail-open), jamais un
    // veto par timing/mélanges comme dans l'implémentation historique.
    assert_eq!(
        control_verdict(BASELINE, MID_SAME, DIFFERENT, false),
        ControlVerdict::Neutral
    );
    // Avec plancher appris (m = 0.58 ; bande `m - DIFF_TOLERANCE` = 0.53) :
    // le Jaccard 0.538 ≥ 0.53 classe le côté same `Same` → Keep.
    assert_eq!(
        control_verdict_with_match_ratio(BASELINE, MID_SAME, DIFFERENT, false, Some(0.58)),
        ControlVerdict::Keep
    );
}

#[test]
fn match_ratio_floor_never_rescues_other_side() {
    // Le côté `other` reste sur les barres fixes en contenu : un contrôle
    // « faux » (ou « vrai » en sens inversé) confondu avec la baseline →
    // veto, avec ET sans plancher.
    for match_ratio in [None, Some(0.9)] {
        assert_eq!(
            control_verdict_with_match_ratio(BASELINE, BASELINE, BASELINE, false, match_ratio),
            ControlVerdict::Veto,
            "other baseline-like → veto ({match_ratio:?})"
        );
        assert_eq!(
            control_verdict_with_match_ratio(BASELINE, BASELINE, DIFFERENT, true, match_ratio),
            ControlVerdict::Veto,
            "other baseline-like en sens inversé → veto ({match_ratio:?})"
        );
    }
}

#[test]
fn match_ratio_none_matches_content_only_when_floor_inactive() {
    // Parité None/Some quand le plancher ne peut pas s'engager : J du côté
    // same hors bande (0.0 < LOWER_RATIO_BOUND, 1.0 > UPPER_RATIO_BOUND) ou
    // non fini (NaN/∞ filtrés par `classify_page_similarity`). La rescousse
    // ne change alors rien au verdict.
    for match_ratio in [Some(0.9), Some(f64::NAN), Some(f64::INFINITY)] {
        // J_same = 0.0 : `Different` dans les deux mondes.
        assert_eq!(
            control_verdict_with_match_ratio(BASELINE, DIFFERENT, DIFFERENT, false, match_ratio),
            control_verdict_with_match_ratio(BASELINE, DIFFERENT, DIFFERENT, false, None),
        );
        // J_same = 1.0 : borne haute → Same dans les deux mondes.
        assert_eq!(
            control_verdict_with_match_ratio(BASELINE, BASELINE, BASELINE, false, match_ratio),
            control_verdict_with_match_ratio(BASELINE, BASELINE, BASELINE, false, None),
        );
        // J_same mid-band + plancher non fini : `Undetermined` des deux côtés.
        assert_eq!(
            control_verdict_with_match_ratio(BASELINE, MID_SAME, DIFFERENT, false, match_ratio),
            control_verdict_with_match_ratio(BASELINE, MID_SAME, DIFFERENT, false, None),
        );
    }
}

#[test]
fn match_ratio_floor_inactive_when_non_finite() {
    // Plancher non exploitable (non fini) : la classification retombe en
    // `Undetermined`, le verdict par contenu seul s'applique (J_same 0.909
    // > 0.6, J_other 0.0 < 0.4) → Keep, plancher ou pas.
    for match_ratio in [Some(f64::NAN), Some(f64::INFINITY)] {
        assert_eq!(
            classify_page_similarity(jaccard(BASELINE, NEAR_BASELINE), match_ratio),
            PageSimilarity::Undetermined
        );
        assert_eq!(
            control_verdict_with_match_ratio(
                BASELINE,
                NEAR_BASELINE,
                DIFFERENT,
                false,
                match_ratio
            ),
            ControlVerdict::Keep
        );
    }
}

#[test]
fn match_ratio_floor_rescues_inverted_same_side() {
    // Sens inversé : c'est `ctl_false_body` (r1=r2) qui doit rester
    // baseline-like ; même rescousse par contenu/plancher.
    assert_eq!(
        control_verdict_with_match_ratio(BASELINE, DIFFERENT, MID_SAME, true, None),
        ControlVerdict::Neutral,
        "mid-band sans plancher : zone grise, neutre"
    );
    assert_eq!(
        control_verdict_with_match_ratio(BASELINE, DIFFERENT, MID_SAME, true, Some(0.58)),
        ControlVerdict::Keep,
        "plancher : même rescousse en sens inversé"
    );
}

#[test]
fn calibration_shared_with_boolean_detector() {
    // Source de vérité unique : les seuils viennent de `BooleanDetector`.
    assert!((SIMILAR_CONFIDENCE_MAX - 0.4).abs() < f64::EPSILON);
    assert!((DIFFERENT_CONFIDENCE_MIN - 0.6).abs() < f64::EPSILON);
}
