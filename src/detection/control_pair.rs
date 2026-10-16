#![deny(unsafe_code)]

//! P0.2 — paires de contrôle à arithmétique aléatoire (`checkFalsePositives`).
//!
//! Après qu'une paire TRUE/FALSE a confirmé une injection booléenne, sqlmap
//! re-teste le même point avec des paires de contrôle « logiquement vraie »
//! (`r=r`) et « logiquement fausse » (`r1=r2`, `r1≠r2`) : si la page ne réagit
//! pas à ces paires comme elle a réagi aux payloads injectés, le différentiel
//! venait du payload lui-même (filtrage d'un motif, reflet, instabilité), pas
//! de la logique SQL → faux positif.
//!
//! Module pur (aucune I/O) :
//! - [`derive_control_pair`] construit les deux payloads de contrôle à partir
//!   des payloads finaux confirmés, sans toucher aux autres chiffres ;
//! - [`control_verdict`] tranche entre « cohérent » ([`ControlVerdict::Keep`]),
//!   « contredit » ([`ControlVerdict::Veto`]) et « non mesuré »
//!   ([`ControlVerdict::Neutral`], jamais de veto) ; sa variante
//!   [`control_verdict_with_match_ratio`] accepte le plancher de bruit appris
//!   (P1.2, `Baseline::match_ratio`) et rescapce un côté baseline-like dont la
//!   similarité Jaccard retombe dans la bande `DIFF_TOLERANCE` autour de ce
//!   plancher.
//!
//! Le budget est borné par construction : une paire dérivée coûte exactement
//! 2 requêtes, et un payload dont le motif arithmétique manque coûte 0 requête.

use crate::{
    detection::response_diff::{
        PageSimilarity, classify_page_similarity, diff_against_baseline, jaccard,
    },
    seeded_rng::make_rng,
    techniques::boolean::detector::{
        DIFF_SIGMA_MS, DIFFERENT_CONFIDENCE_MIN, SIMILAR_CONFIDENCE_MAX,
    },
};
use rand::Rng as _;

/// Borne basse (incluse) des entiers aléatoires de contrôle.
const CONTROL_VALUE_MIN: u64 = 1000;
/// Borne haute (incluse) des entiers aléatoires de contrôle.
const CONTROL_VALUE_MAX: u64 = 9999;

/// Paire de contrôle dérivée d'une paire TRUE/FALSE confirmée.
///
/// `must_true` est logiquement vraie (`r=r`) et `must_false` logiquement
/// fausse (`r1=r2` avec `r1 != r2`) : les deux ne diffèrent du payload
/// d'origine que par les littéraux entiers de la comparaison repérée.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ControlPair {
    /// Payload de contrôle logiquement vrai (`r=r`).
    pub must_true: String,
    /// Payload de contrôle logiquement faux (`r1=r2`, `r1 != r2`).
    pub must_false: String,
}

/// Verdict du contrôle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlVerdict {
    /// Contrôle mesuré et cohérent avec la découverte : finding conservé.
    Keep,
    /// Contrôle mesuré et contredisant la découverte : faux positif, rejet.
    Veto,
    /// Aucune mesure exploitable (transport, corps vide, baseline dégénérée)
    /// ou zone grise : pas de veto, comportement inchangé.
    Neutral,
}

/// Dérive la paire de contrôle depuis les payloads finaux d'une paire
/// TRUE/FALSE confirmée.
///
/// Repère dans `true_payload` une comparaison entière réflexive
/// (`(\d+)\s*=\s*(\d+)` avec `lhs == rhs`, ex. `1=1` dans `' AND 1=1 -- -`)
/// et dans `false_payload` une comparaison entière fausse (`lhs != rhs`,
/// ex. `1=2`), puis remplace **uniquement** les littéraux repérés : côté vrai
/// → `{r}={r}`, côté faux → `{r1}={r2}` (`r1 != r2`), entiers tirés dans
/// `1000..=9999`. Le reste du payload (guillemets, mots-clés, tampers,
/// commentaire) est recopié à l'identique.
///
/// `None` quand un des deux motifs manque (paire `'a'='a'`/`'a'='b'`, JSON,
/// `NoSQL`…) : aucun contrôle n'est possible, l'appelant reste neutre (pas de
/// veto). Seedé via [`crate::seeded_rng::make_rng`] : même `--seed` ⇒ mêmes
/// payloads de contrôle ; `None` = aléatoire OS, comme le reste du crate.
#[must_use]
pub fn derive_control_pair(
    true_payload: &str,
    false_payload: &str,
    seed: Option<u64>,
) -> Option<ControlPair> {
    let (true_range, _, _) = find_int_comparison(true_payload, true)?;
    let (false_range, _, _) = find_int_comparison(false_payload, false)?;
    let mut rng = make_rng(seed);
    let r = rng.random_range(CONTROL_VALUE_MIN..=CONTROL_VALUE_MAX);
    let r1 = rng.random_range(CONTROL_VALUE_MIN..=CONTROL_VALUE_MAX);
    // `r2 != r1` par construction : tirage dans l'intervalle privé de `r1`
    // (décalage d'un cran au-delà), jamais par boucle de rejet.
    let mut r2 = rng.random_range(CONTROL_VALUE_MIN..CONTROL_VALUE_MAX);
    if r2 >= r1 {
        r2 += 1;
    }
    Some(ControlPair {
        must_true: splice_comparison(true_payload, true_range, &format!("{r}={r}")),
        must_false: splice_comparison(false_payload, false_range, &format!("{r1}={r2}")),
    })
}

/// Évalue la paire de contrôle contre la baseline (comportement historique,
/// sans plancher de bruit appris).
///
/// Exige la cohérence de direction attendue : le contrôle `r=r` doit rester
/// baseline-like (`diff_against_baseline` < [`SIMILAR_CONFIDENCE_MAX`]) et le
/// contrôle `r1=r2` doit s'en écarter (`>` [`DIFFERENT_CONFIDENCE_MIN`]).
/// `inverted` est le sens renvoyé par
/// [`crate::detection::confirmation::confirm_either`] : en mode inversé, le
/// côté logiquement **faux** est celui qui était baseline-like.
///
/// Délègue à [`control_verdict_with_match_ratio`] avec `match_ratio = None` :
/// sortie bit-à-bit identique à l'implémentation historique, le plancher
/// empirique P1.2 ne s'active jamais sans ratio appris.
///
/// - [`ControlVerdict::Keep`] : les deux contrôles sont mesurés et cohérents ;
/// - [`ControlVerdict::Veto`] : mesure clairement contredisante (un contrôle
///   « vrai » qui s'éloigne de la baseline, ou un contrôle « faux » qui s'y
///   confond) → le différentiel ne vient pas de la logique SQL ;
/// - [`ControlVerdict::Neutral`] : corps vide (défaillance transport, même
///   garde que [`diff_against_baseline`]), baseline vide (pas d'ancre) ou
///   zone grise (entre les deux seuils) → pas de veto.
#[must_use]
pub fn control_verdict(
    baseline_body: &str,
    ctl_true_body: &str,
    ctl_false_body: &str,
    baseline_ms: f64,
    ctl_true_ms: f64,
    ctl_false_ms: f64,
    inverted: bool,
) -> ControlVerdict {
    control_verdict_with_match_ratio(
        baseline_body,
        ctl_true_body,
        ctl_false_body,
        baseline_ms,
        ctl_true_ms,
        ctl_false_ms,
        inverted,
        None,
    )
}

/// Évalue la paire de contrôle contre la baseline, avec le plancher de bruit
/// empirique (P1.2, [`crate::detection::baseline::Baseline::match_ratio`])
/// pour rescaper le côté baseline-like.
///
/// Même sémantique que [`control_verdict`] — `same` = côté qui doit rester
/// baseline-like (`diff_true` si `!inverted`, `diff_false` sinon), `other` =
/// côté qui doit s'en écarter — avec une rescousse supplémentaire :
///
/// # Rescousse empirique (P1.2)
///
/// Sur une page naturellement instable, le contrôle baseline-like peut lire
/// « différent » par confiance (timing/composition) alors que sa similarité
/// Jaccard retombe dans la bande de bruit apprise (`match_ratio`, marge
/// [`crate::detection::response_diff::DIFF_TOLERANCE`]) : un veto serait alors
/// injustifié et dropperait un vrai positif. Quand
/// `classify_page_similarity(jaccard(baseline, same), match_ratio)` vaut
/// [`PageSimilarity::Same`], le côté `same` est traité comme baseline-like
/// même si sa confiance dépasse [`SIMILAR_CONFIDENCE_MAX`] : un
/// [`ControlVerdict::Keep`] reste possible et le veto « same s'éloigne » est
/// levé.
///
/// Le côté `other` garde ses barres fixes : le plancher ne peut jamais
/// transformer un [`ControlVerdict::Keep`] en [`ControlVerdict::Veto`], ni
/// créer un [`ControlVerdict::Keep`] quand `other < SIMILAR_CONFIDENCE_MAX`.
/// `match_ratio = None` (ou non fini) restaure exactement le comportement
/// historique ; les gardes d'entrée (corps vide → [`ControlVerdict::Neutral`])
/// sont inchangées.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn control_verdict_with_match_ratio(
    baseline_body: &str,
    ctl_true_body: &str,
    ctl_false_body: &str,
    baseline_ms: f64,
    ctl_true_ms: f64,
    ctl_false_ms: f64,
    inverted: bool,
    match_ratio: Option<f64>,
) -> ControlVerdict {
    // Corps vide = aucune mesure ; baseline vide = pas d'ancre de comparaison.
    // Dans les deux cas : neutre, jamais de veto (le call site, lui, filtre
    // déjà les statuts transport `0`).
    if baseline_body.is_empty() || ctl_true_body.is_empty() || ctl_false_body.is_empty() {
        return ControlVerdict::Neutral;
    }
    let diff_true = diff_against_baseline(
        baseline_body,
        ctl_true_body,
        baseline_ms,
        ctl_true_ms,
        DIFF_SIGMA_MS,
    );
    let diff_false = diff_against_baseline(
        baseline_body,
        ctl_false_body,
        baseline_ms,
        ctl_false_ms,
        DIFF_SIGMA_MS,
    );
    // `same` = contrôle qui doit rester sur la baseline, `other` = contrôle
    // qui doit s'en écarter. En mode inversé, c'est la comparaison fausse
    // (`r1=r2`) qui joue le rôle baseline-like de la découverte.
    let (same, other) = if inverted {
        (diff_false.confidence, diff_true.confidence)
    } else {
        (diff_true.confidence, diff_false.confidence)
    };
    // P1.2 — côté `same` uniquement : le plancher de bruit appris explique une
    // similarité Jaccard du contrôle baseline-like qui retombe dans la bande
    // du bruit (`DIFF_TOLERANCE` autour de `match_ratio`) : cohérent.
    let same_body = if inverted {
        ctl_false_body
    } else {
        ctl_true_body
    };
    let floor_same = match_ratio.is_some()
        && classify_page_similarity(jaccard(baseline_body, same_body), match_ratio)
            == PageSimilarity::Same;
    let same_like = same < SIMILAR_CONFIDENCE_MAX || floor_same;
    if same_like && other > DIFFERENT_CONFIDENCE_MIN {
        ControlVerdict::Keep
    } else if (same > DIFFERENT_CONFIDENCE_MIN && !floor_same) || other < SIMILAR_CONFIDENCE_MAX {
        ControlVerdict::Veto
    } else {
        ControlVerdict::Neutral
    }
}

/// Repère la première comparaison entière `(\d+)\s*=\s*(\d+)` de `payload`
/// dont le résultat est `want_equal` (`lhs == rhs` si `true`, `lhs != rhs`
/// sinon). Retourne l'intervalle d'octets couvrant `lhs…rhs` (jamais un
/// chiffre hors comparaison : un littéral doit commencer un nombre, donc
/// `'1'='1'`, `:1}` ou `)=1` ne matchent pas) et les deux valeurs.
fn find_int_comparison(
    payload: &str,
    want_equal: bool,
) -> Option<(std::ops::Range<usize>, u64, u64)> {
    let bytes = payload.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // Début de littéral uniquement : un chiffre précédé d'un autre chiffre
        // (ou `_`) est un suffixe de nombre — sans cette garde, un long
        // littéral non parsable se re-découperait en faux `\d+=\d+`.
        if i > 0 && (bytes[i - 1].is_ascii_digit() || bytes[i - 1] == b'_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let lhs_end = i;
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if bytes.get(j) != Some(&b'=') {
            continue;
        }
        j += 1;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        let rhs_start = j;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j == rhs_start {
            continue;
        }
        let (Some(lhs), Some(rhs)) = (
            payload[start..lhs_end].parse::<u64>().ok(),
            payload[rhs_start..j].parse::<u64>().ok(),
        ) else {
            continue;
        };
        if (lhs == rhs) == want_equal {
            return Some((start..j, lhs, rhs));
        }
    }
    None
}

/// Recopie `payload` en remplaçant l'intervalle `range` (la comparaison
/// entière repérée, bornes ASCII donc sûres en UTF-8) par `replacement`.
fn splice_comparison(payload: &str, range: std::ops::Range<usize>, replacement: &str) -> String {
    let mut out = String::with_capacity(payload.len() + replacement.len());
    out.push_str(&payload[..range.start]);
    out.push_str(replacement);
    out.push_str(&payload[range.end..]);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
        let pair = derive_control_pair("' AND 1=1 -- -", "' AND 1=2 -- -", Some(7))
            .expect("pair derivable");
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
}
