use crate::detection::response_diff::{
    PageSimilarity, classify_page_similarity, diff_against_baseline, jaccard,
};
use crate::seeded_rng::make_rng;
use crate::techniques::boolean::detector::{
    DIFF_SIGMA_MS, DIFFERENT_CONFIDENCE_MIN, SIMILAR_CONFIDENCE_MAX,
};
use rand::Rng as _;

/// Borne basse (incluse) des entiers aléatoires de contrôle.
pub(super) const CONTROL_VALUE_MIN: u64 = 1000;
/// Borne haute (incluse) des entiers aléatoires de contrôle.
pub(super) const CONTROL_VALUE_MAX: u64 = 9999;

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
pub(super) fn find_int_comparison(
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
