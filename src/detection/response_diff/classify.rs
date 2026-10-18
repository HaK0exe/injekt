// ---------------------------------------------------------------------------
// Classification de similarité de page (plan anti-FP P1.2, partie 1/2).
//
// Reprend la fin de `comparison()` de sqlmap 2026 (`lib/core/comparison.py`,
// constantes dans `lib/core/settings.py`) sous forme pure, sans toucher à
// `diff_against_baseline` : les seuils sont consommés par la couche détection
// dans une passe ultérieure.
// ---------------------------------------------------------------------------

/// Borne haute sqlmap 2026 (`lib/core/settings.py::UPPER_RATIO_BOUND`) : au-delà
/// de cette similarité la page est considérée identique à la baseline, sans
/// attendre de ratio appris.
pub const UPPER_RATIO_BOUND: f64 = 0.98;

/// Borne basse sqlmap 2026 (`lib/core/settings.py::LOWER_RATIO_BOUND`) : en
/// dessous, la page est considérée complètement différente.
pub const LOWER_RATIO_BOUND: f64 = 0.02;

/// Tolérance sqlmap 2026 (`lib/core/settings.py::DIFF_TOLERANCE`) : marge
/// autour du plancher de bruit appris (`match_ratio`) avant qu'une similarité
/// en zone grise ne soit classée `Different`.
pub const DIFF_TOLERANCE: f64 = 0.05;

/// Verdict de similarité d'une page candidate face à la baseline, calqué sur
/// le triplet `True`/`False`/`None` renvoyé par `comparison()` de sqlmap 2026.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PageSimilarity {
    /// Page jugée identique : similarité au-dessus de [`UPPER_RATIO_BOUND`],
    /// ou au-dessus du plancher de bruit appris à [`DIFF_TOLERANCE`] près.
    Same,
    /// Page jugée franchement différente : similarité sous
    /// [`LOWER_RATIO_BOUND`], ou sous le plancher de bruit appris à
    /// [`DIFF_TOLERANCE`] près.
    Different,
    /// Zone grise sans plancher de bruit appris (ou entrée NaN) : impossible
    /// de trancher sans calibration — l'appelant doit rester prudent.
    Undetermined,
}

/// Classe une similarité de page `0..1` (1 = identique) selon la logique de
/// `comparison()` de sqlmap 2026 :
///
/// 1. `similarity > UPPER_RATIO_BOUND` → [`PageSimilarity::Same`] ;
/// 2. `similarity < LOWER_RATIO_BOUND` → [`PageSimilarity::Different`] ;
/// 3. sinon `match_ratio`, appris empiriquement sur des paires de réponses
///    « même page » (chez nous : les échantillons de baseline) :
///    - `None` → [`PageSimilarity::Undetermined`], comme sqlmap qui ne tranche
///      pas tant que `kb.matchRatio` n'est pas calibré ;
///    - `Some(m)` → `Same` si `similarity >= m - DIFF_TOLERANCE`, sinon
///      `Different`.
///
/// # Déviation assumée vs sqlmap
///
/// sqlmap renvoie `(ratio - matchRatio) > DIFF_TOLERANCE` dans une convention
/// « negative logic » propre à son moteur d'inférence (`True` y signifie
/// « page inchangée » pour l'inférence booléenne). Ici la polarité est
/// exprimée en espace-similarité : une branche reste « baseline-like » tant
/// que sa similarité ne chute pas sous le plancher de bruit appris
/// (`match_ratio`), à `DIFF_TOLERANCE` près. La borne est donc
/// `m - DIFF_TOLERANCE` et non `m + DIFF_TOLERANCE` : le ratio appris est
/// traité comme un plancher de bruit à ne pas percer, pas comme un seuil à
/// dépasser.
///
/// # Entrées dégénérées
///
/// `similarity` est d'abord clampée dans `[0,1]` (les `±∞` retombent donc sur
/// les bornes) ; NaN, que le clamp laisse inchangé, donne `Undetermined`. Un
/// `match_ratio` non fini (`Some(NaN)`) est également traité comme
/// `Undetermined` : un plancher de bruit NaN rendrait le verdict `Different`
/// par simple échec de comparaison, soit un faux positif — on préfère
/// l'abstention. La fonction ne panique jamais.
#[must_use]
pub fn classify_page_similarity(similarity: f64, match_ratio: Option<f64>) -> PageSimilarity {
    let similarity = similarity.clamp(0.0, 1.0);
    if !similarity.is_finite() {
        return PageSimilarity::Undetermined;
    }
    if similarity > UPPER_RATIO_BOUND {
        return PageSimilarity::Same;
    }
    if similarity < LOWER_RATIO_BOUND {
        return PageSimilarity::Different;
    }
    match match_ratio.filter(|m| m.is_finite()) {
        None => PageSimilarity::Undetermined,
        Some(m) => {
            if similarity >= m - DIFF_TOLERANCE {
                PageSimilarity::Same
            } else {
                PageSimilarity::Different
            }
        }
    }
}
