#![deny(unsafe_code)]

use crate::detection::response_diff::{
    PageSimilarity, classify_page_similarity, diff_against_baseline, jaccard,
};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BooleanResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub true_similarity: f64,
    pub false_similarity: f64,
    /// Veto empirique P1.2 : `true` quand les deux branches restent dans la
    /// bande de bruit de la page (`match_ratio` appris, similarités ≥
    /// `m - DIFF_TOLERANCE`) — le couple ne porte aucun signal d'oracle. Les
    /// appelants qui décident sur les `Trial`s (similarités brutes) doivent
    /// le traduire en trial neutre ; les appelants qui lisent `is_vulnerable`
    /// sont déjà couverts par le veto. Toujours `false` quand aucun plancher
    /// n'a été appris (comportement historique).
    pub noise_vetoed: bool,
}

#[derive(Debug, Default)]
pub struct BooleanDetector;

/// Minimum absolute TRUE-vs-FALSE Jaccard gap to treat the pair as differential.
const JACCARD_DIFF_THRESHOLD: f64 = 0.15;
/// `diff_against_baseline` confidence at or below this counts as "similar to baseline".
/// Shared with `detection::control_pair` (P0.2 control pairs) so every
/// boolean-oracle verdict uses one calibration.
pub(crate) const SIMILAR_CONFIDENCE_MAX: f64 = 0.4;
/// `diff_against_baseline` confidence above this counts as "different from baseline".
/// Shared with `detection::control_pair` (P0.2 control pairs).
pub(crate) const DIFFERENT_CONFIDENCE_MIN: f64 = 0.6;
/// Timing sigma (ms) for the baseline diff — small enough to ignore clock jitter.
/// Shared with `detection::control_pair` (P0.2 control pairs).
pub(crate) const DIFF_SIGMA_MS: f64 = 100.0;

impl BooleanDetector {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Compare TRUE vs FALSE payload responses against baseline.
    ///
    /// Délègue à [`Self::evaluate_with_match_ratio`] sans plancher de bruit
    /// (`None`) : comportement historique strictement inchangé (les wrappers
    /// JSON/NoSQL, qui n'ont pas de baseline en portée, passent aussi par ici).
    #[must_use]
    pub fn evaluate(
        &self,
        baseline_body: &str,
        true_body: &str,
        false_body: &str,
        baseline_ms: f64,
        true_ms: f64,
        false_ms: f64,
    ) -> BooleanResult {
        self.evaluate_with_match_ratio(
            baseline_body,
            true_body,
            false_body,
            baseline_ms,
            true_ms,
            false_ms,
            None,
        )
    }

    /// Compare TRUE vs FALSE payload responses against baseline, avec le veto
    /// empirique du plancher de bruit appris (P1.2, partie 2/2).
    ///
    /// Logique identique à [`Self::evaluate`], plus un garde-fou anti-faux-
    /// positif **réducteur uniquement** : quand un plancher de bruit a été
    /// appris (`match_ratio = Some(m)`, voir
    /// [`crate::detection::baseline::Baseline::match_ratio`]) et que les DEUX
    /// branches restent `Same` au sens de [`classify_page_similarity`] — leur
    /// similarité Jaccard ne chute pas sous `m - DIFF_TOLERANCE` —, le
    /// « différentiel » mesuré n'est qu'une fluctuation de la page :
    /// `is_vulnerable` passe à `false` et `confidence` retombe à `0.2`, comme
    /// le chemin non vulnérable historique. Les similarités mesurées restent
    /// reportées telles quelles (`true_similarity` / `false_similarity`).
    ///
    /// # Polarité (déviation assumée vs sqlmap)
    ///
    /// sqlmap évalue `(ratio - matchRatio) > DIFF_TOLERANCE` en logique
    /// négative propre à son moteur d'inférence. Ici la polarité est exprimée
    /// en espace-similarité : une branche est baseline-like tant que sa
    /// similarité ne perce pas le plancher `m - DIFF_TOLERANCE` (voir
    /// [`classify_page_similarity`]). Le ratio appris est un plancher de bruit
    /// à ne pas franchir, pas un seuil à dépasser.
    ///
    /// # Sûreté du veto
    ///
    /// - il n'agit que quand `match_ratio` est `Some` : une page stable apprend
    ///   `None` (médiane Jaccard ~1.0) et le comportement de [`Self::evaluate`]
    ///   est conservé tel quel ;
    /// - il ne peut que retirer un verdict vulnérable — jamais créer de
    ///   finding ;
    /// - si une seule branche sort de la bande de bruit (`Different`), la
    ///   logique historique (gap ancré / confiances différentielles)
    ///   s'applique inchangée : un vrai oracle dont une branche s'écarte
    ///   franchement n'est jamais vetoé.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_with_match_ratio(
        &self,
        baseline_body: &str,
        true_body: &str,
        false_body: &str,
        baseline_ms: f64,
        true_ms: f64,
        false_ms: f64,
        match_ratio: Option<f64>,
    ) -> BooleanResult {
        let diff_true = diff_against_baseline(
            baseline_body,
            true_body,
            baseline_ms,
            true_ms,
            DIFF_SIGMA_MS,
        );
        let diff_false = diff_against_baseline(
            baseline_body,
            false_body,
            baseline_ms,
            false_ms,
            DIFF_SIGMA_MS,
        );
        // TRUE should be similar to baseline, FALSE should differ, or vice versa depending on injection.
        let j_true = jaccard(baseline_body, true_body);
        let j_false = jaccard(baseline_body, false_body);
        // Anchored heuristic: a bare TRUE-vs-FALSE gap alone is not enough —
        // on unstable pages (e.g. 0.2 vs 0.4, neither resembling the
        // baseline) it fires false positives. Require at least one branch to
        // still look like the baseline (`diff confidence < 0.4`), in either
        // direction (normal: TRUE≈baseline; inverted login-style: FALSE≈baseline).
        let gap = (j_true - j_false).abs();
        let anchored = diff_true.confidence < SIMILAR_CONFIDENCE_MAX
            || diff_false.confidence < SIMILAR_CONFIDENCE_MAX;
        let legacy_vuln = (gap > JACCARD_DIFF_THRESHOLD && anchored)
            || (diff_true.confidence < SIMILAR_CONFIDENCE_MAX
                && diff_false.confidence > DIFFERENT_CONFIDENCE_MIN)
            || (diff_false.confidence < SIMILAR_CONFIDENCE_MAX
                && diff_true.confidence > DIFFERENT_CONFIDENCE_MIN);
        // Veto empirique P1.2 : les deux branches restent dans la bande de
        // bruit de la page (`Same` à `m - DIFF_TOLERANCE` près) → le
        // différentiel n'est pas un oracle. Uniquement réducteur, et seulement
        // quand un plancher a été appris.
        let same_true = classify_page_similarity(j_true, match_ratio) == PageSimilarity::Same;
        let same_false = classify_page_similarity(j_false, match_ratio) == PageSimilarity::Same;
        let noise_veto = match_ratio.is_some() && same_true && same_false;
        let is_vuln = legacy_vuln && !noise_veto;
        let confidence = if is_vuln {
            (0.5 + (j_true - j_false).abs() * 0.5).clamp(0.0, 1.0)
        } else {
            0.2
        };
        BooleanResult {
            is_vulnerable: is_vuln,
            confidence,
            true_similarity: j_true,
            false_similarity: j_false,
            noise_vetoed: noise_veto,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Baseline de test : 20 tokens stables distincts (Jaccard mesurable
    /// exactement, sans dépendre de `diff_against_baseline`).
    fn baseline_body() -> String {
        (1..=20)
            .map(|i| format!("tok{i:02}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Les `n` premiers tokens de [`baseline_body`].
    fn prefix_tokens(n: usize) -> String {
        (1..=n)
            .map(|i| format!("tok{i:02}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Branche TRUE ≈ baseline : +1 token → Jaccard 20/21 ≈ 0.952.
    fn true_like_body() -> String {
        format!("{} extra_true_marker", baseline_body())
    }

    /// Branche FALSE dans la bande de bruit d'un plancher m=0.8
    /// (plancher `m - 0.05` = 0.75) : 16 tokens partagés + 1 nouveau →
    /// 16/21 ≈ 0.762.
    fn false_in_band_body() -> String {
        format!("{} extra_false_marker", prefix_tokens(16))
    }

    /// Branche FALSE juste sous le plancher : baseline − 6 tokens → 14/20 = 0.70.
    fn false_just_out_body() -> String {
        prefix_tokens(14)
    }

    /// Branche FALSE franchement différente : 8 tokens partagés + 6 nouveaux →
    /// 8/26 ≈ 0.308 ≪ plancher.
    fn false_far_body() -> String {
        let extra = (1..=6)
            .map(|i| format!("other{i:02}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!("{} {extra}", prefix_tokens(8))
    }

    /// Gap ≈ 0.19 > 0.15 et branche TRUE ancrée : sans plancher la logique
    /// historique confirme ; avec le plancher m=0.8 les DEUX branches restent
    /// `Same` → veto, confiance 0.2, mesures intactes.
    #[test]
    fn both_branches_in_noise_band_are_vetoed() {
        let detector = BooleanDetector::new();
        let base = baseline_body();
        let true_body = true_like_body();
        let false_body = false_in_band_body();
        let legacy = detector.evaluate(&base, &true_body, &false_body, 100.0, 100.0, 100.0);
        assert!(
            legacy.is_vulnerable,
            "sans plancher : gap ancré → vulnérable : {legacy:?}"
        );
        let vetoed = detector.evaluate_with_match_ratio(
            &base,
            &true_body,
            &false_body,
            100.0,
            100.0,
            100.0,
            Some(0.8),
        );
        assert!(
            !vetoed.is_vulnerable,
            "les deux branches dans la bande de bruit : veto attendu : {vetoed:?}"
        );
        assert!(
            vetoed.noise_vetoed,
            "le flag de veto doit être exposé pour la traduction en trial neutre : {vetoed:?}"
        );
        assert!(
            !legacy.noise_vetoed,
            "sans plancher, le flag reste faux : {legacy:?}"
        );
        assert!(
            (vetoed.confidence - 0.2).abs() < 1e-9,
            "confiance non vulnérable attendue, got {}",
            vetoed.confidence
        );
        // Les similarités mesurées restent reportées telles quelles.
        assert!((vetoed.true_similarity - legacy.true_similarity).abs() < 1e-12);
        assert!((vetoed.false_similarity - legacy.false_similarity).abs() < 1e-12);
    }

    /// Même entrée, `match_ratio = None` : verdict historique conservé
    /// (vulnérable via gap ancré + confiance > 0.2).
    #[test]
    fn without_floor_legacy_verdict_is_kept() {
        let detector = BooleanDetector::new();
        let r = detector.evaluate_with_match_ratio(
            &baseline_body(),
            &true_like_body(),
            &false_in_band_body(),
            100.0,
            100.0,
            100.0,
            None,
        );
        assert!(r.is_vulnerable, "{r:?}");
        assert!(
            r.confidence > 0.2,
            "confiance différentielle : {}",
            r.confidence
        );
    }

    /// Une seule branche hors bande (`j_false` = 0.70 < plancher 0.75) : pas de
    /// veto abusif, la logique historique garde le verdict.
    #[test]
    fn branch_just_out_of_band_is_not_vetoed() {
        let detector = BooleanDetector::new();
        let base = baseline_body();
        let true_body = true_like_body();
        let false_body = false_just_out_body();
        let legacy = detector.evaluate(&base, &true_body, &false_body, 100.0, 100.0, 100.0);
        assert!(legacy.is_vulnerable, "{legacy:?}");
        let floored = detector.evaluate_with_match_ratio(
            &base,
            &true_body,
            &false_body,
            100.0,
            100.0,
            100.0,
            Some(0.8),
        );
        assert!(
            floored.is_vulnerable,
            "une branche hors bande : pas de veto : {floored:?}"
        );
        assert!(
            !floored.noise_vetoed,
            "pas de flag neutre quand une branche sort de la bande : {floored:?}"
        );
    }

    /// Oracle franc : `j_false` ≈ 0.31, très en dessous du plancher → aucun
    /// veto, comportement inchangé même avec un plancher appris.
    #[test]
    fn far_different_branch_is_not_vetoed() {
        let detector = BooleanDetector::new();
        let base = baseline_body();
        let true_body = true_like_body();
        let false_body = false_far_body();
        let floored = detector.evaluate_with_match_ratio(
            &base,
            &true_body,
            &false_body,
            100.0,
            100.0,
            100.0,
            Some(0.8),
        );
        assert!(
            floored.is_vulnerable,
            "branche franchement différente : pas de veto : {floored:?}"
        );
    }

    /// `evaluate` == `evaluate_with_match_ratio(..., None)` sur un cas
    /// représentatif (même chemin de code, aucune divergence).
    #[test]
    #[allow(clippy::float_cmp)]
    fn evaluate_is_with_none() {
        let detector = BooleanDetector::new();
        let base = baseline_body();
        let true_body = true_like_body();
        let false_body = false_in_band_body();
        let a = detector.evaluate(&base, &true_body, &false_body, 100.0, 105.0, 103.0);
        let b = detector.evaluate_with_match_ratio(
            &base,
            &true_body,
            &false_body,
            100.0,
            105.0,
            103.0,
            None,
        );
        assert_eq!(a.is_vulnerable, b.is_vulnerable);
        assert_eq!(a.confidence, b.confidence);
        assert_eq!(a.true_similarity, b.true_similarity);
        assert_eq!(a.false_similarity, b.false_similarity);
    }
}
