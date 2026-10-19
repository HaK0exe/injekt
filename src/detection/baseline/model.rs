use crate::detection::dynamic_content::DynamicMarking;
use std::time::Duration;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Baseline {
    pub status_codes: Vec<u16>,
    /// SHA-256 of each raw sample body. Kept for diagnostics; stability
    /// decisions use [`Self::normalized_hashes`].
    pub body_hashes: Vec<String>,
    /// SHA-256 of each sample body after [`crate::detection::response_diff::normalize_response_for_diff`]
    /// blanked volatile regions (rotating CSRF/JWT/JSON noise). Drives
    /// [`Baseline::is_stable`] together with the NORMALIZED lengths
    /// ([`Self::normalized_lengths`]).
    pub normalized_hashes: Vec<String>,
    /// Byte lengths of each NORMALIZED sample text (the same texts hashed in
    /// [`Self::normalized_hashes`]). The stability key uses these instead of
    /// the raw lengths: raw lengths drift with volatile-field repr
    /// variability (a `generated_at` epoch float losing a trailing zero is a
    /// ±1 byte move), while real content changes still shift the normalized
    /// length. See [`Self::is_stable`].
    pub normalized_lengths: Vec<usize>,
    /// Raw byte lengths of each sample body (diagnostics only; stability
    /// decisions use [`Self::normalized_lengths`]).
    pub body_lengths: Vec<usize>,
    pub durations: Vec<Duration>,
    pub mean_ms: f64,
    pub stddev_ms: f64,
    pub representative_body: Vec<u8>,
    /// Zones dynamiques génériques repérées entre les échantillons (P1.1,
    /// port sqlmap `findDynamicContent`) : paires de flancs stables identiques
    /// encadrant un contenu qui bouge sans être un champ volatil nommé.
    /// Accumulées par paires de pages de même statut, dédupliquées.
    pub dynamic_markings: Vec<DynamicMarking>,
    /// SHA-256 des textes normalisés après [`Self::strip_dynamic_content`].
    /// Clé de stabilité de secours quand la page ne bouge que dans une zone
    /// marquée (voir [`Self::is_stable`]).
    pub stripped_hashes: Vec<String>,
    /// Longueurs (octets) des textes normalisés après stripping, associées à
    /// [`Self::stripped_hashes`].
    pub stripped_lengths: Vec<usize>,
    /// Plancher de bruit empirique `match_ratio` (P1.2 partie 2/2, port sqlmap
    /// `kb.matchRatio`) : médiane des similarités Jaccard entre échantillons
    /// de même statut, apprise par [`Self::new`] (voir
    /// [`Self::learn_match_ratio`]).
    ///
    /// `Some(m)` uniquement quand `m ∈ [LOWER_RATIO_BOUND, UPPER_RATIO_BOUND]` :
    /// une page parfaitement stable (médiane ~1.0, au-dessus de
    /// `UPPER_RATIO_BOUND`) reste `None` — le veto empirique du détecteur
    /// booléen ne s'active donc que sur une page qui a un vrai bruit résiduel,
    /// et le comportement historique (sans plancher) est conservé partout
    /// ailleurs (page stable, page chaotique, moins de deux échantillons).
    pub(crate) match_ratio: Option<f64>,
    /// WAF/CDN vendor observed across samples (`"cloudflare"`, …), if any.
    pub waf_vendor: Option<String>,
    /// Signal names that fired (header/body markers, never values).
    pub waf_hits: Vec<String>,
    /// `true` when a *blocking* signal (challenge/deny/rate-limit) was seen
    /// in any sample. Mere CDN presence (`cf-ray` alone) records
    /// `waf_vendor`/`waf_hits` but leaves this `false`.
    pub waf_blocking: bool,
}

#[derive(Debug, Clone)]
pub struct Sample {
    pub status: u16,
    pub body: Vec<u8>,
    pub duration: Duration,
    /// Response headers as `(lowercased-name, value-prefix ≤128 chars)`.
    /// Values are truncated at collection time (OPSEC: bounds retention of
    /// `Set-Cookie` tokens in RAM); detection only needs `contains` on
    /// markers such as `__cf_bm`.
    pub headers: Vec<(String, String)>,
}

/// Collect 3-5 baseline samples via client.
pub async fn collect_baseline<F, Fut>(mut fetcher: F, count: usize) -> Baseline
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Sample>,
{
    let mut samples = Vec::new();
    let n = count.clamp(3, 5);
    for _ in 0..n {
        samples.push(fetcher().await);
    }
    Baseline::new(&samples)
}
