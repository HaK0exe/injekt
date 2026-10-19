use super::model::{Baseline, Sample};
use crate::detection::dynamic_content::{
    DynamicMarking, find_dynamic_content, remove_dynamic_content,
};
use crate::detection::response_diff::{
    LOWER_RATIO_BOUND, UPPER_RATIO_BOUND, jaccard, normalize_response_for_diff,
};
use crate::detection::waf;
use sha2::{Digest, Sha256};

/// Statuses counted as WAF blocks for [`Baseline::is_waf_blocked`].
/// `403`/`406` are classic deny/challenge codes; `429` is throttling (the
/// `is_waf_blocking` signal path corroborates it via headers/body markers).
/// `5xx` deliberately excluded: origin errors on a down target must not
/// trigger bypass tampers.
const WAF_BLOCK_STATUSES: [u16; 3] = [403, 406, 429];
/// Minimum block count across baseline samples before calling it a WAF.
const MIN_WAF_BLOCKS: usize = 2;

impl Baseline {
    #[must_use]
    // Sample counts are small (single-digit baseline probes); usize->f64 precision loss is not reachable.
    #[allow(clippy::cast_precision_loss)]
    pub fn new(samples: &[Sample]) -> Self {
        let status_codes = samples.iter().map(|s| s.status).collect();
        let body_hashes = samples.iter().map(|s| Self::hash(&s.body)).collect();
        // Hash the normalized text as well: baseline bodies are arbitrary
        // bytes, decoded lossily for normalization, with volatile regions
        // blanked first so per-response CSRF/JWT/JSON rotation does not
        // destabilize the oracle. Keep the texts around: the dynamic-content
        // marking below works on the same normalized text.
        let normalized_texts: Vec<String> = samples
            .iter()
            .map(|s| normalize_response_for_diff(&String::from_utf8_lossy(&s.body)))
            .collect();
        let normalized_hashes = normalized_texts
            .iter()
            .map(|text| Self::hash(text.as_bytes()))
            .collect();
        let body_lengths = samples.iter().map(|s| s.body.len()).collect();
        // Longueurs des textes NORMALISÉS (mêmes textes que
        // `normalized_hashes`) : clé de stabilité. Les longueurs brutes
        // oscillent avec la variabilité d'affichage des champs volatils
        // (re-trims de zéros de queue d'un epoch float `generated_at` :
        // 173↔174 octets sur le lab bench) ; le texte normalisé ne bouge
        // qu'avec le contenu réel.
        let normalized_lengths: Vec<usize> = normalized_texts.iter().map(String::len).collect();
        let durations = samples.iter().map(|s| s.duration).collect();
        let ms: Vec<f64> = samples
            .iter()
            .map(|s| s.duration.as_secs_f64() * 1000.0)
            .collect();
        let mean = if ms.is_empty() {
            0.0
        } else {
            ms.iter().sum::<f64>() / ms.len() as f64
        };
        let var = if ms.len() < 2 {
            0.0
        } else {
            // Bessel's correction for sample variance (n-1) more accurate for n=3..5
            ms.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (ms.len() - 1) as f64
        };
        let stddev = var.sqrt();
        let representative_body = if samples.is_empty() {
            Vec::new()
        } else {
            // Median by length (robust against outliers), fallback to most common hash
            let mut sorted = samples.to_vec();
            sorted.sort_by_key(|s| s.body.len());
            sorted[sorted.len() / 2].body.clone()
        };
        // P1.1 — marquage générique du contenu dynamique (port sqlmap
        // `findDynamicContent`, équivalent `merge=True`) : compare les textes
        // normalisés des échantillons de même statut par paires
        // (premier échantillon vs suivants) et accumule les zones encadrées
        // par deux flancs stables identiques (> 40 chars), dédupliquées en
        // ordre d'apparition.
        let dynamic_markings = Self::find_baseline_markings(samples, &normalized_texts);
        // Hash + longueur de chaque texte normalisé APRÈS purge des zones
        // marquées : clé de stabilité de secours (voir `is_stable`).
        let (stripped_hashes, stripped_lengths): (Vec<String>, Vec<usize>) = normalized_texts
            .iter()
            .map(|text| {
                let stripped = remove_dynamic_content(text, &dynamic_markings);
                (Self::hash(stripped.as_bytes()), stripped.len())
            })
            .unzip();
        // P1.2 (partie 2/2) — apprentissage du plancher de bruit empirique
        // `match_ratio` sur les textes normalisés bruts (avant purge P1.1),
        // comme sqlmap qui calibre `matchRatio` sur des paires de réponses
        // « même page ». Voir [`Self::learn_match_ratio`].
        let match_ratio = Self::learn_match_ratio(samples, &normalized_texts);
        // Aggregate WAF signals across samples (headers + body per sample).
        // A specific vendor wins over `Generic` when both appear; hits are
        // deduplicated in first-seen order; blocking sticks if any sample
        // blocked.
        let mut waf_vendor: Option<String> = None;
        let mut waf_hits: Vec<String> = Vec::new();
        let mut waf_blocking = false;
        for sample in samples {
            let signals = waf::detect_cloudflare_flat(sample.status, &sample.headers, &sample.body);
            if let Some(vendor) = signals.vendor {
                let label = vendor.to_string();
                match &waf_vendor {
                    None => waf_vendor = Some(label),
                    Some(current) if current == "generic" && label != "generic" => {
                        waf_vendor = Some(label);
                    }
                    _ => {}
                }
                for hit in &signals.hits {
                    if !waf_hits.contains(hit) {
                        waf_hits.push(hit.clone());
                    }
                }
            }
            waf_blocking = waf_blocking || signals.blocking;
        }
        Self {
            status_codes,
            body_hashes,
            normalized_hashes,
            normalized_lengths,
            body_lengths,
            durations,
            mean_ms: mean,
            stddev_ms: stddev,
            representative_body,
            dynamic_markings,
            stripped_hashes,
            stripped_lengths,
            match_ratio,
            waf_vendor,
            waf_hits,
            waf_blocking,
        }
    }

    /// P1.2 (partie 2/2) — plancher de bruit empirique `match_ratio` (port
    /// sqlmap `kb.matchRatio`, calibré par `comparison()` sur des paires de
    /// réponses de la MÊME page — ici les échantillons baseline).
    ///
    /// La similarité apprise est la Jaccard par tokens de [`jaccard`], médiane
    /// sur **toutes les paires `i < j` de samples de même statut** (un
    /// changement de statut est un signal, pas du bruit). Les textes sont déjà
    /// normalisés par [`normalize_response_for_diff`] ; la re-normalisation
    /// interne de `jaccard` est donc sans effet (idempotente).
    ///
    /// Garde d'apprentissage (fidèle à sqlmap, où `matchRatio` reste indéfini
    /// tant que la comparaison ne le calibre pas) :
    /// - `Some(médiane)` seulement si la médiane tombe dans
    ///   `[LOWER_RATIO_BOUND, UPPER_RATIO_BOUND]` ;
    /// - page parfaitement stable (médiane > `UPPER_RATIO_BOUND`, typiquement
    ///   1.0) → `None` : aucun plancher n'est nécessaire, le comportement
    ///   historique du détecteur booléen est inchangé ;
    /// - page franchement chaotique (médiane < `LOWER_RATIO_BOUND`) → `None` :
    ///   la page n'est pas un oracle exploitable ;
    /// - moins de deux samples (ou aucune paire de même statut) → `None`.
    #[must_use]
    fn learn_match_ratio(samples: &[Sample], normalized_texts: &[String]) -> Option<f64> {
        if samples.len() < 2 || normalized_texts.len() != samples.len() {
            return None;
        }
        let mut similarities: Vec<f64> = Vec::new();
        for (idx, left) in samples.iter().enumerate() {
            for (right_idx, right) in samples.iter().enumerate().skip(idx + 1) {
                if left.status == right.status {
                    similarities.push(jaccard(
                        &normalized_texts[idx],
                        &normalized_texts[right_idx],
                    ));
                }
            }
        }
        if similarities.is_empty() {
            return None;
        }
        similarities.sort_by(f64::total_cmp);
        // Médiane « haute » (index `len / 2`) : pour 3 samples (3 paires) c'est
        // la paire centrale, valeur de coupure robuste pour de petits n.
        let median = *similarities.get(similarities.len() / 2)?;
        if (LOWER_RATIO_BOUND..=UPPER_RATIO_BOUND).contains(&median) {
            Some(median)
        } else {
            None
        }
    }

    /// Accumule les marquages de contenu dynamique (P1.1) sur les échantillons
    /// de même statut : premier échantillon du groupe vs suivants, dédup en
    /// ordre d'apparition (équivalent sqlmap `merge=True`).
    fn find_baseline_markings(
        samples: &[Sample],
        normalized_texts: &[String],
    ) -> Vec<DynamicMarking> {
        let mut markings: Vec<DynamicMarking> = Vec::new();
        let mut seen_statuses: Vec<u16> = Vec::new();
        for sample in samples {
            if !seen_statuses.contains(&sample.status) {
                seen_statuses.push(sample.status);
            }
        }
        for status in seen_statuses {
            let group: Vec<usize> = samples
                .iter()
                .enumerate()
                .filter(|(_, s)| s.status == status)
                .map(|(idx, _)| idx)
                .collect();
            if group.len() < 2 {
                continue;
            }
            let first_idx = group[0];
            for &idx in &group[1..] {
                for marking in
                    find_dynamic_content(&normalized_texts[first_idx], &normalized_texts[idx])
                {
                    if !markings.contains(&marking) {
                        markings.push(marking);
                    }
                }
            }
        }
        markings
    }

    fn hash(body: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(body);
        hex::encode(h.finalize())
    }

    #[must_use]
    pub fn threshold_ms(&self, sigma: f64) -> f64 {
        // Unified floor 100ms per 2026 audit (time detector uses 100).
        // PR20 divergence note: this static floor is intentional for generic
        // (fast-differential) use. `TimeDetector::threshold` reuses the same
        // mean/stddev via `from_baseline` but swaps the floor for
        // `adaptive_stddev_floor_ms` (`max(100ms, mean*0.1)`): byte-identical
        // below/at 1s mean, proportionally wider above (e.g. mean 5s →
        // threshold 6000 vs 5200 here). Rationale: on slow targets a static
        // 100ms floor flags every ±200ms wobble as anomalous for sleep
        // probes, while boolean/error differentials still want the tight
        // static bar — so the time channel alone adapts, this helper stays
        // put.
        self.mean_ms + sigma * self.stddev_ms.max(100.0)
    }

    #[must_use]
    pub fn representative_body_str(&self) -> String {
        String::from_utf8_lossy(&self.representative_body).into_owned()
    }

    /// Plancher de bruit empirique appris sur les échantillons de baseline
    /// (médiane Jaccard des paires de même statut, voir
    /// `Baseline::learn_match_ratio`).
    ///
    /// `Some(m)` seulement quand `m ∈ [LOWER_RATIO_BOUND, UPPER_RATIO_BOUND]` ;
    /// `None` = aucun plancher appris (page stable, page chaotique, moins de
    /// deux échantillons). Les appelants (détecteur booléen) doivent alors
    /// conserver leur comportement historique : le veto empirique P1.2 ne
    /// s'active jamais sans plancher.
    #[must_use]
    pub const fn match_ratio(&self) -> Option<f64> {
        self.match_ratio
    }

    /// Purge `body` des zones dynamiques marquées à la construction (P1.1).
    ///
    /// À appliquer aux corps probes **avant** leur pre-processing, pour que
    /// baseline et probes soient comparés dans le même référentiel (chemin
    /// cheap quand aucun marquage n'a été trouvé).
    #[must_use]
    pub fn strip_dynamic_content(&self, body: &str) -> String {
        if self.dynamic_markings.is_empty() {
            return body.to_owned();
        }
        remove_dynamic_content(body, &self.dynamic_markings)
    }

    /// Returns whether the samples are stable enough to be used as an oracle.
    ///
    /// A differential detector cannot distinguish injection from application
    /// noise when the baseline itself changes between requests.  Status
    /// consistency is required, then the median pairwise body agreement is
    /// checked over the *normalized* hashes: [`normalize_response_for_diff`]
    /// blanked volatile regions (CSRF/JWT/JSON noise) before hashing, so a
    /// page rotating those no longer flips to unstable (see
    /// [`Self::normalized_hashes`]). The key pairs each normalized hash with
    /// its NORMALIZED text length ([`Self::normalized_lengths`]): raw byte
    /// lengths drift with volatile-field repr variability (a `generated_at`
    /// epoch float losing a trailing zero reads 173↔174 bytes) while real
    /// content changes still shift the normalized length, so any
    /// non-volatile difference keeps the gate fail-closed. This is
    /// deliberately conservative: callers should report an inconclusive scan
    /// rather than manufacture a finding from an unstable page.
    ///
    /// P1.1: when [`Self::dynamic_markings`] is non-empty, a second
    /// acceptance path compares the normalized texts *after*
    /// [`Self::strip_dynamic_content`] (`stripped_hashes` +
    /// `stripped_lengths`): a page that only moves inside marked regions
    /// becomes a usable oracle. Without any marking, the historical
    /// fail-closed logic is unchanged.
    #[must_use]
    pub fn is_stable(&self) -> bool {
        if self.status_codes.len() < 3
            || self.body_hashes.len() < 3
            || self.normalized_hashes.len() < 3
        {
            return false;
        }
        if self.status_codes.windows(2).any(|pair| pair[0] != pair[1]) {
            return false;
        }
        let bodies: Vec<String> = self
            .normalized_hashes
            .iter()
            .zip(self.normalized_lengths.iter())
            .map(|(hash, length)| format!("{hash}:{length}"))
            .collect();
        // Exact normalized-hash + length agreement is a cheap fast path:
        // volatile-only rotation cancels here.
        if bodies.iter().all(|body| body == &bodies[0]) {
            return true;
        }
        // P1.1 — port sqlmap `findDynamicContent` : si des zones dynamiques
        // ont été marquées (flancs stables identiques de part et d'autre),
        // une page qui ne bouge que dans ces zones redevient un oracle
        // utilisable. Sans marquage, la logique fail-closed d'origine
        // s'applique telle quelle.
        if !self.dynamic_markings.is_empty()
            && self.stripped_hashes.len() >= 3
            && self.stripped_hashes.len() == self.stripped_lengths.len()
        {
            let stripped: Vec<String> = self
                .stripped_hashes
                .iter()
                .zip(self.stripped_lengths.iter())
                .map(|(hash, length)| format!("{hash}:{length}"))
                .collect();
            if stripped.iter().all(|body| body == &stripped[0]) {
                return true;
            }
        }
        let mut similarities = Vec::new();
        for (idx, left) in self.normalized_hashes.iter().enumerate() {
            for (right_idx, right) in self.normalized_hashes.iter().enumerate().skip(idx + 1) {
                if left == right
                    && self.normalized_lengths[idx] == self.normalized_lengths[right_idx]
                {
                    similarities.push(1.0);
                } else {
                    // Hashes are one-way: a normalized-hash or length mismatch
                    // cannot be scored partially, and any non-volatile
                    // difference must keep the gate closed
                    // (fail-closed).
                    similarities.push(0.0);
                }
            }
        }
        similarities.sort_by(f64::total_cmp);
        similarities[similarities.len() / 2] >= 0.8
    }

    #[must_use]
    pub fn is_waf_blocked(&self) -> bool {
        let blocked = self
            .status_codes
            .iter()
            .filter(|c| WAF_BLOCK_STATUSES.contains(c))
            .count();
        blocked >= MIN_WAF_BLOCKS
    }

    /// Any WAF/CDN presence (headers or challenge markers observed).
    /// Drives the informational warn + light auto-tamper.
    #[must_use]
    pub const fn is_waf_suspected(&self) -> bool {
        self.waf_vendor.is_some()
    }

    /// A *blocking* signal (challenge/deny/rate-limit) was observed.
    /// Drives finding confidence downgrade (see `waf::downgrade_for_waf`).
    #[must_use]
    pub const fn is_waf_blocking(&self) -> bool {
        self.waf_blocking
    }

    /// Short evidence fragment (`" waf=cloudflare:… blocking=…"`) or `""`
    /// when nothing was detected. Appended to finding evidence strings.
    #[must_use]
    pub fn waf_evidence_suffix(&self) -> String {
        let Some(vendor) = self.waf_vendor.as_deref() else {
            return String::new();
        };
        format!(
            " waf={}:{} blocking={}",
            vendor,
            self.waf_hits.join(","),
            self.waf_blocking
        )
    }

    /// Merge a request/response Content-Type mismatch signal (P0-4) into the
    /// aggregate: the caller sent an API payload (`expected_ct`, e.g.
    /// `application/json` from `--raw-file`) but a sample answered with a
    /// different document kind (typically `text/html` — a challenge/deny
    /// page intercepted the call).
    ///
    /// A mismatch alone is presence-level (`Generic`, `blocking=false` —
    /// informational, never auto-tamper/downgrade by itself); it turns
    /// `blocking` only together with a corroborating status on a mismatching
    /// sample, mirroring the marker+status contract in
    /// [`crate::detection::waf::detect_cloudflare_flat`]. No-op when `expected_ct` is
    /// not an API kind or every sample agrees (see
    /// [`crate::detection::waf::ct_mismatch_hit`]).
    pub fn apply_ct_mismatch(&mut self, samples: &[Sample], expected_ct: &str) {
        let mut blocking = false;
        for sample in samples {
            let Some(hit) = waf::ct_mismatch_hit(expected_ct, &sample.headers) else {
                continue;
            };
            if !self.waf_hits.contains(&hit) {
                self.waf_hits.push(hit);
            }
            if waf::is_coroborating_status(sample.status) {
                blocking = true;
            }
        }
        if self.waf_hits.iter().any(|h| h.starts_with("ct-mismatch:")) {
            if self.waf_vendor.is_none() {
                self.waf_vendor = Some("generic".to_owned());
            }
            self.waf_blocking = self.waf_blocking || blocking;
        }
    }
}
