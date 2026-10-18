use super::{Detectability, Finding, StoredProbe};
use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Session state — RAM only, zeroized on drop.
///
/// ```rust
/// use injekt::session::state::SessionState;
/// let mut s = SessionState::new();
/// s.increment_requests();
/// assert_eq!(s.request_count(), 1);
/// ```
///
/// `Debug` is manual: `findings` render via the scrubbed [`Finding`] impl,
/// `extracted` (dump DB material) only ever shows a count — never values.
#[derive(Default)]
pub struct SessionState {
    #[allow(dead_code)]
    findings: Vec<Finding>,
    // SecretString already zeroizes; we keep count and wipe on drop.
    pub(super) extracted: Vec<SecretString>,
    /// Second-order candidates passifs (marqueurs stockés, 0 revisit auto).
    stored: Vec<StoredProbe>,
    request_count: u64,
    /// Throttle detectability (C10): `403`/`429` observed this run.
    detectability: Detectability,
    started_at: Option<DateTime<Utc>>,
    /// Reasoning trace (C6): hashes only, RAM-only, zeroized on drop.
    /// Never holds clear payload/body/cookie/token.
    trace: crate::reasoning::ReasoningTrace,
    /// Param keys (`id@query`) whose boolean probe hit the app signature
    /// filter (`400` streak ≥ `FILTER_STREAK_LIMIT`, A1-style). Drives the
    /// `--ai-suggest` trigger (post-échec uniquement). RAM-only, cleared on
    /// `wipe`/drop like the rest of the session.
    app_filter_hits: Vec<String>,
    /// Param keys (`id@query`) dont au moins une sonde a reçu `403`/`406`/`429`
    /// en phase détection (WAF/challenge/rate-limit live). Distinct de
    /// `app_filter_hits` (`400` applicatif) et des compteurs `detectability`
    /// absorbés en fin de run : mémorisé pour le trigger `--ai-suggest`.
    /// RAM-only, cleared on `wipe`/drop.
    waf_hits: Vec<String>,
    /// Param keys déjà couvertes par un passage `--ai-suggest` ce run
    /// (détection ou post-confirm). Un seul appel LLM par param : borne les
    /// coûts même en cas de triggers multiples. RAM-only, cleared on
    /// `wipe`/drop.
    ai_attempted: Vec<String>,
    /// Effective run seed (`--seed`), recorded for `--explain` / replay.
    /// `None` = historical OS-random behaviour.
    seed: Option<u64>,
}

impl Zeroize for SessionState {
    fn zeroize(&mut self) {
        for finding in &mut self.findings {
            finding.target.zeroize();
            finding.parameter.zeroize();
            finding.evidence.zeroize();
            finding.remediation.summary.zeroize();
            finding.remediation.parameterized_example.zeroize();
            for h in &mut finding.evidence_detail.hashes {
                h.zeroize();
            }
            if let Some(diff) = finding.evidence_detail.diff.as_mut() {
                diff.zeroize();
            }
            if let Some(trace_ref) = finding.evidence_detail.trace_ref.as_mut() {
                trace_ref.zeroize();
            }
            if let Some(vendor) = finding.waf.vendor.as_mut() {
                vendor.zeroize();
            }
            if let Some(dbms) = &mut finding.dbms {
                dbms.zeroize();
            }
        }
        self.findings.clear();
        self.extracted.zeroize();
        self.extracted.clear();
        for probe in &mut self.stored {
            probe.zeroize();
        }
        self.stored.clear();
        self.request_count.zeroize();
        self.detectability = Detectability::default();
        self.started_at = None;
        self.trace.zeroize();
        for hit in &mut self.app_filter_hits {
            hit.zeroize();
        }
        self.app_filter_hits.clear();
        for hit in &mut self.waf_hits {
            hit.zeroize();
        }
        self.waf_hits.clear();
        for hit in &mut self.ai_attempted {
            hit.zeroize();
        }
        self.ai_attempted.clear();
        self.seed = None;
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SessionState {}

// Manual `Debug`: findings use the scrubbed `Finding` impl; `extracted`
// (dumped DB rows) and `stored` markers only show counts — a `{:?}` dump of
// RAM must never carry secret material into logs.
impl core::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionState")
            .field("findings", &self.findings)
            .field("extracted_count", &self.extracted.len())
            .field("stored_count", &self.stored.len())
            .field("request_count", &self.request_count)
            .field("detectability", &self.detectability)
            .field("seed", &self.seed)
            .finish_non_exhaustive()
    }
}

impl SessionState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            extracted: Vec::new(),
            stored: Vec::new(),
            request_count: 0,
            detectability: Detectability::default(),
            started_at: Some(Utc::now()),
            trace: crate::reasoning::ReasoningTrace::new(),
            app_filter_hits: Vec::new(),
            waf_hits: Vec::new(),
            ai_attempted: Vec::new(),
            seed: None,
        }
    }

    /// Set the effective run seed (`--seed`) for `--explain` / replay.
    pub fn set_seed(&mut self, seed: Option<u64>) {
        self.seed = seed;
    }

    #[must_use]
    pub fn seed(&self) -> Option<u64> {
        self.seed
    }

    /// Append a reasoning-trace record (hashes only, never clear secrets).
    pub fn push_trace(&mut self, record: crate::reasoning::ProbeRecord) {
        self.trace.push(record);
    }

    /// Next trace sequence number.
    #[must_use]
    pub fn next_trace_seq(&self) -> u64 {
        self.trace.next_seq()
    }

    #[must_use]
    pub fn trace(&self) -> &crate::reasoning::ReasoningTrace {
        &self.trace
    }

    #[must_use]
    pub fn trace_mut(&mut self) -> &mut crate::reasoning::ReasoningTrace {
        &mut self.trace
    }

    /// One-line `--explain` verdict for `param_key` (`id@query`).
    /// Returns `None` when no finding matches (case-insensitive).
    #[must_use]
    pub fn explain(&self, param_key: &str) -> Option<String> {
        let wanted = param_key.trim().to_ascii_lowercase();
        let finding = self.findings.iter().find(|f| {
            f.parameter.to_ascii_lowercase() == wanted
                || f.parameter
                    .to_ascii_lowercase()
                    .ends_with(&format!("@{wanted}"))
        })?;
        Some(crate::reasoning::explain_line(
            &finding.evidence,
            finding.confidence,
            &finding.parameter,
            &self.trace,
            self.request_count,
            self.seed,
        ))
    }

    pub fn push_finding(&mut self, f: Finding) {
        let mut normalized = f;
        normalized.normalize();
        self.findings.push(normalized);
    }

    pub fn push_extracted(&mut self, s: SecretString) {
        self.extracted.push(s);
    }

    /// Track a stored second-order candidate (passive, 0 revisit auto).
    /// Bounded by caller (`max_stores`); hashes only in trace, never clair.
    pub fn push_stored(&mut self, probe: StoredProbe) {
        self.stored.push(probe);
    }

    #[must_use]
    pub fn stored(&self) -> &[StoredProbe] {
        &self.stored
    }

    #[must_use]
    pub fn stored_count(&self) -> usize {
        self.stored.len()
    }

    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    #[must_use]
    pub fn findings_mut(&mut self) -> &mut Vec<Finding> {
        &mut self.findings
    }

    /// Fill `None` dbms with guessed kind (e.g., from fingerprint).
    pub fn fill_missing_dbms(&mut self, kind: crate::dbms::DbmsKind) {
        if kind == crate::dbms::DbmsKind::Unknown {
            return;
        }
        let s = kind.to_string();
        for f in &mut self.findings {
            if f.dbms.is_none() {
                f.dbms = Some(s.clone());
            }
        }
    }

    #[must_use]
    pub fn extracted_count(&self) -> usize {
        self.extracted.len()
    }

    /// Returns cloned secrets — caller must handle sensitivity.
    #[must_use]
    pub fn extracted_exposed(&self) -> Vec<String> {
        self.extracted
            .iter()
            .map(|s| s.expose_secret().to_owned())
            .collect()
    }

    pub fn increment_requests(&mut self) {
        self.request_count = self.request_count.wrapping_add(1);
    }

    #[must_use]
    pub fn request_count(&self) -> u64 {
        self.request_count
    }

    /// Record one response status into the throttle detectability counters
    /// (C10): `403`/`429` only, everything else is a no-op.
    pub fn record_status(&mut self, status: u16) {
        if status == 403 {
            self.detectability.count_403 = self.detectability.count_403.saturating_add(1);
        } else if status == 429 {
            self.detectability.count_429 = self.detectability.count_429.saturating_add(1);
        }
    }

    /// Absorb drained [`crate::http::client::HttpClient`] counters at the end
    /// of a run (the client sees every hop, including responses consumed by a
    /// `429` retry that never reach a probe).
    pub fn add_detectability(&mut self, count_403: u64, count_429: u64) {
        self.detectability.count_403 = self.detectability.count_403.saturating_add(count_403);
        self.detectability.count_429 = self.detectability.count_429.saturating_add(count_429);
    }

    #[must_use]
    pub const fn detectability(&self) -> Detectability {
        self.detectability
    }

    /// Record that `param_key` (`id@query`) hit the app signature filter
    /// (boolean `400` streak pruned early). Bounded: one entry per param
    /// (deduped), set only from the boolean probe. Drives `--ai-suggest`.
    pub fn note_app_filter_hit(&mut self, param_key: &str) {
        if !self.app_filter_hits.iter().any(|k| k == param_key) {
            self.app_filter_hits.push(param_key.to_owned());
        }
    }

    /// `true` when `param_key` was pruned by the app signature filter.
    #[must_use]
    pub fn app_filter_hit(&self, param_key: &str) -> bool {
        self.app_filter_hits.iter().any(|k| k == param_key)
    }

    /// Record a live WAF/challenge/rate-limit hit (`403`/`406`/`429`) on a
    /// probe for `param_key`. Bounded: one entry per param (deduped).
    pub fn note_waf_hit(&mut self, param_key: &str) {
        if !self.waf_hits.iter().any(|k| k == param_key) {
            self.waf_hits.push(param_key.to_owned());
        }
    }

    /// `true` when `param_key` saw a live WAF hit during detection.
    #[must_use]
    pub fn waf_hit(&self, param_key: &str) -> bool {
        self.waf_hits.iter().any(|k| k == param_key)
    }

    /// Record an `--ai-suggest` pass for `param_key` (one LLM call max per
    /// param per run, detection + post-confirm sharing this lock).
    pub fn note_ai_attempted(&mut self, param_key: &str) {
        if !self.ai_attempted.iter().any(|k| k == param_key) {
            self.ai_attempted.push(param_key.to_owned());
        }
    }

    /// `true` when `param_key` already got its AI pass.
    #[must_use]
    pub fn has_ai_attempted(&self, param_key: &str) -> bool {
        self.ai_attempted.iter().any(|k| k == param_key)
    }

    #[must_use]
    pub fn started_at(&self) -> Option<DateTime<Utc>> {
        self.started_at
    }

    /// Wipe all sensitive data immediately.
    pub fn wipe(&mut self) {
        for finding in &mut self.findings {
            finding.target.zeroize();
            finding.parameter.zeroize();
            finding.evidence.zeroize();
            finding.remediation.summary.zeroize();
            finding.remediation.parameterized_example.zeroize();
            for h in &mut finding.evidence_detail.hashes {
                h.zeroize();
            }
            if let Some(diff) = finding.evidence_detail.diff.as_mut() {
                diff.zeroize();
            }
            if let Some(trace_ref) = finding.evidence_detail.trace_ref.as_mut() {
                trace_ref.zeroize();
            }
            if let Some(vendor) = finding.waf.vendor.as_mut() {
                vendor.zeroize();
            }
            if let Some(dbms) = &mut finding.dbms {
                dbms.zeroize();
            }
        }
        self.findings.clear();
        self.extracted.zeroize();
        self.extracted.clear();
        for probe in &mut self.stored {
            probe.zeroize();
        }
        self.stored.clear();
        self.request_count = 0;
        self.detectability = Detectability::default();
        self.trace.zeroize();
        for hit in &mut self.app_filter_hits {
            hit.zeroize();
        }
        self.app_filter_hits.clear();
        for hit in &mut self.waf_hits {
            hit.zeroize();
        }
        self.waf_hits.clear();
        for hit in &mut self.ai_attempted {
            hit.zeroize();
        }
        self.ai_attempted.clear();
        self.seed = None;
    }
}

// Manual Clone not derived because ZeroizeOnDrop + SecretString.
impl Clone for SessionState {
    fn clone(&self) -> Self {
        Self {
            findings: self.findings.clone(),
            extracted: self
                .extracted
                .iter()
                .map(|s| SecretString::from(s.expose_secret().to_owned()))
                .collect(),
            stored: self
                .stored
                .iter()
                .map(|p| {
                    StoredProbe::new(
                        p.store_param.clone(),
                        SecretString::from(p.marker.expose_secret().to_owned()),
                        p.store_url_hash.clone(),
                    )
                })
                .collect(),
            request_count: self.request_count,
            detectability: self.detectability,
            started_at: self.started_at,
            trace: self.trace.clone(),
            app_filter_hits: self.app_filter_hits.clone(),
            waf_hits: self.waf_hits.clone(),
            ai_attempted: self.ai_attempted.clone(),
            seed: self.seed,
        }
    }
}
