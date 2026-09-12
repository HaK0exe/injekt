#![deny(unsafe_code)]

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Technique that produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TechniqueKind {
    Boolean,
    Time,
    Error,
    Union,
    Stacked,
    Oob,
    Json,
    Nosql,
}

impl core::fmt::Display for TechniqueKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Boolean => write!(f, "boolean"),
            Self::Time => write!(f, "time"),
            Self::Error => write!(f, "error"),
            Self::Union => write!(f, "union"),
            Self::Stacked => write!(f, "stacked"),
            Self::Oob => write!(f, "oob"),
            Self::Json => write!(f, "json"),
            Self::Nosql => write!(f, "nosql"),
        }
    }
}

/// Calibrated severity bucket for a finding (C7 intelligent reporting).
///
/// Buckets are assigned by [`crate::reporting::verdict::severity_for`] from
/// `(confidence, false_positive_prob)`; the bar is deliberately conservative
/// (both signals must agree) so the documented precision claims hold:
/// `High` → precision ≥ 95 %, `Medium` → precision ≥ 80 %.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Severity {
    High,
    Medium,
    #[default]
    Low,
}

impl core::fmt::Display for Severity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

/// Remediation guidance attached to a finding (C7).
///
/// `parameterized_example` is a *generic* code pattern (never the live
/// payload, never target data) showing how to fix the sink.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Remediation {
    pub summary: String,
    pub parameterized_example: String,
}

impl Remediation {
    /// Generic fix guidance per technique. Examples are dialect-agnostic
    /// placeholders (`?` bind variables) — no target-specific content.
    #[must_use]
    pub fn for_technique(technique: TechniqueKind) -> Self {
        let summary = match technique {
            TechniqueKind::Boolean
            | TechniqueKind::Time
            | TechniqueKind::Union
            | TechniqueKind::Stacked
            | TechniqueKind::Error => {
                "Use parameterized queries / prepared statements; never concatenate input into SQL. \
                 Enforce least-privilege DB accounts and validate input server-side."
                    .to_owned()
            }
            TechniqueKind::Json => {
                "Validate and schema-check JSON input before use; bind extracted values as \
                 parameters instead of interpolating them into SQL/JSON-path expressions."
                    .to_owned()
            }
            TechniqueKind::Nosql => {
                "Reject MongoDB operators ($gt/$ne/$where/...) in client input; enforce a \
                 strict allow-list schema (deny unknown keys starting with `$`), never pass \
                 raw JSON bodies to the driver."
                    .to_owned()
            }
            TechniqueKind::Oob => {
                "Block unexpected outbound DB traffic (egress filtering); use parameterized \
                 queries so injected subselects cannot exfiltrate via DNS/HTTP."
                    .to_owned()
            }
        };
        Self {
            summary,
            parameterized_example: "db.query(\"SELECT * FROM users WHERE id = ?\", [user_input])"
                .to_owned(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.summary.is_empty() && self.parameterized_example.is_empty()
    }
}

/// Structured evidence pointers (C7): hashes for traceability without leaking
/// secrets, a short human diff summary, and the reasoning-trace reference
/// (C6 `trace.rs`; `None` until the trace engine lands — field is reserved).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EvidenceDetail {
    #[serde(default)]
    pub hashes: Vec<String>,
    #[serde(default)]
    pub diff: Option<String>,
    #[serde(default)]
    pub trace_ref: Option<String>,
}

impl EvidenceDetail {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// WAF context observed for the finding (C7).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WafInfo {
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub blocking: bool,
}

impl WafInfo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// A single confirmed finding — kept in RAM only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Finding {
    pub target: String,
    pub parameter: String,
    pub technique: TechniqueKind,
    pub confidence: f64,
    /// Probability the finding is a false positive (`0.0` = certain true
    /// positive). Exposed for calibrated reporting (C7); defaults to
    /// `1.0 - confidence` when the detector only yields a score.
    #[serde(default = "default_false_positive_prob")]
    pub false_positive_prob: f64,
    /// Calibrated bucket (`high` → precision ≥ 95 %, `medium` → ≥ 80 %).
    /// Recomputed from `(confidence, false_positive_prob)` by
    /// [`Finding::normalize`]; renderers always recompute live via
    /// [`crate::reporting::verdict::severity_for`] so stale values from
    /// pre-C7 exports cannot inflate a report.
    #[serde(default)]
    pub severity: Severity,
    /// Fix guidance with a generic parameterized-query example.
    #[serde(default)]
    pub remediation: Remediation,
    /// Hashes / diff summary / reasoning-trace reference.
    #[serde(default)]
    pub evidence_detail: EvidenceDetail,
    /// WAF vendor observed + whether it was actively blocking.
    #[serde(default)]
    pub waf: WafInfo,
    pub dbms: Option<String>,
    pub evidence: String,
    pub timestamp: DateTime<Utc>,
}

fn default_false_positive_prob() -> f64 {
    1.0
}

impl Finding {
    #[must_use]
    pub fn new(
        target: impl Into<String>,
        parameter: impl Into<String>,
        technique: TechniqueKind,
        confidence: f64,
        evidence: impl Into<String>,
    ) -> Self {
        let confidence = confidence.clamp(0.0, 1.0);
        let false_positive_prob = (1.0 - confidence).clamp(0.0, 1.0);
        Self {
            target: target.into(),
            parameter: parameter.into(),
            technique,
            confidence,
            false_positive_prob,
            severity: crate::reporting::verdict::severity_for(confidence, false_positive_prob),
            remediation: Remediation::for_technique(technique),
            evidence_detail: EvidenceDetail::new(),
            waf: WafInfo::new(),
            dbms: None,
            evidence: evidence.into(),
            timestamp: Utc::now(),
        }
    }

    /// Override the false-positive probability (e.g. from
    /// [`crate::detection::confirmation::ConfirmationResult`]) and refresh
    /// the calibrated severity bucket.
    #[must_use]
    pub fn with_false_positive_prob(mut self, fp: f64) -> Self {
        self.false_positive_prob = fp.clamp(0.0, 1.0);
        self.severity =
            crate::reporting::verdict::severity_for(self.confidence, self.false_positive_prob);
        self
    }

    /// Attach WAF context observed during detection.
    #[must_use]
    pub fn with_waf(mut self, vendor: Option<String>, blocking: bool) -> Self {
        self.waf = WafInfo { vendor, blocking };
        self
    }

    /// Attach the reasoning-trace reference (C6 `trace.rs` record id / hash).
    /// Trace refs are opaque hashes — no secret content.
    #[must_use]
    pub fn with_trace_ref(mut self, trace_ref: impl Into<String>) -> Self {
        self.evidence_detail.trace_ref = Some(trace_ref.into());
        self
    }

    /// Attach a short human-readable diff summary (already scrubbed or
    /// secret-free at the call site; renderers scrub again).
    #[must_use]
    pub fn with_diff(mut self, diff: impl Into<String>) -> Self {
        self.evidence_detail.diff = Some(diff.into());
        self
    }

    /// Override the timestamp (primarily for deterministic golden-file tests).
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Recompute derived fields (`severity` from
    /// `(confidence, false_positive_prob)`, remediation fallback when empty).
    /// Called by [`SessionState::push_finding`] so findings built field-by-field
    /// (or deserialized from pre-C7 exports via `#[serde(default)]`) still
    /// carry a coherent verdict.
    pub fn normalize(&mut self) {
        self.confidence = self.confidence.clamp(0.0, 1.0);
        self.false_positive_prob = self.false_positive_prob.clamp(0.0, 1.0);
        self.severity =
            crate::reporting::verdict::severity_for(self.confidence, self.false_positive_prob);
        if self.remediation.is_empty() {
            self.remediation = Remediation::for_technique(self.technique);
        }
    }

    /// Live calibrated severity — always recomputed, never trusts the stored
    /// bucket (pre-C7 exports deserialize with `Low` default).
    #[must_use]
    pub fn live_severity(&self) -> Severity {
        crate::reporting::verdict::severity_for(self.confidence, self.false_positive_prob)
    }

    /// Scrubbed clone for reports / MCP output. `no_redact=true` is passthrough.
    #[must_use]
    pub fn scrubbed(&self, scrubber: &super::scrubber::Scrubber) -> Self {
        Self {
            target: scrubber.scrub(&self.target),
            parameter: scrubber.scrub(&self.parameter),
            technique: self.technique,
            confidence: self.confidence,
            false_positive_prob: self.false_positive_prob,
            severity: self.live_severity(),
            remediation: Remediation {
                summary: scrubber.scrub(&self.remediation.summary),
                parameterized_example: scrubber.scrub(&self.remediation.parameterized_example),
            },
            evidence_detail: EvidenceDetail {
                hashes: self
                    .evidence_detail
                    .hashes
                    .iter()
                    .map(|h| scrubber.scrub(h))
                    .collect(),
                diff: self
                    .evidence_detail
                    .diff
                    .as_deref()
                    .map(|d| scrubber.scrub(d)),
                trace_ref: self
                    .evidence_detail
                    .trace_ref
                    .as_deref()
                    .map(|t| scrubber.scrub(t)),
            },
            waf: WafInfo {
                vendor: self.waf.vendor.as_deref().map(|v| scrubber.scrub(v)),
                blocking: self.waf.blocking,
            },
            dbms: self.dbms.clone().map(|d| scrubber.scrub(&d)),
            evidence: scrubber.scrub(&self.evidence),
            timestamp: self.timestamp,
        }
    }
}

/// Per-run throttle detectability (C10, bench Annexe A): `403`/`429`
/// responses observed during the run. Fed by the orchestrator from the
/// [`crate::http::client::HttpClient`] counters at the end of each run;
/// surfaces in the JSON report so `run.py compare` can gate A3 `0×429 p95`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Detectability {
    #[serde(default)]
    pub count_403: u64,
    #[serde(default)]
    pub count_429: u64,
}

impl Detectability {
    #[must_use]
    pub const fn new(count_403: u64, count_429: u64) -> Self {
        Self {
            count_403,
            count_429,
        }
    }

    #[must_use]
    pub const fn total(self) -> u64 {
        self.count_403.saturating_add(self.count_429)
    }
}

/// Second-order candidate (Option A passive, 0 requête extra).
///
/// Marqueur bénin injecté via le chemin existant (union / stacked) et
/// potentiellement persisté côté serveur. Aucun revisit automatique :
/// l'opérateur vérifie manuellement sur la 2e page. Le marqueur reste
/// `SecretString` + `Zeroize`, la trace ne garde que des hashes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StoredProbe {
    /// Clé param `name@location` (ex: `user@body`), déjà scrubbed à l'affichage.
    pub store_param: String,
    /// Marqueur bénin jetable (ex: `u<8hex>`), jamais loggé en clair.
    pub marker: SecretString,
    /// `sha256 hex` de l'URL de stockage, pas l'URL claire en trace.
    pub store_url_hash: String,
}

impl StoredProbe {
    #[must_use]
    pub fn new(
        store_param: impl Into<String>,
        marker: SecretString,
        store_url_hash: impl Into<String>,
    ) -> Self {
        Self {
            store_param: store_param.into(),
            marker,
            store_url_hash: store_url_hash.into(),
        }
    }
}

impl Zeroize for StoredProbe {
    fn zeroize(&mut self) {
        self.store_param.zeroize();
        // `SecretString` zeroizes on drop; explicit wipe via replace.
        self.marker = SecretString::from(String::new());
        self.store_url_hash.zeroize();
    }
}

/// Session state — RAM only, zeroized on drop.
///
/// ```rust
/// use injekt::session::state::SessionState;
/// let mut s = SessionState::new();
/// s.increment_requests();
/// assert_eq!(s.request_count(), 1);
/// ```
#[derive(Debug, Default)]
pub struct SessionState {
    #[allow(dead_code)]
    findings: Vec<Finding>,
    // SecretString already zeroizes; we keep count and wipe on drop.
    extracted: Vec<SecretString>,
    /// Second-order candidates passifs (marqueurs stockés, 0 revisit auto).
    stored: Vec<StoredProbe>,
    request_count: u64,
    /// Throttle detectability (C10): `403`/`429` observed this run.
    detectability: Detectability,
    started_at: Option<DateTime<Utc>>,
    /// Reasoning trace (C6): hashes only, RAM-only, zeroized on drop.
    /// Never holds clear payload/body/cookie/token.
    trace: crate::reasoning::ReasoningTrace,
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
        self.seed = None;
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SessionState {}

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
            seed: self.seed,
        }
    }
}
