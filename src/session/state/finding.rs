use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
    Transit,
    Orm,
    Graphql,
    Elasticsearch,
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
            Self::Transit => write!(f, "transit"),
            Self::Orm => write!(f, "orm"),
            Self::Graphql => write!(f, "graphql"),
            Self::Elasticsearch => write!(f, "elasticsearch"),
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
            TechniqueKind::Transit => {
                "Do not pass decoded client-controlled Transit/Clojure maps directly to \
                 HoneySQL or another query builder. Coerce expected scalar inputs before \
                 query construction, validate allow-listed keys/types, and reject unexpected \
                 serialized structures."
                    .to_owned()
            }
            TechniqueKind::Orm => {
                "Avoid raw query escape hatches in ORMs. Use parameterized APIs, validate \
                 and coerce identifiers, and never interpolate user input into ORM raw SQL."
                    .to_owned()
            }
            TechniqueKind::Graphql => {
                "Parameterize all GraphQL resolver database calls. Never interpolate \
                 arguments into raw SQL, and validate/sanitize GraphQL inputs server-side."
                    .to_owned()
            }
            TechniqueKind::Elasticsearch => {
                "Do not accept full Elasticsearch Query DSL from clients. Use fixed \
                 server-side queries, strict allow-lists, and validate all filters."
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
///
/// `Debug` is manual + scrubbed (see below): `target`/`parameter`/`evidence`
/// may carry `?token=` secrets or userinfo, so a derived `Debug` would leak
/// them into any `tracing::debug!("{finding:?}")`.
#[derive(Clone, Serialize, Deserialize)]
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

// Manual `Debug`: `target`/`parameter`/`evidence` are scrubbed (query secrets,
// userinfo, tokens) and evidence is truncated — `Debug` is for triage, full
// evidence lives in reports. Never `derive(Debug)` here.
impl core::fmt::Debug for Finding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let scrubber = crate::session::scrubber::Scrubber::new(false);
        let evidence: String = scrubber.scrub(&self.evidence).chars().take(256).collect();
        f.debug_struct("Finding")
            .field("target", &scrubber.scrub(&self.target))
            .field("parameter", &scrubber.scrub(&self.parameter))
            .field("technique", &self.technique)
            .field("confidence", &self.confidence)
            .field("false_positive_prob", &self.false_positive_prob)
            .field("severity", &self.severity)
            .field("dbms", &self.dbms)
            .field("evidence", &evidence)
            .field("evidence_hashes", &self.evidence_detail.hashes.len())
            .field("waf", &self.waf)
            .field("timestamp", &self.timestamp)
            .finish_non_exhaustive()
    }
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
    /// Called by [`crate::session::state::SessionState::push_finding`] so findings built field-by-field
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
    pub fn scrubbed(&self, scrubber: &crate::session::scrubber::Scrubber) -> Self {
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
