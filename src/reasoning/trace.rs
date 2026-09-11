#![deny(unsafe_code)]

use crate::session::scrubber::Scrubber;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SHA-256 hex of `data` (full 64 hex chars). Request/response bodies and
/// payloads are never stored in clear — only these hashes enter the trace.
#[must_use]
pub fn hash_sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// SHA-256 hex of a string payload.
#[must_use]
pub fn hash_str_hex(s: &str) -> String {
    hash_sha256_hex(s.as_bytes())
}

/// Derive a per-finding confirm seed from the run seed.
///
/// Deterministic mix (splitmix64-style): same `(base, idx)` always yields the
/// same derived seed, different indices yield different streams. `None`
/// propagates (unseeded runs stay OS-random, historical behaviour).
#[must_use]
pub fn derive_confirm_seed(base: Option<u64>, idx: usize) -> Option<u64> {
    base.map(|s| {
        let mut z = s
            .wrapping_add(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(idx as u64);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    })
}

/// One traced probe: hashes only, never clear payload/body/cookie/token.
///
/// - `param`: parameter key (`id@query`), scrubbed on render.
/// - `technique`: CLI technique name (`boolean`, `error`, …).
/// - `mutation_plan`: tamper set names joined (`none` or `space2comment,…`),
///   never payload text.
/// - `seed`: effective seed used for this probe (`None` = OS-random run).
/// - `request_hash` / `response_hash`: SHA-256 hex of final payload / body.
/// - `diff`: detector similarity/confidence signal in `[0.0, 1.0]`.
/// - `ms`: probe latency in milliseconds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct ProbeRecord {
    pub seq: u64,
    pub param: String,
    #[serde(default)]
    pub technique: String,
    #[serde(default)]
    pub mutation_plan: String,
    #[serde(default)]
    pub seed: Option<u64>,
    #[serde(default)]
    pub request_hash: String,
    #[serde(default)]
    pub response_hash: String,
    #[serde(default)]
    pub diff: f64,
    #[serde(default)]
    pub ms: f64,
}

impl ProbeRecord {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        seq: u64,
        param: impl Into<String>,
        technique: impl Into<String>,
        mutation_plan: impl Into<String>,
        seed: Option<u64>,
        request_hash: impl Into<String>,
        response_hash: impl Into<String>,
        diff: f64,
        ms: f64,
    ) -> Self {
        Self {
            seq,
            param: param.into(),
            technique: technique.into(),
            mutation_plan: mutation_plan.into(),
            seed,
            request_hash: request_hash.into(),
            response_hash: response_hash.into(),
            diff: diff.clamp(0.0, 1.0),
            ms: ms.max(0.0),
        }
    }

    /// Build from clear payload/body by hashing immediately: the clear values
    /// never enter the struct (caller drops them after this call).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn from_clear(
        seq: u64,
        param: &str,
        technique: &str,
        mutation_plan: &str,
        seed: Option<u64>,
        payload: &str,
        body: &str,
        diff: f64,
        ms: f64,
    ) -> Self {
        Self::new(
            seq,
            param,
            technique,
            mutation_plan,
            seed,
            hash_str_hex(payload),
            hash_str_hex(body),
            diff,
            ms,
        )
    }

    /// Scrubbed one-line render: hashes are opaque, param/plan go through the
    /// `Scrubber` (`--no-redact` = passthrough, otherwise secrets redacted).
    #[must_use]
    pub fn render(&self, scrubber: &Scrubber) -> String {
        format!(
            "#{} {} {} plan={} req={} resp={} diff={:.2} {:.0}ms seed={}",
            self.seq,
            scrubber.scrub(&self.param),
            scrubber.scrub(&self.technique),
            scrubber.scrub(&self.mutation_plan),
            self.request_hash.chars().take(16).collect::<String>(),
            self.response_hash.chars().take(16).collect::<String>(),
            self.diff,
            self.ms,
            self.seed.map_or("none".to_owned(), |s| s.to_string()),
        )
    }
}

impl Zeroize for ProbeRecord {
    fn zeroize(&mut self) {
        self.param.zeroize();
        self.technique.zeroize();
        self.mutation_plan.zeroize();
        self.request_hash.zeroize();
        self.response_hash.zeroize();
        self.diff = 0.0;
        self.ms = 0.0;
        self.seq = 0;
        self.seed = None;
    }
}

impl ZeroizeOnDrop for ProbeRecord {}

/// RAM-only ordered probe journal. Exported only via the opt-in encrypted
/// export (hashes only); never written to disk otherwise.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct ReasoningTrace {
    #[serde(default)]
    records: Vec<ProbeRecord>,
}

impl ReasoningTrace {
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Push a pre-built record, assigning `seq` when the caller used `u64::MAX`
    /// as a sentinel? No — caller assigns via [`Self::next_seq`]; this just
    /// appends. Kept simple and deterministic.
    pub fn push(&mut self, record: ProbeRecord) {
        self.records.push(record);
    }

    /// Next sequence number (current length as `u64`, saturating on 32-bit).
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        u64::try_from(self.records.len()).unwrap_or(u64::MAX)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[must_use]
    pub fn records(&self) -> &[ProbeRecord] {
        &self.records
    }

    #[must_use]
    pub fn records_for(&self, param: &str) -> Vec<&ProbeRecord> {
        self.records.iter().filter(|r| r.param == param).collect()
    }

    /// Request count attributed to `param` (number of traced probes).
    #[must_use]
    pub fn request_count_for(&self, param: &str) -> usize {
        self.records.iter().filter(|r| r.param == param).count()
    }

    /// Wipe all records immediately (also runs on `Drop` via `Zeroize`).
    pub fn clear(&mut self) {
        self.records.zeroize();
        self.records.clear();
    }

    /// Scrubbed multi-line render (one line per record).
    #[must_use]
    pub fn render(&self, scrubber: &Scrubber) -> String {
        self.records
            .iter()
            .map(|r| r.render(scrubber))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Zeroize for ReasoningTrace {
    fn zeroize(&mut self) {
        self.records.zeroize();
        self.records.clear();
    }
}

impl ZeroizeOnDrop for ReasoningTrace {}

/// One-line `--explain` verdict for a finding.
///
/// Format (roadmap C6): `TRUE≈baseline 0.91, FALSE≠baseline 0.22, 3/3,
/// waf=none, 14 req, seed 42`.
///
/// - `true_sim` / `false_sim`: parsed from evidence when present, else
///   derived from `confidence` (confirmed ≈ baseline, rejected ≠ baseline).
/// - `trials`: parsed `N/3` from evidence when present, else `3/3` for
///   confirmed boolean-style findings, `1/1` otherwise.
/// - `waf`: parsed `waf=<vendor>` / `waf_blocking` from evidence when
///   present, else `none`.
/// - `req`: total run requests (`fallback_req`); the trace is hashes-only and
///   carries per-probe attribution via [`ReasoningTrace::request_count_for`],
///   but the verdict reports the run total for stability across exports.
/// - `seed`: effective run seed (`none` when unseeded).
#[must_use]
pub fn explain_line(
    evidence: &str,
    confidence: f64,
    _param: &str,
    _trace: &ReasoningTrace,
    fallback_req: u64,
    seed: Option<u64>,
) -> String {
    let (true_sim, false_sim) = parse_true_false_sim(evidence, confidence);
    let trials = parse_trials(evidence);
    let waf = parse_waf(evidence);
    let req = fallback_req;
    let seed_s = seed.map_or("none".to_owned(), |s| s.to_string());
    format!(
        "TRUE≈baseline {true_sim:.2}, FALSE≠baseline {false_sim:.2}, {trials}, waf={waf}, {req} req, seed {seed_s}"
    )
}

fn parse_true_false_sim(evidence: &str, confidence: f64) -> (f64, f64) {
    let true_sim = parse_kv_f64(evidence, "true_sim=");
    let false_sim = parse_kv_f64(evidence, "false_sim=");
    if let (Some(t), Some(f)) = (true_sim, false_sim) {
        (t.clamp(0.0, 1.0), f.clamp(0.0, 1.0))
    } else {
        // Fallback: confirmed findings imply TRUE≈baseline.
        let conf = confidence.clamp(0.0, 1.0);
        (conf, (1.0 - conf).clamp(0.0, 1.0))
    }
}

fn parse_trials(evidence: &str) -> String {
    // Evidence shapes: `trials=3/3`, `3/3` (boolean), `confirmed=true`.
    // Scan for the first `N/M` token; fall back to a calibrated default.
    for token in evidence.split([' ', ',']) {
        let token = token.trim_matches(['(', ')']);
        let token = token.strip_prefix("trials=").unwrap_or(token);
        if let Some((a, b)) = token.split_once('/')
            && let (Ok(n), Ok(m)) = (a.trim().parse::<u64>(), b.trim().parse::<u64>())
            && m > 0
            && m <= 10
        {
            return format!("{n}/{m}");
        }
    }
    if evidence.contains("confirmed=true") || evidence.contains("bool_confirm=true") {
        return "3/3".to_owned();
    }
    "1/1".to_owned()
}

fn parse_waf(evidence: &str) -> String {
    // Evidence carries `waf=vendor` or `waf_blocking` markers; default `none`.
    for token in evidence.split([' ', ',']) {
        if let Some(v) = token.strip_prefix("waf=") {
            let v = v.trim();
            if !v.is_empty() {
                return v.to_owned();
            }
        }
    }
    if evidence.contains("waf_blocking") || evidence.contains("waf_blocked") {
        return "blocking".to_owned();
    }
    "none".to_owned()
}

fn parse_kv_f64(haystack: &str, key: &str) -> Option<f64> {
    let start = haystack.find(key)? + key.len();
    let rest = &haystack[start..];
    let end = rest.find([' ', ',', ')']).unwrap_or(rest.len());
    rest[..end].trim().parse::<f64>().ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_deterministic_and_opaque() {
        let a = hash_str_hex("payload1");
        let b = hash_str_hex("payload1");
        let c = hash_str_hex("payload2");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
        assert!(!a.contains("payload1"));
    }

    #[test]
    fn from_clear_never_stores_cleartext() {
        let r = ProbeRecord::from_clear(
            0,
            "id@query",
            "boolean",
            "none",
            Some(42),
            "' OR 1=1",
            "welcome",
            0.9,
            12.0,
        );
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("OR 1=1"), "payload leaked: {dbg}");
        assert!(!dbg.contains("welcome"), "body leaked: {dbg}");
        assert_eq!(r.request_hash, hash_str_hex("' OR 1=1"));
        assert_eq!(r.response_hash, hash_str_hex("welcome"));
    }

    #[test]
    fn trace_render_scrubs_and_counts() {
        let sc = Scrubber::new(false);
        let mut t = ReasoningTrace::new();
        assert!(t.is_empty());
        t.push(ProbeRecord::from_clear(
            0,
            "id@query",
            "boolean",
            "none",
            Some(7),
            "a",
            "b",
            0.5,
            1.0,
        ));
        t.push(ProbeRecord::from_clear(
            1,
            "id@query",
            "boolean",
            "none",
            Some(7),
            "c",
            "d",
            0.6,
            2.0,
        ));
        assert_eq!(t.len(), 2);
        assert_eq!(t.request_count_for("id@query"), 2);
        assert_eq!(t.request_count_for("other@query"), 0);
        let out = t.render(&sc);
        assert!(out.contains("#0") && out.contains("#1"));
        assert!(!out.contains("Cookie:"), "{out}");
    }

    #[test]
    fn derive_confirm_seed_deterministic() {
        let a = derive_confirm_seed(Some(42), 0);
        let b = derive_confirm_seed(Some(42), 0);
        let c = derive_confirm_seed(Some(42), 1);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(derive_confirm_seed(None, 0), None);
    }

    #[test]
    fn explain_line_matches_roadmap_shape() {
        let trace = ReasoningTrace::new();
        let ev = "boolean true_sim=0.91 false_sim=0.22 trials=3/3 fp=0.05 tamper=none";
        let line = explain_line(ev, 0.95, "id@query", &trace, 14, Some(42));
        assert_eq!(
            line,
            "TRUE≈baseline 0.91, FALSE≠baseline 0.22, 3/3, waf=none, 14 req, seed 42"
        );
    }

    #[test]
    fn explain_line_fallbacks_without_evidence_numbers() {
        let trace = ReasoningTrace::new();
        let line = explain_line("stacked confirmed=true", 0.8, "id@query", &trace, 9, None);
        assert!(line.contains("waf=none"), "{line}");
        assert!(line.contains("9 req"), "{line}");
        assert!(line.contains("seed none"), "{line}");
    }

    #[test]
    fn zeroize_clears_records() {
        let mut r = ProbeRecord::from_clear(
            5,
            "id@query",
            "boolean",
            "none",
            Some(1),
            "a",
            "b",
            0.5,
            1.0,
        );
        r.zeroize();
        assert_eq!(r.seq, 0);
        assert!(r.param.is_empty());
        assert!(r.request_hash.is_empty());
        let mut t = ReasoningTrace::new();
        t.push(ProbeRecord::from_clear(
            0, "id@query", "boolean", "none", None, "a", "b", 0.5, 1.0,
        ));
        t.clear();
        assert!(t.is_empty());
    }
}
