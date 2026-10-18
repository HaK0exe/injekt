#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExportError {
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedBlob {
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
    v: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf: Option<String>,
}

/// `Debug` is manual: `findings` render via the scrubbed [`Finding`]
/// impl, `extracted` (dump DB rows) shows a count only — a `{:?}` of a
/// snapshot must never carry secret material into logs.
#[derive(Serialize, Deserialize)]
struct Snapshot {
    findings: Vec<crate::session::state::Finding>,
    /// Extracted DB data (banner, tables, dump rows, …) — the whole point of
    /// `--export-encrypted`; previously dropped on export, silently losing
    /// every `--dump`/`--banner`/`--current-user` result once the process exited.
    #[serde(default)]
    extracted: Vec<String>,
    request_count: u64,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Reasoning trace (C6): hashes only, never clear payload/body/secrets.
    /// `#[serde(default)]` keeps v1/v2 exports readable (empty trace).
    #[serde(default)]
    trace: Vec<crate::reasoning::ProbeRecord>,
    /// Effective run seed (`--seed`) for replay determinism.
    #[serde(default)]
    seed: Option<u64>,
}

impl Zeroize for Snapshot {
    fn zeroize(&mut self) {
        // Mirror `SessionState::zeroize`: wipe cleartext findings/extracted
        // clones before drop (the serialized `json` bytes are already
        // `Zeroizing`; this covers the transient struct itself).
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
        for s in &mut self.extracted {
            s.zeroize();
        }
        self.extracted.clear();
        self.trace.zeroize();
        self.trace.clear();
        self.request_count.zeroize();
        self.started_at = None;
        self.seed = None;
    }
}

impl core::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Snapshot")
            .field("findings", &self.findings)
            .field("extracted_count", &self.extracted.len())
            .field("request_count", &self.request_count)
            .field("trace_count", &self.trace.len())
            .field("seed", &self.seed)
            .finish_non_exhaustive()
    }
}

/// Current encrypted-export blob version (C6: trace + seed added).
/// Readers accept v1 (legacy), v2 (argon2id explicit) and v3 (trace).
/// v1.0-rc freeze: bump only with a migration test (legacy v1/v2 blobs must
/// still decrypt — see `legacy_v1_snapshot_still_deserializes`).
pub const EXPORT_BLOB_VERSION: u8 = 3;

/// Minimum passphrase length enforced by the library (the CLI also enforces
/// it interactively): a shorter passphrase derives a dictionary-breakable
/// key and a false sense of security. Enforced on encrypt only — decrypt
/// stays permissive so pre-guard blobs are never locked out (a wrong/short
/// passphrase simply fails authentication there).
pub const MIN_PASSPHRASE_LEN: usize = 12;

/// KDF identifier written by [`EncryptedExport::encrypt_to_file`].
/// `decrypt_from_file` accepts `None` (v1/v2 legacy) or exactly this value;
/// anything else is rejected instead of being silently ignored (no quiet
/// downgrade to weaker parameters).
pub const EXPORT_KDF_ID: &str = "argon2id-m65536-t3-p1-v19";

/// Salt length (bytes) written on encrypt; shorter salts are rejected on
/// decrypt (a short/empty salt collapses Argon2id strength).
pub const EXPORT_SALT_LEN: usize = 16;

/// Encrypted export (OPT-IN only). Snapshot XChaCha20-Poly1305, key derived Argon2id.
#[derive(Debug)]
#[non_exhaustive]
pub struct EncryptedExport;

mod crypto;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
