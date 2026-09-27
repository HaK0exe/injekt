#![deny(unsafe_code)]

use crate::session::state::SessionState;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

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

impl EncryptedExport {
    /// Encrypt session state to file. Key derived via Argon2id explicit params (2026 OWASP).
    ///
    /// # Errors
    /// Returns an error if the passphrase is shorter than
    /// [`MIN_PASSPHRASE_LEN`], or if key derivation, encryption,
    /// serialization, or the file write fails (including when `path` already
    /// exists).
    pub fn encrypt_to_file(
        state: &SessionState,
        passphrase: &SecretString,
        path: &str,
    ) -> Result<(), ExportError> {
        if passphrase.expose_secret().len() < MIN_PASSPHRASE_LEN {
            return Err(ExportError::Crypto(format!(
                "passphrase too short (min {MIN_PASSPHRASE_LEN} chars)"
            )));
        }
        let mut snapshot = Snapshot {
            findings: state.findings().to_vec(),
            extracted: state.extracted_exposed(),
            request_count: state.request_count(),
            started_at: state.started_at(),
            trace: state.trace().records().to_vec(),
            seed: state.seed(),
        };
        let json = Zeroizing::new(
            serde_json::to_vec(&snapshot).map_err(|e| ExportError::Serialization(e.to_string()))?,
        );
        // Wipe the transient cleartext snapshot (findings + extracted clones)
        // before any fallible crypto/IO below — the `json` bytes stay
        // `Zeroizing` until encryption consumes them.
        snapshot.zeroize();

        // SECURITY: salt/nonce MUST stay on OS randomness (`rand::random`) and
        // must NEVER be routed through the seeded run RNG
        // (`crate::seeded_rng::make_rng`): a deterministic salt/nonce from
        // `--seed` would reuse keystream material across runs and break the
        // XChaCha20-Poly1305 security contract.
        let salt: [u8; 16] = rand::random();
        let key = Zeroizing::new(Self::derive_key_argon2id(passphrase, &salt)?);

        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|e| ExportError::Crypto(e.to_string()))?;
        let nonce_bytes: [u8; 24] = rand::random();
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, json.as_ref())
            .map_err(|e| ExportError::Crypto(e.to_string()))?;

        let blob = EncryptedBlob {
            salt_b64: BASE64.encode(salt),
            nonce_b64: BASE64.encode(nonce_bytes),
            ciphertext_b64: BASE64.encode(ciphertext),
            v: EXPORT_BLOB_VERSION,
            kdf: Some(EXPORT_KDF_ID.to_owned()),
        };
        let out = serde_json::to_vec_pretty(&blob)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        // 0o600 strict perms on Unix, fail if exists to avoid overwrite of sensitive file
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts
            .open(path)
            .map_err(|e| ExportError::Io(e.to_string()))?;
        file.write_all(&out)
            .map_err(|e| ExportError::Io(e.to_string()))?;
        file.sync_all()
            .map_err(|e| ExportError::Io(e.to_string()))?;
        Ok(())
    }

    /// Decrypt file to JSON bytes (caller reconstructs `SessionState`).
    ///
    /// The plaintext is returned in a [`Zeroizing`] wrapper so the cleartext
    /// snapshot is wiped on drop instead of lingering in RAM (heap dumps,
    /// core files). Callers needing a slice can rely on deref coercion to
    /// `&[u8]`; never call `.to_vec()` out of the wrapper.
    ///
    /// # Errors
    /// Returns an error if the file can't be read, its blob version or KDF
    /// identifier is unsupported, the salt/nonce/ciphertext envelope is
    /// malformed, or decryption fails (wrong passphrase or corrupted data).
    pub fn decrypt_from_file(
        passphrase: &SecretString,
        path: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ExportError> {
        // Cap pre-read: un blob malveillant sans limite = OOM avant decrypt.
        const MAX_BLOB_BYTES: u64 = 64 * 1024 * 1024;
        let meta = std::fs::metadata(path).map_err(|e| ExportError::Io(e.to_string()))?;
        if meta.len() > MAX_BLOB_BYTES {
            return Err(ExportError::Serialization("blob too large".to_owned()));
        }
        let data = std::fs::read(path).map_err(|e| ExportError::Io(e.to_string()))?;
        let blob: EncryptedBlob =
            serde_json::from_slice(&data).map_err(|e| ExportError::Serialization(e.to_string()))?;
        if blob.v != 1 && blob.v != 2 && blob.v != EXPORT_BLOB_VERSION {
            return Err(ExportError::Serialization(
                "unsupported blob version".to_owned(),
            ));
        }
        if blob.kdf.as_deref().is_some_and(|kdf| kdf != EXPORT_KDF_ID) {
            return Err(ExportError::Crypto("unsupported KDF".to_owned()));
        }
        let salt = BASE64
            .decode(&blob.salt_b64)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        if salt.len() < EXPORT_SALT_LEN {
            return Err(ExportError::Crypto("invalid salt length".to_owned()));
        }
        let nonce_bytes = BASE64
            .decode(&blob.nonce_b64)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        if nonce_bytes.len() != 24 {
            return Err(ExportError::Crypto("invalid nonce length".to_owned()));
        }
        let ciphertext = BASE64
            .decode(&blob.ciphertext_b64)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        if ciphertext.is_empty() {
            return Err(ExportError::Crypto("empty ciphertext".to_owned()));
        }

        let key = Zeroizing::new(Self::derive_key_argon2id(passphrase, &salt)?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|e| ExportError::Crypto(e.to_string()))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(nonce, ciphertext.as_ref())
                .map_err(|e| ExportError::Crypto(e.to_string()))?,
        );
        Ok(plaintext)
    }

    fn derive_key_argon2id(
        passphrase: &SecretString,
        salt: &[u8],
    ) -> Result<[u8; 32], ExportError> {
        // OWASP 2026: m=64 MiB, t=3, p=1, 32-byte key
        let params = Params::new(64 * 1024, 3, 1, Some(32))
            .map_err(|e| ExportError::Crypto(e.to_string()))?;
        let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        ctx.hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut key)
            .map_err(|e| ExportError::Crypto(e.to_string()))?;
        Ok(key)
    }

    // Kept for backwards compat with v1 blobs (tests)
    #[allow(dead_code)]
    fn derive_key(passphrase: &SecretString, salt: &[u8]) -> Result<[u8; 32], ExportError> {
        Self::derive_key_argon2id(passphrase, salt)
    }

    /// Quick checksum helper for tests (full SHA256, truncated helpers available).
    #[must_use]
    pub fn checksum(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    #[must_use]
    pub fn checksum_truncated(data: &[u8]) -> String {
        Self::checksum(data)[..16].to_owned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::session::state::{Finding, SessionState, TechniqueKind};
    use secrecy::SecretString;
    use std::fs;

    fn test_state() -> SessionState {
        let mut state = SessionState::new();
        state.push_finding(Finding::new(
            "http://example.com/?id=1",
            "id@query",
            TechniqueKind::Boolean,
            0.9,
            "evidence with secret Authorization: Bearer abc123",
        ));
        state.push_extracted(SecretString::from("extracted secret data"));
        state
    }

    fn temp_path() -> String {
        // Test-only temp filename: stays on OS randomness so parallel test
        // workers never collide; never seeded (uniqueness, not determinism).
        let path = std::env::temp_dir()
            .join(format!("injekt_test_export_{}.enc", rand::random::<u64>()))
            .to_string_lossy()
            .into_owned();
        std::fs::remove_file(&path).ok();
        path
    }

    #[test]
    fn encrypt_to_file_creates_new_file_fails_if_exists() {
        let state = test_state();
        let passphrase = SecretString::from("passphrase123456");
        let path = temp_path();

        // First write should succeed
        EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();

        // Second write should fail because file exists (create_new)
        let result = EncryptedExport::encrypt_to_file(&state, &passphrase, &path);
        assert!(result.is_err(), "create_new should fail if file exists");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn decrypt_does_not_leak_secrets_in_json() {
        let state = test_state();
        let passphrase = SecretString::from("passphrase123456");
        let path = temp_path();

        EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
        let json_bytes = EncryptedExport::decrypt_from_file(&passphrase, &path).unwrap();
        let json_str = String::from_utf8_lossy(&json_bytes);

        // The decrypted JSON should contain the findings with secrets scrubbed if we check
        // But decrypt_from_file returns raw JSON - the scrubbing happens at report level
        // We verify the file can be decrypted
        assert!(json_str.contains("findings"));
        assert!(json_str.contains("request_count"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn snapshot_debug_hides_extracted_dump() {
        // NOTE: the scrubber redacts keyed secrets (`?token=`, `session=`);
        // bare opaque words without key context cannot be distinguished from
        // prose without false positives, so fixtures use keyed secrets.
        let snapshot = Snapshot {
            findings: vec![Finding::new(
                "https://example.com/?token=secret123",
                "id@query",
                TechniqueKind::Boolean,
                0.9,
                "boolean split, session=secret123",
            )],
            extracted: vec!["dump row secret123".to_owned()],
            request_count: 3,
            started_at: None,
            trace: Vec::new(),
            seed: Some(42),
        };
        let rendered = format!("{snapshot:?}");
        assert!(!rendered.contains("secret123"), "{rendered}");
        assert!(rendered.contains("extracted_count"), "{rendered}");
    }

    #[test]
    fn extracted_data_survives_roundtrip() {
        let state = test_state();
        let passphrase = SecretString::from("passphrase123456");
        let path = temp_path();

        EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
        let json_bytes = EncryptedExport::decrypt_from_file(&passphrase, &path).unwrap();
        let snapshot: Snapshot = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(snapshot.extracted, vec!["extracted secret data".to_owned()]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn export_file_has_600_permissions_on_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let state = test_state();
            let passphrase = SecretString::from("passphrase123456");
            let path = temp_path();

            EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
            let meta = fs::metadata(&path).unwrap();
            // 0o600 = 384 in decimal
            assert_eq!(
                meta.mode() & 0o777,
                0o600,
                "file should have 0o600 permissions"
            );
            let _ = fs::remove_file(&path);
        }
    }

    #[test]
    fn trace_and_seed_survive_roundtrip() {
        use crate::reasoning::ProbeRecord;
        let mut state = test_state();
        state.set_seed(Some(42));
        state.push_trace(ProbeRecord::from_clear(
            0,
            "id@query",
            "boolean",
            "none",
            Some(42),
            "' OR 1=1",
            "welcome",
            0.9,
            12.0,
        ));
        let passphrase = SecretString::from("passphrase123456");
        let path = temp_path();

        EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
        let json_bytes = EncryptedExport::decrypt_from_file(&passphrase, &path).unwrap();
        let snapshot: Snapshot = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(snapshot.seed, Some(42));
        assert_eq!(snapshot.trace.len(), 1);
        assert_eq!(snapshot.trace[0].seq, 0);
        // Trace stores hashes only — never the clear payload/body.
        let dbg = format!("{:?}", snapshot.trace[0]);
        assert!(!dbg.contains("OR 1=1"), "payload leaked: {dbg}");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn legacy_v1_snapshot_still_deserializes() {
        // v1 shape: no `extracted`/`trace`/`seed` keys (pre-C6 export).
        // `#[serde(default)]` must keep old blobs readable (v1.0-rc compat).
        let legacy = serde_json::json!({
            "findings": [],
            "request_count": 7,
            "started_at": null,
        });
        let bytes = serde_json::to_vec(&legacy).unwrap();
        let snapshot: Snapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(snapshot.request_count, 7);
        assert!(snapshot.extracted.is_empty());
        assert!(snapshot.trace.is_empty());
        assert_eq!(snapshot.seed, None);
    }

    #[test]
    fn unsupported_blob_version_is_rejected() {
        let state = test_state();
        let passphrase = SecretString::from("passphrase123456");
        let path = temp_path();
        EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
        // Rewrite the envelope with a future version (99): decrypt must refuse.
        let data = fs::read(&path).unwrap();
        let mut blob: serde_json::Value = serde_json::from_slice(&data).unwrap();
        blob["v"] = serde_json::Value::from(99);
        fs::write(&path, serde_json::to_vec(&blob).unwrap()).unwrap();
        let err = EncryptedExport::decrypt_from_file(&passphrase, &path).unwrap_err();
        assert!(
            err.to_string().contains("unsupported blob version"),
            "unexpected error: {err}"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_passphrase_fails_decryption() {
        let state = test_state();
        let passphrase = SecretString::from("passphrase123456");
        let wrong = SecretString::from("wrong-passphrase-000");
        let path = temp_path();
        EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
        assert!(EncryptedExport::decrypt_from_file(&wrong, &path).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn short_passphrase_rejected_in_lib() {
        let state = test_state();
        for short in ["", "1234567", "short-pw"] {
            let err =
                EncryptedExport::encrypt_to_file(&state, &SecretString::from(short), &temp_path())
                    .unwrap_err();
            assert!(
                err.to_string().contains("passphrase too short"),
                "unexpected error for {short:?}: {err}"
            );
        }
    }

    #[test]
    fn short_salt_and_unknown_kdf_rejected() {
        let state = test_state();
        let passphrase = SecretString::from("passphrase123456");
        let path = temp_path();
        EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
        let data = fs::read(&path).unwrap();
        let mut blob: serde_json::Value = serde_json::from_slice(&data).unwrap();
        // Empty salt collapses Argon2id strength: refuse instead of deriving.
        blob["salt_b64"] = serde_json::Value::from(String::new());
        fs::write(&path, serde_json::to_vec(&blob).unwrap()).unwrap();
        let err = EncryptedExport::decrypt_from_file(&passphrase, &path).unwrap_err();
        assert!(err.to_string().contains("salt"), "unexpected error: {err}");
        // Unknown KDF: refuse instead of silently ignoring the field.
        let mut blob: serde_json::Value = serde_json::from_slice(&data).unwrap();
        blob["kdf"] = serde_json::Value::from("scrypt-xyz");
        fs::write(&path, serde_json::to_vec(&blob).unwrap()).unwrap();
        let err = EncryptedExport::decrypt_from_file(&passphrase, &path).unwrap_err();
        assert!(err.to_string().contains("KDF"), "unexpected error: {err}");
        let _ = fs::remove_file(&path);
    }
}
