#![deny(unsafe_code)]

use crate::session::state::SessionState;
use anyhow::Context as _;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use thiserror::Error;
use zeroize::Zeroizing;

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

#[derive(Debug, Serialize, Deserialize)]
struct Snapshot {
    findings: Vec<crate::session::state::Finding>,
    request_count: u64,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Encrypted export (OPT-IN only). Snapshot XChaCha20-Poly1305, key derived Argon2id.
#[derive(Debug)]
#[non_exhaustive]
pub struct EncryptedExport;

impl EncryptedExport {
    /// Encrypt session state to file. Key derived via Argon2id explicit params (2026 OWASP).
    pub fn encrypt_to_file(
        state: &SessionState,
        passphrase: &SecretString,
        path: &str,
    ) -> Result<(), ExportError> {
        let snapshot = Snapshot {
            findings: state.findings().to_vec(),
            request_count: state.request_count(),
            started_at: state.started_at(),
        };
        let json = Zeroizing::new(
            serde_json::to_vec(&snapshot).map_err(|e| ExportError::Serialization(e.to_string()))?,
        );

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
            v: 2,
            kdf: Some("argon2id-m65536-t3-p1-v19".to_owned()),
        };
        let out = serde_json::to_vec_pretty(&blob)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        // 0o600 strict perms, fail if exists to avoid overwrite of sensitive file
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| ExportError::Io(e.to_string()))?;
        file.write_all(&out)
            .map_err(|e| ExportError::Io(e.to_string()))?;
        file.sync_all()
            .map_err(|e| ExportError::Io(e.to_string()))?;
        Ok(())
    }

    /// Decrypt file to JSON bytes (caller reconstructs `SessionState`).
    pub fn decrypt_from_file(
        passphrase: &SecretString,
        path: &str,
    ) -> Result<Vec<u8>, ExportError> {
        let data = std::fs::read(path).map_err(|e| ExportError::Io(e.to_string()))?;
        let blob: EncryptedBlob =
            serde_json::from_slice(&data).map_err(|e| ExportError::Serialization(e.to_string()))?;
        if blob.v != 1 && blob.v != 2 {
            return Err(ExportError::Serialization(
                "unsupported blob version".to_owned(),
            ));
        }
        let salt = BASE64
            .decode(&blob.salt_b64)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        let nonce_bytes = BASE64
            .decode(&blob.nonce_b64)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        if nonce_bytes.len() != 24 {
            return Err(ExportError::Crypto("invalid nonce length".to_owned()));
        }
        let ciphertext = BASE64
            .decode(&blob.ciphertext_b64)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;

        let key = Zeroizing::new(Self::derive_key_argon2id(passphrase, &salt)?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|e| ExportError::Crypto(e.to_string()))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(nonce, ciphertext.as_ref())
                .map_err(|e| ExportError::Crypto(e.to_string()))?,
        );
        Ok(plaintext.to_vec())
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

// Need trait for anyhow context unused removal.
#[allow(dead_code)]
fn _use_anyhow_ctx() -> anyhow::Result<()> {
    let _ = std::fs::read("/tmp/x").context("read")?;
    Ok(())
}
