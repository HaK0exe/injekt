#![deny(unsafe_code)]

use crate::session::state::SessionState;
use anyhow::Context as _;
use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

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
}

/// Encrypted export (OPT-IN only). Snapshot XChaCha20-Poly1305, key derived Argon2id.
#[derive(Debug)]
#[non_exhaustive]
pub struct EncryptedExport;

impl EncryptedExport {
    /// Encrypt session state to file. Key derived from passphrase via Argon2id.
    pub fn encrypt_to_file(
        state: &SessionState,
        passphrase: &SecretString,
        path: &str,
    ) -> Result<(), ExportError> {
        let json = serde_json::to_vec(state.findings())
            .map_err(|e| ExportError::Serialization(e.to_string()))?;

        let salt: [u8; 16] = rand::random();
        let key = Self::derive_key(passphrase, &salt)?;

        let cipher = XChaCha20Poly1305::new_from_slice(&key)
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
            v: 1,
        };
        let out = serde_json::to_vec_pretty(&blob)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        std::fs::write(path, out).map_err(|e| ExportError::Io(e.to_string()))?;
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
        let salt = BASE64
            .decode(&blob.salt_b64)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        let nonce_bytes = BASE64
            .decode(&blob.nonce_b64)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        let ciphertext = BASE64
            .decode(&blob.ciphertext_b64)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;

        let key = Self::derive_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| ExportError::Crypto(e.to_string()))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| ExportError::Crypto(e.to_string()))?;
        Ok(plaintext)
    }

    fn derive_key(passphrase: &SecretString, salt: &[u8]) -> Result<[u8; 32], ExportError> {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut key)
            .map_err(|e| ExportError::Crypto(e.to_string()))?;
        Ok(key)
    }

    /// Quick checksum helper for tests.
    #[must_use]
    pub fn checksum(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())[..8].to_owned()
    }
}

// Need trait for anyhow context unused removal.
#[allow(dead_code)]
fn _use_anyhow_ctx() -> anyhow::Result<()> {
    let _ = std::fs::read("/tmp/x").context("read")?;
    Ok(())
}
