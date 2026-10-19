//! XChaCha20-Poly1305 blob engine for `EncryptedExport` (P5 split):
//! Argon2id KDF, encrypt/decrypt file entry points and SHA-256 checksum
//! helpers over the snapshot/blob formats.

use super::{
    EXPORT_BLOB_VERSION, EXPORT_KDF_ID, EXPORT_SALT_LEN, EncryptedBlob, EncryptedExport,
    ExportError, MIN_PASSPHRASE_LEN, Snapshot,
};
use crate::session::state::SessionState;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use zeroize::{Zeroize, Zeroizing};

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
        // digest 0.11: `Nonce::from_slice` deprecated — const-array `From` impl
        // is the preferred constructor (length checked at compile time).
        let nonce = XNonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, json.as_ref())
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
        // digest 0.11: `Nonce::from_slice` deprecated — `TryInto<[u8; 24]>` is
        // the replacement and enforces the exact 24-byte nonce length itself.
        let nonce_arr: [u8; 24] = nonce_bytes
            .try_into()
            .map_err(|_| ExportError::Crypto("invalid nonce length".to_owned()))?;
        let ciphertext = BASE64
            .decode(&blob.ciphertext_b64)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        if ciphertext.is_empty() {
            return Err(ExportError::Crypto("empty ciphertext".to_owned()));
        }

        let key = Zeroizing::new(Self::derive_key_argon2id(passphrase, &salt)?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|e| ExportError::Crypto(e.to_string()))?;
        let nonce = XNonce::from(nonce_arr);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(&nonce, ciphertext.as_ref())
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
