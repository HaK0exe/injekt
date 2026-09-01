#![deny(unsafe_code)]

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerificationResult {
    pub ok: bool,
    pub expected_len: usize,
    pub actual_len: usize,
    pub checksum_ok: bool,
}

#[must_use]
pub fn verify_length(expected: usize, actual: usize) -> VerificationResult {
    VerificationResult {
        ok: expected == actual,
        expected_len: expected,
        actual_len: actual,
        checksum_ok: expected == actual,
    }
}

#[must_use]
pub fn checksum(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    // Full SHA256 hex (64 chars); truncation was 32-bit weak — keep full for 2026 strength
    hex::encode(h.finalize())
}

#[must_use]
pub fn checksum_bytes(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[must_use]
pub fn verify_checksum(data: &str, expected_hex: &str) -> bool {
    checksum(data) == expected_hex
}

#[must_use]
pub fn checksum_truncated8(data: &str) -> String {
    checksum(data)[..8].to_owned()
}
