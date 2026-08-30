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
    hex::encode(h.finalize())[..8].to_owned()
}

#[must_use]
pub fn verify_checksum(data: &str, expected_hex: &str) -> bool {
    checksum(data) == expected_hex
}
