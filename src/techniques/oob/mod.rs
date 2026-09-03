#![deny(unsafe_code)]
pub mod detector;
pub mod payloads;
pub mod verifier;
pub use detector::{OobDetector, OobResult, contains_oob_error};
pub use payloads::{
    OobChannel, OobPayload, build_subdomain, chunk_for_dns, encode_for_dns, encode_oob_payload,
    is_valid_oob_domain, new_token, oob_exfil_payloads_for, oob_payloads_for, sanitize_dns_label,
};
pub use verifier::{HttpPollVerifier, InMemoryVerifier, NoopVerifier, OobVerifier};
