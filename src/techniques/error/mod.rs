#![deny(unsafe_code)]
pub mod detector;
pub mod payloads;
pub use detector::{
    ErrorDetector, ErrorResult, contains_xpath_keyword, is_payload_reflected, mask_reflected,
};
pub use payloads::{ErrorPayload, error_payloads_for};
