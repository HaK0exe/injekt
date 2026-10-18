#![deny(unsafe_code)]

mod classify;
mod extract;
mod model;
mod rules;
#[cfg(test)]
mod tests;

pub use classify::{
    classify_cast_error, contains_xpath_keyword, is_aspnet_yellow_screen, is_payload_reflected,
    mask_reflected,
};
pub use model::{ErrorDetector, ErrorResult};
