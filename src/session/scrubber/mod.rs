#![deny(unsafe_code)]

mod headers;
mod oob;
mod patterns;
mod redact;
mod secrets;
#[cfg(test)]
mod tests;

pub use redact::Scrubber;
