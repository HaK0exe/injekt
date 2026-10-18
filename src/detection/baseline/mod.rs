#![deny(unsafe_code)]

mod analysis;
mod model;
#[cfg(test)]
mod tests;

pub use model::{Baseline, Sample, collect_baseline};
