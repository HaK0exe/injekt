#![deny(unsafe_code)]

mod classify;
mod diff;
mod normalize;
mod similarity;
#[cfg(test)]
mod tests;

pub use classify::{
    DIFF_TOLERANCE, LOWER_RATIO_BOUND, PageSimilarity, UPPER_RATIO_BOUND, classify_page_similarity,
};
pub use diff::{DiffResult, diff_against_baseline};
pub use normalize::normalize_response_for_diff;
pub use similarity::{adaptive_similarity, jaccard, levenshtein_similarity};
