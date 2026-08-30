#![deny(unsafe_code)]
#![allow(clippy::expect_used)]

use crate::extraction::{
    inference::InferenceExtractor,
    verification::{checksum, verify_length},
};
use futures::StreamExt;
use secrecy::SecretString;
use std::sync::Arc;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExtractionConfig {
    pub concurrency: usize,
    pub max_retries: usize,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            concurrency: 5,
            max_retries: 3,
        }
    }
}

#[derive(Debug)]
pub struct ExtractionEngine {
    config: ExtractionConfig,
}

impl ExtractionEngine {
    #[must_use]
    pub fn new(config: ExtractionConfig) -> Self {
        Self { config }
    }

    /// Binary search extraction with bounded parallelism (`buffer_unordered`).
    /// `oracle` is async Fn(position, mid) -> bool where bool = (actual >= mid)
    pub async fn extract<F, Fut>(&self, len: usize, oracle: F) -> SecretString
    where
        F: Fn(usize, u8) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = bool> + Send + 'static,
    {
        let extractor = Arc::new(InferenceExtractor::new());
        let mut results = vec![' '; len];

        // Build tasks per position char binary search sequentially per char but parallel across positions using buffer_unordered
        let tasks: Vec<usize> = (0..len).collect();
        let stream = futures::stream::iter(tasks)
            .map({
                let extractor = Arc::clone(&extractor);
                let oracle = oracle.clone();
                move |pos| {
                    let oracle = oracle.clone();
                    let _extractor = Arc::clone(&extractor);
                    async move {
                        // binary search for this position
                        let mut low = 32u8;
                        let mut high = 126u8;
                        let mut retries = 0usize;
                        while low < high {
                            let mid = low + (high - low) / 2;
                            let ge = oracle(pos, mid).await;
                            if ge {
                                low = mid + 1;
                                if low > 126 {
                                    low = 126;
                                    break;
                                }
                            } else {
                                high = mid;
                            }
                            if high - low <= 1 {
                                break;
                            }
                            retries += 1;
                            if retries > 20 {
                                break;
                            }
                        }
                        let c = low.clamp(32, 126) as char;
                        (pos, c)
                    }
                }
            })
            .buffer_unordered(self.config.concurrency);

        let collected: Vec<(usize, char)> = stream.collect().await;
        for (pos, c) in collected {
            results[pos] = c;
        }
        let s: String = results.into_iter().collect();
        // verification: length + checksum
        let v = verify_length(len, s.len());
        debug_assert!(v.ok, "length mismatch");
        let _cs = checksum(&s);
        SecretString::from(s)
    }
}
