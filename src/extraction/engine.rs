#![deny(unsafe_code)]

use crate::error::InjektError;
use crate::extraction::InferenceExtractor;
use crate::extraction::verification::{checksum, verify_length};
use futures::StreamExt;
use secrecy::SecretString;

const MAX_LEN: usize = 4096;

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

    /// Fallible oracle with retry + majority vote.
    async fn oracle_with_retry<F, Fut>(
        oracle: &F,
        pos: usize,
        guess: u8,
        max_retries: usize,
    ) -> Result<bool, InjektError>
    where
        F: Fn(usize, u8) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<bool, InjektError>> + Send + 'static,
    {
        let mut votes = 0usize;
        for _ in 0..max_retries {
            match oracle(pos, guess).await {
                Ok(true) => votes += 1,
                Ok(false) => {}
                Err(e) => return Err(e),
            }
        }
        // Majority vote: true if > half retries returned true
        Ok(votes > max_retries / 2)
    }

    /// Binary search extraction with bounded parallelism (`buffer_unordered`).
    /// `oracle` is async `Fn(position, mid) -> Result<bool, InjektError>` where `bool = (actual >= mid)`.
    /// Uses upper-mid logic for 7 req/char worst-case, with per-probe timeout via caller.
    /// Returns `Result<SecretString, InjektError>` with length cap and retry majority vote.
    ///
    /// # Errors
    /// Returns an error if `len` exceeds `MAX_LEN`, or the `oracle` itself errors.
    pub async fn extract<F, Fut>(&self, len: usize, oracle: F) -> Result<SecretString, InjektError>
    where
        F: Fn(usize, u8) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<bool, InjektError>> + Send + 'static,
    {
        if len == 0 {
            return Ok(SecretString::from(String::new()));
        }
        if len > MAX_LEN {
            return Err(InjektError::Extraction(format!(
                "extraction length {len} exceeds MAX_LEN {MAX_LEN}"
            )));
        }
        let mut results = vec![' '; len];

        let tasks: Vec<usize> = (0..len).collect();
        let concurrency = self.config.concurrency.max(1);
        let max_retries = self.config.max_retries.max(1);
        let oracle_clone = oracle.clone();

        let stream = futures::stream::iter(tasks)
            .map(move |pos| {
                let oracle = oracle_clone.clone();
                async move {
                    let _extractor = InferenceExtractor::new();
                    let mut low: u8 = 32;
                    let mut high: u8 = 126;
                    while low < high {
                        #[allow(clippy::manual_div_ceil)]
                        let mid = low + (high - low + 1) / 2;
                        let ge = Self::oracle_with_retry(&oracle, pos, mid, max_retries).await?;
                        if ge {
                            low = mid;
                        } else {
                            high = mid - 1;
                        }
                    }
                    // Consistency check: actual must be exactly low
                    let ge_low = Self::oracle_with_retry(&oracle, pos, low, max_retries).await?;
                    if !ge_low {
                        return Err(InjektError::Extraction(format!(
                            "inference inconsistency at pos {pos}: actual < low ({low})"
                        )));
                    }
                    if low < 126 {
                        let ge_next =
                            Self::oracle_with_retry(&oracle, pos, low + 1, max_retries).await?;
                        if ge_next {
                            return Err(InjektError::Extraction(format!(
                                "inference inconsistency at pos {pos}: actual >= low+1"
                            )));
                        }
                    }
                    Ok::<(usize, char), InjektError>((pos, low as char))
                }
            })
            .buffer_unordered(concurrency);

        let collected: Vec<Result<(usize, char), InjektError>> = stream.collect().await;
        for res in collected {
            let (pos, c) = res?;
            if pos < results.len() {
                results[pos] = c;
            }
        }
        let s: String = results.into_iter().collect();
        let v = verify_length(len, s.len());
        if !v.ok {
            return Err(InjektError::Extraction(format!(
                "length mismatch in extraction: expected {len}, got {}",
                s.len()
            )));
        }
        let _cs = checksum(&s);
        Ok(SecretString::from(s))
    }
}
