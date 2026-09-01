#![deny(unsafe_code)]

use crate::extraction::verification::{checksum, verify_length};
use futures::StreamExt;
use secrecy::SecretString;

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
    /// `oracle` is async `Fn(position, mid) -> bool` where `bool = (actual >= mid)`.
    /// Uses upper-mid logic for 7 req/char worst-case, with per-probe timeout via caller.
    pub async fn extract<F, Fut>(&self, len: usize, oracle: F) -> SecretString
    where
        F: Fn(usize, u8) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = bool> + Send + 'static,
    {
        if len == 0 {
            return SecretString::from(String::new());
        }
        let mut results = vec![' '; len];

        let tasks: Vec<usize> = (0..len).collect();
        let stream = futures::stream::iter(tasks)
            .map({
                let oracle = oracle.clone();
                move |pos| {
                    let oracle = oracle.clone();
                    async move {
                        let mut low: u8 = 32;
                        let mut high: u8 = 126;
                        while low < high {
                            #[allow(clippy::manual_div_ceil)]
                            let mid = low + (high - low + 1) / 2;
                            let ge = oracle(pos, mid).await;
                            if ge {
                                low = mid;
                            } else {
                                // high >=1 checked via loop invariant
                                high = mid - 1;
                            }
                        }
                        (pos, low as char)
                    }
                }
            })
            .buffer_unordered(self.config.concurrency);

        let collected: Vec<(usize, char)> = stream.collect().await;
        for (pos, c) in collected {
            if pos < results.len() {
                results[pos] = c;
            }
        }
        let s: String = results.into_iter().collect();
        let v = verify_length(len, s.len());
        if !v.ok {
            tracing::warn!(
                expected = len,
                actual = s.len(),
                "length mismatch in extraction"
            );
        }
        let _cs = checksum(&s);
        SecretString::from(s)
    }

    /// Extraction with fallible oracle `Result<bool, E>` plus timeout handling.
    pub async fn extract_fallible<F, Fut, E>(
        &self,
        len: usize,
        oracle: F,
    ) -> Result<SecretString, E>
    where
        F: Fn(usize, u8) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<bool, E>> + Send + 'static,
        E: Send + 'static,
    {
        if len == 0 {
            return Ok(SecretString::from(String::new()));
        }
        let mut results = vec![' '; len];
        let tasks: Vec<usize> = (0..len).collect();
        let stream = futures::stream::iter(tasks)
            .map({
                let oracle = oracle.clone();
                move |pos| {
                    let oracle = oracle.clone();
                    async move {
                        let mut low: u8 = 32;
                        let mut high: u8 = 126;
                        while low < high {
                            #[allow(clippy::manual_div_ceil)]
                            let mid = low + (high - low + 1) / 2;
                            let ge = oracle(pos, mid).await?;
                            if ge {
                                low = mid;
                            } else {
                                high = mid - 1;
                            }
                        }
                        Ok::<(usize, char), E>((pos, low as char))
                    }
                }
            })
            .buffer_unordered(self.config.concurrency);

        let collected: Vec<Result<(usize, char), E>> = stream.collect().await;
        for res in collected {
            let (pos, c) = res?;
            if pos < results.len() {
                results[pos] = c;
            }
        }
        let s: String = results.into_iter().collect();
        Ok(SecretString::from(s))
    }
}
