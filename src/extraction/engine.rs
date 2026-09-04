#![deny(unsafe_code)]

use crate::error::InjektError;
use crate::extraction::verification::verify_length;
use futures::StreamExt;
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

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

    /// Fallible oracle with retry + majority vote, cancellable via `select!`.
    /// A fired `cancel` aborts the pending probe and returns
    /// [`InjektError::Cancelled`] — never converted into a `bool` vote.
    /// Probe errors are abstentions (no vote, next retry), not aborts: a
    /// single WAF hiccup must not kill the whole extraction. Majority is
    /// computed over cast votes; all-error returns the last error.
    async fn oracle_with_retry<F, Fut>(
        oracle: &F,
        pos: usize,
        guess: u8,
        max_retries: usize,
        cancel: &CancellationToken,
    ) -> Result<bool, InjektError>
    where
        F: Fn(usize, u8) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<bool, InjektError>> + Send + 'static,
    {
        if cancel.is_cancelled() {
            return Err(InjektError::Cancelled);
        }
        let mut votes_true = 0usize;
        let mut votes_cast = 0usize;
        let mut last_err: Option<InjektError> = None;
        for _ in 0..max_retries.max(1) {
            if cancel.is_cancelled() {
                return Err(InjektError::Cancelled);
            }
            // Official tokio pattern: race the probe against cancellation.
            let probe = tokio::select! {
                () = cancel.cancelled() => return Err(InjektError::Cancelled),
                r = oracle(pos, guess) => r,
            };
            match probe {
                Ok(true) => {
                    votes_true += 1;
                    votes_cast += 1;
                }
                Ok(false) => {
                    votes_cast += 1;
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        if votes_cast == 0 {
            return Err(last_err.unwrap_or_else(|| {
                InjektError::Extraction(format!("oracle unavailable at pos {pos}"))
            }));
        }
        // Majority vote over cast votes.
        Ok(votes_true * 2 > votes_cast)
    }

    /// Binary search extraction with bounded parallelism (`buffer_unordered`).
    /// `oracle` is async `Fn(position, mid) -> Result<bool, InjektError>` where `bool = (actual >= mid)`.
    /// Uses upper-mid logic for 7 req/char worst-case, with per-probe timeout via caller.
    /// Returns `Result<SecretString, InjektError>` with length cap and retry majority vote.
    ///
    /// Cancellation is checked per char/position: a fired `cancel` aborts
    /// pending probes via `tokio::select!` and the whole collect, returning
    /// [`InjektError::Cancelled`].
    ///
    /// # Errors
    /// Returns an error if `len` exceeds `MAX_LEN`, the run is cancelled,
    /// or the `oracle` itself errors.
    pub async fn extract<F, Fut>(
        &self,
        len: usize,
        oracle: F,
        cancel: &CancellationToken,
    ) -> Result<SecretString, InjektError>
    where
        F: Fn(usize, u8) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<bool, InjektError>> + Send + 'static,
    {
        if cancel.is_cancelled() {
            return Err(InjektError::Cancelled);
        }
        if len == 0 {
            return Ok(SecretString::from(String::new()));
        }
        if len > MAX_LEN {
            return Err(InjektError::Extraction(format!(
                "extraction length {len} exceeds MAX_LEN {MAX_LEN}"
            )));
        }
        let mut results = vec![' '; len];

        let concurrency = self.config.concurrency.clamp(1, 32);
        let max_retries = self.config.max_retries.max(1);
        let oracle_clone = oracle.clone();

        // Range streamed directly: no intermediate `Vec<usize>` alloc.
        let stream = futures::stream::iter(0..len)
            .map(move |pos| {
                let oracle = oracle_clone.clone();
                let cancel = cancel.clone();
                async move {
                    if cancel.is_cancelled() {
                        return Err::<(usize, char), InjektError>(InjektError::Cancelled);
                    }
                    let mut low: u8 = 32;
                    let mut high: u8 = 126;
                    while low < high {
                        if cancel.is_cancelled() {
                            return Err(InjektError::Cancelled);
                        }
                        #[allow(clippy::manual_div_ceil)]
                        let mid = low + (high - low + 1) / 2;
                        let ge = Self::oracle_with_retry(&oracle, pos, mid, max_retries, &cancel)
                            .await?;
                        if ge {
                            low = mid;
                        } else {
                            high = mid - 1;
                        }
                    }
                    // Consistency check: actual must be exactly low
                    let ge_low =
                        Self::oracle_with_retry(&oracle, pos, low, max_retries, &cancel).await?;
                    if !ge_low {
                        return Err(InjektError::Extraction(format!(
                            "inference inconsistency at pos {pos}: actual < low ({low})"
                        )));
                    }
                    if low < 126 {
                        let ge_next =
                            Self::oracle_with_retry(&oracle, pos, low + 1, max_retries, &cancel)
                                .await?;
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

        // Race the whole collect against cancellation so Ctrl+C does not wait
        // for straggler positions to finish their retries.
        let collected: Vec<Result<(usize, char), InjektError>> = tokio::select! {
            () = cancel.cancelled() => return Err(InjektError::Cancelled),
            c = stream.collect() => c,
        };
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
        Ok(SecretString::from(s))
    }
}
