#![deny(unsafe_code)]

use futures::StreamExt;
use tokio_util::sync::CancellationToken;

/// Config for bounded concurrency scanning.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ScanConfig {
    pub concurrency: usize,
    pub timeout_secs: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 5,
            timeout_secs: 15,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanTask {
    pub target: String,
    pub parameter: String,
    pub payload: String,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub task: ScanTask,
    pub success: bool,
    pub confidence: f64,
}

/// Bounded-concurrency engine.
///
/// Concurrency is bounded once, by `buffer_unordered` below. (A previous
/// revision also held a `Semaphore` permit per task — redundant double
/// bound, now removed.)
#[derive(Debug)]
pub struct ScanEngine {
    config: ScanConfig,
    cancel: CancellationToken,
}

impl ScanEngine {
    #[must_use]
    pub fn new(config: ScanConfig, cancel: CancellationToken) -> Self {
        // Clamp once and store: `buffer_unordered(0)` stalls forever, and an
        // unbounded value would spawn without bound. Stored clamped 1..=32.
        let clamped = ScanConfig {
            concurrency: config.concurrency.clamp(1, 32),
            timeout_secs: config.timeout_secs,
        };
        Self {
            config: clamped,
            cancel,
        }
    }

    pub async fn run<F, Fut>(&self, tasks: Vec<ScanTask>, f: F) -> Vec<ScanResult>
    where
        F: Fn(ScanTask) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = ScanResult> + Send + 'static,
    {
        let stream = futures::stream::iter(tasks)
            .map({
                let cancel = self.cancel.clone();
                let cfg_timeout = self.config.timeout_secs;
                move |t| {
                    let cancel = cancel.clone();
                    let f = f.clone();
                    async move {
                        if cancel.is_cancelled() {
                            return ScanResult {
                                task: t,
                                success: false,
                                confidence: 0.0,
                            };
                        }
                        // One clone is unavoidable: `t` moves into `f`'s
                        // future, but the timeout arm still needs it when
                        // that future is dropped on timeout. Timeouts are
                        // rare, success reuses the moved value via `r`.
                        let t_for_timeout = t.clone();
                        let fut = f(t);
                        tokio::select! {
                            () = cancel.cancelled() => ScanResult {
                                task: t_for_timeout,
                                success: false,
                                confidence: 0.0,
                            },
                            r = tokio::time::timeout(
                                std::time::Duration::from_secs(cfg_timeout),
                                fut,
                            ) => match r {
                                Ok(r) => r,
                                Err(_) => ScanResult {
                                    task: t_for_timeout,
                                    success: false,
                                    confidence: 0.0,
                                },
                            },
                        }
                    }
                }
            })
            .buffer_unordered(self.config.concurrency.clamp(1, 32));

        stream.collect::<Vec<_>>().await
    }
}
