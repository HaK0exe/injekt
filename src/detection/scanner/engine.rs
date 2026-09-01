#![deny(unsafe_code)]

use futures::StreamExt;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// Config for bounded concurrency scanning.
#[derive(Debug, Clone)]
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
#[derive(Debug)]
pub struct ScanEngine {
    config: ScanConfig,
    semaphore: Arc<Semaphore>,
    cancel: CancellationToken,
}

impl ScanEngine {
    #[must_use]
    pub fn new(config: ScanConfig, cancel: CancellationToken) -> Self {
        let sem = Arc::new(Semaphore::new(config.concurrency.max(1)));
        Self {
            config,
            semaphore: sem,
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
                let sem = Arc::clone(&self.semaphore);
                let cancel = self.cancel.clone();
                let cfg_timeout = self.config.timeout_secs;
                move |t| {
                    let sem = Arc::clone(&sem);
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
                        let Ok(_permit) = sem.acquire().await else {
                            return ScanResult {
                                task: t,
                                success: false,
                                confidence: 0.0,
                            };
                        };
                        // enforce per-task timeout
                        let fut = f(t.clone());
                        match tokio::time::timeout(std::time::Duration::from_secs(cfg_timeout), fut)
                            .await
                        {
                            Ok(r) => r,
                            Err(_) => ScanResult {
                                task: t,
                                success: false,
                                confidence: 0.0,
                            },
                        }
                    }
                }
            })
            .buffer_unordered(self.config.concurrency);

        stream.collect::<Vec<_>>().await
    }
}
