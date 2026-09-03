#![deny(unsafe_code)]

use crate::{
    engine::orchestrator::{Engine, EngineConfig},
    error::Result,
    http::client::HttpClient,
    reporting::bulk::{BULK_REPORT_VERSION, BulkReport, BulkTargetResult},
    session::scrubber::Scrubber,
};
use tokio_util::sync::CancellationToken;

/// Scan several targets one after another.
///
/// Sequential on purpose: intra-target detection already uses bounded
/// `buffer_unordered(threads)`, so inter-target parallelism would only
/// multiply load and mix signals. A fresh [`Engine`] + [`HttpClient`] is
/// built per target, which guarantees `CookieJar` / `RateLimiter` isolation
/// between targets. A per-target error (including client build failure) is
/// recorded in the report and the loop continues; a cancelled token stops
/// the loop early.
pub async fn run_bulk(
    targets: Vec<String>,
    cfg: &EngineConfig,
    build_client: impl Fn() -> Result<HttpClient>,
    cancel: &CancellationToken,
    scrubber: &Scrubber,
) -> BulkReport {
    let mut report = BulkReport::empty(targets.len());
    for target in &targets {
        if cancel.is_cancelled() {
            tracing::info!("bulk scan cancelled, stopping early");
            break;
        }
        tracing::info!(target=%scrubber.scrub(target), "bulk scan target start");
        // Fresh client + engine per target = isolation (cookies, rate limit).
        let client = match build_client() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(target=%scrubber.scrub(target), error=%e, "bulk client build failed");
                report.targets_failed += 1;
                report.per_target.push(BulkTargetResult::failed(
                    target.clone(),
                    0,
                    format!("client build: {e}"),
                ));
                continue;
            }
        };
        let engine = Engine::new(cfg.clone(), client, cancel.clone());
        match engine.run(target).await {
            Ok(_) => {
                let handle = engine.state_handle();
                let state = handle.read().await;
                let findings = state.findings().to_vec();
                let request_count = state.request_count();
                drop(state);
                report.targets_ok += 1;
                report.request_count_total = report.request_count_total.wrapping_add(request_count);
                report.per_target.push(BulkTargetResult::ok(
                    target.clone(),
                    findings,
                    request_count,
                ));
            }
            Err(e) => {
                let request_count = engine.state_handle().read().await.request_count();
                tracing::warn!(target=%scrubber.scrub(target), error=%e, "bulk target failed");
                report.targets_failed += 1;
                report.request_count_total = report.request_count_total.wrapping_add(request_count);
                report.per_target.push(BulkTargetResult::failed(
                    target.clone(),
                    request_count,
                    e.to_string(),
                ));
            }
        }
    }
    report.version = BULK_REPORT_VERSION;
    report
}
