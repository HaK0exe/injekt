//! Detectability counters (C10, bench Annexe A): `403`/`406` and `429`.

use std::sync::atomic::Ordering;

use super::HttpClient;

impl HttpClient {
    pub(super) fn record_throttle(&self, status: u16) {
        // `406` counts with `403`: both are WAF deny/challenge codes in
        // `Baseline::WAF_BLOCK_STATUSES`; `429` stays separate (rate-limit).
        if status == 403 || status == 406 {
            self.throttle_403.fetch_add(1, Ordering::Relaxed);
        } else if status == 429 {
            self.throttle_429.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drain the per-run detectability counters as `(403, 429)` (C10, bench
    /// Annexe A `detectability`). Take-semantics (`swap(0)`) so the
    /// orchestrator absorbs each run exactly once, even when the client is
    /// reused across runs.
    #[must_use]
    pub fn take_detectability_counts(&self) -> (u64, u64) {
        (
            self.throttle_403.swap(0, Ordering::Relaxed),
            self.throttle_429.swap(0, Ordering::Relaxed),
        )
    }
}
