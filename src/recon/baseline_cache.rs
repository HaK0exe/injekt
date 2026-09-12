#![deny(unsafe_code)]

use crate::{
    detection::baseline::Baseline,
    engine::orchestrator::ProbeOpts,
    target::{raw_request::RawRequest, url::TargetUrl},
    techniques::tamper::Tamper,
};
use sha2::{Digest as _, Sha256};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, RwLock};

/// Tuple representing a cached baseline: (Baseline, effective tampers, effective probe opts).
pub type CachedBaselineEntry = (Baseline, Vec<Tamper>, ProbeOpts);

/// In-memory thread-safe cache for baseline responses keyed by origin.
///
/// Key is `host:port:scheme` when no raw request is present, otherwise
/// `host:port:scheme:raw_hash` where `raw_hash` covers method + headers
/// (excluding `host`/`content-length`) + body. The request path/query is
/// deliberately excluded so N candidates on the same host (same form, same
/// method) share one baseline sequence (10 candidates = 1 baseline = 3 req
/// instead of 30). Per-key async mutexes singleflight concurrent
/// `collect_baseline` calls for the same origin.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct BaselineCache {
    entries: Arc<RwLock<HashMap<String, CachedBaselineEntry>>>,
    key_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl BaselineCache {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            key_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Retrieve cached baseline entry for a cache key if present.
    pub async fn get(&self, host: &str) -> Option<CachedBaselineEntry> {
        let read_guard = self.entries.read().await;
        read_guard.get(host).cloned()
    }

    /// Store baseline entry for a cache key.
    pub async fn insert(&self, host: String, entry: CachedBaselineEntry) {
        let mut write_guard = self.entries.write().await;
        write_guard.insert(host, entry);
    }

    /// Number of cached keys.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Check if cache is empty.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    /// Per-key mutex singleflighting concurrent baseline collections.
    ///
    /// Same key shares the same mutex (created on first use); different keys
    /// collect in parallel. Callers hold the returned guard across the
    /// `get` → network → `insert` sequence and re-check `get` after
    /// acquiring it (another task may have filled the entry while waiting).
    pub async fn lock_for_key(&self, key: &str) -> Arc<Mutex<()>> {
        let mut guard = self.key_locks.lock().await;
        if let Some(existing) = guard.get(key) {
            return Arc::clone(existing);
        }
        let fresh = Arc::new(Mutex::new(()));
        guard.insert(key.to_owned(), Arc::clone(&fresh));
        fresh
    }

    /// Cache key for a target + optional raw request.
    ///
    /// `host:port:scheme` without raw, `host:port:scheme:raw_hash` with raw.
    /// Host is lowercased, port is explicit-or-default (`port_or_known_default`).
    #[must_use]
    pub fn cache_key(target: &TargetUrl, raw: Option<&RawRequest>) -> String {
        let url = target.inner();
        let host = url
            .host_str()
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        let port = url.port_or_known_default().unwrap_or(0);
        let scheme = url.scheme();
        if let Some(raw_request) = raw {
            let hash = Self::raw_hash(raw_request);
            format!("{host}:{port}:{scheme}:{hash}")
        } else {
            format!("{host}:{port}:{scheme}")
        }
    }

    /// Stable hash of the raw shape that affects baseline semantics.
    ///
    /// Covers uppercased method + sorted lowercased headers (excluding `host`
    /// and `content-length`, which are derived) + body. Path/query are
    /// excluded on purpose: candidates with different `?id=` values on the
    /// same host share the backend baseline.
    fn raw_hash(raw: &RawRequest) -> String {
        let mut canonical = String::new();
        canonical.push_str(&raw.method.to_ascii_uppercase());
        canonical.push('\n');
        let mut headers: Vec<(String, &str)> = Vec::new();
        for (name, value) in &raw.headers {
            let lowered = name.to_ascii_lowercase();
            if lowered == "host" || lowered == "content-length" {
                continue;
            }
            headers.push((lowered, value.as_str()));
        }
        headers.sort();
        for (name, value) in &headers {
            canonical.push_str(name);
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('\n');
        }
        canonical.push('\n');
        if let Some(body) = raw.body.as_deref() {
            canonical.push_str(body);
        }
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_baseline_cache_insert_and_get() {
        let cache = BaselineCache::new();
        assert!(cache.is_empty().await);

        let baseline = Baseline {
            status_codes: vec![200],
            body_hashes: vec!["hash1".to_owned()],
            body_lengths: vec![100],
            durations: vec![Duration::from_millis(50)],
            mean_ms: 50.0,
            stddev_ms: 0.0,
            representative_body: b"test".to_vec(),
            waf_vendor: None,
            waf_hits: Vec::new(),
            waf_blocking: false,
        };

        let entry = (baseline, vec![Tamper::Space2Comment], ProbeOpts::default());
        cache.insert("example.com".to_owned(), entry).await;

        assert_eq!(cache.len().await, 1);
        let retrieved = cache.get("example.com").await;
        assert!(retrieved.is_some());
        let (retrieved_baseline, tampers, _) = retrieved.unwrap();
        assert_eq!(retrieved_baseline.body_hashes[0], "hash1");
        assert_eq!(tampers.len(), 1);
    }
}
