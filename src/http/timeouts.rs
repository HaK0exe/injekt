#![deny(unsafe_code)]

use std::time::Duration;

/// Latency class of a probe: selects the per-class timeout and, for
/// [`RequestClass::Time`], the isolated 2-slot pool (C10).
///
/// Mapping from detection technique is owned by the orchestrator
/// (`request_class_for`): `boolean → Boolean`, `time → Time`, `oob → Oob`,
/// everything else (`error`, `union`, `stacked`, `json`, baseline, context,
/// fingerprint) → `Default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RequestClass {
    /// Fast differentials (`boolean`): 10s.
    Boolean,
    /// Sleep-based probes (`time`): 15s + isolated pool.
    Time,
    /// Collaborator round-trips (`oob`): 30s (same as default).
    Oob,
    /// Everything else: the effective `--timeout` (default 30s).
    Default,
}

/// Concurrent `time`-class requests in flight (C10): slow `pg_sleep` probes
/// queue on these 2 permits instead of saturating the `buffer_unordered`
/// slots, so `boolean`/`error` probes (which never touch the semaphore)
/// keep flowing.
pub const TIME_POOL_SLOTS: usize = 2;

/// Per-class timeouts (C10): `boolean` 10s, `time` 15s, `oob` 30s,
/// default 30s (= effective `--timeout`).
pub const BOOLEAN_TIMEOUT: Duration = Duration::from_secs(10);
pub const TIME_TIMEOUT: Duration = Duration::from_secs(15);
pub const OOB_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-class timeout set derived from the effective `--timeout` base.
///
/// `boolean`/`time` are capped at their class ceiling (`10s`/`15s`) so a
/// slow `time` probe can never park a slot for the full default, while
/// `oob` keeps the full base (collaborator lag is operator infrastructure,
/// not target latency). A base below a ceiling (e.g. `--timeout 5`) applies
/// as-is: the operator's explicit bound always wins downwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClassTimeouts {
    pub boolean: Duration,
    pub time: Duration,
    pub oob: Duration,
    pub default: Duration,
}

impl ClassTimeouts {
    #[must_use]
    pub fn from_default(default: Duration) -> Self {
        Self {
            boolean: default.min(BOOLEAN_TIMEOUT),
            time: default.min(TIME_TIMEOUT),
            oob: default,
            default,
        }
    }

    #[must_use]
    pub const fn for_class(self, class: RequestClass) -> Duration {
        match class {
            RequestClass::Boolean => self.boolean,
            RequestClass::Time => self.time,
            RequestClass::Oob => self.oob,
            RequestClass::Default => self.default,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_base_yields_spec_values() {
        let t = ClassTimeouts::from_default(Duration::from_secs(30));
        assert_eq!(t.for_class(RequestClass::Boolean), Duration::from_secs(10));
        assert_eq!(t.for_class(RequestClass::Time), Duration::from_secs(15));
        assert_eq!(t.for_class(RequestClass::Oob), Duration::from_secs(30));
        assert_eq!(t.for_class(RequestClass::Default), Duration::from_secs(30));
    }

    #[test]
    fn small_base_wins_downwards() {
        let t = ClassTimeouts::from_default(Duration::from_secs(5));
        assert_eq!(t.for_class(RequestClass::Boolean), Duration::from_secs(5));
        assert_eq!(t.for_class(RequestClass::Time), Duration::from_secs(5));
        assert_eq!(t.for_class(RequestClass::Oob), Duration::from_secs(5));
        assert_eq!(t.for_class(RequestClass::Default), Duration::from_secs(5));
    }

    #[test]
    fn quick_profile_base_keeps_time_ceiling() {
        let t = ClassTimeouts::from_default(Duration::from_secs(15));
        assert_eq!(t.for_class(RequestClass::Boolean), Duration::from_secs(10));
        assert_eq!(t.for_class(RequestClass::Time), Duration::from_secs(15));
    }
}
