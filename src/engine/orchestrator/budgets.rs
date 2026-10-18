//! Request/duration budget and detection-deadline tests
//! (ex `orchestrator_gating_tests`, P5 split).

#[test]
fn budget_request_budget_defaults_to_none_and_helper() {
    // CODE calibration: default None = unlimited, byte-identical.
    // A1 evasion (~1032 req live) must never trip a default cap.
    let cfg = super::BudgetConfig::default();
    assert_eq!(cfg.request_budget, None);
    assert!(!super::BudgetConfig::is_over_request_budget(0, None));
    assert!(!super::BudgetConfig::is_over_request_budget(10_000, None));
    // Zero budget trips immediately (early-break path, cooperative stop).
    assert!(super::BudgetConfig::is_over_request_budget(0, Some(0)));
    assert!(super::BudgetConfig::is_over_request_budget(11, Some(0)));
    // Boundary: `>=` trips exactly at the cap, never before.
    assert!(!super::BudgetConfig::is_over_request_budget(24, Some(25)));
    assert!(super::BudgetConfig::is_over_request_budget(25, Some(25)));
    assert!(super::BudgetConfig::is_over_request_budget(666, Some(25)));
    assert!(!super::BudgetConfig::is_over_request_budget(
        1031,
        Some(1032)
    ));
    assert!(super::BudgetConfig::is_over_request_budget(
        1032,
        Some(1032)
    ));
}

#[test]
fn budget_max_duration_defaults_to_none_and_helper() {
    // Phase 3: default None = unlimited, byte-identical.
    let cfg = super::BudgetConfig::default();
    assert_eq!(cfg.max_duration_secs, None);
    let now = std::time::Instant::now();
    assert!(!super::BudgetConfig::is_over_max_duration(now, None));
    // Zero budget trips immediately (early-break path).
    assert!(super::BudgetConfig::is_over_max_duration(now, Some(0)));
    // Future start + generous budget does not trip.
    assert!(!super::BudgetConfig::is_over_max_duration(now, Some(3600)));
    // Past start beyond budget trips.
    let past = now
        .checked_sub(std::time::Duration::from_secs(10))
        .unwrap_or(now);
    assert!(super::BudgetConfig::is_over_max_duration(past, Some(5)));
    assert!(!super::BudgetConfig::is_over_max_duration(past, Some(60)));
}

#[test]
fn detection_deadline_none_is_unlimited_noop() {
    // `None` (default) = no deadline: mid-technique checks no-op,
    // detection byte-identical.
    let now = std::time::Instant::now();
    assert_eq!(super::BudgetConfig::detection_deadline(now, None), None);
    assert!(!super::BudgetConfig::is_past_deadline(None));
}

#[test]
fn detection_deadline_trips_after_budget() {
    use super::BudgetConfig;
    let now = std::time::Instant::now();
    // Zero budget: deadline is (about) now, already past.
    let zero = BudgetConfig::detection_deadline(now, Some(0)).expect("deadline");
    assert!(BudgetConfig::is_past_deadline(Some(zero)));
    // Generous budget: future deadline, not past.
    let far = BudgetConfig::detection_deadline(now, Some(3600)).expect("deadline");
    assert!(!BudgetConfig::is_past_deadline(Some(far)));
    // Past start beyond budget: deadline already behind us.
    let past = now
        .checked_sub(std::time::Duration::from_secs(10))
        .unwrap_or(now);
    let blown = BudgetConfig::detection_deadline(past, Some(5)).expect("deadline");
    assert!(BudgetConfig::is_past_deadline(Some(blown)));
}

#[test]
fn detection_deadline_clamps_huge_values_without_silent_unlimited() {
    // PR20: `u64::MAX` used to make `checked_add` return `None`,
    // conflated with "unlimited". Now clamped to the 24h cap: always a
    // real (future) deadline, never a silent fail-open.
    use super::{BudgetConfig, MAX_DETECTION_DURATION_SECS_CAP};
    assert_eq!(MAX_DETECTION_DURATION_SECS_CAP, 86_400);
    let now = std::time::Instant::now();
    let clamped = BudgetConfig::detection_deadline(now, Some(u64::MAX)).expect("clamped deadline");
    assert!(!BudgetConfig::is_past_deadline(Some(clamped)));
    // The clamp equals the capped input (idempotent).
    let at_cap = BudgetConfig::detection_deadline(now, Some(86_400)).expect("cap deadline");
    assert!(!BudgetConfig::is_past_deadline(Some(at_cap)));
    // `is_over_max_duration` never panics on huge values and never trips
    // immediately (Duration compare, no overflow).
    assert!(!BudgetConfig::is_over_max_duration(now, Some(u64::MAX)));
    assert!(BudgetConfig::is_over_max_duration(now, Some(0)));
}
