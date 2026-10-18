use super::*;
use crate::session::state::TechniqueKind;

#[test]
fn test_scheduler_heap_ordering_by_score() {
    let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());

    // Low score: evi 0.2, cost 2.0 -> score 0.1
    s.push("id", TechniqueKind::Time, "sleep", 0.2, 2.0, None);
    // High score: evi 0.8, cost 1.0 -> score 0.8
    s.push("id", TechniqueKind::Boolean, "1=1", 0.8, 1.0, None);
    // Medium score: evi 0.5, cost 1.0 -> score 0.5
    s.push("id", TechniqueKind::Error, "xpath", 0.5, 1.0, None);

    let p1 = s.pop().expect("first probe");
    assert_eq!(p1.technique, TechniqueKind::Boolean);

    let p2 = s.pop().expect("second probe");
    assert_eq!(p2.technique, TechniqueKind::Error);

    let p3 = s.pop().expect("third probe");
    assert_eq!(p3.technique, TechniqueKind::Time);
}

#[test]
fn test_knowledge_boost_bounds_and_neutrality() {
    let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());

    // Neutral boost (None or 1.0)
    s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
    s.push("id", TechniqueKind::Error, "p2", 1.0, 1.0, Some(1.0));

    let p1 = s.pop().expect("p1");
    assert!((p1.score - 1.0).abs() < 1e-6);
    let p2 = s.pop().expect("p2");
    assert!((p2.score - 1.0).abs() < 1e-6);

    // Boost clamping: requested 10.0 -> clamped to 2.0
    s.push("id", TechniqueKind::Union, "p3", 1.0, 1.0, Some(10.0));
    let p3 = s.pop().expect("p3");
    assert!((p3.knowledge_boost - 2.0).abs() < 1e-6);
    assert!((p3.score - 2.0).abs() < 1e-6);

    // Boost clamping: requested 0.01 -> clamped to 0.5
    s.push("id", TechniqueKind::Stacked, "p4", 1.0, 1.0, Some(0.01));
    let p4 = s.pop().expect("p4");
    assert!((p4.knowledge_boost - 0.5).abs() < 1e-6);
    assert!((p4.score - 0.5).abs() < 1e-6);
}

#[test]
fn test_request_budget_exhaustion() {
    let budget = RequestBudget::new(Some(10), None);
    let mut s = Scheduler::new(budget, EarlyStop::default());

    s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
    s.record_outcome("id", false, 10);

    assert!(s.budget().is_exhausted());
    assert!(s.pop().is_none());
}

#[test]
fn test_early_stop_clean_target() {
    let early_stop = EarlyStop::new(5);
    let mut s = Scheduler::new(RequestBudget::unlimited(), early_stop);

    s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
    s.push("id", TechniqueKind::Boolean, "p2", 1.0, 1.0, None);

    // Real flow: pop marks the family attempted, then negatives accumulate.
    let first = s.pop().expect("first probe");
    assert_eq!(first.technique, TechniqueKind::Boolean);

    // 5 consecutive negatives
    for _ in 0..5 {
        s.record_outcome("id", false, 1);
    }

    assert!(s.early_stop().should_stop());
    // Full pass complete (sole enqueued family attempted): veto honored
    // with an immediate None that leaves the heap intact (no drain).
    assert!(s.pop().is_none());
    assert_eq!(s.len(), 1);
}

#[test]
fn test_cost_time_greater_than_boolean() {
    assert!((cost_for(TechniqueKind::Boolean) - 1.0).abs() < 1e-12);
    assert!((cost_for(TechniqueKind::Error) - 1.0).abs() < 1e-12);
    assert!((cost_for(TechniqueKind::Union) - 1.5).abs() < 1e-12);
    assert!((cost_for(TechniqueKind::Json) - 1.5).abs() < 1e-12);
    assert!((cost_for(TechniqueKind::Nosql) - 1.5).abs() < 1e-12);
    assert!((cost_for(TechniqueKind::Stacked) - 2.0).abs() < 1e-12);
    assert!((cost_for(TechniqueKind::Oob) - 2.0).abs() < 1e-12);
    assert!((cost_for(TechniqueKind::Time) - 3.0).abs() < 1e-12);
    assert!(cost_for(TechniqueKind::Time) > cost_for(TechniqueKind::Boolean));
}

#[test]
fn test_cost_for_with_ttfb_static_by_default() {
    // mean 0 (unknown) / fast baseline => static cost unchanged.
    let base = cost_for(TechniqueKind::Time);
    assert!((cost_for_with_ttfb(base, 0.0) - base).abs() < 1e-12);
    assert!((cost_for_with_ttfb(base, 500.0) - base).abs() < 1e-12);
    assert!((cost_for_with_ttfb(base, 2000.0) - base).abs() < 1e-12);
    // Non-finite inputs are pass-through (never NaN-poison the heap).
    assert!((cost_for_with_ttfb(base, f64::NAN) - base).abs() < 1e-12);
}

#[test]
fn test_cost_for_with_ttfb_scales_slow_targets() {
    // mean 5s => factor (1 + 5000/5000) = 2.0, time 3.0 -> 6.0.
    let base = cost_for(TechniqueKind::Time);
    let scaled = cost_for_with_ttfb(base, 5000.0);
    assert!((scaled - 6.0).abs() < 1e-12, "got {scaled}");
    assert!(scaled > base);
    // Boundary just above 2000ms scales slightly.
    let just_over = cost_for_with_ttfb(base, 2001.0);
    assert!(just_over > base);
    assert!((just_over - base * (1.0 + 2001.0 / 5000.0)).abs() < 1e-9);
}

#[test]
fn test_evi_entropy_peaks_at_half() {
    // Phase 0 : variance binaire normalisée `4·p·(1-p)·base`
    // (pic `base` à 0.5, 0 aux convergences 0/1).
    let base = base_evi_for(TechniqueKind::Boolean);
    assert!((evi_for(TechniqueKind::Boolean, 0.5) - base).abs() < 1e-12);
    assert!((evi_for(TechniqueKind::Boolean, 0.0)).abs() < 1e-12);
    assert!((evi_for(TechniqueKind::Boolean, 1.0)).abs() < 1e-12);
    assert!((evi_for(TechniqueKind::Boolean, 0.1) - 0.36 * base).abs() < 1e-12);
    assert!((evi_for(TechniqueKind::Boolean, 0.8) - 0.64 * base).abs() < 1e-12);
    // Symétrie p ↔ 1-p, pic strict à 0.5.
    assert!(
        (evi_for(TechniqueKind::Boolean, 0.2) - evi_for(TechniqueKind::Boolean, 0.8)).abs() < 1e-12
    );
    assert!(evi_for(TechniqueKind::Boolean, 0.5) > evi_for(TechniqueKind::Boolean, 0.8));
    assert!(evi_for(TechniqueKind::Boolean, 0.5) > evi_for(TechniqueKind::Boolean, 0.1));
    // Score hérite du pic sous knowledge neutre.
    assert!(
        score_for(TechniqueKind::Boolean, 0.5, None) > score_for(TechniqueKind::Boolean, 0.8, None)
    );
    assert!(
        score_for(TechniqueKind::Boolean, 0.5, None) > score_for(TechniqueKind::Boolean, 0.1, None)
    );
}

#[test]
fn test_early_stop_counts_requests_trips_mid_pass() {
    // Phase 0 : `max_negative_probes` se compare à des requêtes.
    // 3 outcomes × 10 req = 30 ≥ 25 → stop (l'ancien comptage par
    // technique aurait exigé 25 outcomes et ne trippait jamais mid-pass
    // sur 8 techniques). B1 : le pop préalable marque la famille
    // tentée (full pass complet sur une seule famille enfilée), donc
    // le veto armé s'applique sans drainer le heap.
    let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::new(25));
    s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
    s.push("id", TechniqueKind::Boolean, "p2", 1.0, 1.0, None);
    let _first = s.pop().expect("family attempted before outcomes");
    assert!(!s.early_stop().should_stop());
    s.record_outcome("id", false, 10);
    assert!(!s.early_stop().should_stop());
    s.record_outcome("id", false, 10);
    assert!(!s.early_stop().should_stop());
    s.record_outcome("id", false, 10);
    assert!(s.early_stop().should_stop());
    assert!(s.pop().is_none());
    assert_eq!(s.len(), 1);
    // Un finding verrouille `confirmed` et désactive le stop.
    let mut c = Scheduler::new(RequestBudget::unlimited(), EarlyStop::new(5));
    c.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
    c.record_outcome("id", false, 10);
    c.record_outcome("id", true, 1);
    assert!(!c.early_stop().should_stop());
}

#[test]
fn test_early_stop_streak_resets_per_technique_family() {
    // No cross-family starvation: boolean 24 + error 40 must NOT block
    // nosql (boolean-negative != nosql-negative). The per-family reset
    // keeps arming per-family, while the B1 full-pass gate keeps an
    // armed veto from blocking never-attempted families. Guards
    // `nosql_in_all_techniques`.
    let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::new(25));
    s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
    s.push("id", TechniqueKind::Error, "p2", 1.0, 1.0, None);
    s.push("id", TechniqueKind::Nosql, "p3", 1.0, 1.0, None);
    // Family 1: pop (attempted), 24 negatives, then boundary reset.
    let first = s.pop().expect("boolean first (FIFO tie-break)");
    assert_eq!(first.technique, TechniqueKind::Boolean);
    s.record_outcome("id", false, 24);
    assert!(!s.early_stop().should_stop());
    s.early_stop_mut().reset_negative_streak();
    // Family 2: pop (attempted), 40 negatives -> veto ARMS, no reset:
    // the B1 gate alone must let the unattempted family through.
    let second = s.pop().expect("error serves: full pass incomplete");
    assert_eq!(second.technique, TechniqueKind::Error);
    s.record_outcome("id", false, 40);
    assert!(s.early_stop().should_stop());
    // Family 3 runs: armed veto does not block a never-attempted family.
    let third = s.pop().expect("B1: armed veto must not block nosql");
    assert_eq!(third.technique, TechniqueKind::Nosql);
    // But a single family spending >= 25 still trips once its pass is
    // complete (L2 long tails stay bounded, heap left intact).
    let mut t = Scheduler::new(RequestBudget::unlimited(), EarlyStop::new(25));
    t.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
    t.push("id", TechniqueKind::Boolean, "p2", 1.0, 1.0, None);
    let _ = t.pop().expect("family attempted before outcomes");
    t.record_outcome("id", false, 100);
    assert!(t.early_stop().should_stop());
    assert!(t.pop().is_none());
    assert_eq!(t.len(), 1);
    // `confirmed` survives the streak reset (veto stays off).
    let mut c = Scheduler::new(RequestBudget::unlimited(), EarlyStop::new(5));
    c.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
    c.record_outcome("id", true, 1);
    c.early_stop_mut().reset_negative_streak();
    assert!(!c.early_stop().should_stop());
}

#[test]
fn test_early_stop_record_requests_unit() {
    let mut e = EarlyStop::new(5);
    e.record_requests(false, 3);
    assert_eq!(e.negative_count, 3);
    assert!(!e.should_stop());
    e.record_requests(false, 2);
    assert!(e.should_stop());
    // `record_result` reste l'alias 1-req pour compat.
    let mut r = EarlyStop::new(2);
    r.record_result(false);
    assert_eq!(r.negative_count, 1);
    r.record_result(false);
    assert!(r.should_stop());
}

#[test]
fn test_early_stop_after_25_negatives_default() {
    let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());
    s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
    s.push("id", TechniqueKind::Boolean, "p2", 1.0, 1.0, None);
    let _ = s.pop().expect("family attempted before outcomes");
    for _ in 0..25 {
        s.record_outcome("id", false, 1);
    }
    assert!(s.early_stop().should_stop());
    assert!(s.pop().is_none());
    assert!(s.next_best_probe().is_none());
    assert_eq!(s.len(), 1);
}

#[test]
fn test_b1_l2_boolean_negatives_do_not_starve_untested_nosql() {
    // B1 regression: at L2 the boolean family (top EVI/cost) spends ~40
    // negative requests (4 payloads x 5 sets x 2) before error/nosql ever
    // run. The 25-negative veto arms but must stay gated until every
    // enqueued family was attempted once, so a nosql-only target still
    // gets tested instead of `pop` returning `None` unseen.
    let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::new(25));
    s.push_for_posterior("id", TechniqueKind::Boolean, "b", 0.5, None);
    s.push_for_posterior("id", TechniqueKind::Error, "e", 0.15, None);
    s.push_for_posterior("id", TechniqueKind::Nosql, "n", 0.05, None);

    let first = s.pop().expect("boolean serves first (top EVI/cost)");
    assert_eq!(first.technique, TechniqueKind::Boolean);

    // L2 boolean matrix, all negative: veto arms...
    s.record_outcome("id", false, 40);
    assert!(s.early_stop().should_stop());

    // ...but the full pass is incomplete: preview + pop still serve error.
    assert!(s.next_best_probe().is_some());
    let second = s
        .pop()
        .expect("B1: armed veto must not block unattempted error");
    assert_eq!(second.technique, TechniqueKind::Error);
    s.record_outcome("id", false, 40);
    assert!(s.early_stop().should_stop());

    // nosql (never attempted) still pops: the nosql-only target is tested.
    let third = s
        .pop()
        .expect("B1: armed veto must not block unattempted nosql");
    assert_eq!(third.technique, TechniqueKind::Nosql);
}

#[test]
fn test_boost_bounds_clamp_helper() {
    assert!((clamp_knowledge_boost(10.0) - 2.0).abs() < 1e-12);
    assert!((clamp_knowledge_boost(0.01) - 0.5).abs() < 1e-12);
    assert!((clamp_knowledge_boost(1.0) - 1.0).abs() < 1e-12);
    assert!((clamp_knowledge_boost(f64::NAN) - 1.0).abs() < 1e-12);
}

#[test]
fn test_same_seed_same_order() {
    use TechniqueKind as K;
    let candidates = [
        (K::Boolean, 0.2),
        (K::Error, 0.15),
        (K::Time, 0.1),
        (K::Union, 0.05),
        (K::Stacked, 0.05),
        (K::Json, 0.45),
        (K::Nosql, 0.05),
        (K::Oob, 0.02),
    ];
    let first = ordered_techniques_by_score(&candidates, None, Some(42));
    let second = ordered_techniques_by_score(&candidates, None, Some(42));
    assert_eq!(first, second);

    // Heap path is equally deterministic: same pushes -> same pop order.
    let mut a = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());
    let mut b = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());
    for (kind, posterior) in &candidates {
        a.push_for_posterior("id", *kind, "p", *posterior, None);
        b.push_for_posterior("id", *kind, "p", *posterior, None);
    }
    let mut order_a = Vec::new();
    let mut order_b = Vec::new();
    while let Some(p) = a.pop() {
        order_a.push(p.technique);
    }
    while let Some(p) = b.pop() {
        order_b.push(p.technique);
    }
    assert_eq!(order_a, order_b);
    assert_eq!(order_a, first);
}

#[test]
fn test_union_starvation_guard() {
    let mut order = vec![TechniqueKind::Boolean, TechniqueKind::Error];
    ensure_union_starvation_guard(&mut order, true);
    assert!(order.contains(&TechniqueKind::Union));

    let mut already = vec![TechniqueKind::Boolean, TechniqueKind::Union];
    ensure_union_starvation_guard(&mut already, true);
    assert_eq!(
        already
            .iter()
            .filter(|k| **k == TechniqueKind::Union)
            .count(),
        1
    );

    let mut disabled = vec![TechniqueKind::Boolean];
    ensure_union_starvation_guard(&mut disabled, false);
    assert!(!disabled.contains(&TechniqueKind::Union));
}

#[test]
fn test_budget_spent_total_next_best_probe() {
    let mut s = Scheduler::new(RequestBudget::new(Some(10), None), EarlyStop::default());
    assert_eq!(s.budget_spent(), 0);
    assert_eq!(s.budget_total(), Some(10));
    assert!(s.next_best_probe().is_none());
    s.push_for_posterior("id", TechniqueKind::Boolean, "p1", 0.2, None);
    s.push_for_posterior("id", TechniqueKind::Time, "p2", 0.1, None);
    let next = s.next_best_probe().expect("preview");
    assert_eq!(next.technique, TechniqueKind::Boolean);
    // Preview does not consume.
    assert_eq!(s.len(), 2);
    let first = s.pop().expect("pop");
    assert_eq!(first.technique, next.technique);
    s.record_outcome("id", false, 3);
    assert_eq!(s.budget_spent(), 3);
    assert_eq!(s.budget_total(), Some(10));
}

#[test]
fn test_early_stop_reset_for_new_param_isolates_params() {
    // Inter-param isolation: a clean first param must not veto the next one.
    let mut s = Scheduler::new(RequestBudget::unlimited(), EarlyStop::default());
    s.push("id", TechniqueKind::Boolean, "p1", 1.0, 1.0, None);
    for _ in 0..25 {
        s.record_outcome("id", false, 1);
    }
    assert!(s.early_stop().should_stop());
    s.early_stop_mut().reset_for_new_param();
    assert!(!s.early_stop().should_stop());
    // Seeding the global context cost keeps budget accounting honest.
    s.budget_mut().record_request("id2", 8);
    assert_eq!(s.budget_spent(), 33);
}
