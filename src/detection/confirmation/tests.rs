use super::stats::binomial_tail_at_least;
use super::*;
#[test]
fn needs_three_trials() {
    let r = confirm(&[Trial {
        true_conf: 0.9,
        false_conf: 0.1,
    }]);
    assert!(!r.confirmed);
}
#[test]
fn confirms_majority_pass() {
    let r = confirm(&[
        Trial {
            true_conf: 0.8,
            false_conf: 0.2,
        },
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
        Trial {
            true_conf: 0.7,
            false_conf: 0.3,
        },
    ]);
    assert!(r.confirmed);
    assert!(r.false_positive_prob < 0.5);
}
#[test]
fn rejects_false_high() {
    let r = confirm(&[
        Trial {
            true_conf: 0.8,
            false_conf: 0.5,
        },
        Trial {
            true_conf: 0.9,
            false_conf: 0.6,
        },
        Trial {
            true_conf: 0.7,
            false_conf: 0.4,
        },
    ]);
    assert!(!r.confirmed);
}
#[test]
fn either_accepts_normal_direction() {
    let trials = [
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
        Trial {
            true_conf: 0.8,
            false_conf: 0.2,
        },
        Trial {
            true_conf: 0.85,
            false_conf: 0.15,
        },
    ];
    let (r, inverted) = confirm_either(&trials);
    assert!(r.confirmed);
    assert!(!inverted);
}
#[test]
fn either_accepts_inverted_login_style_oracle() {
    // Baseline IS the failed state: FALSE≈baseline, TRUE differs.
    let trials = [
        Trial {
            true_conf: 0.3,
            false_conf: 0.95,
        },
        Trial {
            true_conf: 0.25,
            false_conf: 0.9,
        },
        Trial {
            true_conf: 0.35,
            false_conf: 0.92,
        },
    ];
    assert!(!confirm(&trials).confirmed);
    let (r, inverted) = confirm_either(&trials);
    assert!(r.confirmed);
    assert!(inverted);
}
#[test]
fn either_rejects_ambiguous_superset_oracle() {
    // Neither branch matches the baseline (e.g. OR-superset TRUE plus
    // empty FALSE on a 1-row baseline): no direction is stable.
    let trials = [
        Trial {
            true_conf: 0.54,
            false_conf: 0.28,
        },
        Trial {
            true_conf: 0.55,
            false_conf: 0.3,
        },
        Trial {
            true_conf: 0.52,
            false_conf: 0.27,
        },
    ];
    let (r, _) = confirm_either(&trials);
    assert!(!r.confirmed);
}
#[test]
fn confirms_locked_baseline_with_decisive_gap() {
    // Live bench A1 shape: TRUE == baseline (1.0), FALSE = empty `data`
    // set (0.4375 — envelope boilerplate floors it above the 0.4 bar).
    // The gap clause (1.0 - 0.4375 = 0.5625 > 0.5) must confirm.
    let trials = [
        Trial {
            true_conf: 1.0,
            false_conf: 0.4375,
        },
        Trial {
            true_conf: 1.0,
            false_conf: 0.4375,
        },
        Trial {
            true_conf: 1.0,
            false_conf: 0.4375,
        },
    ];
    let (r, inverted) = confirm_either(&trials);
    assert!(r.confirmed);
    assert!(!inverted);
}
#[test]
fn rejects_small_gap_near_threshold() {
    // TRUE locked but gap indecisive (0.95 - 0.5 = 0.45 < 0.5):
    // stays rejected so the gap clause cannot launder weak oracles.
    let trials = [
        Trial {
            true_conf: 0.95,
            false_conf: 0.5,
        },
        Trial {
            true_conf: 0.95,
            false_conf: 0.5,
        },
        Trial {
            true_conf: 0.95,
            false_conf: 0.5,
        },
    ];
    let (r, _) = confirm_either(&trials);
    assert!(!r.confirmed);
}
#[test]
fn aggregate_sims_means_passing_trials_only() {
    // Two passing trials + one neutral transport trial: the neutral
    // trial must not drag the evidence mean.
    let (t, f) = aggregate_sims(&[
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
        Trial {
            true_conf: 0.5,
            false_conf: 0.5,
        },
        Trial {
            true_conf: 0.8,
            false_conf: 0.2,
        },
    ]);
    assert!((t - 0.85).abs() < 1e-9, "{t}");
    assert!((f - 0.15).abs() < 1e-9, "{f}");
}
#[test]
fn aggregate_sims_falls_back_to_all_when_none_pass() {
    // Inverted oracle (decided on the swapped pass): no original trial
    // passes, so evidence is the mean over all trials.
    let (t, f) = aggregate_sims(&[
        Trial {
            true_conf: 0.3,
            false_conf: 0.9,
        },
        Trial {
            true_conf: 0.3,
            false_conf: 0.9,
        },
        Trial {
            true_conf: 0.3,
            false_conf: 0.9,
        },
    ]);
    assert!((t - 0.3).abs() < 1e-9, "{t}");
    assert!((f - 0.9).abs() < 1e-9, "{f}");
    assert_eq!(aggregate_sims(&[]), (0.0, 0.0));
}
#[test]
fn binomial_tail_at_least_matches_closed_forms() {
    // P(Bin(3, 1/2) >= 3) = 1/8; >= 2 = 1/2; P(Bin(5, 1/2) >= 5) = 1/32.
    assert!((binomial_tail_at_least(3, 3, 0.5) - 0.125).abs() < 1e-12);
    assert!((binomial_tail_at_least(3, 2, 0.5) - 0.5).abs() < 1e-12);
    assert!((binomial_tail_at_least(5, 5, 0.5) - 0.031_25).abs() < 1e-12);
    // Degenerate bounds are total, never panicking.
    assert!((binomial_tail_at_least(3, 0, 0.5) - 1.0).abs() < 1e-12);
    assert!(binomial_tail_at_least(3, 4, 0.5).abs() < 1e-12);
    assert!(binomial_tail_at_least(3, 2, 0.0).abs() < 1e-12);
    assert!((binomial_tail_at_least(3, 2, 1.0) - 1.0).abs() < 1e-12);
}
#[test]
fn confirmed_fp_strong_separation_reaches_high_bucket() {
    // 3/3 passes at 0.9/0.1: p_value = P(Bin(3, 0.5) >= 3) = 0.125 and
    // sep = 0.8, so fp = 0.125 * 0.2 = 0.025 <= 0.05 (High bucket bound).
    let r = confirm(&[
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
    ]);
    assert!(r.confirmed);
    assert!(r.false_positive_prob <= 0.05, "{}", r.false_positive_prob);
}
#[test]
fn confirmed_fp_weak_separation_stays_above_high_bucket() {
    // 3/3 at 0.65/0.35: p_value = 0.125, sep = 0.3
    // -> fp = 0.125 * 0.7 = 0.0875, above the High bucket bound (0.05)
    // but still inside the Medium bucket (< 0.2).
    let r = confirm(&[
        Trial {
            true_conf: 0.65,
            false_conf: 0.35,
        },
        Trial {
            true_conf: 0.65,
            false_conf: 0.35,
        },
        Trial {
            true_conf: 0.65,
            false_conf: 0.35,
        },
    ]);
    assert!(r.confirmed);
    assert!(r.false_positive_prob > 0.05, "{}", r.false_positive_prob);
    assert!(r.false_positive_prob < 0.2, "{}", r.false_positive_prob);
}
#[test]
fn confirmed_fp_bare_majority_pays_the_sign_test_floor() {
    // 2/3 passes (neutral third trial fails): p_value = P(Bin(3, 0.5) >= 2)
    // = 0.5 and sep = (0.8 + 0.6) / 2 = 0.7 -> fp = 0.5 * 0.3 = 0.15,
    // so a bare majority can no longer look better than the sign-test floor.
    let r = confirm(&[
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
        Trial {
            true_conf: 0.8,
            false_conf: 0.2,
        },
        Trial {
            true_conf: 0.5,
            false_conf: 0.5,
        },
    ]);
    assert!(r.confirmed);
    assert!(r.false_positive_prob > 0.05, "{}", r.false_positive_prob);
    assert!(r.false_positive_prob >= 0.1, "{}", r.false_positive_prob);
}
#[test]
fn confirmed_fp_shrinks_with_more_trials() {
    // Same separation, 5/5 vs 3/3: p_value 1/32 < 1/8, so the estimate
    // must be strictly smaller (monotonicity in n).
    let three = confirm(&[
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
    ]);
    let five = confirm(&[
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
        Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        },
    ]);
    assert!(three.confirmed && five.confirmed);
    assert!(
        five.false_positive_prob < three.false_positive_prob,
        "{} vs {}",
        five.false_positive_prob,
        three.false_positive_prob
    );
}
#[test]
fn confirmed_fp_gap_clause_bench_a1_shape() {
    // Live bench A1: TRUE == baseline (1.0), FALSE = empty set (0.4375).
    // p_value = 0.125, sep = 0.5625 -> fp = 0.125 * 0.4375 = 0.0546875.
    let r = confirm(&[
        Trial {
            true_conf: 1.0,
            false_conf: 0.4375,
        },
        Trial {
            true_conf: 1.0,
            false_conf: 0.4375,
        },
        Trial {
            true_conf: 1.0,
            false_conf: 0.4375,
        },
    ]);
    assert!(r.confirmed);
    assert!(
        (0.05..=0.06).contains(&r.false_positive_prob),
        "{}",
        r.false_positive_prob
    );
}
#[test]
fn unconfirmed_fp_keeps_historical_score_estimate() {
    // Rejected: fp must stay the historical `score` (no statistical
    // re-derivation on the rejected path).
    let r = confirm(&[
        Trial {
            true_conf: 0.8,
            false_conf: 0.5,
        },
        Trial {
            true_conf: 0.9,
            false_conf: 0.6,
        },
        Trial {
            true_conf: 0.7,
            false_conf: 0.4,
        },
    ]);
    assert!(!r.confirmed);
    assert!(
        (r.false_positive_prob - r.score).abs() < 1e-12,
        "{} vs {}",
        r.false_positive_prob,
        r.score
    );
    assert!((r.score - 0.35).abs() < 1e-12, "{}", r.score);
    // The n < 3 early return is untouched too (fp = 0.0, score = 0.0).
    let short = confirm(&[Trial {
        true_conf: 0.9,
        false_conf: 0.1,
    }]);
    assert!(!short.confirmed);
    assert!(short.false_positive_prob.abs() < 1e-12);
}
