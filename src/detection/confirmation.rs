#![deny(unsafe_code)]

//! Boolean-oracle confirmation: repeated TRUE/FALSE trials, a strict-majority
//! pass rule, and a statistically grounded false-positive estimate for
//! confirmed oracles (one-sided sign test weighted by effect size — see
//! [`confirm`]).

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Trial {
    pub true_conf: f64,
    pub false_conf: f64,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConfirmationResult {
    pub confirmed: bool,
    pub score: f64,
    pub false_positive_prob: f64,
    pub trials: usize,
}

impl ConfirmationResult {
    #[must_use]
    pub fn new(confirmed: bool, score: f64, trials: usize) -> Self {
        let fp = if confirmed {
            (1.0 - score).clamp(0.0, 1.0)
        } else {
            score.clamp(0.0, 1.0)
        };
        Self {
            confirmed,
            score,
            false_positive_prob: fp,
            trials,
        }
    }
}

/// Upper-tail probability `P(X >= k)` for `X ~ Binomial(n, p)`:
///
/// ```text
/// P(Bin(n, p) >= k) = Σ_{i=k}^{n} C(n, i) · p^i · (1 - p)^(n - i)
/// ```
///
/// The binomial coefficient is accumulated multiplicatively
/// (`C(n, i+1) = C(n, i) · (n - i) / (i + 1)`) and the powers are carried
/// forward term by term, so no factorial is ever materialized (nothing can
/// overflow for the single-digit `n` used by confirmation). Edge cases are
/// total and never panic: `k == 0` is the certain event (`1.0`), `k > n` the
/// impossible one (`0.0`), and `p` is clamped to `[0, 1]`.
#[must_use]
// Trial counts are small (single-digit confirmation retries); usize->f64 precision loss is not reachable.
#[allow(clippy::cast_precision_loss)]
fn binomial_tail_at_least(n: usize, k: usize, p: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    if k > n {
        return 0.0;
    }
    let p = p.clamp(0.0, 1.0);
    if p >= 1.0 {
        return 1.0;
    }
    let inv_p = 1.0 - p;
    // C(n, k), built multiplicatively from C(n, 0) = 1.
    let mut coeff = 1.0_f64;
    for i in 1..=k {
        coeff = coeff * (n - i + 1) as f64 / i as f64;
    }
    // p^k and (1 - p)^(n - k) without powi (avoids usize->i32 casts).
    let mut p_pow = 1.0_f64;
    for _ in 0..k {
        p_pow *= p;
    }
    let mut q_pow = 1.0_f64;
    for _ in 0..n - k {
        q_pow *= inv_p;
    }
    let mut tail = 0.0_f64;
    for i in k..n {
        tail += coeff * p_pow * q_pow;
        // Advance to i + 1: coefficient ratio (n - i) / (i + 1), p^i -> p^(i+1),
        // q^(n - i) -> q^(n - i - 1). `inv_p > 0` here (p < 1), so no division by zero.
        coeff = coeff * (n - i) as f64 / (i + 1) as f64;
        p_pow *= p;
        q_pow /= inv_p;
    }
    // Final term (i == n), after the loop advanced the factors once more:
    // coeff == C(n, n) == 1, p_pow == p^n, q_pow == (1 - p)^0 == 1.
    (tail + coeff * p_pow * q_pow).clamp(0.0, 1.0)
}

/// Re-test TRUE/FALSE inverted payload pairs. Requires 3 trials minimum.
/// Confirmation requires majority of trials with `true_conf` > 0.6 AND
/// (`false_conf` < 0.4 OR a decisive gap: `true_conf` > 0.9 with
/// `true_conf - false_conf` > 0.5). The gap clause covers small JSON
/// envelopes whose boilerplate tokens (`request_id`, …) floor the FALSE
/// similarity above 0.4 even for a textbook oracle (TRUE == baseline,
/// FALSE = empty set — live bench A1: 1.0 vs 0.4375).
///
/// # False-positive estimate (confirmed oracles)
///
/// A pass requires both a *directional* separation (which branch looks like
/// the baseline) and its magnitude, so under H0 (no oracle: TRUE/FALSE
/// branches exchangeable) a passing trial is at best a biased coin —
/// `p0 = 0.5` is a conservative upper bound on the per-trial probability of
/// a lucky pass. The estimate is the one-sided sign test
///
/// ```text
/// p_value = P(Bin(n, 0.5) >= pass_count)
/// ```
///
/// discounted by the observed effect size `sep` (mean
/// `(true_conf - false_conf).clamp(0.0, 1.0)` over passing trials), because a
/// lucky pass typically shows a small separation:
///
/// ```text
/// false_positive_prob = p_value * (1 - sep), clamped to [0, 1]
/// ```
///
/// So 3/3 textbook passes (0.9 vs 0.1) score `0.125 * 0.2 = 0.025`, while a
/// bare 2/3 majority cannot go below `0.5 * (1 - sep)`. `score` keeps its
/// historical meaning (mean per-trial similarity, inverted when rejected).
/// Unconfirmed oracles keep the historical `false_positive_prob = score`.
#[must_use]
// Trial counts are small (single-digit confirmation retries); usize->f64 precision loss is not reachable.
#[allow(clippy::cast_precision_loss)]
pub fn confirm(trials: &[Trial]) -> ConfirmationResult {
    let n = trials.len();
    if n < 3 {
        return ConfirmationResult::new(false, 0.0, n);
    }
    let mut pass_count = 0usize;
    let mut score_sum = 0.0;
    let mut sep_sum = 0.0;
    for t in trials {
        let true_ok = t.true_conf > 0.6;
        // Gap clause: a TRUE branch locked on the baseline (> 0.9) with a
        // decisive differential (> 0.5) confirms even when envelope
        // boilerplate keeps the FALSE similarity at/above 0.4.
        let false_ok =
            t.false_conf < 0.4 || (t.true_conf > 0.9 && t.true_conf - t.false_conf > 0.5);
        if true_ok && false_ok {
            pass_count += 1;
            sep_sum += (t.true_conf - t.false_conf).clamp(0.0, 1.0);
        }
        score_sum += f64::midpoint(t.true_conf, 1.0 - t.false_conf);
    }
    let avg_score = score_sum / n as f64;
    let confirmed = pass_count as f64 / n as f64 > 0.5;
    if !confirmed {
        // Rejected: keep the historical estimate (`fp = score`).
        return ConfirmationResult::new(false, (1.0 - avg_score).clamp(0.0, 1.0), n);
    }
    // Mean separation over passing trials. `0.0` is a fail-safe (unreachable:
    // confirmation already implies `pass_count >= 2`) that only makes the
    // estimate more conservative.
    let sep = if pass_count == 0 {
        0.0
    } else {
        sep_sum / pass_count as f64
    };
    let p_value = binomial_tail_at_least(n, pass_count, 0.5);
    ConfirmationResult {
        confirmed: true,
        score: avg_score.clamp(0.0, 1.0),
        false_positive_prob: (p_value * (1.0 - sep)).clamp(0.0, 1.0),
        trials: n,
    }
}

/// Aggregate per-trial similarities for evidence display.
///
/// Returns the mean `(true_conf, false_conf)` over *passing* trials (same
/// per-trial pass rule as [`confirm`]), so the rendered `true_sim` /
/// `false_sim` reflect the measured majority instead of whichever trial ran
/// last. Neutral transport trials (`0.5`/`0.5`) and ignored-status trials
/// (`0.0`/`1.0`) never pass and are excluded. When no trial passes (e.g. an
/// inverted oracle decided on the swapped pass), falls back to the mean over
/// all trials; empty input yields `(0.0, 0.0)`.
///
/// Decision inputs (`score`, `false_positive_prob`) still come from
/// [`confirm`]/[`confirm_either`]; this only affects display.
#[must_use]
// Trial counts are small (single-digit confirmation retries); usize->f64 precision loss is not reachable.
#[allow(clippy::cast_precision_loss)]
pub fn aggregate_sims(trials: &[Trial]) -> (f64, f64) {
    fn passes(t: &Trial) -> bool {
        t.true_conf > 0.6
            && (t.false_conf < 0.4 || (t.true_conf > 0.9 && t.true_conf - t.false_conf > 0.5))
    }
    let mut sum_true = 0.0;
    let mut sum_false = 0.0;
    let mut count = 0usize;
    for t in trials.iter().filter(|t| passes(t)) {
        sum_true += t.true_conf;
        sum_false += t.false_conf;
        count += 1;
    }
    if count == 0 {
        // No passing trial: mean over all trials (inverted/degenerate
        // shapes), still more representative than the last trial alone.
        for t in trials {
            sum_true += t.true_conf;
            sum_false += t.false_conf;
        }
        count = trials.len();
    }
    if count == 0 {
        return (0.0, 0.0);
    }
    (sum_true / count as f64, sum_false / count as f64)
}

/// Confirm a boolean oracle in EITHER direction.
///
/// A boolean injection has two stable states; either one may coincide with
/// the baseline page. Normal direction: TRUE≈baseline, FALSE differs (e.g.
/// id-lookup sinks). Inverted direction: FALSE≈baseline, TRUE differs (e.g.
/// login-bypass sinks where the baseline IS the failed state).
/// Returns the result plus whether the inverted assignment won. When both
/// directions confirm (degenerate page), normal wins.
#[must_use]
pub fn confirm_either(trials: &[Trial]) -> (ConfirmationResult, bool) {
    let normal = confirm(trials);
    if normal.confirmed {
        return (normal, false);
    }
    let swapped: Vec<Trial> = trials
        .iter()
        .map(|t| Trial {
            true_conf: t.false_conf,
            false_conf: t.true_conf,
        })
        .collect();
    // Swapping exchanges the roles: the confirmation rule stays
    // "baseline-like > 0.6 AND different < 0.4", now tested against the
    // FALSE branch as the baseline-like one. Same bar, no extra FP room
    // beyond the symmetry of a two-state oracle.
    let inverted = confirm(&swapped);
    if inverted.confirmed {
        (inverted, true)
    } else {
        (normal, false)
    }
}

#[cfg(test)]
mod tests {
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
}
