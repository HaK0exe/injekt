use super::model::{ConfirmationResult, Trial};
use super::stats::binomial_tail_at_least;

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
