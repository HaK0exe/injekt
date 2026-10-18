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
pub(super) fn binomial_tail_at_least(n: usize, k: usize, p: f64) -> f64 {
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
