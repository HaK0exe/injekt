#![deny(unsafe_code)]

//! Seeded RNG for deterministic runs (`--seed`, C1 metrology).
//!
//! [`make_rng`] is the single entry point for all *non-cryptographic*
//! randomness (tampers, jitter, UA rotation, retry backoff): `Some(seed)` yields
//! a deterministic [`StdRng`] via [`SeedableRng::seed_from_u64`], `None`
//! preserves the historical nondeterministic behaviour via
//! [`StdRng::from_os_rng`].
//!
//! Cryptographic randomness (`session/export.rs` salt/nonce, temp filenames)
//! must NEVER use this helper — those stay on OS randomness unconditionally.

use rand::{SeedableRng as _, rngs::StdRng};

/// Build the run RNG: deterministic when `seed` is `Some`, OS-random otherwise.
#[must_use]
pub fn make_rng(seed: Option<u64>) -> StdRng {
    match seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_os_rng(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rand::Rng as _;

    #[test]
    fn same_seed_same_stream() {
        let mut a = make_rng(Some(42));
        let mut b = make_rng(Some(42));
        for _ in 0..10 {
            assert_eq!(a.random::<u64>(), b.random::<u64>());
        }
    }

    #[test]
    fn different_seeds_likely_differ() {
        let mut a = make_rng(Some(1));
        let mut b = make_rng(Some(2));
        let xs: Vec<u64> = (0..10).map(|_| a.random()).collect();
        let ys: Vec<u64> = (0..10).map(|_| b.random()).collect();
        assert_ne!(xs, ys);
    }

    #[test]
    fn none_path_produces_values() {
        let mut rng = make_rng(None);
        // Smoke: OS RNG yields values without panicking; no determinism asserted.
        let _: u64 = rng.random();
    }
}
