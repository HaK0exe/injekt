#![deny(unsafe_code)]

/// Binary search ASCII 32..126 inference.
/// Oracle semantics: `oracle(guess) -> true iff actual >= guess` (documented, 2026 best practice).
/// Invariant: actual ∈ [low, high] inclusive, mid upper ensures convergence in ≤7 steps for 95 values.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InferenceResult {
    pub value: String,
    pub confidence: f64,
}

#[derive(Debug, Default)]
pub struct InferenceExtractor;

impl InferenceExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Simulate narrowing: given oracle `Fn(guess) -> bool` where bool = (actual >= guess), infer char.
    /// Returns None if oracle inconsistent (out of alphabet).
    ///
    /// # Errors
    /// Propagates any error returned by `oracle`.
    pub fn infer_char<F, E>(&self, mut oracle: F) -> Result<Option<char>, E>
    where
        F: FnMut(u8) -> Result<bool, E>,
    {
        let mut low: u8 = 32;
        let mut high: u8 = 126;
        while low < high {
            #[allow(clippy::manual_div_ceil)]
            let mid = low + (high - low + 1) / 2; // upper-mid avoids infinite loop
            let ge = oracle(mid)?;
            if ge {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        // Consistency check: actual must be exactly low
        let ge_low = oracle(low)?;
        if !ge_low {
            return Ok(None);
        }
        if low < 126 {
            let ge_next = oracle(low + 1)?;
            if ge_next {
                return Ok(None);
            }
        }
        Ok(Some(low as char))
    }

    /// Infer string of known length via oracle per position. Oracle: (pos, guess) -> actual[pos] >= guess
    ///
    /// # Errors
    /// Propagates any error returned by `oracle`.
    pub fn infer_string<F, E>(&self, len: usize, mut oracle: F) -> Result<String, E>
    where
        F: FnMut(usize, u8) -> Result<bool, E>,
    {
        let mut out = String::with_capacity(len);
        for pos in 0..len {
            let mut low: u8 = 32;
            let mut high: u8 = 126;
            while low < high {
                #[allow(clippy::manual_div_ceil)]
                let mid = low + (high - low + 1) / 2;
                if oracle(pos, mid)? {
                    low = mid;
                } else {
                    high = mid - 1;
                }
            }
            out.push(low as char);
        }
        Ok(out)
    }

    /// Backwards-compatible sync bool API for tests (uses corrected logic internally).
    pub fn infer_char_sync<F>(&self, mut oracle: F) -> Option<char>
    where
        F: FnMut(u8) -> bool,
    {
        let res: Result<Option<char>, core::convert::Infallible> =
            self.infer_char(|g| Ok::<bool, core::convert::Infallible>(oracle(g)));
        res.unwrap_or(None)
    }

    pub fn infer_string_sync<F>(&self, len: usize, mut oracle: F) -> String
    where
        F: FnMut(usize, u8) -> bool,
    {
        let res: Result<String, core::convert::Infallible> = self.infer_string(len, |pos, g| {
            Ok::<bool, core::convert::Infallible>(oracle(pos, g))
        });
        res.unwrap_or_default()
    }
}
