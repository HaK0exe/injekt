#![deny(unsafe_code)]
#![allow(clippy::expect_used)]

/// Binary search ASCII 32..126 inference.
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

    /// Simulate narrowing: given oracle `Fn(char_position`, guess) -> bool (`is_ge`), infer char.
    pub fn infer_char<F>(&self, mut oracle: F) -> Option<char>
    where
        F: FnMut(u8) -> bool,
    {
        let mut low = 32u8;
        let mut high = 126u8;
        while low < high {
            let mid = low + (high - low) / 2;
            if oracle(mid) {
                // guess <= actual? depends; assume oracle returns true if actual >= mid
                low = mid + 1;
            } else {
                high = mid;
            }
            if high - low <= 1 {
                break;
            }
        }
        // final check
        if oracle(low) && low < 126 {
            Some((low + 1) as char)
        } else {
            Some(low as char)
        }
    }

    /// Infer string of known length via oracle per position.
    pub fn infer_string<F>(&self, len: usize, mut oracle: F) -> String
    where
        F: FnMut(usize, u8) -> bool,
    {
        let mut out = String::with_capacity(len);
        for pos in 0..len {
            let mut low = 32u8;
            let mut high = 126u8;
            // binary search per pos
            while low <= high {
                let mid = low + (high - low) / 2;
                let ge = oracle(pos, mid);
                if ge && mid < 126 {
                    low = mid + 1;
                } else if !ge && mid > 32 {
                    if mid == 0 {
                        break;
                    }
                    high = mid - 1;
                } else {
                    break;
                }
                if low >= high {
                    break;
                }
            }
            let c = low.clamp(32, 126) as char;
            out.push(c);
        }
        out
    }
}
