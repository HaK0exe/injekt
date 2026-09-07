#![deny(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedirectPolicy {
    None,
    Limited(usize),
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self::Limited(5)
    }
}

impl RedirectPolicy {
    #[must_use]
    pub fn should_follow(&self, count: usize) -> bool {
        match self {
            Self::None => false,
            Self::Limited(max) => count < *max,
        }
    }

    /// Max hops for manual follow. `None` means "do not follow".
    #[must_use]
    pub const fn max_hops(&self) -> Option<usize> {
        match self {
            Self::None => None,
            Self::Limited(max) => Some(*max),
        }
    }
}
