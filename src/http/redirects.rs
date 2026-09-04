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

    /// Maximum number of redirect hops to follow, or `None` if redirects
    /// must not be followed at all.
    #[must_use]
    pub fn max_hops(&self) -> Option<usize> {
        match self {
            Self::None => None,
            Self::Limited(max) => Some(*max),
        }
    }
}
