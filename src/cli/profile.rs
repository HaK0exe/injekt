#![deny(unsafe_code)]

use clap::ValueEnum;

/// Named scan preset. All fields remain overridable by explicit flags,
/// environment variables or config file values (explicit always wins).
///
/// * `quick` — fast lab triage, minimal request budget.
/// * `balanced` — historical defaults, byte-identical behaviour (default when
///   `--profile` is absent).
/// * `stealth` — slow OPSEC-friendly cadence, reduced technique set.
/// * `aggressive` — thorough enumeration, widest payload budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum Profile {
    Quick,
    Stealth,
    Balanced,
    Aggressive,
}

impl Profile {
    #[must_use]
    pub const fn threads(self) -> usize {
        match self {
            Self::Quick => 10,
            Self::Balanced => 5,
            Self::Stealth => 2,
            Self::Aggressive => 8,
        }
    }

    #[must_use]
    pub const fn timeout_secs(self) -> u64 {
        match self {
            Self::Quick => 15,
            Self::Balanced | Self::Stealth | Self::Aggressive => 30,
        }
    }

    #[must_use]
    pub const fn retries(self) -> usize {
        match self {
            Self::Quick => 1,
            Self::Balanced | Self::Stealth | Self::Aggressive => 3,
        }
    }

    #[must_use]
    pub const fn delay_ms(self) -> u64 {
        match self {
            Self::Quick => 200,
            Self::Balanced | Self::Aggressive => 500,
            Self::Stealth => 800,
        }
    }

    #[must_use]
    pub const fn rate_limit_rps(self) -> f64 {
        match self {
            Self::Quick => 20.0,
            Self::Balanced | Self::Aggressive => 10.0,
            Self::Stealth => 3.0,
        }
    }

    /// Default jitter as `"mean_ms,std_ms"` (milliseconds, see `--jitter`).
    #[must_use]
    pub const fn jitter(self) -> &'static str {
        match self {
            Self::Quick => "200,100",
            Self::Balanced => "750,250",
            Self::Stealth => "1200,400",
            Self::Aggressive => "500,200",
        }
    }

    #[must_use]
    pub const fn level(self) -> u8 {
        match self {
            Self::Quick | Self::Balanced | Self::Stealth => 1,
            Self::Aggressive => 3,
        }
    }

    /// Default technique set. `None` means "all" (historical default).
    /// `Some` is a restricted subset for fast/stealth presets.
    #[must_use]
    pub fn techniques(self) -> Vec<String> {
        match self {
            Self::Quick | Self::Stealth => {
                vec!["boolean".to_owned(), "error".to_owned()]
            }
            Self::Balanced | Self::Aggressive => vec!["all".to_owned()],
        }
    }

    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Quick => "quick: fast lab triage (10 threads, 20 rps, level 1, boolean+error)",
            Self::Balanced => {
                "balanced: historical defaults (5 threads, 10 rps, level 1, all techniques)"
            }
            Self::Stealth => {
                "stealth: slow OPSEC cadence (2 threads, 3 rps, level 1, boolean+error)"
            }
            Self::Aggressive => {
                "aggressive: thorough scan (8 threads, 10 rps, level 3, all techniques)"
            }
        }
    }

    #[must_use]
    pub fn all_names() -> &'static [&'static str] {
        &["quick", "balanced", "stealth", "aggressive"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::float_cmp)]
    fn balanced_matches_historical_defaults() {
        assert_eq!(Profile::Balanced.threads(), 5);
        assert_eq!(Profile::Balanced.timeout_secs(), 30);
        assert_eq!(Profile::Balanced.retries(), 3);
        assert_eq!(Profile::Balanced.delay_ms(), 500);
        assert_eq!(Profile::Balanced.rate_limit_rps(), 10.0);
        assert_eq!(Profile::Balanced.jitter(), "750,250");
        assert_eq!(Profile::Balanced.level(), 1);
        assert_eq!(Profile::Balanced.techniques(), vec!["all".to_owned()]);
    }

    #[test]
    fn stealth_is_slower_than_quick() {
        assert!(Profile::Stealth.threads() < Profile::Quick.threads());
        assert!(Profile::Stealth.rate_limit_rps() < Profile::Quick.rate_limit_rps());
    }
}
