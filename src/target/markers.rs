#![deny(unsafe_code)]

use regex::Regex;
use std::sync::OnceLock;

/// Supported injection markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InjectionMarker {
    Asterisk,    // *
    Section,     // §
    DoubleBrace, // {{}}
}

impl InjectionMarker {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Asterisk => "*",
            Self::Section => "§",
            Self::DoubleBrace => "{{}}",
        }
    }
}

/// Detected markers in a target string.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct MarkerSet {
    pub asterisk: bool,
    pub section: bool,
    pub double_brace: bool,
}

impl MarkerSet {
    #[must_use]
    pub fn detect(input: &str) -> Self {
        let lower = input.to_ascii_lowercase();
        Self {
            asterisk: input.contains('*') || lower.contains("%2a"),
            section: input.contains('§') || lower.contains("%c2%a7"),
            double_brace: input.contains("{{") && input.contains("}}"),
        }
    }

    #[must_use]
    pub fn has_any(&self) -> bool {
        self.asterisk || self.section || self.double_brace
    }

    /// # Panics
    /// Panics if an internal static regex fails to compile (never happens in practice).
    #[must_use]
    pub fn positions(&self, input: &str) -> Vec<(usize, InjectionMarker)> {
        let mut v = Vec::new();
        if self.asterisk {
            for (i, _) in input.match_indices('*') {
                v.push((i, InjectionMarker::Asterisk));
            }
        }
        if self.section {
            // § comes in pairs: §payload§
            static RE: OnceLock<Regex> = OnceLock::new();
            let re = RE.get_or_init(|| {
                #[allow(clippy::expect_used)]
                {
                    Regex::new(r"§[^§]*§").expect("static regex §")
                }
            });
            for m in re.find_iter(input) {
                v.push((m.start(), InjectionMarker::Section));
            }
        }
        if self.double_brace {
            static RE2: OnceLock<Regex> = OnceLock::new();
            let re = RE2.get_or_init(|| {
                #[allow(clippy::expect_used)]
                {
                    Regex::new(r"\{\{[^}]*\}\}").expect("static regex double brace")
                }
            });
            for m in re.find_iter(input) {
                v.push((m.start(), InjectionMarker::DoubleBrace));
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_asterisk() {
        let m = MarkerSet::detect("id=1*");
        assert!(m.asterisk);
        assert!(!m.section);
    }

    #[test]
    fn detects_section() {
        let m = MarkerSet::detect("id=§1§");
        assert!(m.section);
    }
}
