/// HPP/chunked switches for one probe. `Copy` so detection workers and
/// extraction oracles can capture it cheaply.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ProbeOpts {
    /// HTTP Parameter Pollution: duplicate `?id=1&id=<PAYLOAD>` (Query/Body).
    pub hpp: bool,
    /// Chunked transfer: `Transfer-Encoding: chunked` streaming body (Body only).
    pub chunked: bool,
}

impl ProbeOpts {
    #[must_use]
    pub const fn new(hpp: bool, chunked: bool) -> Self {
        Self { hpp, chunked }
    }

    #[must_use]
    pub const fn is_active(self) -> bool {
        self.hpp || self.chunked
    }

    /// Short evidence suffix, e.g. `" hpp=true chunked=false"`, or `""` when inactive.
    #[must_use]
    pub fn evidence_suffix(self) -> String {
        if !self.is_active() {
            return String::new();
        }
        format!(" hpp={} chunked={}", self.hpp, self.chunked)
    }
}
