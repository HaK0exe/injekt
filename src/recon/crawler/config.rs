use crate::recon::parameter::ParameterCandidate;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct CrawlConfig {
    pub depth: usize,
    pub max_pages: usize,
    /// Cap on how many pages sharing the same [`crate::recon::filters::page_template_key`] are
    /// fetched — guards against pagination/listing/calendar traps burning
    /// the whole `max_pages` budget on redundant instances of one page shape.
    pub max_per_template: usize,
    /// Cap on redundant candidate instances sharing one sink shape
    /// ([`crate::recon::filters::candidate_template_key`]) and on the total candidate list
    /// (`max_candidates`): listing/gallery/proxy endpoints otherwise queue
    /// hundreds of near-identical params that burn scan budget.
    pub max_candidates: usize,
    pub include_subdomains: bool,
    pub respect_robots: bool,
    pub allow_private: bool,
    /// Skip local DNS-time SSRF resolution (proxy resolves remotely, e.g.
    /// `socks5h://`). Lexical + IP-literal checks still apply.
    pub remote_dns: bool,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            depth: 2,
            max_pages: 100,
            max_per_template: 3,
            max_candidates: 500,
            include_subdomains: false,
            respect_robots: true,
            allow_private: false,
            remote_dns: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlReport {
    pub target: Url,
    pub pages_visited: usize,
    pub candidates: Vec<ParameterCandidate>,
    pub warnings: Vec<String>,
}

impl CrawlReport {
    /// Scrubbed clone for CLI / MCP output (candidate URLs may carry tokens).
    #[must_use]
    pub fn scrubbed(&self, scrubber: &crate::session::scrubber::Scrubber) -> Self {
        let target = scrubber
            .scrub(self.target.as_str())
            .parse()
            .unwrap_or_else(|_| self.target.clone());
        Self {
            target,
            pages_visited: self.pages_visited,
            candidates: self
                .candidates
                .iter()
                .map(|c| c.scrubbed(scrubber))
                .collect(),
            warnings: self.warnings.iter().map(|w| scrubber.scrub(w)).collect(),
        }
    }
}
