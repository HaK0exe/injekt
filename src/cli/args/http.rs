#![deny(unsafe_code)]

use clap::Args;

/// HTTP / network behaviour (method, auth, proxy, throughput, SSRF gate).
#[derive(Clone, Args)]
#[non_exhaustive]
pub struct HttpOpts {
    #[arg(long, global = true, help_heading = "HTTP")]
    pub method: Option<String>,

    #[arg(long, global = true, value_delimiter = ',', help_heading = "HTTP")]
    pub headers: Vec<String>,

    #[arg(long, global = true, help_heading = "HTTP")]
    pub cookies: Option<String>,

    #[arg(long, global = true, env = "INJEKT_PROXY", help_heading = "HTTP")]
    pub proxy: Option<String>,

    /// Request timeout in seconds [default: 30]
    #[arg(long, global = true, env = "INJEKT_TIMEOUT", help_heading = "HTTP")]
    pub timeout: Option<u64>,

    /// Max retries for failed requests [default: 3]
    #[arg(long, global = true, env = "INJEKT_RETRIES", help_heading = "HTTP")]
    pub retries: Option<usize>,

    /// Base retry delay in milliseconds [default: 500]
    #[arg(long, global = true, env = "INJEKT_DELAY", help_heading = "HTTP")]
    pub delay: Option<u64>,

    #[arg(long, global = true, env = "INJEKT_RATE_LIMIT", help_heading = "HTTP")]
    pub rate_limit: Option<f64>,

    #[arg(long, global = true, env = "INJEKT_JITTER", help_heading = "HTTP")]
    pub jitter: Option<String>,

    #[arg(long, global = true, help_heading = "HTTP")]
    pub allow_private: bool,

    /// Max redirects followed per request [default: 5, range 0..=10].
    /// `0` disables following entirely (the 3xx is returned as-is): no
    /// cross-origin hop can then carry `--cookies`/`--headers`/jar cookies.
    /// Every followed hop is re-validated (SSRF) and strips secrets
    /// cross-origin regardless of this value.
    #[arg(long = "max-redirects", global = true, value_parser = clap::value_parser!(u8).range(0..=10), env = "INJEKT_MAX_REDIRECTS", help_heading = "HTTP")]
    pub max_redirects: Option<u8>,
}

// Manual `Debug` for `HttpOpts` so `--cookies` / `--proxy` / `--headers`
// never appear in logs, panics or `tracing` records.
impl core::fmt::Debug for HttpOpts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let redacted_opt = |v: &Option<String>| v.as_ref().map(|_| "[REDACTED]".to_owned());
        let redacted_headers: Vec<&str> = self.headers.iter().map(|_| "[REDACTED]").collect();
        f.debug_struct("HttpOpts")
            .field("method", &self.method)
            .field("headers", &redacted_headers)
            .field("cookies", &redacted_opt(&self.cookies))
            .field("proxy", &redacted_opt(&self.proxy))
            .field("timeout", &self.timeout)
            .field("retries", &self.retries)
            .field("delay", &self.delay)
            .field("rate_limit", &self.rate_limit)
            .field("jitter", &self.jitter)
            .field("allow_private", &self.allow_private)
            .field("max_redirects", &self.max_redirects)
            .finish_non_exhaustive()
    }
}
