//! WAF/CDN vendor taxonomy and the per-response fingerprint bundle.

/// WAF/CDN vendor behind the response, when identifiable.
///
/// Infrastructure fingerprints are kept distinct from security products:
/// `AwsAlb` (plain ALB / `x-amzn-*` IDs — every ALB/API-GW response carries
/// them, WAF or not) and `Varnish` (bare reverse-proxy/cache — Fastly
/// derives from it but a bare `via: varnish` proves no Fastly) never imply
/// `AwsWaf` / `Fastly`. `AwsWaf` / `Fastly` are reserved for explicit
/// product signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WafVendor {
    Cloudflare,
    Akamai,
    Imperva,
    ModSecurity,
    F5,
    AwsWaf,
    AwsAlb,
    Sucuri,
    Fastly,
    Varnish,
    DataDome,
    Kasada,
    Human,
    Turnstile,
    Generic,
}

impl core::fmt::Display for WafVendor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cloudflare => write!(f, "cloudflare"),
            Self::Akamai => write!(f, "akamai"),
            Self::Imperva => write!(f, "imperva"),
            Self::ModSecurity => write!(f, "modsecurity"),
            Self::F5 => write!(f, "f5"),
            Self::AwsWaf => write!(f, "aws-waf"),
            Self::AwsAlb => write!(f, "aws-alb"),
            Self::Sucuri => write!(f, "sucuri"),
            Self::Fastly => write!(f, "fastly"),
            Self::Varnish => write!(f, "varnish"),
            Self::DataDome => write!(f, "datadome"),
            Self::Kasada => write!(f, "kasada"),
            Self::Human => write!(f, "human"),
            Self::Turnstile => write!(f, "turnstile"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

/// Fingerprinting outcome for one response (or an aggregated baseline).
///
/// Two tiers: `vendor.is_some()` means presence (CDN headers observed —
/// informational), `blocking` means an active challenge/deny/rate-limit was
/// observed and findings should be doubted (see [`downgrade_for_waf`]).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct WafSignals {
    pub vendor: Option<WafVendor>,
    pub hits: Vec<String>,
    pub blocking: bool,
}

impl WafSignals {
    #[must_use]
    pub const fn is_suspected(&self) -> bool {
        self.vendor.is_some()
    }

    /// Short evidence fragment, e.g. `" waf=cloudflare:cf-ray,body:just a
    /// moment blocking=true"`, or `""` when nothing was detected. Only
    /// signal *names* are included — never header values or body excerpts.
    #[must_use]
    pub fn evidence_suffix(&self) -> String {
        let Some(vendor) = self.vendor else {
            return String::new();
        };
        format!(
            " waf={}:{} blocking={}",
            vendor,
            self.hits.join(","),
            self.blocking
        )
    }
}

/// Lower `confidence` by a fixed step when a blocking WAF was observed.
/// `0.9 → 0.6`: the finding stays visible but can no longer auto-qualify for
/// heavy extraction on its own. Never raises, never goes below `0.0`.
#[must_use]
pub fn downgrade_for_waf(confidence: f64) -> f64 {
    (confidence - 0.3).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::waf::detect_cloudflare_flat;
    use crate::detection::waf::tests::headers;

    #[test]
    fn downgrade_steps_down_and_floors() {
        assert!((downgrade_for_waf(0.9) - 0.6).abs() < f64::EPSILON);
        assert!((downgrade_for_waf(0.75) - 0.45).abs() < f64::EPSILON);
        assert!((downgrade_for_waf(0.2) - 0.0).abs() < f64::EPSILON);
        assert!(downgrade_for_waf(1.5) <= 1.0);
    }

    #[test]
    fn evidence_suffix_format() {
        let r = detect_cloudflare_flat(200, &headers(&[("cf-ray", "x")]), b"ok");
        let suffix = r.evidence_suffix();
        assert!(suffix.starts_with(" waf=cloudflare:"), "{suffix}");
        assert!(suffix.contains("blocking=false"), "{suffix}");
        let clean = WafSignals::default();
        assert_eq!(clean.evidence_suffix(), "");
    }

    #[test]
    fn vendor_display_labels() {
        assert_eq!(WafVendor::Cloudflare.to_string(), "cloudflare");
        assert_eq!(WafVendor::Akamai.to_string(), "akamai");
        assert_eq!(WafVendor::Imperva.to_string(), "imperva");
        assert_eq!(WafVendor::ModSecurity.to_string(), "modsecurity");
        assert_eq!(WafVendor::F5.to_string(), "f5");
        assert_eq!(WafVendor::AwsWaf.to_string(), "aws-waf");
        assert_eq!(WafVendor::AwsAlb.to_string(), "aws-alb");
        assert_eq!(WafVendor::Sucuri.to_string(), "sucuri");
        assert_eq!(WafVendor::Fastly.to_string(), "fastly");
        assert_eq!(WafVendor::Varnish.to_string(), "varnish");
        assert_eq!(WafVendor::DataDome.to_string(), "datadome");
        assert_eq!(WafVendor::Kasada.to_string(), "kasada");
        assert_eq!(WafVendor::Human.to_string(), "human");
        assert_eq!(WafVendor::Turnstile.to_string(), "turnstile");
        assert_eq!(WafVendor::Generic.to_string(), "generic");
    }
}
