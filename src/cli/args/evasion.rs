#![deny(unsafe_code)]

use clap::Args;

/// Payload/request evasion (WAF bypass knobs, advanced).
#[derive(Clone, Args)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
pub struct EvasionOpts {
    /// Payload prefix prepended after tampers (e.g. "')")
    #[arg(long, global = true, help_heading = "Evasion", hide_short_help = true)]
    pub prefix: Option<String>,

    /// Payload suffix appended after tampers (e.g. "-- -")
    #[arg(long, global = true, help_heading = "Evasion", hide_short_help = true)]
    pub suffix: Option<String>,

    /// Extra chars exempted from percent-encoding (e.g. "(),")
    #[arg(long, global = true, help_heading = "Evasion", hide_short_help = true)]
    pub safe_chars: Option<String>,

    /// Send payloads without URL-encoding (use with care)
    #[arg(long, global = true, help_heading = "Evasion", hide_short_help = true)]
    pub skip_urlencode: bool,

    /// Disable the C5-tardif mini-mutation second-pass (escape hatch).
    /// Default is mutation ON but strictly scoped: only on already-confirmed
    /// findings, only from the `--confirm` second-pass, ≤4 variants / ≤8
    /// requests per finding, seeded, traced (`mutation:<famille>`), silent
    /// failure (the original finding is kept). No mutation ever runs in
    /// first-pass detection or on unconfirmed targets.
    #[arg(
        long = "no-mutation",
        global = true,
        help_heading = "Evasion",
        hide_short_help = true
    )]
    pub no_mutation: bool,

    /// Second-order actif borné (Option B, lab only, même-origine) : stocke
    /// un marqueur bénin `u+8hex` (payload `'<marker>'` style union, jamais
    /// de RCE/stacked) puis revisite `--second-order-revisit-url` (ex:
    /// `/admin`, max 2 GET séquentiels). OFF par défaut = 0 requête extra,
    /// chemin byte-identique.
    #[arg(
        long = "second-order",
        global = true,
        env = "INJEKT_SECOND_ORDER",
        requires = "second_order_revisit_url",
        help_heading = "Evasion",
        hide_short_help = true
    )]
    pub second_order: bool,

    /// URL de revisit second-order : chemin même-origine (ex: `/admin`) ou
    /// URL absolue même-origine que la cible. Schéma/host/port différent =
    /// erreur. Requis quand `--second-order` est actif.
    #[arg(
        long,
        global = true,
        env = "INJEKT_SECOND_ORDER_REVISIT_URL",
        requires = "second_order",
        help_heading = "Evasion",
        hide_short_help = true
    )]
    pub second_order_revisit_url: Option<String>,

    /// Nombre max de params Body/Query/Header stockés en second-order [default: 8, range 1..=32].
    /// 1 store + max 2 revisits GET par param, séquentiel, `RequestClass::Default`.
    /// Les headers exotiques (User-Agent/X-Forwarded-For/Referer, souvent loggés
    /// en base) sont couverts comme les Body/Query.
    #[arg(
        long,
        global = true,
        default_value_t = 8,
        value_parser = clap::value_parser!(u8).range(1..=32),
        env = "INJEKT_SECOND_ORDER_MAX_STORES",
        help_heading = "Evasion",
        hide_short_help = true
    )]
    pub second_order_max_stores: u8,

    /// HTTP Parameter Pollution: duplicate param (?id=1&id=PAYLOAD) for Query/Body — WAFs inspecting only first occurrence are bypassed
    #[arg(long, global = true, help_heading = "Evasion")]
    pub hpp: bool,

    /// Chunked transfer: send Body injections with Transfer-Encoding: chunked (streamed) to bypass content-length inspection
    #[arg(long, global = true, help_heading = "Evasion")]
    pub chunked: bool,
}

// Manual `Debug` for `EvasionOpts`: `--second-order-revisit-url` may carry
// secrets in query strings — scrubbed, never printed raw.
impl core::fmt::Debug for EvasionOpts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let scrub = crate::session::scrubber::Scrubber::new(false);
        let scrubbed_opt = |v: &Option<String>| v.as_ref().map(|s| scrub.scrub(s));
        f.debug_struct("EvasionOpts")
            .field("prefix", &self.prefix)
            .field("suffix", &self.suffix)
            .field("safe_chars", &self.safe_chars)
            .field("skip_urlencode", &self.skip_urlencode)
            .field("no_mutation", &self.no_mutation)
            .field("second_order", &self.second_order)
            .field(
                "second_order_revisit_url",
                &scrubbed_opt(&self.second_order_revisit_url),
            )
            .field("second_order_max_stores", &self.second_order_max_stores)
            .field("hpp", &self.hpp)
            .field("chunked", &self.chunked)
            .finish_non_exhaustive()
    }
}
