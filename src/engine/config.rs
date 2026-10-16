#![deny(unsafe_code)]

use crate::{reasoning::knowledge::KnowledgeStore, target::raw_request::RawRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BudgetConfig {
    pub threads: usize,
    pub level: u8,
    pub request_budget: Option<usize>,
    /// Global detection time budget in seconds (Phase 3 `--max-duration`).
    /// `None` (default) = unlimited, historical behaviour byte-identical.
    /// SCOPE: detection phase only (clock starts in `run_detection` after
    /// baseline + context); never bounds the total run. OPT-IN hors
    /// profils/config-file (CLI/env only, range `0..=86400` enforced at parse).
    pub max_duration_secs: Option<u64>,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            threads: 5,
            level: 1,
            request_budget: None,
            max_duration_secs: None,
        }
    }
}

/// Cap for `--max-duration` (24h). MUST stay consistent with
/// `crate::cli::args::MAX_DURATION_SECS` (kept local: `cli::args` depends on
/// this module via `synthetic_raw_from_data`, so importing it here would
/// cycle). The CLI rejects larger values at parse time; programmatic
/// `BudgetConfig` values above it are clamped in
/// [`BudgetConfig::detection_deadline`].
pub const MAX_DETECTION_DURATION_SECS_CAP: u64 = 86_400;

impl BudgetConfig {
    /// `true` once `started` exceeds the configured `max_duration_secs`.
    /// `None` (default) never trips. Pure and unit-testable.
    ///
    /// SCOPE (PR20): `started` is the *detection* clock (set once in
    /// `run_detection`, AFTER baseline + context) — this never bounds the
    /// total run, only the detection loops. Compared as `Duration`
    /// (sub-second precision), not `as_secs()` truncation.
    #[must_use]
    pub fn is_over_max_duration(
        started: std::time::Instant,
        max_duration_secs: Option<u64>,
    ) -> bool {
        let Some(max) = max_duration_secs else {
            return false;
        };
        started.elapsed() >= std::time::Duration::from_secs(max)
    }

    /// Shared `--max-duration` deadline for mid-technique checks.
    /// `None` (default) = unlimited: every `is_past_deadline` call is a
    /// no-op and detection stays byte-identical. Pure and unit-testable.
    ///
    /// Overflow (PR20): `checked_add` returns `None` on overflow, which would
    /// conflate an explicit huge budget with "unlimited" (silent fail-open).
    /// User input can never reach it — the CLI rejects `> 86400s` at parse
    /// time (`crate::cli::args::MAX_DURATION_SECS`, mirrored as
    /// `MAX_DETECTION_DURATION_SECS_CAP` below since `cli` depends on this
    /// module and cannot be imported here). Programmatic values are clamped
    /// to that cap first, so `checked_add` only returns `None` in the
    /// pathological case of an `Instant` within one day of its maximum
    /// (practically unreachable): there `None` = effectively-infinite
    /// deadline, documented here rather than silent.
    #[must_use]
    pub fn detection_deadline(
        started: std::time::Instant,
        max_duration_secs: Option<u64>,
    ) -> Option<std::time::Instant> {
        let max = max_duration_secs?;
        let capped = max.min(MAX_DETECTION_DURATION_SECS_CAP);
        started.checked_add(std::time::Duration::from_secs(capped))
    }

    /// `true` once the shared `--max-duration` deadline has passed.
    /// `None` = unlimited (never trips). Pure and unit-testable.
    #[must_use]
    pub fn is_past_deadline(deadline: Option<std::time::Instant>) -> bool {
        deadline.is_some_and(|d| std::time::Instant::now() >= d)
    }

    /// `true` once the shared `request_count` reaches `request_budget`.
    /// `None` (default) never trips: historical behaviour byte-identical
    /// (A1 evasion needs ~1032 req live — no default cap, ever).
    ///
    /// CODE calibration (`--request-budget N`, OPT-IN): the per-parameter
    /// scheduler already caps each param at the same value via
    /// [`RequestBudget::max_requests`], but schedulers are per-param
    /// instances — only this check against the shared
    /// `SessionState::request_count` is a true global plafond. Cooperative:
    /// the running technique finishes, no new one starts, the run ends as
    /// [`EngineState::Inconclusive`] when no finding was produced (never an
    /// error, never a new finding).
    /// Concurrent params may overshoot by one technique each.
    /// Pure and unit-testable.
    #[must_use]
    pub fn is_over_request_budget(request_count: u64, request_budget: Option<usize>) -> bool {
        let Some(max) = request_budget else {
            return false;
        };
        u64::try_from(max).is_ok_and(|m| request_count >= m)
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct EvasionConfig {
    pub payload_opts: crate::techniques::payload_opts::PayloadOpts,
    pub tampers: Vec<crate::techniques::tamper::Tamper>,
    pub hpp: bool,
    pub chunked: bool,
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct NetConfig {
    pub allow_private: bool,
    pub remote_dns: bool,
    pub ignore_codes: Vec<u16>,
    pub method_override: Option<String>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OobConfig {
    pub oob_domain: Option<String>,
    pub oob_poll_url: Option<String>,
    pub oob_wait_secs: u64,
}

impl Default for OobConfig {
    fn default() -> Self {
        Self {
            oob_domain: None,
            oob_poll_url: None,
            oob_wait_secs: 5,
        }
    }
}

/// Option B second-order actif borné (lab only, même-origine).
///
/// `enabled=false` (défaut) = 0 requête extra, chemin byte-identique.
/// `enabled=true` = `run_second_order()` stocke un marqueur bénin
/// (`u+8hex`, payload `'<marker>'` style union, jamais de RCE/stacked)
/// sur ≤`max_stores` params Body/Query/Header puis revisite `revisit_url`
/// (même-origine uniquement, max 2 GET séquentiels, `RequestClass::Default`).
/// Les headers (`User-Agent`/`X-Forwarded-For`/`Referer`, souvent loggés en
/// base sans sanitisation) sont couverts comme les Body/Query.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SecondOrderConfig {
    pub enabled: bool,
    pub revisit_url: Option<String>,
    pub max_stores: usize,
}

impl Default for SecondOrderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            revisit_url: None,
            max_stores: 8,
        }
    }
}

impl SecondOrderConfig {
    /// Borne effective `1..=32` (défense en profondeur si construit à la main).
    /// `&self` (pas `const`): le struct porte des `String` (`Drop`), donc
    /// `const fn` par valeur est rejeté par le compilateur.
    #[must_use]
    pub fn effective_max_stores(&self) -> usize {
        self.max_stores.clamp(1, 32)
    }
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
#[non_exhaustive]
pub struct EnumConfig {
    pub extract: bool,
    pub dbs: bool,
    pub tables: bool,
    pub columns: bool,
    pub dump: bool,
    pub banner: bool,
    pub current_user: bool,
    pub current_db: bool,
    pub hostname: bool,
    pub db: Option<String>,
    pub table: Option<String>,
    pub column: Option<String>,
    pub start: Option<usize>,
    pub stop: Option<usize>,
    pub count: bool,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EngineConfig {
    pub budget: BudgetConfig,
    pub evasion: EvasionConfig,
    pub net: NetConfig,
    pub oob: OobConfig,
    pub enumeration: EnumConfig,
    pub second_order: SecondOrderConfig,

    pub techniques: Vec<String>,
    pub test_params: Vec<String>,
    pub post_data: Option<String>,
    pub matcher: crate::detection::matcher::MatcherConfig,
    pub confirm: bool,
    pub seed: Option<u64>,
    /// C5-tardif escape hatch (`--no-mutation`): when `true`, the
    /// confirm-second-pass mini-mutation is fully skipped (0 extra request,
    /// 0 trace record). Default `false` = mutation ON but strictly scoped
    /// (confirmed findings only, ≤4 variants / ≤8 req per finding).
    pub no_mutation: bool,
    /// `--explain <param>`: after the run, print the one-line reasoning
    /// verdict for the matching finding (`id@query`). `None` = no explain.
    pub explain: Option<String>,
    pub no_redact: bool,
    pub dbms_hint: Option<String>,
    pub marker: Option<String>,
    pub raw_request: Option<RawRequest>,
    /// C13 Knowledge Engine (opt-in) : `None` = OFF, RAM-only, boost `1.0`
    /// neutre (chemin byte-identique au sans-knowledge). `Some(store)` =
    /// snapshot lu au boot (`--allow-knowledge`), boost `1+alpha` borné
    /// `[0.5,1.5]` puis clamp scheduler `[0.5,2.0]` (jamais de veto).
    pub knowledge: Option<KnowledgeStore>,
    /// `--ai-suggest` second-pass (opt-in post-échec/WAF). `enabled == false`
    /// (défaut) = 0 appel LLM, chemin byte-identical. Config RAM-only, clé
    /// API `SecretString` redacted en `Debug`.
    pub ai: crate::ai::AiSuggestConfig,
    /// Génération à la volée par grammaire (`--generative`, `--max-generated`).
    /// `mode == Off` (défaut) = listes historiques, chemin byte-identical.
    /// Config RAM-only, aucun secret.
    pub generative: crate::generation::GenerativeConfig,
}

impl EngineConfig {
    #[must_use]
    pub fn test_defaults() -> Self {
        let mut cfg = Self::default();
        cfg.budget.threads = 1;
        cfg.net.allow_private = true;
        cfg.no_redact = true;
        cfg
    }
}

/// Request-level evasion options live in [`crate::target::injection::ProbeOpts`].
/// Re-exported at the top of this module for backward compatibility.
impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            budget: BudgetConfig::default(),
            evasion: EvasionConfig::default(),
            net: NetConfig::default(),
            oob: OobConfig::default(),
            enumeration: EnumConfig::default(),
            second_order: SecondOrderConfig::default(),
            techniques: vec![
                "boolean".to_owned(),
                "time".to_owned(),
                "error".to_owned(),
                "union".to_owned(),
            ],
            test_params: Vec::new(),
            post_data: None,
            matcher: crate::detection::matcher::MatcherConfig::default(),
            confirm: false,
            seed: None,
            no_mutation: false,
            explain: None,
            no_redact: false,
            dbms_hint: None,
            marker: None,
            raw_request: None,
            knowledge: None,
            ai: crate::ai::AiSuggestConfig::default(),
            generative: crate::generation::GenerativeConfig::default(),
        }
    }
}
