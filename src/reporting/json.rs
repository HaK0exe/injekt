#![deny(unsafe_code)]

use crate::{
    engine::diagnostics::Diagnostic,
    reporting::evidence::Evidence,
    session::{
        scrubber::Scrubber,
        state::{Detectability, Finding},
    },
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct JsonReport {
    pub target: String,
    pub findings: Vec<Finding>,
    pub evidences: Vec<Evidence>,
    /// Extracted DB data (banner, tables, dump rows, …) collected during the
    /// scan — the actual payoff of `--dump`/`--banner`/`--current-user`/etc.
    /// Previously only ever reachable via `--export-encrypted`; now surfaced
    /// in the plain report too so it isn't silently lost when that flag is
    /// omitted.
    pub extracted: Vec<String>,
    pub request_count: u64,
    /// Throttle detectability (C10, bench Annexe A): `403`/`429` observed
    /// during the run. `run.py compare` gates A3 `0×429 p95` on this.
    /// `#[serde(default)]` keeps pre-C10 readers/exports parsing.
    #[serde(default)]
    pub detectability: Detectability,
    /// Run provenance for benchmarking (C1 metrology): flattened to top-level
    /// keys so `bench/runner` parsers read them without nesting. Purely
    /// additive — existing readers (`request_count`, `findings`) are unaffected.
    #[serde(flatten)]
    pub meta: ReportMeta,
    /// C14 — diagnostic `INCONCLUSIVE` éventuel (cause figée + preuve +
    /// suggestion argv déjà scrubbée + why). `None` = run complet/clean :
    /// `skip_serializing_if` conserve **byte-identique** la forme historique
    /// du rapport (aucun consommateur pré-C14 ne voit une clé nouvelle),
    /// `#[serde(default)]` garde la désérialisation tolérante.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<Diagnostic>,
}

/// Provenance + effective run configuration attached to every [`JsonReport`].
/// Feeds `bench/reports/history.jsonl` (`version`, `seed`, `profile`,
/// `tampers`, `git_sha`) so runs are comparable across versions.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ReportMeta {
    /// Crate version (`CARGO_PKG_VERSION` at compile time).
    #[serde(default = "default_version")]
    pub version: String,
    /// Git SHA when built with `GIT_SHA` set (release/CI); `None` otherwise.
    #[serde(default)]
    pub git_sha: Option<String>,
    /// Effective `--seed` (`None` = nondeterministic historical behaviour).
    #[serde(default)]
    pub seed: Option<u64>,
    /// Active preset name (`quick|balanced|stealth|aggressive`), if any.
    #[serde(default)]
    pub profile: Option<String>,
    /// Effective techniques as run (post `--fetch-using` narrowing).
    #[serde(default)]
    pub techniques: Vec<String>,
    /// Effective aggressiveness level 1-5.
    #[serde(default = "default_level")]
    pub level: u8,
    /// Effective tamper names as run.
    #[serde(default)]
    pub tampers: Vec<String>,
}

fn default_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

fn default_level() -> u8 {
    1
}

impl Default for ReportMeta {
    fn default() -> Self {
        Self {
            version: default_version(),
            git_sha: option_env!("GIT_SHA").map(str::to_owned),
            seed: None,
            profile: None,
            techniques: Vec::new(),
            level: default_level(),
            tampers: Vec::new(),
        }
    }
}

impl ReportMeta {
    #[must_use]
    pub fn current(
        seed: Option<u64>,
        profile: Option<String>,
        techniques: Vec<String>,
        level: u8,
        tampers: Vec<String>,
    ) -> Self {
        Self {
            version: default_version(),
            git_sha: option_env!("GIT_SHA").map(str::to_owned),
            seed,
            profile,
            techniques,
            level,
            tampers,
        }
    }
}

impl JsonReport {
    #[must_use]
    pub fn new(
        target: impl Into<String>,
        findings: Vec<Finding>,
        evidences: Vec<Evidence>,
        extracted: Vec<String>,
        request_count: u64,
        meta: ReportMeta,
    ) -> Self {
        Self {
            target: target.into(),
            findings,
            evidences,
            extracted,
            request_count,
            detectability: Detectability::default(),
            meta,
            diagnostic: None,
        }
    }

    /// Attach the run's throttle detectability (C10).
    #[must_use]
    pub fn with_detectability(mut self, detectability: Detectability) -> Self {
        self.detectability = detectability;
        self
    }

    /// Attach the run's `INCONCLUSIVE` diagnostic (C14). `None` (run
    /// complet/clean) est un no-op explicite.
    #[must_use]
    pub fn with_diagnostic(mut self, diagnostic: Option<Diagnostic>) -> Self {
        self.diagnostic = diagnostic;
        self
    }

    #[must_use]
    pub fn scrubbed(&self, scrubber: &Scrubber) -> Self {
        let scrubbed_evidences: Vec<Evidence> = self
            .evidences
            .iter()
            .map(|e| e.scrubbed(scrubber))
            .collect();
        let scrubbed_findings: Vec<Finding> =
            self.findings.iter().map(|f| f.scrubbed(scrubber)).collect();
        Self {
            target: scrubber.scrub(&self.target),
            findings: scrubbed_findings,
            evidences: scrubbed_evidences,
            extracted: self.extracted.clone(),
            request_count: self.request_count,
            detectability: self.detectability,
            meta: self.meta.clone(),
            // C14 : la suggestion porte l'argv original (tokens possiblement
            // secrets) — scrub au moment de la sortie, jamais en interne.
            diagnostic: self.diagnostic.as_ref().map(|d| d.scrubbed(scrubber)),
        }
    }

    #[must_use]
    pub fn to_json(&self, scrubber: &Scrubber) -> String {
        let report = self.scrubbed(scrubber);
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_owned())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn meta_defaults_match_historical_behaviour() {
        let meta = ReportMeta::default();
        assert_eq!(meta.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(meta.seed, None);
        assert_eq!(meta.profile, None);
        assert_eq!(meta.techniques, [] as [String; 0]);
        assert_eq!(meta.level, 1);
        assert_eq!(meta.tampers, [] as [String; 0]);
    }

    #[test]
    fn report_serializes_provenance_top_level() {
        let meta = ReportMeta::current(
            Some(42),
            Some("stealth".to_owned()),
            vec!["boolean".to_owned()],
            1,
            vec!["space2comment".to_owned()],
        );
        let report = JsonReport::new(
            "https://example.com/?id=1",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            50,
            meta,
        );
        let value: serde_json::Value =
            serde_json::from_str(&report.to_json(&Scrubber::new(false))).expect("valid json");
        assert_eq!(value["seed"], 42);
        assert_eq!(value["profile"], "stealth");
        assert_eq!(value["techniques"], serde_json::json!(["boolean"]));
        assert_eq!(value["level"], 1);
        assert_eq!(value["tampers"], serde_json::json!(["space2comment"]));
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["request_count"], 50);
    }

    #[test]
    fn report_carries_detectability_by_default_and_explicit() {
        let meta = ReportMeta::default();
        let report = JsonReport::new(
            "https://example.com/?id=1",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            7,
            meta,
        );
        let value: serde_json::Value =
            serde_json::from_str(&report.to_json(&Scrubber::new(false))).expect("valid json");
        assert_eq!(value["detectability"]["count_403"], 0);
        assert_eq!(value["detectability"]["count_429"], 0);
        let report = report.with_detectability(Detectability::new(2, 3));
        let value: serde_json::Value =
            serde_json::from_str(&report.to_json(&Scrubber::new(false))).expect("valid json");
        assert_eq!(value["detectability"]["count_403"], 2);
        assert_eq!(value["detectability"]["count_429"], 3);
    }

    #[test]
    fn report_without_diagnostic_stays_byte_identical() {
        // C14 : aucun diagnostic ⇒ aucune clé nouvelle (consommateurs
        // pré-C14 byte-identiques).
        let report = JsonReport::new(
            "https://example.com/?id=1",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            1,
            ReportMeta::default(),
        );
        let value: serde_json::Value =
            serde_json::from_str(&report.to_json(&Scrubber::new(false))).expect("valid json");
        assert!(value.get("diagnostic").is_none(), "{}", value);
    }

    #[test]
    fn report_scrubs_the_attached_diagnostic() {
        let diag = Diagnostic::derive(&crate::engine::diagnostics::DiagSignals {
            count_429: 9,
            argv: vec![
                "--target".to_owned(),
                "https://lab.tld/?id=1&token=abcd".to_owned(),
            ],
            ..crate::engine::diagnostics::DiagSignals::default()
        })
        .expect("rate limited derives");
        let report = JsonReport::new(
            "https://example.com/?id=1",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            1,
            ReportMeta::default(),
        )
        .with_diagnostic(Some(diag));
        let scrubbed = report.scrubbed(&Scrubber::new(false));
        let suggestion = scrubbed
            .diagnostic
            .as_ref()
            .and_then(|d| d.suggestion.clone())
            .expect("suggestion present");
        assert!(
            !suggestion.contains("abcd"),
            "raw token in scrubbed report: {suggestion}"
        );
        let value: serde_json::Value =
            serde_json::from_str(&scrubbed.to_json(&Scrubber::new(false))).expect("valid json");
        assert_eq!(value["diagnostic"]["cause"], "RateLimited");
        assert!(
            !value["diagnostic"]["suggestion"]
                .as_str()
                .unwrap_or_default()
                .contains("abcd"),
            "raw token serialized: {}",
            value["diagnostic"]
        );
    }

    #[test]
    fn report_serializes_diagnostic_with_default_key_order() {
        let diag = Diagnostic::derive(&crate::engine::diagnostics::DiagSignals {
            over_request_budget: true,
            argv: vec!["--target".to_owned(), "https://lab.tld/".to_owned()],
            ..crate::engine::diagnostics::DiagSignals::default()
        })
        .expect("budget derives");
        let report = JsonReport::new(
            "https://example.com/?id=1",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            1,
            ReportMeta::default(),
        )
        .with_diagnostic(Some(diag));
        let value: serde_json::Value =
            serde_json::from_str(&report.to_json(&Scrubber::new(false))).expect("valid json");
        assert_eq!(value["diagnostic"]["cause"], "BudgetExhausted");
        assert!(value["diagnostic"]["suggestion"].is_null());
        assert!(value.get("diagnostic").is_some());
    }
}
