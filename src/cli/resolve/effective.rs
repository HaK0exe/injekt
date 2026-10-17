//! Legacy `effective_*` getters (backward compatible): each resolves
//! through the memoised [`super::snapshot`] snapshot, so no extra I/O.

use crate::cli::args::Cli;
use crate::cli::profile::Profile;

impl Cli {
    /// Effective concurrency. Precedence: CLI/env > config file > profile > 5.
    /// Clamped to `>= 1`: `--threads 0` would make `buffer_unordered(0)`
    /// stall forever (self-DoS).
    #[must_use]
    pub fn effective_threads(&self) -> usize {
        if let Some(v) = self.detection.threads {
            return v.max(1);
        }
        let file = self.file_snapshot();
        if let Some(v) = file.threads {
            return v.max(1);
        }
        self.active_profile().map_or(5, Profile::threads).max(1)
    }

    /// Effective request timeout (seconds). Precedence: CLI/env > file > profile > 30.
    /// Clamped to `>= 1`: `--timeout 0` would time out every request.
    #[must_use]
    pub fn effective_timeout(&self) -> u64 {
        if let Some(v) = self.http.timeout {
            return v.max(1);
        }
        let file = self.file_snapshot();
        if let Some(v) = file.timeout {
            return v.max(1);
        }
        self.active_profile()
            .map_or(30, Profile::timeout_secs)
            .max(1)
    }

    /// Effective retry count. Precedence: CLI/env > file > profile > 3.
    #[must_use]
    pub fn effective_retries(&self) -> usize {
        if let Some(v) = self.http.retries {
            return v;
        }
        let file = self.file_snapshot();
        if let Some(v) = file.retries {
            return v;
        }
        self.active_profile().map_or(3, Profile::retries)
    }

    /// Effective retry base delay (ms). Precedence: CLI/env > file > profile > 500.
    #[must_use]
    pub fn effective_delay(&self) -> u64 {
        if let Some(v) = self.http.delay {
            return v;
        }
        let file = self.file_snapshot();
        if let Some(v) = file.delay {
            return v;
        }
        self.active_profile().map_or(500, Profile::delay_ms)
    }

    /// Effective rate limit (req/s). Always enforced; no unlimited mode.
    /// Precedence: CLI/env > file > profile > 10.0.
    #[must_use]
    pub fn effective_rate_limit(&self) -> f64 {
        if let Some(v) = self.http.rate_limit {
            return v;
        }
        let file = self.file_snapshot();
        if let Some(v) = file.rate_limit {
            return v;
        }
        self.active_profile().map_or(10.0, Profile::rate_limit_rps)
    }

    /// Effective jitter `"mean_ms,std_ms"`. Precedence: CLI/env > file > profile > `"750,250"`.
    #[must_use]
    pub fn effective_jitter(&self) -> String {
        if let Some(v) = self.http.jitter.clone() {
            return v;
        }
        let file = self.file_snapshot();
        if let Some(v) = file.jitter.clone() {
            return v;
        }
        self.active_profile()
            .map_or_else(|| "750,250".to_owned(), |p| p.jitter().to_owned())
    }

    /// Effective aggressiveness level 1-5. Precedence: CLI/env > file > profile > 1.
    #[must_use]
    pub fn effective_level(&self) -> u8 {
        if let Some(v) = self.detection.level {
            return v.clamp(1, 5);
        }
        let file = self.file_snapshot();
        if let Some(v) = file.level {
            return v.clamp(1, 5);
        }
        self.active_profile().map_or(1, Profile::level)
    }

    /// Effective deterministic seed. Precedence: CLI/env > file.
    /// Profiles never set a seed (reproducibility is explicit opt-in).
    #[must_use]
    pub fn effective_seed(&self) -> Option<u64> {
        if let Some(v) = self.detection.seed {
            return Some(v);
        }
        self.file_snapshot().seed
    }

    /// Effective global detection time budget in seconds (Phase 3).
    /// `None` (default) = unlimited, historical behaviour byte-identical.
    /// Profiles / config file never set it (explicit opt-in only).
    #[must_use]
    pub const fn effective_max_duration(&self) -> Option<u64> {
        self.detection.max_duration
    }

    /// Effective global request budget (CODE calibration).
    /// `None` (default) = unlimited, historical behaviour byte-identical.
    /// Profiles / config file never set it (explicit opt-in only, like
    /// `--max-duration`): only `--request-budget N` / `INJEKT_REQUEST_BUDGET`
    /// enables the cooperative global stop.
    #[must_use]
    pub const fn effective_request_budget(&self) -> Option<usize> {
        self.detection.request_budget
    }

    /// C13 opt-in gate: `false` par défaut → RAM-only, aucune IO knowledge,
    /// boost neutre `1.0` (chemin byte-identique au sans-knowledge).
    #[must_use]
    pub const fn knowledge_enabled(&self) -> bool {
        self.allow_knowledge
    }

    /// Borne effective second-order `1..=32` (clap garantit déjà la range ;
    /// clamp défensif pour les constructions manuelles). Défaut 8.
    #[must_use]
    pub const fn effective_second_order_max_stores(&self) -> usize {
        let v = self.evasion.second_order_max_stores as usize;
        if v < 1 {
            1
        } else if v > 32 {
            32
        } else {
            v
        }
    }

    /// Chemin effectif du store (`--knowledge-path` > `INJEKT_KNOWLEDGE_PATH` >
    /// `~/.cache/injekt/knowledge.json`). Non résolu / non touché quand OFF.
    #[must_use]
    pub fn effective_knowledge_path(&self) -> std::path::PathBuf {
        crate::reasoning::knowledge::resolve_knowledge_path(self.knowledge_path.as_deref())
    }

    /// Effective technique list. Non-empty CLI `--techniques` always wins
    /// (explicit, non-breaking); then config file; then profile; then `["all"]`.
    #[must_use]
    pub fn effective_techniques(&self) -> Vec<String> {
        if !self.detection.techniques.is_empty() {
            return self.detection.techniques.clone();
        }
        let file = self.file_snapshot();
        if let Some(v) = file.techniques.clone()
            && !v.is_empty()
        {
            return v;
        }
        self.active_profile()
            .map_or_else(|| vec!["all".to_owned()], Profile::techniques)
    }

    /// Effective proxy URL. Precedence: CLI/env > config file. Profiles never
    /// set a proxy (OPSEC: explicit opt-in only).
    #[must_use]
    pub fn effective_proxy(&self) -> Option<String> {
        if let Some(v) = self.http.proxy.clone() {
            return Some(v);
        }
        self.file_snapshot().proxy.clone()
    }

    /// Effective OOB wait (seconds). Precedence: CLI/env > file > 5.
    /// Profiles never change it (collaborator timing is operator-specific).
    #[must_use]
    pub fn effective_oob_wait_secs(&self) -> u64 {
        if let Some(v) = self.detection.oob_wait_secs {
            return v;
        }
        self.file_snapshot().oob_wait_secs.unwrap_or(5)
    }
}
