#![deny(unsafe_code)]

use crate::cli::args::{Cli, Commands};
use crate::cli::profile::Profile;
use crate::http::redirects::RedirectPolicy;
use secrecy::SecretString;

impl Cli {
    #[must_use]
    pub fn cookies_secret(&self) -> Option<SecretString> {
        self.http.cookies.clone().map(SecretString::from)
    }

    /// Load the config file snapshot for this invocation.
    /// Explicit `--config` errors are logged and ignored here (the scan
    /// entry points surface them); auto-discovered files never fail.
    fn file_snapshot(&self) -> crate::cli::file_config::FileConfig {
        match crate::cli::file_config::load(self.config.as_deref()) {
            Ok(Some((path, cfg))) => {
                tracing::debug!(path=%path.display(), "config file loaded");
                cfg
            }
            Ok(None) => crate::cli::file_config::FileConfig::default(),
            Err(e) => {
                tracing::warn!(error=%e, "invalid --config file, ignoring");
                crate::cli::file_config::FileConfig::default()
            }
        }
    }

    /// Active preset: explicit `--profile` (or `INJEKT_PROFILE`) wins over the
    /// `profile` key from the config file. Unknown file profile names warn.
    #[must_use]
    pub fn active_profile(&self) -> Option<Profile> {
        if let Some(p) = self.profile {
            return Some(p);
        }
        let file = self.file_snapshot();
        if file.profile.is_some() {
            let resolved = file.file_profile();
            if resolved.is_none() {
                tracing::warn!(
                    profile=?file.profile,
                    available=?Profile::all_names(),
                    "unknown profile in config file, ignoring"
                );
            }
            return resolved;
        }
        None
    }

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

    /// Effective AI suggestion count `1..=5` (clap garantit déjà la range ;
    /// clamp défensif pour les constructions manuelles). Défaut 3.
    #[must_use]
    pub const fn effective_ai_max_suggestions(&self) -> u8 {
        let v = self.detection.ai_max_suggestions;
        if v < 1 {
            1
        } else if v > 5 {
            5
        } else {
            v
        }
    }

    /// Effective LLM provider timeout in seconds. Clamped to `>= 1`.
    #[must_use]
    pub const fn effective_ai_timeout(&self) -> u64 {
        if self.detection.ai_timeout < 1 {
            1
        } else {
            self.detection.ai_timeout
        }
    }

    /// Normalized AI provider (`openai` / `anthropic`), lowercase-trimmed.
    /// `None` when unset. Unknown values yield `None` (caller fails closed).
    #[must_use]
    pub fn effective_ai_provider(&self) -> Option<String> {
        let raw = self.detection.ai_provider.as_deref()?;
        let norm = raw.trim().to_ascii_lowercase();
        match norm.as_str() {
            "openai" | "anthropic" => Some(norm),
            _ => None,
        }
    }

    /// Fail fast on incoherent `--ai-*` options. OFF (`ai_suggest == false`)
    /// always passes (byte-identical default, no behaviour change).
    ///
    /// # Errors
    /// Returns an error when `--ai-suggest` lacks `--ai-provider`,
    /// `--ai-endpoint` or `--ai-model`, when the provider is unknown, or
    /// when the endpoint is not an `http(s)://` URL.
    pub fn validate_ai_opts(&self) -> Result<(), String> {
        if !self.detection.ai_suggest {
            return Ok(());
        }
        let provider = self.effective_ai_provider();
        if provider.is_none() {
            return Err(
                "--ai-suggest requires --ai-provider <openai|anthropic>".to_owned(),
            );
        }
        let endpoint = self.detection.ai_endpoint.as_deref().unwrap_or("").trim();
        if endpoint.is_empty() {
            return Err("--ai-suggest requires --ai-endpoint <URL>".to_owned());
        }
        if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
            return Err(format!(
                "invalid --ai-endpoint '{endpoint}': expected http:// or https:// URL"
            ));
        }
        let model = self.detection.ai_model.as_deref().unwrap_or("").trim();
        if model.is_empty() {
            return Err("--ai-suggest requires --ai-model <name>".to_owned());
        }
        Ok(())
    }

    /// Fail fast on an explicit `--config` path that cannot be read or parsed.
    /// Auto-discovered files never fail (they warn in [`Self::file_snapshot`]).
    ///
    /// # Errors
    /// Returns an error describing the invalid explicit config file.
    pub fn validate_explicit_config(&self) -> Result<(), String> {
        let Some(path) = self.config.as_deref() else {
            return Ok(());
        };
        match std::fs::read_to_string(path) {
            Ok(content) => crate::cli::file_config::FileConfig::parse(&content)
                .map(|_| ())
                .map_err(|e| format!("invalid config file {path}: {e}")),
            Err(e) => Err(format!("cannot read config file {path}: {e}")),
        }
    }

    /// One-line summary of the active preset/config for `tracing::info!` logs.
    /// Keeps startup output readable without dumping every resolved knob.
    #[must_use]
    pub fn resolution_summary(&self) -> String {
        let profile = self.active_profile().map_or_else(
            || "none".to_owned(),
            |p| format!("{p:?}").to_ascii_lowercase(),
        );
        let config = self.config.clone().unwrap_or_else(|| "auto".to_owned());
        format!(
            "profile={profile} config={config} threads={} rate={} jitter={} level={}",
            self.effective_threads(),
            self.effective_rate_limit(),
            self.effective_jitter(),
            self.effective_level(),
        )
    }

    /// Assemble [`PayloadOpts`] from CLI flags. Unknown `--fetch-using`
    /// values fall back to `Direct` (clap constrains choices anyway).
    #[must_use]
    pub fn payload_opts(&self) -> crate::techniques::payload_opts::PayloadOpts {
        use crate::techniques::payload_opts::FetchUsing;
        let fetch_using = match self.detection.fetch_using.as_deref() {
            Some("boolean") => FetchUsing::Boolean,
            Some("time") => FetchUsing::Time,
            _ => FetchUsing::Direct,
        };
        crate::techniques::payload_opts::PayloadOpts {
            prefix: self.evasion.prefix.clone(),
            suffix: self.evasion.suffix.clone(),
            safe_chars: self.evasion.safe_chars.clone().unwrap_or_default(),
            skip_urlencode: self.evasion.skip_urlencode,
            fetch_using,
        }
    }

    /// Assemble [`MatcherConfig`](crate::detection::matcher::MatcherConfig)
    /// from CLI flags (`--string`, `--not-string`, `--code`, `--text-only`).
    #[must_use]
    pub fn matcher_config(&self) -> crate::detection::matcher::MatcherConfig {
        crate::detection::matcher::MatcherConfig {
            string: self.detection.string.clone(),
            not_string: self.detection.not_string.clone(),
            code: self.detection.code,
            text_only: self.detection.text_only,
        }
    }

    /// Assemble tuning config from CLI flags (`--level`, `--confirm`, `--ignore-code`).
    #[must_use]
    pub fn tuning_config(&self) -> (u8, bool, Vec<u16>) {
        (
            self.effective_level(),
            self.detection.confirm,
            self.detection.ignore_codes.clone(),
        )
    }

    #[must_use]
    pub fn effective_target(&self) -> Option<String> {
        if let Some(raw) = &self.target_opts.raw_file {
            let content = match crate::target::ingest::read_limited_file(
                raw,
                crate::target::ingest::MAX_RAW_FILE_BYTES,
            ) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error=%e, path=%raw, "failed to read raw file");
                    return None;
                }
            };
            let req = match crate::target::raw_request::RawRequest::parse(&content) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error=%e, path=%raw, "failed to parse raw file");
                    return None;
                }
            };
            if let Some(url) = req.to_url_with_port_hint() {
                return Some(url);
            }
            tracing::warn!(path=%raw, "raw request missing Host header or invalid path");
            return None;
        }
        self.target_opts
            .target
            .clone()
            .or_else(|| match &self.command {
                Some(Commands::Scan(a)) => a.target.clone(),
                _ => None,
            })
    }

    /// Same resolution as [`Self::effective_target`], but propagates raw-file
    /// read/parse failures as errors instead of silently returning `None`
    /// (prevents a malformed `--raw` file from being mistaken for "no
    /// target").
    ///
    /// # Errors
    /// Returns an error if `--raw` is set but the file cannot be read,
    /// fails to parse as a raw HTTP request, or lacks a usable Host header.
    pub fn try_effective_target(&self) -> anyhow::Result<Option<String>> {
        if let Some(raw) = &self.target_opts.raw_file {
            let content = crate::target::ingest::read_limited_file(
                raw,
                crate::target::ingest::MAX_RAW_FILE_BYTES,
            )
            .map_err(|e| anyhow::anyhow!("failed to read raw file '{raw}': {e}"))?;
            let req = crate::target::raw_request::RawRequest::parse(&content)
                .map_err(|e| anyhow::anyhow!("failed to parse raw file '{raw}': {e}"))?;
            if let Some(url) = req.to_url_with_port_hint() {
                return Ok(Some(url));
            }
            anyhow::bail!("raw request in '{raw}' missing Host header or invalid path");
        }
        Ok(self
            .target_opts
            .target
            .clone()
            .or_else(|| match &self.command {
                Some(Commands::Scan(a)) => a.target.clone(),
                _ => None,
            }))
    }

    #[must_use]
    pub fn raw_request(&self) -> Option<crate::target::raw_request::RawRequest> {
        let path = self.target_opts.raw_file.as_ref()?;
        let content = match crate::target::ingest::read_limited_file(
            path,
            crate::target::ingest::MAX_RAW_FILE_BYTES,
        ) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error=%e, path=%path, "failed to read raw file");
                return None;
            }
        };
        match crate::target::raw_request::RawRequest::parse(&content) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(error=%e, path=%path, "failed to parse raw file");
                None
            }
        }
    }

    /// Fused raw request: `--raw-file` base + `--method` / `--headers` /
    /// `--cookies` / `--data` overlays. CLI flags win over the file; the file
    /// wins over `--data` (with a warning when both carry a body).
    #[must_use]
    pub fn merged_raw_request(&self) -> Option<crate::target::raw_request::RawRequest> {
        let mut base = self.raw_request();
        // `--data` alone becomes a synthetic POST raw (same path as raw-file).
        if base.is_none()
            && let Some(data) = self.detection.data.as_deref()
        {
            let trimmed = data.trim();
            if !trimmed.is_empty() {
                base = crate::engine::orchestrator::synthetic_raw_from_data(trimmed);
            }
        }
        // `--headers`/`--cookies` alone (no file, no `--data`) still need a
        // raw to fuse into, otherwise cookie/header params are never
        // discovered and the flags only ride along passively.
        if base.is_none()
            && (!self.http.headers.is_empty()
                || self
                    .http
                    .cookies
                    .as_deref()
                    .is_some_and(|c| !c.trim().is_empty()))
        {
            base = Some(crate::target::raw_request::RawRequest {
                method: "GET".to_owned(),
                path: "/".to_owned(),
                headers: std::collections::HashMap::new(),
                body: None,
                http_version: "HTTP/1.1".to_owned(),
            });
        }
        let mut req = base?;
        // `--method` overrides the file method (validated later; uppercased here).
        if let Some(m) = self.http.method.as_deref() {
            let m = m.trim();
            if !m.is_empty() {
                req.method = m.to_ascii_uppercase();
            }
        }
        // `--headers "Name: value"` override / extend the file headers
        // (keys are lowercased, matching `RawRequest::parse` canonical form).
        for h in &self.http.headers {
            let Some((name, value)) = h.split_once(':') else {
                continue;
            };
            let key = name.trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            req.headers.insert(key, value.trim().to_owned());
        }
        // `--cookies` merges with the file `Cookie` header (`; `-joined),
        // preserving both the Burp session and the CLI session.
        if let Some(cookies) = self.http.cookies.as_deref() {
            let cookies = cookies.trim();
            if !cookies.is_empty() {
                let merged = match req.headers.get("cookie") {
                    Some(existing) if !existing.trim().is_empty() => {
                        format!("{}; {cookies}", existing.trim())
                    }
                    _ => cookies.to_owned(),
                };
                req.headers.insert("cookie".to_owned(), merged);
            }
        }
        // `--data` fills an empty body only; a file body always wins.
        if let Some(data) = self.detection.data.as_deref() {
            let trimmed = data.trim();
            let file_has_body = req.body.as_deref().is_some_and(|b| !b.trim().is_empty());
            if !trimmed.is_empty() && !file_has_body {
                req.body = Some(trimmed.to_owned());
                if !req.headers.contains_key("content-type") {
                    let kind = crate::target::structured::sniff_kind(None, trimmed);
                    let ct = match kind {
                        crate::target::structured::StructuredKind::Json => "application/json",
                        crate::target::structured::StructuredKind::Xml => "application/xml",
                        _ => "application/x-www-form-urlencoded",
                    };
                    req.headers.insert("content-type".to_owned(), ct.to_owned());
                }
            }
        }
        Some(req)
    }

    /// `true` when the proxy performs remote DNS (`socks5h://`): local
    /// DNS-time SSRF resolution must be skipped (no local leak, no false
    /// `.onion` failure). Lexical + IP-literal checks still apply.
    #[must_use]
    pub fn uses_remote_dns(&self) -> bool {
        self.effective_proxy()
            .is_some_and(|p| p.to_ascii_lowercase().starts_with("socks5h://"))
    }

    /// Effective redirect policy from `--max-redirects` (`None` = 5).
    /// `0` means "do not follow" ([`RedirectPolicy::None`]); values above
    /// 10 are clamped defensively (clap already constrains CLI input, but
    /// MCP/manual constructions bypass it).
    #[must_use]
    pub fn effective_redirect_policy(&self) -> RedirectPolicy {
        match self.http.max_redirects.unwrap_or(5) {
            0 => RedirectPolicy::None,
            n => RedirectPolicy::Limited(usize::from(n.min(10))),
        }
    }

    /// `true` when operator auth secrets are configured (`--cookies` or an
    /// `Authorization:`/`Cookie:` header): replaying them outside their
    /// origin leaks sessions.
    #[must_use]
    pub fn has_auth_secrets(&self) -> bool {
        if self
            .http
            .cookies
            .as_deref()
            .is_some_and(|c| !c.trim().is_empty())
        {
            return true;
        }
        self.http.headers.iter().any(|h| {
            h.split_once(':').is_some_and(|(name, _)| {
                name.trim().eq_ignore_ascii_case("authorization")
                    || name.trim().eq_ignore_ascii_case("cookie")
            })
        })
    }

    /// Fail-closed gate against cross-origin secret replay: a run whose
    /// targets span more than one origin (scheme/host/port) while auth
    /// secrets are configured is refused unless `--allow-secret-reuse` was
    /// passed explicitly. Single-origin runs always pass. The error carries
    /// only the origin count, never target URLs (which may hold tokens).
    ///
    /// # Errors
    /// Returns an error when secrets would be sprayed across origins
    /// without explicit opt-in.
    pub fn check_secret_reuse(&self, targets: &[String]) -> anyhow::Result<()> {
        if self.allow_secret_reuse || !self.has_auth_secrets() {
            return Ok(());
        }
        let mut origins = std::collections::HashSet::new();
        for target in targets {
            match url::Url::parse(target) {
                Ok(parsed) => {
                    origins.insert((
                        parsed.scheme().to_owned(),
                        parsed.host_str().unwrap_or("").to_ascii_lowercase(),
                        parsed.port_or_known_default(),
                    ));
                }
                // Unparseable lines were already rejected at ingestion; count
                // them as distinct so the gate fails closed, never open.
                Err(_) => {
                    origins.insert((String::new(), target.clone(), None));
                }
            }
            if origins.len() > 1 {
                anyhow::bail!(
                    "refusing to replay --cookies/--headers across {} origins; pass --allow-secret-reuse to confirm cross-origin secret reuse",
                    origins.len()
                );
            }
        }
        Ok(())
    }

    /// Normalized `--dbms` hint (`mysql|postgres|mssql|oracle|sqlite`) or `None`
    /// when absent/unknown (unknown warns, falls back to auto-fingerprint).
    #[must_use]
    pub fn normalized_dbms_hint(&self) -> Option<String> {
        let raw = self.detection.dbms.as_deref()?;
        let v = raw.trim().to_ascii_lowercase();
        // Accept common aliases.
        let norm = match v.as_str() {
            "mysql" | "mariadb" | "my" => "mysql",
            "postgres" | "postgresql" | "pg" | "pgsql" => "postgres",
            "mssql" | "sqlserver" | "sql-server" | "tsql" => "mssql",
            "oracle" | "ora" => "oracle",
            "sqlite" => "sqlite",
            _ => {
                tracing::warn!(dbms=%raw, "unknown --dbms, ignoring (auto-fingerprint)");
                return None;
            }
        };
        Some(norm.to_owned())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::cli::args::{
        Cli, DetectionOpts, EnumOpts, EvasionOpts, HttpOpts, OutputOpts, ReportFormat, TargetOpts,
    };
    use crate::cli::profile::Profile;

    fn blank_cli() -> Cli {
        Cli {
            command: None,
            profile: None,
            // Point at a path that never exists so auto-discovered files
            // (`./injekt.toml`, `~/.config/...`) still apply, but the
            // explicit slot never shadows them in these unit tests.
            config: Some("/nonexistent-injekt-test-config-9f3a.toml".to_owned()),
            target_opts: TargetOpts {
                target: None,
                bulk_file: None,
                raw_file: None,
                raw_dir: None,
                stdin: false,
                openapi_file: None,
                sitemap_file: None,
            },
            http: HttpOpts {
                method: None,
                headers: Vec::new(),
                cookies: None,
                proxy: None,
                timeout: None,
                retries: None,
                delay: None,
                rate_limit: None,
                jitter: None,
                allow_private: false,
                max_redirects: None,
            },
            detection: DetectionOpts {
                threads: None,
                level: None,
                techniques: Vec::new(),
                tamper: Vec::new(),
                params: Vec::new(),
                data: None,
                fetch_using: None,
                dbms: None,
                marker: None,
                string: None,
                not_string: None,
                code: None,
                text_only: false,
                max_duration: None,
                request_budget: None,
                confirm: false,
                seed: None,
                ignore_codes: Vec::new(),
                oob_domain: None,
                oob_poll_url: None,
                oob_wait_secs: None,
            },
            evasion: EvasionOpts {
                prefix: None,
                suffix: None,
                safe_chars: None,
                skip_urlencode: false,
                no_mutation: false,
                second_order: false,
                second_order_revisit_url: None,
                second_order_max_stores: 8,
                hpp: false,
                chunked: false,
            },
            enumeration: EnumOpts {
                extract: false,
                dbs: false,
                tables: false,
                columns: false,
                dump: false,
                banner: false,
                current_user: false,
                current_db: false,
                hostname: false,
                db: None,
                table: None,
                column: None,
                start: None,
                stop: None,
                count: false,
            },
            output_opts: OutputOpts {
                output: None,
                format: ReportFormat::Json,
                dry_run: false,
                no_redact: false,
                explain: None,
                export_encrypted: None,
                import: None,
                force: false,
            },
            allow_secret_reuse: false,
            allow_knowledge: false,
            knowledge_path: None,
            verbose: false,
            no_banner: true,
        }
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn defaults_are_historical_without_profile() {
        let cli = blank_cli();
        assert_eq!(cli.effective_threads(), 5);
        assert_eq!(cli.effective_timeout(), 30);
        assert_eq!(cli.effective_retries(), 3);
        assert_eq!(cli.effective_delay(), 500);
        assert_eq!(cli.effective_rate_limit(), 10.0);
        assert_eq!(cli.effective_jitter(), "750,250");
        assert_eq!(cli.effective_level(), 1);
        assert_eq!(cli.effective_techniques(), vec!["all".to_owned()]);
        assert_eq!(cli.effective_oob_wait_secs(), 5);
        assert_eq!(cli.effective_proxy(), None);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn stealth_profile_defaults() {
        let mut cli = blank_cli();
        cli.profile = Some(Profile::Stealth);
        assert_eq!(cli.effective_threads(), 2);
        assert_eq!(cli.effective_rate_limit(), 3.0);
        assert_eq!(cli.effective_level(), 1);
        assert_eq!(
            cli.effective_techniques(),
            vec!["boolean".to_owned(), "error".to_owned()]
        );
    }

    #[test]
    fn explicit_cli_wins_over_profile() {
        let mut cli = blank_cli();
        cli.profile = Some(Profile::Stealth);
        cli.detection.threads = Some(9);
        cli.detection.level = Some(3);
        cli.detection.techniques = vec!["union".to_owned()];
        assert_eq!(cli.effective_threads(), 9);
        assert_eq!(cli.effective_level(), 3);
        assert_eq!(cli.effective_techniques(), vec!["union".to_owned()]);
    }

    #[test]
    fn seed_defaults_to_none_and_ignores_profile() {
        let cli = blank_cli();
        assert_eq!(cli.effective_seed(), None);
        let mut cli = blank_cli();
        cli.profile = Some(Profile::Stealth);
        assert_eq!(cli.effective_seed(), None);
    }

    #[test]
    fn redirect_policy_defaults_to_five_and_zero_disables() {
        use crate::http::redirects::RedirectPolicy;
        let cli = blank_cli();
        assert_eq!(cli.effective_redirect_policy(), RedirectPolicy::Limited(5));
        let mut cli = blank_cli();
        cli.http.max_redirects = Some(0);
        assert_eq!(cli.effective_redirect_policy(), RedirectPolicy::None);
        let mut cli = blank_cli();
        cli.http.max_redirects = Some(2);
        assert_eq!(cli.effective_redirect_policy(), RedirectPolicy::Limited(2));
        // Defensive clamp for non-clap constructions (e.g. MCP).
        let mut cli = blank_cli();
        cli.http.max_redirects = Some(u8::MAX);
        assert_eq!(cli.effective_redirect_policy(), RedirectPolicy::Limited(10));
    }

    #[test]
    fn secret_reuse_gate_blocks_multi_origin_spray() {
        let multi = [
            "https://a.example/?id=1".to_owned(),
            "https://b.example/?id=1".to_owned(),
        ];
        let single = ["https://a.example/?id=1".to_owned()];
        // No secrets: always passes, even multi-origin.
        assert!(blank_cli().check_secret_reuse(&multi).is_ok());
        // Secrets, single origin: passes (same-origin replay is legitimate).
        let mut cli = blank_cli();
        cli.http.cookies = Some("sess=abc".to_owned());
        assert!(cli.check_secret_reuse(&single).is_ok());
        assert!(cli.check_secret_reuse(&[]).is_ok());
        // Secrets, multi origin: fail-closed without the flag.
        let err = cli.check_secret_reuse(&multi).unwrap_err();
        assert!(err.to_string().contains("--allow-secret-reuse"), "{err}");
        // ... and the error never echoes targets (they may hold tokens).
        assert!(!err.to_string().contains("a.example"), "{err}");
        // Explicit opt-in passes.
        cli.allow_secret_reuse = true;
        assert!(cli.check_secret_reuse(&multi).is_ok());
        // Authorization / Cookie headers count as secrets too.
        let mut cli = blank_cli();
        cli.http.headers = vec!["Authorization: Bearer x".to_owned()];
        assert!(cli.has_auth_secrets());
        assert!(cli.check_secret_reuse(&multi).is_err());
        let mut cli = blank_cli();
        cli.http.headers = vec!["X-Custom: 1".to_owned()];
        assert!(!cli.has_auth_secrets());
        assert!(cli.check_secret_reuse(&multi).is_ok());
    }

    #[test]
    fn seed_cli_wins_over_file() {
        use std::io::Write as _;
        let mut path = std::env::temp_dir();
        path.push(format!("injekt-test-seed-{}.toml", std::process::id()));
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "seed = 42\n").unwrap();
        drop(file);
        let mut cli = blank_cli();
        cli.config = Some(path.to_string_lossy().into_owned());
        assert_eq!(cli.effective_seed(), Some(42));
        cli.detection.seed = Some(7);
        assert_eq!(cli.effective_seed(), Some(7));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn config_file_wins_over_profile() {
        use std::io::Write as _;
        let mut path = std::env::temp_dir();
        path.push(format!("injekt-test-{}.toml", std::process::id()));
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "profile = \"stealth\"\nthreads = 3\n").unwrap();
        drop(file);
        let mut cli = blank_cli();
        cli.config = Some(path.to_string_lossy().into_owned());
        // File says stealth + threads 3: threads from file, techniques from profile.
        assert_eq!(cli.effective_threads(), 3);
        assert_eq!(
            cli.effective_techniques(),
            vec!["boolean".to_owned(), "error".to_owned()]
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn explicit_config_validation_rejects_missing_file() {
        let mut cli = blank_cli();
        cli.config = Some("/nonexistent-injekt-test-config-9f3a.toml".to_owned());
        assert!(cli.validate_explicit_config().is_err());
        cli.config = None;
        assert!(cli.validate_explicit_config().is_ok());
    }

    #[test]
    fn max_duration_defaults_to_none_byte_identical() {
        // Phase 3: default None = unlimited, historical behaviour.
        let cli = blank_cli();
        assert_eq!(cli.effective_max_duration(), None);
        let mut cli = blank_cli();
        cli.detection.max_duration = Some(120);
        assert_eq!(cli.effective_max_duration(), Some(120));
    }

    #[test]
    fn max_duration_parses_from_cli() {
        use clap::Parser as _;
        let cli =
            Cli::try_parse_from(["injekt", "--max-duration", "60"]).unwrap_or_else(|_| blank_cli());
        assert_eq!(cli.effective_max_duration(), Some(60));
        let cli_default = Cli::try_parse_from(["injekt"]).unwrap_or_else(|_| blank_cli());
        // Explicit config slot may shadow auto-discovery in this harness;
        // the flag itself must be None when absent.
        assert!(
            cli_default.detection.max_duration.is_none(),
            "default --max-duration must be None"
        );
    }

    #[test]
    fn request_budget_defaults_to_none_byte_identical() {
        // CODE calibration: default None = unlimited, historical behaviour
        // (A1 evasion ~1032 req live must never trip a default cap).
        let cli = blank_cli();
        assert_eq!(cli.effective_request_budget(), None);
        let mut cli = blank_cli();
        cli.detection.request_budget = Some(25);
        assert_eq!(cli.effective_request_budget(), Some(25));
    }

    #[test]
    fn request_budget_parses_from_cli() {
        use clap::Parser as _;
        let cli = Cli::try_parse_from(["injekt", "--request-budget", "25"])
            .unwrap_or_else(|_| blank_cli());
        assert_eq!(cli.effective_request_budget(), Some(25));
        let cli_default = Cli::try_parse_from(["injekt"]).unwrap_or_else(|_| blank_cli());
        assert!(
            cli_default.detection.request_budget.is_none(),
            "default --request-budget must be None"
        );
    }

    #[test]
    fn budget_parsers_reject_absurd_values() {
        // PR20: absurd CLI values are rejected at parse time (no silent
        // `checked_add` overflow → unlimited, no unbounded request flood).
        assert_eq!(
            crate::cli::args::detection::parse_max_duration_secs("0"),
            Ok(0)
        );
        assert_eq!(
            crate::cli::args::detection::parse_max_duration_secs("86400"),
            Ok(86_400)
        );
        assert!(crate::cli::args::detection::parse_max_duration_secs("86401").is_err());
        assert!(crate::cli::args::detection::parse_max_duration_secs("99999999").is_err());
        assert!(crate::cli::args::detection::parse_max_duration_secs("nope").is_err());
        assert_eq!(
            crate::cli::args::detection::parse_request_budget("0"),
            Ok(0)
        );
        assert_eq!(
            crate::cli::args::detection::parse_request_budget("1000000"),
            Ok(1_000_000)
        );
        assert!(crate::cli::args::detection::parse_request_budget("1000001").is_err());
        assert!(crate::cli::args::detection::parse_request_budget("nope").is_err());
    }

    #[test]
    fn dbms_hint_normalizes_sqlite_and_aliases() {
        // P0-3: `--dbms sqlite` must survive normalization (was: rejected as
        // unknown, silently falling back to auto-fingerprint).
        let mut cli = blank_cli();
        cli.detection.dbms = Some("sqlite".to_owned());
        assert_eq!(cli.normalized_dbms_hint().as_deref(), Some("sqlite"));
        cli.detection.dbms = Some("  SQLITE ".to_owned());
        assert_eq!(cli.normalized_dbms_hint().as_deref(), Some("sqlite"));
        cli.detection.dbms = Some("pg".to_owned());
        assert_eq!(cli.normalized_dbms_hint().as_deref(), Some("postgres"));
        cli.detection.dbms = Some("nope".to_owned());
        assert_eq!(cli.normalized_dbms_hint(), None);
        let cli = blank_cli();
        assert_eq!(cli.normalized_dbms_hint(), None);
    }

    #[test]
    fn budget_flags_reject_absurd_cli_values() {
        // End-to-end through clap (flags + env share the same value_parser).
        use clap::Parser as _;
        assert!(Cli::try_parse_from(["injekt", "--max-duration", "99999999"]).is_err());
        assert!(Cli::try_parse_from(["injekt", "--request-budget", "99999999"]).is_err());
        assert_eq!(
            Cli::try_parse_from(["injekt", "--max-duration", "120"])
                .unwrap_or_else(|_| blank_cli())
                .effective_max_duration(),
            Some(120)
        );
    }
}
