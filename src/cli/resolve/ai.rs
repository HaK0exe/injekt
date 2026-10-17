//! `--ai-suggest` option resolution + validation.

use crate::cli::args::Cli;

impl Cli {
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
            return Err("--ai-suggest requires --ai-provider <openai|anthropic>".to_owned());
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

    /// Normalized generation mode (`--generative`). `None`/unknown →
    /// `Off` (fail-closed, byte-identical default).
    #[must_use]
    pub fn effective_generative_mode(&self) -> crate::generation::GenerativeMode {
        self.detection
            .generative
            .as_deref()
            .and_then(crate::generation::GenerativeMode::from_name)
            .unwrap_or(crate::generation::GenerativeMode::Off)
    }

    /// Effective generated-pairs cap `0..=MAX_GENERATED` (clap garantit déjà la range ;
    /// clamp défensif pour les constructions manuelles). Défaut 4.
    #[must_use]
    pub const fn effective_max_generated(&self) -> u8 {
        let v = self.detection.max_generated;
        if v > crate::generation::MAX_GENERATED {
            crate::generation::MAX_GENERATED
        } else {
            v
        }
    }
}
