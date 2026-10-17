//! Secret handling gates (cookies/headers reuse across origins).

use crate::cli::args::Cli;
use secrecy::SecretString;

impl Cli {
    #[must_use]
    pub fn cookies_secret(&self) -> Option<SecretString> {
        self.http.cookies.clone().map(SecretString::from)
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
}
