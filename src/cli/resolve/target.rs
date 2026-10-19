//! Target resolution: `--target` / positional / bulk / raw request precedence.

use crate::cli::args::{Cli, Commands};

impl Cli {
    /// C16 positional target location: the top-level `injekt <URL>`
    /// positional, else the `auto` subcommand's own `<URL|HOST>` positional.
    /// The whole precedence chain (raw-file > positional > flag > env) lives
    /// in [`Self::effective_target`].
    #[must_use]
    pub fn positional_target(&self) -> Option<&str> {
        self.target_positional.as_deref().or(match &self.command {
            Some(Commands::Auto(a)) => a.target_positional.as_deref(),
            _ => None,
        })
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
        // C16: the positional outranks the explicit flag / env (both parse
        // into `TargetOpts::target`). A positional that disagrees with a
        // CLI-typed `-u/--target` is a usage error raised by
        // `validate_target_conflict` at the command entry points; here we
        // only resolve deterministically.
        if let Some(pos) = self.positional_target() {
            return Some(pos.to_owned());
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
        if let Some(pos) = self.positional_target() {
            return Ok(Some(pos.to_owned()));
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
}
