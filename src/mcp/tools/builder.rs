use super::{InjektServer, ReconCrawlParams, ReconScanParams, ScanParams};
use crate::cli::args::{
    Cli, Commands, ReconArgs, ReconCommands, ReconCrawlArgs, ReconScanArgs, ScanArgs,
};
use rmcp::ErrorData;

impl InjektServer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cancel: tokio_util::sync::CancellationToken::new(),
        }
    }

    /// Validate an MCP `output` path: relative-only, no parent traversal.
    /// MCP agents must not overwrite arbitrary files; absolute paths and
    /// `..` are rejected with `invalid_params`. Writes use 0o600 on Unix
    /// with `create_new` (no overwrite, same model as `EncryptedExport`).
    /// The parent is canonicalized so symlink escapes fail fast.
    pub(super) fn validate_output_path(path: &str) -> Result<std::path::PathBuf, ErrorData> {
        use std::path::Component;
        let p = std::path::Path::new(path);
        if path.is_empty() {
            return Err(ErrorData::invalid_params("output path is empty", None));
        }
        if p.is_absolute() {
            return Err(ErrorData::invalid_params(
                "output must be a relative path (absolute paths rejected in MCP mode)",
                None,
            ));
        }
        if p.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(ErrorData::invalid_params(
                "output must not contain '..' (path traversal rejected)",
                None,
            ));
        }
        let Some(file_name) = p.file_name() else {
            return Err(ErrorData::invalid_params(
                "output path has no file name",
                None,
            ));
        };
        let parent = p.parent().unwrap_or_else(|| std::path::Path::new(""));
        let canonical_parent = if parent.as_os_str().is_empty() {
            std::fs::canonicalize(".").map_err(|e| {
                ErrorData::internal_error(format!("cannot canonicalize current dir: {e}"), None)
            })?
        } else {
            std::fs::canonicalize(parent).map_err(|e| {
                ErrorData::internal_error(
                    format!("cannot canonicalize parent '{}': {e}", parent.display()),
                    None,
                )
            })?
        };
        Ok(canonical_parent.join(file_name))
    }

    /// Opt-in disk write for MCP `output` param (already-scrubbed JSON).
    /// Uses `create_new` + `0o600` (no overwrite for OPSEC, like `EncryptedExport`).
    pub(super) fn write_output_file(path: &std::path::Path, json: &str) -> Result<(), ErrorData> {
        use std::io::Write as _;
        if json.len() > crate::cli::output::file::MAX_OUTPUT_BYTES {
            return Err(ErrorData::invalid_params("output report too large", None));
        }
        tracing::warn!(
            path=%path.display(),
            "MCP output requested — opt-in disk write (sensitive report, 0o600, no overwrite)"
        );
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                ErrorData::invalid_params(
                    "output file already exists (no overwrite for OPSEC; choose another path)",
                    None,
                )
            } else {
                ErrorData::internal_error(format!("output write failed: {e}"), None)
            }
        })?;
        file.write_all(json.as_bytes())
            .map_err(|e| ErrorData::internal_error(format!("output write failed: {e}"), None))?;
        file.write_all(b"\n")
            .map_err(|e| ErrorData::internal_error(format!("output write failed: {e}"), None))?;
        file.sync_all()
            .map_err(|e| ErrorData::internal_error(format!("output write failed: {e}"), None))?;
        Ok(())
    }

    pub(super) fn warn_no_redact(no_redact: bool) {
        if no_redact {
            tracing::warn!(
                "no_redact=true in MCP mode — redaction disabled, output may contain secrets (local debugging only)"
            );
        }
    }

    /// Base CLI with safe defaults; each tool overrides the relevant fields.
    /// Note: `raw_file` / `marker` / `method` / `import` / `replay` are
    /// intentionally not exposed via MCP (see docs/MCP.md); Burp raw bodies
    /// and marker modes stay CLI-only to keep the stdio surface minimal.
    #[allow(clippy::too_many_lines)] // test fixture: exhaustive struct literal grows with each new flag
    pub(super) fn base_cli() -> Cli {
        Cli {
            file_cache: std::sync::Arc::default(),
            // C14 : pas d'argv capturé par MCP (les outils construisent le
            // `Cli` programmatiquement) ⇒ le patch de suggestion rend `None`.
            captured_argv: Vec::new(),
            command: None,
            profile: None,
            config: None,
            quiet: false,
            target_opts: crate::cli::args::TargetOpts {
                target: None,
                bulk_file: None,
                raw_file: None,
                // C17 : `--input` est une shape CLI seulement — le MCP
                // continue d'exposer les modes individuels.
                input: None,
                raw_dir: None,
                stdin: false,
                openapi_file: None,
                sitemap_file: None,
            },
            http: crate::cli::args::HttpOpts {
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
                discover_params: false,
                max_discover: 0,
            },
            detection: crate::cli::args::DetectionOpts {
                threads: None,
                level: Some(1),
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
                // C17 : `--match`/`--veto` = shapes CLI — le MCP expose
                // toujours les paramètres string/not-string/code directs.
                match_expr: Vec::new(),
                veto_expr: Vec::new(),
                text_only: false,
                max_duration: None,
                // Budgets OPT-IN (None = illimité, comportement historique) :
                // exposés comme params MCP optionnels, câblés dans
                // `build_scan_cli` / `build_recon_scan`.
                request_budget: None,
                confirm: false,
                seed: None,
                ignore_codes: Vec::new(),
                oob_domain: None,
                oob_poll_url: None,
                oob_wait_secs: None,
                // `--ai-suggest` stays CLI-only (external LLM egress must be
                // an explicit operator opt-in, never via the MCP surface).
                ai_suggest: false,
                ai_provider: None,
                ai_endpoint: None,
                ai_model: None,
                ai_api_key: None,
                ai_max_suggestions: 3,
                ai_timeout: 30,
                // Generation stays CLI-only like `--ai-suggest` (explicit
                // operator opt-in; MCP keeps the historical lists).
                generative: None,
                max_generated: 4,
            },
            evasion: crate::cli::args::EvasionOpts {
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
            enumeration: crate::cli::args::EnumOpts {
                extract: false,
                // C17 : `--enum`/`--scope` sont des shapes CLI — le MCP
                // écrit les bools directs (shapes individuelles conservées).
                enum_items: Vec::new(),
                scope: None,
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
            output_opts: crate::cli::args::OutputOpts {
                output: None,
                // C16 : pas de format explicite côté MCP (default `json`
                // effectif à la résolution, extension désactivée : pas de
                // `--output` sur la surface stdio).
                format: None,
                dry_run: false,
                no_redact: false,
                explain: None,
                export_encrypted: None,
                import: None,
                force: false,
            },
            allow_secret_reuse: false,
            // C13: MCP = RAM-only, knowledge jamais activé (surface stdio minimale).
            allow_knowledge: false,
            knowledge_path: None,
            verbose: false,
            no_banner: true,
            // C16 : positional jamais exposée via MCP (surface stdio) ; le
            // flag CLI n'y est pas « typé » (constructions programmatiques)
            // — `validate_target_conflict` est un no-op garantie.
            target_positional: None,
            cli_typed_target: false,
            format_conflict_warned: std::sync::Arc::default(),
        }
    }

    pub(super) fn build_scan_cli(params: ScanParams) -> Cli {
        let mut cli = Self::base_cli();
        cli.command = Some(Commands::Scan(ScanArgs {
            target: Some(params.target),
        }));
        if let Some(v) = params.threads {
            cli.detection.threads = Some(v);
        }
        if let Some(v) = params.techniques {
            cli.detection.techniques = v;
        }
        if let Some(v) = params.params {
            cli.detection.params = v;
        }
        cli.detection.data = params.data;
        cli.evasion.prefix = params.prefix;
        cli.evasion.suffix = params.suffix;
        cli.evasion.safe_chars = params.safe_chars;
        cli.evasion.skip_urlencode = params.skip_urlencode.unwrap_or(false);
        cli.detection.string = params.string;
        cli.detection.not_string = params.not_string;
        cli.detection.code = params.code;
        cli.detection.text_only = params.text_only.unwrap_or(false);
        cli.detection.fetch_using = params.fetch_using;
        if let Some(v) = params.tamper {
            cli.detection.tamper = v;
        }
        cli.http.proxy = params.proxy;
        cli.http.rate_limit = params.rate_limit;
        cli.http.jitter = params.jitter;
        cli.http.timeout = params.timeout;
        cli.detection.max_duration = params.max_duration;
        cli.detection.request_budget = params.request_budget;
        cli.http.retries = params.retries;
        cli.http.delay = params.delay;
        if let Some(v) = params.headers {
            cli.http.headers = v;
        }
        cli.http.cookies = params.cookies;
        cli.detection.dbms = params.dbms;
        cli.enumeration.extract = params.extract.unwrap_or(false);
        cli.enumeration.dbs = params.dbs.unwrap_or(false);
        cli.enumeration.tables = params.tables.unwrap_or(false);
        cli.enumeration.columns = params.columns.unwrap_or(false);
        cli.enumeration.dump = params.dump.unwrap_or(false);
        cli.enumeration.banner = params.banner.unwrap_or(false);
        cli.enumeration.current_user = params.current_user.unwrap_or(false);
        cli.enumeration.current_db = params.current_db.unwrap_or(false);
        cli.enumeration.hostname = params.hostname.unwrap_or(false);
        cli.enumeration.db = params.db;
        cli.enumeration.table = params.table;
        cli.enumeration.column = params.column;
        cli.enumeration.start = params.start;
        cli.enumeration.stop = params.stop;
        cli.enumeration.count = params.count.unwrap_or(false);
        cli.output_opts.output = params.output;
        cli.detection.oob_domain = params.oob_domain;
        cli.detection.oob_poll_url = params.oob_poll_url;
        if let Some(v) = params.oob_wait_secs {
            cli.detection.oob_wait_secs = Some(v);
        }
        cli.evasion.hpp = params.hpp.unwrap_or(false);
        cli.evasion.chunked = params.chunked.unwrap_or(false);
        cli.http.allow_private = params.allow_private.unwrap_or(false);
        cli.http.max_redirects = params.max_redirects;
        cli.output_opts.no_redact = params.no_redact.unwrap_or(false);
        cli
    }

    fn apply_common_network_opts(
        cli: &mut Cli,
        proxy: Option<String>,
        rate_limit: Option<f64>,
        jitter: Option<String>,
        headers: Option<Vec<String>>,
        cookies: Option<String>,
        allow_private: Option<bool>,
    ) {
        cli.http.proxy = proxy;
        cli.http.rate_limit = rate_limit;
        cli.http.jitter = jitter;
        if let Some(v) = headers {
            cli.http.headers = v;
        }
        cli.http.cookies = cookies;
        cli.http.allow_private = allow_private.unwrap_or(false);
        cli.http.discover_params = false; // default, will be overridden if needed
        cli.http.max_discover = 0; // default
    }

    pub(super) fn build_recon_crawl(params: ReconCrawlParams) -> (Cli, ReconCrawlArgs) {
        let args = ReconCrawlArgs {
            target: params.target,
            depth: params.depth.unwrap_or(2),
            max_pages: params.max_pages.unwrap_or(100),
            max_per_template: params.max_per_template.unwrap_or(3),
            max_candidates: params.max_candidates.unwrap_or(500),
            include_subdomains: params.include_subdomains.unwrap_or(false),
            ignore_robots: params.ignore_robots.unwrap_or(false),
            discover_params: params.discover_params.unwrap_or(false),
            max_discover: params.max_discover.unwrap_or(0),
        };
        let mut cli = Self::base_cli();
        cli.command = Some(Commands::Recon(ReconArgs {
            command: ReconCommands::Crawl(args.clone()),
        }));
        if let Some(v) = params.threads {
            cli.detection.threads = Some(v);
        }
        cli.http.timeout = params.timeout;
        cli.http.retries = params.retries;
        cli.http.delay = params.delay;
        cli.http.max_redirects = params.max_redirects;
        cli.http.discover_params = params.discover_params.unwrap_or(false);
        cli.http.max_discover = params.max_discover.unwrap_or(0);
        Self::apply_common_network_opts(
            &mut cli,
            params.proxy,
            params.rate_limit,
            params.jitter,
            params.headers,
            params.cookies,
            params.allow_private,
        );
        (cli, args)
    }

    pub(super) fn build_recon_scan(params: ReconScanParams) -> (Cli, ReconScanArgs) {
        let args = ReconScanArgs {
            crawl: ReconCrawlArgs {
                target: params.target,
                depth: params.depth.unwrap_or(2),
                max_pages: params.max_pages.unwrap_or(100),
                max_per_template: params.max_per_template.unwrap_or(3),
                max_candidates: params.max_candidates.unwrap_or(500),
                include_subdomains: params.include_subdomains.unwrap_or(false),
                ignore_robots: params.ignore_robots.unwrap_or(false),
                discover_params: params.discover_params.unwrap_or(false),
                max_discover: params.max_discover.unwrap_or(0),
            },
            auto_enumerate: params.auto_enumerate.unwrap_or(false),
        };
        let mut cli = Self::base_cli();
        cli.command = Some(Commands::Recon(ReconArgs {
            command: ReconCommands::Scan(args.clone()),
        }));
        if let Some(v) = params.threads {
            cli.detection.threads = Some(v);
        }
        if let Some(v) = params.techniques {
            cli.detection.techniques = v;
        }
        if let Some(v) = params.params {
            cli.detection.params = v;
        }
        cli.detection.data = params.data;
        cli.evasion.prefix = params.prefix;
        cli.evasion.suffix = params.suffix;
        cli.evasion.safe_chars = params.safe_chars;
        cli.evasion.skip_urlencode = params.skip_urlencode.unwrap_or(false);
        cli.detection.string = params.string;
        cli.detection.not_string = params.not_string;
        cli.detection.code = params.code;
        cli.detection.text_only = params.text_only.unwrap_or(false);
        cli.detection.fetch_using = params.fetch_using;
        if let Some(v) = params.tamper {
            cli.detection.tamper = v;
        }
        cli.detection.dbms = params.dbms;
        cli.enumeration.extract = params.extract.unwrap_or(false);
        cli.enumeration.dbs = params.dbs.unwrap_or(false);
        cli.enumeration.tables = params.tables.unwrap_or(false);
        cli.enumeration.columns = params.columns.unwrap_or(false);
        cli.enumeration.dump = params.dump.unwrap_or(false);
        cli.enumeration.banner = params.banner.unwrap_or(false);
        cli.enumeration.current_user = params.current_user.unwrap_or(false);
        cli.enumeration.current_db = params.current_db.unwrap_or(false);
        cli.enumeration.hostname = params.hostname.unwrap_or(false);
        cli.enumeration.db = params.db;
        cli.enumeration.table = params.table;
        cli.enumeration.column = params.column;
        cli.enumeration.start = params.start;
        cli.enumeration.stop = params.stop;
        cli.enumeration.count = params.count.unwrap_or(false);
        cli.output_opts.output = params.output;
        cli.detection.oob_domain = params.oob_domain;
        cli.detection.oob_poll_url = params.oob_poll_url;
        if let Some(v) = params.oob_wait_secs {
            cli.detection.oob_wait_secs = Some(v);
        }
        cli.evasion.hpp = params.hpp.unwrap_or(false);
        cli.evasion.chunked = params.chunked.unwrap_or(false);
        cli.output_opts.no_redact = params.no_redact.unwrap_or(false);
        cli.http.timeout = params.timeout;
        cli.detection.max_duration = params.max_duration;
        cli.detection.request_budget = params.request_budget;
        cli.http.retries = params.retries;
        cli.http.delay = params.delay;
        cli.http.max_redirects = params.max_redirects;
        cli.http.discover_params = params.discover_params.unwrap_or(false);
        cli.http.max_discover = params.max_discover.unwrap_or(0);
        Self::apply_common_network_opts(
            &mut cli,
            params.proxy,
            params.rate_limit,
            params.jitter,
            params.headers,
            params.cookies,
            params.allow_private,
        );
        (cli, args)
    }
}
