use super::{
    ExplainParams, InfoParams, InjektServer, PlanParams, ReconCrawlParams, ReconScanParams,
    ScanParams,
};
use crate::cli::commands::{info, recon, scan};
use rmcp::{
    ErrorData,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock},
    tool, tool_router,
};

#[tool_router(vis = "pub(super)")]
impl InjektServer {
    #[tool(
        description = "Scan a target URL for SQL injection vulnerabilities. Only use against systems you are authorized to test."
    )]
    async fn scan(
        &self,
        Parameters(params): Parameters<ScanParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // MCP mode never writes encrypted exports (no TTY for passphrase prompt).
        if params.export_encrypted.is_some() {
            return Err(ErrorData::invalid_params(
                "export_encrypted is not supported in MCP mode (no TTY for passphrase); scan results are returned inline as JSON",
                None,
            ));
        }
        let cli = Self::build_scan_cli(params);
        Self::warn_no_redact(cli.output_opts.no_redact);
        // `run_scan` returns an already-scrubbed `JsonReport` (see
        // `cli::commands::scan`), so inline JSON never carries raw secrets.
        let result = scan::run_scan(&cli, self.cancel.clone())
            .await
            .map_err(|e| ErrorData::internal_error(format!("scan failed: {e}"), None))?;

        let json = serde_json::to_value(&result.report)
            .map_err(|e| ErrorData::internal_error(format!("serialization failed: {e}"), None))?;

        if let Some(out) = &cli.output_opts.output {
            let path = Self::validate_output_path(out)?;
            let pretty = serde_json::to_string_pretty(&result.report).map_err(|e| {
                ErrorData::internal_error(format!("serialization failed: {e}"), None)
            })?;
            Self::write_output_file(&path, &pretty)?;
        }

        Ok(CallToolResult::success(vec![ContentBlock::json(json)?]))
    }

    #[tool(
        description = "Crawl a target to discover parameters without testing them. Only use against systems you are authorized to test."
    )]
    async fn recon_crawl(
        &self,
        Parameters(params): Parameters<ReconCrawlParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let (cli, args) = Self::build_recon_crawl(params);
        let result = recon::run_crawl(&cli, self.cancel.clone(), &args)
            .await
            .map_err(|e| ErrorData::internal_error(format!("recon crawl failed: {e}"), None))?;

        let json = serde_json::to_value(&result.report)
            .map_err(|e| ErrorData::internal_error(format!("serialization failed: {e}"), None))?;

        Ok(CallToolResult::success(vec![ContentBlock::json(json)?]))
    }

    #[tool(
        description = "Crawl a target and scan each discovered parameter for SQL injection. Only use against systems you are authorized to test."
    )]
    async fn recon_scan(
        &self,
        Parameters(params): Parameters<ReconScanParams>,
    ) -> Result<CallToolResult, ErrorData> {
        if params.export_encrypted.is_some() {
            return Err(ErrorData::invalid_params(
                "export_encrypted is not supported in MCP mode (no TTY for passphrase); results are returned inline as JSON",
                None,
            ));
        }
        let (cli, args) = Self::build_recon_scan(params);
        Self::warn_no_redact(cli.output_opts.no_redact);
        let result = recon::run_scan(&cli, self.cancel.clone(), &args)
            .await
            .map_err(|e| ErrorData::internal_error(format!("recon scan failed: {e}"), None))?;

        let json = serde_json::to_value(&result)
            .map_err(|e| ErrorData::internal_error(format!("serialization failed: {e}"), None))?;

        if let Some(out) = &cli.output_opts.output {
            let path = Self::validate_output_path(out)?;
            let pretty = serde_json::to_string_pretty(&result).map_err(|e| {
                ErrorData::internal_error(format!("serialization failed: {e}"), None)
            })?;
            Self::write_output_file(&path, &pretty)?;
        }

        Ok(CallToolResult::success(vec![ContentBlock::json(json)?]))
    }

    #[tool(
        description = "Get information about injekt capabilities, techniques, tampers and supported databases."
    )]
    async fn info(
        &self,
        Parameters(InfoParams {}): Parameters<InfoParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = info::info();
        let json = serde_json::to_value(&result)
            .map_err(|e| ErrorData::internal_error(format!("serialization failed: {e}"), None))?;

        Ok(CallToolResult::success(vec![ContentBlock::json(json)?]))
    }

    #[tool(
        description = "Build the offline execution plan for a target: ordered probes (param, technique, EVI, cost, score, seed, budget) with 0 requests sent. Dry-run is forced."
    )]
    async fn plan(
        &self,
        Parameters(params): Parameters<PlanParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // C11: dry-run forcé — ce tool ne construit jamais de `HttpClient`
        // et n'appelle jamais `send` (plan lexical + contexte passif + scores).
        let target = params.target.clone();
        let mut cli = Self::base_cli();
        cli.output_opts.dry_run = true;
        cli.detection.techniques = params.techniques.unwrap_or_default();
        cli.detection.params = params.params.unwrap_or_default();
        cli.detection.data = params.data;
        cli.detection.dbms = params.dbms;
        cli.detection.seed = params.seed;
        if let Some(level) = params.level {
            cli.detection.level = Some(level.clamp(1, 5));
        }
        if let Some(threads) = params.threads {
            cli.detection.threads = Some(threads);
        }
        cli.http.headers = params.headers.unwrap_or_default();
        cli.http.cookies.clone_from(&params.cookies);
        cli.http.allow_private = params.allow_private.unwrap_or(false);
        cli.output_opts.no_redact = params.no_redact.unwrap_or(false);
        Self::warn_no_redact(cli.output_opts.no_redact);
        let cfg = crate::cli::engine_cfg::build_engine_config(
            &cli,
            crate::cli::engine_cfg::EnumGate::Passthrough,
        );
        let plan = crate::cli::plan::build_plan(&target, &cfg)
            .map_err(|e| ErrorData::invalid_params(e, None))?;
        let scrubber = crate::session::scrubber::Scrubber::new(cli.output_opts.no_redact);
        let scrubbed = plan.scrubbed(&scrubber);
        let mut json = serde_json::to_value(&scrubbed)
            .map_err(|e| ErrorData::internal_error(format!("serialization failed: {e}"), None))?;
        // Défense en profondeur : même en `no_redact`, le plan ne porte que
        // des noms de params (jamais de valeurs cookie/header), mais on
        // vérifie qu'aucun secret d'entrée ne fuit dans la sortie.
        if let Some(secret) = params.cookies.as_deref()
            && !secret.trim().is_empty()
            && let Ok(text) = serde_json::to_string(&json)
            && text.contains(secret)
        {
            return Err(ErrorData::internal_error(
                "plan output would exfiltrate cookie material (bug)",
                None,
            ));
        }
        // Marqueur explicite dry-run pour les agents.
        if let Some(obj) = json.as_object_mut() {
            obj.insert("requests_sent".to_owned(), serde_json::Value::from(0));
        }
        Ok(CallToolResult::success(vec![ContentBlock::json(json)?]))
    }

    #[tool(
        description = "Explain a finding offline (0 requests): one-line reasoning verdict from evidence or a decrypted export snapshot. No secrets in output."
    )]
    async fn explain(
        &self,
        Parameters(params): Parameters<ExplainParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let no_redact = params.no_redact.unwrap_or(false);
        Self::warn_no_redact(no_redact);
        let scrubber = crate::session::scrubber::Scrubber::new(no_redact);
        // Source 1 : snapshot/export JSON décrypté (offline, même matching
        // que `replay --explain` : param exact, insensible à la casse).
        let mut evidence = params.evidence.unwrap_or_default();
        let mut confidence = params.confidence.unwrap_or(0.0);
        let mut requests = params.requests.unwrap_or(0);
        let mut seed = params.seed;
        if let Some(export_json) = params.export_json.as_deref() {
            let value: serde_json::Value = serde_json::from_str(export_json).map_err(|e| {
                ErrorData::invalid_params(format!("invalid export_json: {e}"), None)
            })?;
            if let Some((ev, conf, req, sd)) =
                crate::cli::plan::finding_from_export(&value, &params.param)
            {
                evidence = ev;
                confidence = conf;
                if params.requests.is_none() {
                    requests = req;
                }
                if params.seed.is_none() {
                    seed = sd;
                }
            }
        }
        let line = crate::cli::plan::explain_offline(
            &params.param,
            &evidence,
            confidence,
            requests,
            seed,
            no_redact,
        );
        let out = serde_json::json!({
            "param": scrubber.scrub(&params.param),
            "explain": scrubber.scrub(&line),
            "requests_sent": 0,
        });
        Ok(CallToolResult::success(vec![ContentBlock::json(out)?]))
    }
}
