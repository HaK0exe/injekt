#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::cli::args::{
    Cli, DetectionOpts, EnumOpts, EvasionOpts, HttpOpts, OutputOpts, ReportFormat, TargetOpts,
};
use crate::cli::profile::Profile;

#[allow(clippy::too_many_lines)] // test fixture: exhaustive struct literal grows with each new flag
fn blank_cli() -> Cli {
    Cli {
        file_cache: std::sync::Arc::default(),
        // C14 : fixture programmatique — argv jamais capturé ⇒ suggestion `None`.
        captured_argv: Vec::new(),
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
        // C16 : jamais de conflit positional/flag dans le fixture
        // (constructions programmatiques ⇒ `cli_typed_target` false).
        target_positional: None,
        cli_typed_target: false,
        format_conflict_warned: std::sync::Arc::default(),
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
            discover_params: false,
            max_discover: 0,
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
            ai_suggest: false,
            ai_provider: None,
            ai_endpoint: None,
            ai_model: None,
            ai_api_key: None,
            ai_max_suggestions: 3,
            ai_timeout: 30,
            generative: None,
            max_generated: 4,
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
            // C16 : `Option` sans default clap — la résolution
            // (`effective_format`) fournit le `json` effectif.
            format: None,
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
fn file_snapshot_memoized_within_instance() {
    use std::io::Write as _;
    let mut path = std::env::temp_dir();
    path.push(format!("injekt-test-memo-{}.toml", std::process::id()));
    let mut file = std::fs::File::create(&path).unwrap();
    writeln!(file, "threads = 2\n").unwrap();
    drop(file);
    let mut cli = blank_cli();
    cli.config = Some(path.to_string_lossy().into_owned());
    assert_eq!(cli.effective_threads(), 2);
    // Rewrite the file: the memoised per-invocation snapshot keeps the
    // first read (P3: at most one config-file read per process).
    let mut file = std::fs::File::create(&path).unwrap();
    writeln!(file, "threads = 9\n").unwrap();
    drop(file);
    assert_eq!(cli.effective_threads(), 2);
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
    let cli =
        Cli::try_parse_from(["injekt", "--request-budget", "25"]).unwrap_or_else(|_| blank_cli());
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

#[test]
fn ai_opts_off_by_default_byte_identical() {
    // `--ai-suggest` OFF = 0 LLM call, validation always passes.
    let cli = blank_cli();
    assert!(!cli.detection.ai_suggest);
    assert_eq!(cli.effective_ai_max_suggestions(), 3);
    assert_eq!(cli.effective_ai_timeout(), 30);
    assert_eq!(cli.effective_ai_provider(), None);
    assert!(cli.validate_ai_opts().is_ok());
}

#[test]
fn ai_opts_require_provider_endpoint_model() {
    let mut cli = blank_cli();
    cli.detection.ai_suggest = true;
    // Nothing set: provider missing first.
    assert!(cli.validate_ai_opts().is_err());
    cli.detection.ai_provider = Some("openai".to_owned());
    assert!(cli.validate_ai_opts().is_err());
    cli.detection.ai_endpoint = Some("http://localhost:11434/v1/chat/completions".to_owned());
    assert!(cli.validate_ai_opts().is_err());
    cli.detection.ai_model = Some("llama3.1:8b".to_owned());
    assert!(cli.validate_ai_opts().is_ok());
}

#[test]
fn ai_opts_reject_bad_provider_and_endpoint() {
    let mut cli = blank_cli();
    cli.detection.ai_suggest = true;
    cli.detection.ai_provider = Some("nope".to_owned());
    cli.detection.ai_endpoint = Some("http://localhost:11434/v1".to_owned());
    cli.detection.ai_model = Some("m".to_owned());
    assert!(cli.validate_ai_opts().is_err());
    assert_eq!(cli.effective_ai_provider(), None);
    cli.detection.ai_provider = Some("Anthropic".to_owned());
    assert_eq!(cli.effective_ai_provider().as_deref(), Some("anthropic"));
    cli.detection.ai_endpoint = Some("ftp://example.com/x".to_owned());
    assert!(cli.validate_ai_opts().is_err());
    cli.detection.ai_endpoint = Some("https://api.anthropic.com/v1/messages".to_owned());
    assert!(cli.validate_ai_opts().is_ok());
}

#[test]
fn ai_counts_clamp_defensively() {
    let mut cli = blank_cli();
    cli.detection.ai_max_suggestions = 0;
    assert_eq!(cli.effective_ai_max_suggestions(), 1);
    cli.detection.ai_max_suggestions = 9;
    assert_eq!(cli.effective_ai_max_suggestions(), 5);
    cli.detection.ai_max_suggestions = 3;
    assert_eq!(cli.effective_ai_max_suggestions(), 3);
    cli.detection.ai_timeout = 0;
    assert_eq!(cli.effective_ai_timeout(), 1);
}

#[test]
fn generative_defaults_to_off_byte_identical() {
    use crate::generation::GenerativeMode;
    let cli = blank_cli();
    assert_eq!(cli.effective_generative_mode(), GenerativeMode::Off);
    assert_eq!(cli.effective_max_generated(), 4);
    let mut cli = blank_cli();
    cli.detection.generative = Some("conservative".to_owned());
    assert_eq!(
        cli.effective_generative_mode(),
        GenerativeMode::Conservative
    );
    cli.detection.generative = Some("  AGGRESSIVE ".to_owned());
    assert_eq!(cli.effective_generative_mode(), GenerativeMode::Aggressive);
    cli.detection.generative = Some("nope".to_owned());
    assert_eq!(cli.effective_generative_mode(), GenerativeMode::Off);
    cli.detection.max_generated = 99;
    assert_eq!(
        cli.effective_max_generated(),
        crate::generation::MAX_GENERATED
    );
}

// --- C16 : positional target ------------------------------------------------

#[test]
fn positional_target_top_level_wins_between_flag_and_env() {
    // Precedence (doc figée): `--raw-file` > positional > `-u/--target` > env.
    let mut cli = blank_cli();
    cli.target_positional = Some("https://pos.example/?id=1".to_owned());
    cli.target_opts.target = Some("https://flag.example/?id=1".to_owned());
    assert_eq!(
        cli.effective_target().as_deref(),
        Some("https://pos.example/?id=1")
    );
    assert_eq!(
        cli.try_effective_target().unwrap().as_deref(),
        Some("https://pos.example/?id=1")
    );
    // Env-sourced indistinguishable from the field: no typed flag ⇒ no
    // conflict ever (`cli_typed_target` false in programmatic fixtures).
    assert!(cli.validate_target_conflict().is_ok());
}

#[test]
fn positional_conflict_only_for_cli_typed_flag() {
    let mut cli = blank_cli();
    cli.target_positional = Some("https://pos.example/?id=1".to_owned());
    cli.target_opts.target = Some("https://flag.example/?id=1".to_owned());
    // env INJEKT_TARGET occupies the same field: positional > env silently.
    cli.cli_typed_target = false;
    assert!(cli.validate_target_conflict().is_ok());
    cli.cli_typed_target = true;
    // Typed `-u/--target` + different positional = usage error (exit 2).
    let err = cli.validate_target_conflict().unwrap_err();
    assert!(
        matches!(err, crate::error::InjektError::TargetConflict { .. }),
        "{err}"
    );
    // Equal values: silent (zero-break `injekt <URL> -u <URL>`).
    cli.target_opts.target = Some("https://pos.example/?id=1".to_owned());
    assert!(cli.validate_target_conflict().is_ok());
}

#[test]
fn auto_positional_feeds_resolution_and_conflict() {
    use crate::cli::args::{AutoArgs, Commands};
    let mut cli = blank_cli();
    cli.command = Some(Commands::Auto(AutoArgs {
        target_positional: Some("https://auto.example/?id=1".to_owned()),
        target: None,
        with_recon: false,
        depth: 2,
        max_pages: 100,
        no_escalate: false,
        auto_enumerate: false,
    }));
    assert_eq!(
        cli.effective_target().as_deref(),
        Some("https://auto.example/?id=1")
    );
    assert_eq!(cli.positional_target(), Some("https://auto.example/?id=1"));
    let mut cli = blank_cli();
    cli.command = Some(Commands::Auto(AutoArgs {
        target_positional: Some("https://auto.example/?id=1".to_owned()),
        target: Some("https://legacy.example/?id=1".to_owned()),
        with_recon: false,
        depth: 2,
        max_pages: 100,
        no_escalate: false,
        auto_enumerate: false,
    }));
    // Precedence `auto`: positional > legacy alias.
    assert_eq!(
        cli.effective_target().as_deref(),
        Some("https://auto.example/?id=1")
    );
}

#[test]
fn bare_target_flag_unchanged_by_positional() {
    use clap::Parser as _;
    // `-u` alone (historical zero-break): identical resolution.
    let cli = Cli::try_parse_from(["injekt", "-u", "https://flag.example/?id=1"]).unwrap();
    assert!(cli.target_positional.is_none());
    assert_eq!(
        cli.effective_target().as_deref(),
        Some("https://flag.example/?id=1")
    );
    // Top-level positional parses alone (no subcommand match).
    let cli = Cli::try_parse_from(["injekt", "https://pos.example/?id=1"]).unwrap();
    assert!(cli.command.is_none());
    assert_eq!(
        cli.target_positional.as_deref(),
        Some("https://pos.example/?id=1")
    );
}

// --- C16 : `--format` resolution --------------------------------------------

#[test]
fn format_resolution_default_json_without_extension() {
    let mut cli = blank_cli();
    cli.output_opts.output = Some("report.txt".to_owned());
    assert_eq!(cli.effective_format(), ReportFormat::Json);
    cli.output_opts.output = None;
    assert_eq!(cli.effective_format(), ReportFormat::Json);
    // Unknown extension never infers (silently) and never escapes the default.
    cli.output_opts.output = Some("x.yaml".to_owned());
    assert_eq!(cli.effective_format(), ReportFormat::Json);
    // `format_conflict_warned` untouched by inference paths.
    assert!(
        !cli.format_conflict_warned
            .load(std::sync::atomic::Ordering::Relaxed)
    );
}

#[test]
fn format_extension_inference_maps_known_extensions() {
    use crate::cli::resolve::format::infer_from_extension;
    assert_eq!(
        infer_from_extension(Some("x.sarif")),
        Some(ReportFormat::Sarif)
    );
    assert_eq!(
        infer_from_extension(Some("X.SARIF")),
        Some(ReportFormat::Sarif)
    );
    assert_eq!(
        infer_from_extension(Some("x.json")),
        Some(ReportFormat::Json)
    );
    assert_eq!(
        infer_from_extension(Some("x.junit")),
        Some(ReportFormat::Junit)
    );
    assert_eq!(
        infer_from_extension(Some("x.xml")),
        Some(ReportFormat::Junit)
    );
    assert_eq!(infer_from_extension(Some("x.md")), Some(ReportFormat::Md));
    assert_eq!(
        infer_from_extension(Some("x.markdown")),
        Some(ReportFormat::Md)
    );
    // Unknown / no extension / non-UTF8 — silent None.
    assert_eq!(infer_from_extension(Some("x.yaml")), None);
    assert_eq!(infer_from_extension(Some("noext")), None);
    assert_eq!(infer_from_extension(Some(".hidden")), None);
    assert_eq!(
        infer_from_extension(Some("x.tar.gz".to_string().as_str())),
        None
    );
    assert_eq!(infer_from_extension(None), None);
}

#[test]
fn format_explicit_wins_over_extension_with_warn_once() {
    use std::sync::atomic::Ordering;
    let mut cli = blank_cli();
    cli.output_opts.output = Some("x.sarif".to_owned());
    // CLI/env-parsed explicit beats the extension.
    cli.output_opts.format = Some(ReportFormat::Md);
    assert_eq!(cli.effective_format(), ReportFormat::Md);
    assert!(cli.format_conflict_warned.load(Ordering::Relaxed));
    // Warn-once guard: a second clap-owned resolution stays silent.
    assert_eq!(cli.effective_format(), ReportFormat::Md);
    // Equal values (md file + --format md) never raise the guard.
    let mut cli = blank_cli();
    cli.output_opts.output = Some("x.md".to_owned());
    cli.output_opts.format = Some(ReportFormat::Md);
    assert_eq!(cli.effective_format(), ReportFormat::Md);
    assert!(!cli.format_conflict_warned.load(Ordering::Relaxed));
    // Clone shares the warn-once guard (one invocation ⇒ one warning max).
    let mut cli = blank_cli();
    cli.format_conflict_warned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    cli.output_opts.format = Some(ReportFormat::Json);
    assert_eq!(cli.effective_format(), ReportFormat::Json);
}

#[test]
fn config_toml_format_below_extension() {
    use std::io::Write as _;
    let mut path = std::env::temp_dir();
    path.push(format!("injekt-test-fmt-{}.toml", std::process::id()));
    let mut file = std::fs::File::create(&path).unwrap();
    writeln!(file, "format = \"junit\"\n").unwrap();
    drop(file);
    let mut cli = blank_cli();
    cli.config = Some(path.to_string_lossy().into_owned());
    // No --output-format conflict possible: extension is above config.
    cli.output_opts.output = Some("r.sarif".to_owned());
    assert_eq!(cli.effective_format(), ReportFormat::Sarif);
    // Without a known extension, the TOML key applies.
    cli.output_opts.output = Some("r.txt".to_owned());
    assert_eq!(cli.effective_format(), ReportFormat::Junit);
    // Unknown TOML name warns + falls back to the effective default.
    cli.output_opts.format = None;
    let mut file = std::fs::File::create(&path).unwrap();
    writeln!(file, "format = \"yaml\"\n").unwrap();
    drop(file);
    let mut cli = blank_cli();
    cli.config = Some(path.to_string_lossy().into_owned());
    cli.file_cache = std::sync::Arc::default();
    assert_eq!(cli.effective_format(), ReportFormat::Json);
    std::fs::remove_file(&path).unwrap();
}
