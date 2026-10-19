#![allow(clippy::unwrap_used, clippy::expect_used)]

//! C16 — CLI vague 1 (zéro breaking): positional `injekt <URL>` /
//! `injekt auto <URL|HOST>`, conflit positional ≠ `-u/--target` tapé
//! (exit 2 de type usage), format par extension de `--output`.
//!
//! Les chemins réseau restent à zéro requête (compteur `wiremock` ; le seul
//! chemin complet écrit le fichier `--output` hors réseau via l'API lib).

use clap::Parser as _;
use injekt::cli::args::{Cli, ReportFormat};
use wiremock::{Mock, MockServer, matchers::method};

fn run_binary(args: &[&str]) -> (i32, String, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_injekt"))
        .args(args)
        .env_remove("INJEKT_TARGET")
        .env_remove("INJEKT_FORMAT")
        .output()
        .expect("run injekt binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// Item 1 — positional target
// ---------------------------------------------------------------------------

#[tokio::test]
async fn positional_url_runs_the_scan_plan_zero_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());
    let (code, stdout, stderr) =
        run_binary(&[&target, "--dry-run", "--allow-private", "--no-banner"]);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(
        stdout.contains("dry-run: scan plan"),
        "positional target must reach the scan plan: {stdout}"
    );
    assert!(
        stdout.contains("targets: 1"),
        "positional must be resolved as the single target: {stdout}"
    );
}

#[tokio::test]
async fn auto_positional_bare_host_triggers_recon_plan() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    // Bare host ⇒ `--with-recon` implicite (comportement `auto --target`
    // inchangé), l'URL normalisée garde le piège 0-requête du dry-run.
    let (code, stdout, stderr) = run_binary(&[
        "auto",
        "example.com",
        "--allow-private",
        "--no-banner",
        "--dry-run",
    ]);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(
        stdout.contains("dry-run: auto pipeline"),
        "auto positional must reach the auto dry-run: {stdout}"
    );
}

#[tokio::test]
async fn positional_vs_typed_flag_conflict_is_usage_exit_2() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let pos = format!("{}/?id=1", server.uri());
    let other = format!("{}/?id=2", server.uri());
    let (code, stdout, stderr) = run_binary(&[
        &pos,
        "-u",
        &other,
        "--dry-run",
        "--allow-private",
        "--no-banner",
    ]);
    assert_eq!(
        code, 2,
        "usage error expected; stdout: {stdout} stderr: {stderr}"
    );
    assert!(
        stderr.contains("conflicting targets"),
        "explicit conflict message expected: {stderr}"
    );
    // Bare host form on `auto` too (typed legacy alias).
    let (code, stdout, stderr) = run_binary(&[
        "auto",
        "poshost.example",
        "--target",
        "otherhost.example",
        "--dry-run",
        "--allow-private",
        "--no-banner",
    ]);
    assert_eq!(code, 2, "stdout: {stdout} stderr: {stderr}");
    assert!(stderr.contains("conflicting targets"), "{stderr}");
    // Different env value: positional wins silently (env is below the
    // positional in the documented precedence) — no conflict raised.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_injekt"))
        .args([&pos, "--dry-run", "--allow-private", "--no-banner"])
        .env_remove("INJEKT_FORMAT")
        .env("INJEKT_TARGET", &other)
        .output()
        .expect("run injekt binary");
    assert!(
        out.status.success(),
        "env vs positional must silently prefer the positional: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
async fn positional_equal_to_typed_flag_stays_silent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let url = format!("{}/?id=1", server.uri());
    let (code, stdout, stderr) = run_binary(&[
        &url,
        "-u",
        &url,
        "--dry-run",
        "--allow-private",
        "--no-banner",
    ]);
    assert_eq!(
        code, 0,
        "equal target spellings are silent; stderr: {stderr}"
    );
    assert!(stdout.contains("dry-run: scan plan"), "{stdout}");
}

// ---------------------------------------------------------------------------
// Item 2 — format by `--output` extension (offline render)
// ---------------------------------------------------------------------------

fn offline_cli(args: &[&str]) -> Cli {
    // Sentinel config path (never exists): the resolved format depends only
    // on the flags under test, not on the terminal's `~/.config/injekt`.
    // `--force` opts in to the (OPSEC-warned) absolute temp path — the
    // output contract itself (0600, content) is what the tests assert.
    Cli::try_parse_from(
        std::iter::once("injekt")
            .chain(["--config", "/nonexistent-injekt-test-config-9f3a.toml"])
            .chain(args.iter().copied())
            .chain(["--force"]),
    )
    .expect("cli parses")
}

fn sample_report() -> injekt::reporting::json::JsonReport {
    let finding = injekt::session::state::Finding::new(
        "https://example.com/?id=1",
        "id@query",
        injekt::session::state::TechniqueKind::Boolean,
        0.95,
        "boolean true_sim=0.95 false_sim=0.10",
    )
    .with_false_positive_prob(0.02);
    injekt::reporting::json::JsonReport::new(
        "https://example.com/?id=1",
        vec![finding],
        vec![],
        vec![],
        42,
        injekt::reporting::json::ReportMeta::default(),
    )
}

async fn render_to_disk(cli: &Cli, path: &str) {
    let report = sample_report();
    let scrubber = injekt::session::scrubber::Scrubber::new(cli.output_opts.no_redact);
    let body = injekt::reporting::render::render_report(&report, cli.effective_format(), &scrubber);
    injekt::cli::commands::common::write_report_async(
        Some(path),
        &body,
        cli.output_opts.force,
        &scrubber.scrub(path),
    )
    .await
    .expect("file write");
}

#[tokio::test]
async fn output_sarif_extension_sets_sarif_content_without_flag() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("injekt-c16-{}.sarif", std::process::id()));
    let path = path.to_string_lossy().into_owned();
    let cli = offline_cli(&["--output", &path, "--target", "https://example.com/?id=1"]);
    assert!(cli.output_opts.format.is_none());
    assert!(matches!(cli.effective_format(), ReportFormat::Sarif));
    render_to_disk(&cli, &path).await;
    let content = std::fs::read_to_string(&path).expect("read sarif report");
    assert!(
        content.contains("sarif-2.1.0") && content.contains("\"version\": \"2.1.0\""),
        "`--output x.sarif` without --format must write SARIF: {}",
        &content[..content.len().min(200)]
    );
    // Same 0600 contract as any --output write (never a wider mode).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "0600 output contract");
    }
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn unknown_extension_silently_stays_json() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("injekt-c16-{}.yaml", std::process::id()));
    let path = path.to_string_lossy().into_owned();
    let cli = offline_cli(&["--output", &path, "--target", "https://example.com/?id=1"]);
    assert!(cli.output_opts.format.is_none());
    // Unknown extension is never inferred, never warned: effective json.
    assert!(matches!(cli.effective_format(), ReportFormat::Json));
    assert!(
        !cli.format_conflict_warned
            .load(std::sync::atomic::Ordering::Relaxed),
        "unknown extension stays silent"
    );
    render_to_disk(&cli, &path).await;
    let content = std::fs::read_to_string(&path).expect("read json report");
    let value: serde_json::Value = serde_json::from_str(&content).expect("json body");
    assert!(
        value.get("findings").is_some(),
        "json default body: {value}"
    );
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn explicit_format_wins_extension_and_warns_once() {
    let mut cli = offline_cli(&[
        "--format",
        "md",
        "--output",
        "x.sarif",
        "--target",
        "https://example.com/?id=1",
    ]);
    assert!(
        matches!(cli.effective_format(), ReportFormat::Md),
        "explicit --format beats the .sarif extension"
    );
    assert!(
        cli.format_conflict_warned
            .load(std::sync::atomic::Ordering::Relaxed),
        "explicit != extension raises the once-guard"
    );
    // Second resolution this run: no duplicated warn path.
    assert!(matches!(cli.effective_format(), ReportFormat::Md));
    // Equal spelling stays silent.
    cli = offline_cli(&[
        "--format",
        "sarif",
        "--output",
        "x.sarif",
        "--target",
        "https://example.com/?id=1",
    ]);
    assert!(matches!(cli.effective_format(), ReportFormat::Sarif));
    assert!(
        !cli.format_conflict_warned
            .load(std::sync::atomic::Ordering::Relaxed)
    );
}

#[test]
fn config_toml_format_keys_resolve_below_extension() {
    // Config-TOML `format` key: applies without a known extension, loses
    // against the extension, unknown name falls back to json. The key is
    // resolved through `file_snapshot` (explicit `--config`), never through
    // `validate_explicit_config`, so the temp file must be readable.
    let mut toml = std::env::temp_dir();
    toml.push(format!("injekt-c16-fmt-{}.toml", std::process::id()));
    let toml_path = toml.to_string_lossy().into_owned();
    std::fs::write(&toml_path, "format = \"junit\"\n").expect("write toml");
    let cli = Cli::try_parse_from([
        "injekt",
        "--config",
        &toml_path,
        "--output",
        "r.txt",
        "--target",
        "https://example.com/?id=1",
    ])
    .expect("cli parses");
    assert!(matches!(cli.effective_format(), ReportFormat::Junit));
    let cli = Cli::try_parse_from([
        "injekt",
        "--config",
        &toml_path,
        "--output",
        "r.sarif",
        "--target",
        "https://example.com/?id=1",
    ])
    .expect("cli parses");
    assert!(
        matches!(cli.effective_format(), ReportFormat::Sarif),
        "extension outranks the config key"
    );
    std::fs::write(&toml_path, "format = \"yaml\"\n").expect("write toml");
    let cli = Cli::try_parse_from(["injekt", "--config", &toml_path, "--output", "r.txt"])
        .expect("cli parses");
    assert!(matches!(cli.effective_format(), ReportFormat::Json));
    std::fs::remove_file(&toml_path).ok();
}
