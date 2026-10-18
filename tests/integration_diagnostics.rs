#![allow(clippy::unwrap_used, clippy::expect_used)]
//! C14 — diagnostics `INCONCLUSIVE` end-to-end (docs/plan-cli-ux.md §2).
//!
//! Lit le câblage réel : les 3 points de dégradation du pipeline (2 retours
//! précoces de `run_baseline_phase` + tail `finalize_run`) posent le
//! diagnostic RAM-only via `SessionState::set_inconclusive_cause`;
//! `run_scan` le fait remonter dans le `JsonReport` scrubbé. Aucun flag
//! nouveau, aucune évolution du moteur de détection, aucune persistance.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Parser as _;
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

use injekt::engine::diagnostics::InconclusiveCause;
use injekt::engine::{Engine, EngineConfig, EngineState};
use injekt::http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter};
use injekt::reporting::console;
use injekt::session::scrubber::Scrubber;

fn engine_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

/// Les échantillons baseline varient (status 200/500/200, corps tous
/// différents) : l'oracle de comparaison est inutilisable →
/// `UnstableBaseline` au premier point de dégradation (baseline phase).
fn volatile_baseline(
    counter: Arc<AtomicUsize>,
) -> impl Fn(&wiremock::Request) -> ResponseTemplate + use<> {
    move |_req| {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        // Exactement 3 samples (retries coupés dans le test) : le multiset
        // final des statuses est {200, 500, 200}, l'ordre seul varie
        // (les 3 échantillons partent en concurrent).
        let status: u16 = [200, 500, 200].get(n).copied().unwrap_or(200);
        ResponseTemplate::new(status).set_body_string(format!("baseline body vary {n}"))
    }
}

/// Chaque saut est throttlé : le limiter répond avant la base de données.
fn throttle_everything() -> impl Fn(&wiremock::Request) -> ResponseTemplate + use<> {
    |_req| ResponseTemplate::new(429).set_body_string("too many requests")
}

/// Chemin CLI de `run_scan` : argv capturé au travers du `Cli`, exactement la
/// forme de `main` (`std::env::args().skip(1)` = argv sans nom de binaire).
fn parsed_cli(argv_after_binary: &[&str]) -> (injekt::cli::args::Cli, Vec<String>) {
    let mut tokens = vec!["injekt".to_owned()];
    tokens.extend(argv_after_binary.iter().map(|s| (*s).to_owned()));
    let cli = injekt::cli::args::Cli::try_parse_from(&tokens).expect("cli parses");
    // `main` capture `std::env::args().skip(1)` — sans nom de binaire.
    (cli, tokens.into_iter().skip(1).collect())
}

#[tokio::test]
async fn unstable_baseline_yields_diagnostic_and_scrubbed_suggestion() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(volatile_baseline(Arc::new(AtomicUsize::new(0))))
        .mount(&server)
        .await;

    let url = format!("{}/?id=1&token=abcd", server.uri());
    let (mut cli, captured_argv) = parsed_cli(&[
        "--target",
        &url,
        "--allow-private",
        "--threads",
        "1",
        "--retries",
        "0",
        "--techniques",
        "boolean",
    ]);
    // `main` remplit ce champ depuis `std::env::args` — même forme ici pour
    // que le test de patch argv + scrub soit significatif.
    cli.captured_argv = captured_argv;

    let result = injekt::cli::commands::scan::run_scan(&cli, CancellationToken::new())
        .await
        .expect("run_scan");

    assert!(
        matches!(result.engine_state, EngineState::Inconclusive),
        "unstable baseline must degrade: {:?}",
        result.engine_state
    );

    let diag = result
        .report
        .diagnostic
        .clone()
        .expect("unstable baseline diagnostic present");
    match &diag.cause {
        InconclusiveCause::UnstableBaseline { statuses } => {
            assert_eq!(statuses.len(), 3);
            assert!(statuses.contains(&200) && statuses.contains(&500));
        }
        other => panic!("wrong cause: {other:?}"),
    }
    // Evidence cite les statuses ; suggestion = patch rejouable.
    assert!(diag.evidence.contains("200"), "{}", diag.evidence);
    let suggestion = diag.suggestion.clone().expect("suggestion present");
    assert!(suggestion.contains("--fetch-using direct"), "{suggestion}");
    assert!(suggestion.contains("--techniques time"), "{suggestion}");
    // argv rejoué tel quel (rien supprimé/rewrité) + patch en fin.
    assert!(suggestion.contains("--allow-private"), "{suggestion}");
    assert!(suggestion.contains("--threads 1"), "{suggestion}");
    assert!(suggestion.starts_with("injekt --target "), "{suggestion}");

    // Scrub : le token d'URL ne traverse JAMAIS la sortie scrubbée.
    assert!(
        !suggestion.contains("abcd"),
        "raw token leaked into report suggestion: {suggestion}"
    );
    assert!(suggestion.contains("[REDACTED]"), "{suggestion}");

    // JSON du rapport : diagnostic plat à 4 clés sous la racine.
    let scrubber = Scrubber::new(false);
    let json: serde_json::Value =
        serde_json::from_str(&result.report.to_json(&scrubber)).expect("report serializes");
    assert_eq!(json["diagnostic"]["cause"], "UnstableBaseline");
    let keys: Vec<String> = json["diagnostic"]
        .as_object()
        .expect("diagnostic object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(keys, ["cause", "evidence", "suggestion", "why"]);
}

#[tokio::test]
async fn unstable_baseline_without_captured_argv_has_no_fabricated_command() {
    // Chemin programmatique (`Engine::run`, ressemblance MCP :
    // `EngineConfig.argv` vide) — la cause reste affichée, la commande n'est
    // JAMAIS fabriquée sans cible.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(volatile_baseline(Arc::new(AtomicUsize::new(0))))
        .mount(&server)
        .await;

    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let engine = Engine::new(cfg, engine_client(), CancellationToken::new());
    let target = format!("{}/?id=1", server.uri());
    let state = engine.run(&target).await.expect("engine run");
    assert!(matches!(state, EngineState::Inconclusive), "{state:?}");
    let state_arc = engine.state_handle();
    let handle = state_arc.read().await;
    let diag = handle
        .inconclusive_cause()
        .cloned()
        .expect("diagnostic via engine path");
    assert_eq!(diag.cause.code(), "UnstableBaseline");
    assert!(
        diag.suggestion.is_none(),
        "empty argv must not fabricate a command: {:?}",
        diag.suggestion
    );
}

#[tokio::test]
async fn repeated_429s_end_rate_limited_with_flags_suggestion() {
    // Tout-429 (`--retries 0`, pacing par défaut > budget `--max-duration 1`)
    // : la run dégrade en `INCONCLUSIVE` au tail — RateLimited > Budget /
    // Duration (priorité figée) — suggestion patchée complète.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(throttle_everything())
        .mount(&server)
        .await;

    let url = format!("{}/?id=1", server.uri());
    let (mut cli, captured_argv) = parsed_cli(&[
        "--target",
        &url,
        "--allow-private",
        "--threads",
        "1",
        "--retries",
        "0",
        "--max-duration",
        "1",
        "--techniques",
        "boolean",
    ]);
    cli.captured_argv = captured_argv;
    let result = injekt::cli::commands::scan::run_scan(&cli, CancellationToken::new())
        .await
        .expect("run_scan");

    assert!(
        matches!(result.engine_state, EngineState::Inconclusive),
        "throttled + clock stop must degrade: {:?}",
        result.engine_state
    );

    // Compteurs client drainés dans la SessionState une seule fois
    // (`absorb_detectability` au tail) : tous les sauts de la run ≥ 3
    // (baseline *et* detection, retries compris).
    {
        let st = result.state_handle.read().await;
        let detectability = st.detectability();
        assert!(
            detectability.count_429 >= 3,
            "expected ≥3 throttled hops, got {}",
            detectability.count_429
        );
        assert_eq!(detectability.count_403, 0);
        assert!(st.inconclusive_cause().is_some(), "diagnostic posé au tail");
    }

    let diagnostic = result
        .report
        .diagnostic
        .clone()
        .expect("diagnostic present");
    match &diagnostic.cause {
        InconclusiveCause::RateLimited { count_429 } => {
            assert!(*count_429 >= 3, "{count_429}");
        }
        other => panic!("rate limiting must win by priority: {other:?}"),
    }
    let suggestion = diagnostic.suggestion.clone().expect("suggestion present");
    assert!(suggestion.contains("--ignore-code 429"), "{suggestion}");
    assert!(suggestion.contains("--rate-limit 2"), "{suggestion}");
    assert!(suggestion.starts_with("injekt --target "), "{suggestion}");

    // Console : la suggestion ne s'imprime que sous INCONCLUSIVE (smoke —
    // le helper exact est couvert par le test unit `console.rs`) ; elle est
    // déjà scrubbée via le JsonReport.
    console::print_run_summary(
        &result.target,
        "Inconclusive",
        result.report.request_count,
        Duration::from_secs(0),
        result.report.findings.len(),
        Some(suggestion.as_str()),
        &Scrubber::new(false),
    );
}
