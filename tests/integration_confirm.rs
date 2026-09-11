#![allow(clippy::unwrap_used, clippy::expect_used)]
//! C6 integration: `--confirm` real second-pass, `--seed` determinism,
//! hashes-only trace (no clear secrets in export).

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    session::export::EncryptedExport,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn fast_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

fn clean_cfg() -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec![
        "boolean".to_owned(),
        "error".to_owned(),
        "time".to_owned(),
        "union".to_owned(),
        "stacked".to_owned(),
        "json".to_owned(),
    ];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg
}

const CLEAN_BODY: &str = "welcome normal page id=1 content baseline 42 no sqli here";

/// Clean target (N1/N2 shape): identical body for every input, no error
/// patterns, no sleep primitives, no UNION markers.
fn clean_responder(_req: &wiremock::Request) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_string(CLEAN_BODY)
}

/// `--confirm` second-pass must not create findings on a clean target, and
/// must not burn extra requests when there is nothing to re-validate
/// (0 findings → 0 confirm probes by construction).
#[tokio::test]
async fn confirm_second_pass_creates_no_fp_on_clean_target() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(clean_responder)
        .mount(&server)
        .await;
    let target = format!("{}/?id=1", server.uri());

    // Without --confirm.
    let engine_plain = Engine::new(
        {
            let mut c = clean_cfg();
            c.confirm = false;
            c.seed = Some(42);
            c
        },
        fast_client(),
        CancellationToken::new(),
    );
    engine_plain.run(&target).await.expect("run plain");
    let plain_handle = engine_plain.state_handle();
    let plain = plain_handle.read().await;
    let plain_findings = plain.findings().len();
    let plain_req = plain.request_count();
    let plain_trace = plain.trace().len();
    drop(plain);

    // With --confirm.
    let engine_confirm = Engine::new(
        {
            let mut c = clean_cfg();
            c.confirm = true;
            c.seed = Some(42);
            c
        },
        fast_client(),
        CancellationToken::new(),
    );
    engine_confirm.run(&target).await.expect("run confirm");
    let confirm_handle = engine_confirm.state_handle();
    let guarded = confirm_handle.read().await;
    let confirm_findings = guarded.findings().len();
    let confirm_req = guarded.request_count();
    let confirm_trace = guarded.trace().len();
    drop(guarded);

    assert_eq!(plain_findings, 0, "clean target must yield 0 findings");
    assert_eq!(confirm_findings, 0, "--confirm must add 0 FP on N1/N2");
    // No findings → no second-pass probes: request counts identical.
    assert_eq!(
        confirm_req, plain_req,
        "--confirm on clean target must cost 0 extra requests"
    );
    // Trace is RAM-only hashes: baseline (3) + per-technique summaries.
    assert!(plain_trace >= 3, "trace must hold baseline records");
    assert!(confirm_trace >= 3, "confirm run must also trace baseline");
}

/// Same `--seed` → same payload sequence across two runs (wiremock records
/// every request URL). Uses RNG-sensitive tampers (`randomcase`) so an
/// unseeded path would diverge.
#[tokio::test]
async fn same_seed_same_payload_sequence() {
    async fn run_once(seed: u64, sink: Arc<Mutex<Vec<String>>>) -> Vec<String> {
        let server = MockServer::start().await;
        let sink_clone = Arc::clone(&sink);
        Mock::given(method("GET"))
            .respond_with(move |req: &wiremock::Request| {
                sink_clone.lock().expect("sink").push(req.url.to_string());
                ResponseTemplate::new(200).set_body_string(CLEAN_BODY)
            })
            .mount(&server)
            .await;
        let mut cfg = clean_cfg();
        cfg.techniques = vec!["boolean".to_owned()];
        cfg.confirm = false;
        cfg.seed = Some(seed);
        cfg.evasion.tampers =
            injekt::techniques::tamper::parse_tamper_list(Some("randomcase,space2randomblank"));
        let engine = Engine::new(cfg, fast_client(), CancellationToken::new());
        engine
            .run(&format!("{}/?id=1", server.uri()))
            .await
            .expect("run");
        let out = sink.lock().expect("sink").clone();
        assert!(!out.is_empty(), "expected recorded requests");
        out
    }

    let seq_a = run_once(42, Arc::new(Mutex::new(Vec::new()))).await;
    let seq_b = run_once(42, Arc::new(Mutex::new(Vec::new()))).await;
    assert_eq!(
        seq_a, seq_b,
        "2 runs with seed 42 must emit the identical payload sequence"
    );
}

/// Trace export holds hashes only: no cookie/token cleartext survives
/// `SessionState → XChaCha20/Argon2id → decrypt → grep`.
#[tokio::test]
async fn trace_export_holds_hashes_only_no_secrets() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(clean_responder)
        .mount(&server)
        .await;

    // Client carries a secret cookie + Authorization-equivalent custom header
    // value; the responder ignores them (clean target, 0 findings).
    let secret_cookie = "session=supersecret_cookie_abc123_xyz";
    let client = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .user_header(
            http::header::COOKIE,
            http::HeaderValue::from_str(secret_cookie).expect("cookie"),
        )
        .build()
        .expect("client build");

    let mut cfg = clean_cfg();
    cfg.confirm = true;
    cfg.seed = Some(7);
    let engine = Engine::new(cfg, client, CancellationToken::new());
    engine
        .run(&format!("{}/?id=1", server.uri()))
        .await
        .expect("run");
    let handle = engine.state_handle();
    let st = handle.read().await;
    assert!(
        st.trace().len() >= 3,
        "trace must be non-empty (baseline + summaries)"
    );
    // No clear payload/body in the live trace debug render.
    let live_dbg = format!("{:?}", st.trace().records());
    assert!(
        !live_dbg.contains("supersecret_cookie_abc123_xyz"),
        "live trace leaks cookie: {live_dbg}"
    );
    let st_clone = st.clone();
    drop(st);

    // Encrypted round-trip (v3, trace + seed) then grep the plaintext JSON.
    let path = std::env::temp_dir().join(format!(
        "injekt_c6_trace_{}_{}.enc",
        std::process::id(),
        rand::random::<u64>()
    ));
    let path_s = path.to_string_lossy().into_owned();
    std::fs::remove_file(&path).ok();
    let pass = secrecy::SecretString::from("c6-trace-passphrase-123");
    EncryptedExport::encrypt_to_file(&st_clone, &pass, &path_s).expect("encrypt");
    let plain = EncryptedExport::decrypt_from_file(&pass, &path_s).expect("decrypt");
    std::fs::remove_file(&path).ok();
    let text = String::from_utf8_lossy(&plain);
    assert!(
        !text.contains("supersecret_cookie_abc123_xyz"),
        "exported trace leaks cookie"
    );
    assert!(
        !text.contains("Authorization"),
        "exported trace leaks auth header name"
    );
    let v: serde_json::Value = serde_json::from_str(&text).expect("snapshot json");
    let trace = v
        .get("trace")
        .and_then(serde_json::Value::as_array)
        .expect("snapshot has trace");
    assert!(!trace.is_empty(), "exported trace must be non-empty");
    for r in trace {
        let req_h = r
            .get("request_hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let resp_h = r
            .get("response_hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        assert_eq!(req_h.len(), 64, "request_hash must be full SHA-256 hex");
        assert_eq!(resp_h.len(), 64, "response_hash must be full SHA-256 hex");
        let rendered = serde_json::to_string(r).expect("record json");
        assert!(
            !rendered.contains("supersecret_cookie_abc123_xyz"),
            "trace record leaks secret"
        );
    }
    // Seed survives the round-trip for replay determinism.
    assert_eq!(v.get("seed").and_then(serde_json::Value::as_u64), Some(7));
}
