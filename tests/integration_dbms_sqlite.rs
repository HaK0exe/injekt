#![allow(clippy::unwrap_used, clippy::expect_used)]

//! P5 — SQLite dialect acceptance suite (`--dbms sqlite`):
//! 1. boolean pairs confirm on a simulated SQLite backend and the
//!    `tables` knob dumps user tables via `sqlite_master` (`group_concat`
//!    oracle over `LENGTH((...))>=N` / `UNICODE(SUBSTR((...),p,1))>=m`);
//! 2. with the sqlite hint, the engine never sends MySQL/Postgres/MSSQL/
//!    Oracle error payloads (dialect purity asserted on the request sink);
//! 3. the `sqlite3` alias routes identically to `sqlite`.
//!
//! Default (no hint) behavior is untouched by P5: byte-identical auto
//! fingerprinting is covered by `integration_dbms_fingerprint.rs`.

use injekt::{
    engine::{Engine, EngineConfig, EngineState},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn test_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(std::sync::Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

/// Canned simulation values — lengths are load-bearing for the length
/// inference phase (11 / 7 / 6).
const TABLES_VALUE: &str = "users,posts";
const COLUMNS_VALUE: &str = "id,name";
const VERSION_VALUE: &str = "3.50.2";

const BASE: &str = "welcome normal page id=1 content baseline 42";
const ALT: &str = "welcome normal page id=1 content baseline 42 BUT THIS PAGE WAS ALTERED BY THE FALSE BRANCH OF THE INJECTION AND SAYS SOMETHING ELSE ENTIRELY";

/// Minimal query decoder (ASCII-only payloads): `+` → space, `%XX` → byte.
fn decoded_query(req: &wiremock::Request) -> String {
    let raw = req.url.query().unwrap_or_default().replace('+', " ");
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 3 <= bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(char::from(byte));
            i += 3;
            continue;
        }
        out.push(char::from(bytes[i]));
        i += 1;
    }
    out
}

/// Value the simulated SQLite engine would return for an extraction query.
fn canned_value(query: &str) -> Option<&'static str> {
    if query.contains("sqlite_master") {
        Some(TABLES_VALUE)
    } else if query.contains("pragma_table_info") {
        Some(COLUMNS_VALUE)
    } else if query.contains("sqlite_version()") {
        Some(VERSION_VALUE)
    } else {
        None
    }
}

/// First integer comparison found (any `a=b` with both ASCII digits).
/// `Some(true)` = logically true, `Some(false)` = false, `None` = none.
/// P0.2-shaped: random `r=r`/`r1=r2` controls are evaluated literally so
/// they are never voted as baseline by mistake.
fn eval_int_comparison(text: &str) -> Option<bool> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'=' {
            i += 1;
            continue;
        }
        let mut start = i;
        while start > 0 && bytes[start - 1].is_ascii_digit() {
            start -= 1;
        }
        let rhs_start = i + 1;
        let mut end = rhs_start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if start < i
            && end > rhs_start
            && let (Ok(lhs), Ok(rhs)) = (
                text[start..i].parse::<u64>(),
                text[rhs_start..end].parse::<u64>(),
            )
        {
            return Some(lhs == rhs);
        }
        i = rhs_start;
    }
    None
}

/// The same-as-baseline body means "predicate is TRUE" (the engine scores
/// the boolean channel as a differential against the baseline page).
fn sqlite_responder(req: &wiremock::Request) -> ResponseTemplate {
    let q = decoded_query(req);
    let holds = if let (Some(value), Some(rest)) = (canned_value(&q), q.split_once(",1))>=")) {
        // UNICODE(SUBSTR((<query>),<pos>,1))>=<mid> — pos is the digit run
        // right before the `,1))>=` seam (digits reversed during scan).
        let pos_digits: String = rest
            .0
            .bytes()
            .rev()
            .take_while(u8::is_ascii_digit)
            .map(|b| b as char)
            .collect();
        let pos: usize = pos_digits
            .chars()
            .rev()
            .collect::<String>()
            .parse()
            .unwrap_or(0);
        let mid: u32 = rest
            .1
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or(0);
        value
            .chars()
            .nth(pos.saturating_sub(1))
            .is_some_and(|c| u32::from(c) >= mid)
    } else if q.contains("LENGTH((") {
        match (canned_value(&q), q.split_once(">=")) {
            (Some(value), Some((_, n))) => {
                let guess: usize = n
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0);
                value.chars().count() >= guess
            }
            _ => true,
        }
    } else if q.contains("'1'='2'") {
        false
    } else {
        eval_int_comparison(&q).unwrap_or(true)
    };
    let body = if holds { BASE } else { ALT };
    ResponseTemplate::new(200).set_body_string(body)
}

fn base_cfg(hint: &str) -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg.dbms_hint = Some(hint.to_owned());
    cfg
}

/// 1. Boolean pairs confirm on the sqlite dialect + `tables` (and `banner`)
///    enumeration rides the same boolean oracle with the sqlite grammar:
///    `sqlite_master` (tables) / `sqlite_version()` (banner).
#[tokio::test]
async fn sqlite_boolean_confirms_and_enumerates_sqlite_master() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(sqlite_responder)
        .mount(&server)
        .await;

    let mut cfg = base_cfg("sqlite");
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.enumeration.tables = true;
    cfg.enumeration.banner = true;
    cfg.enumeration.db = Some("main".to_owned());
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let target = format!("{}/?id=1", server.uri());
    let state = engine.run(&target).await.expect("run stays Ok");
    assert_eq!(state, EngineState::Done);
    let confirmed = engine
        .state_handle()
        .read()
        .await
        .findings()
        .iter()
        .any(|f| {
            f.technique == injekt::session::state::TechniqueKind::Boolean
                && f.confidence >= 0.5
                && !f.evidence.contains("unconfirmed")
        });
    assert!(confirmed, "boolean finding expected");

    let extracted = engine.state_handle().read().await.extracted_exposed();
    assert!(
        extracted.iter().any(|v| v == TABLES_VALUE),
        "sqlite_master tables dump expected, got {extracted:?}"
    );
    assert!(
        extracted.iter().any(|v| v == VERSION_VALUE),
        "sqlite_version banner expected, got {extracted:?}"
    );
}

/// 2. With the sqlite hint the error sweep is dialect-pure: only the
///    SQLite payloads are sent, the MySQL/Postgres/MSSQL/Oracle legacies
///    never reach the wire (request-sink assertion + no finding on an
///    inert backend).
#[tokio::test]
async fn sqlite_hint_error_sweep_is_dialect_pure() {
    let server = MockServer::start().await;
    let sink = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink_for_mock = Arc::clone(&sink);
    Mock::given(method("GET"))
        .respond_with(move |req: &wiremock::Request| {
            sink_for_mock.lock().expect("sink").push(decoded_query(req));
            ResponseTemplate::new(200).set_body_string(BASE)
        })
        .mount(&server)
        .await;

    let mut cfg = base_cfg("sqlite");
    cfg.techniques = vec!["error".to_owned()];
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let target = format!("{}/?id=1", server.uri());
    let state = engine.run(&target).await.expect("run stays Ok");
    assert_eq!(state, EngineState::Done);
    assert!(
        engine.state_handle().read().await.findings().is_empty(),
        "an inert backend must yield zero findings"
    );

    let seen = sink.lock().expect("sink").clone();
    assert!(!seen.is_empty(), "the error sweep must have sent requests");
    assert!(
        seen.iter().any(|q| q.contains("abs(-9223372036854775808")),
        "sqlite overflow probe expected in {:?}",
        seen.iter().take(6).collect::<Vec<_>>()
    );
    for legacy in [
        "EXTRACTVALUE",
        "@@version",
        "v$version",
        "CTXSYS",
        "DB_NAME(",
        "version()",
    ] {
        assert!(
            !seen.iter().any(|q| q.contains(legacy)),
            "non-sqlite payload caught on the wire: {legacy}"
        );
    }
}

/// 3. `sqlite3` alias routes through the same resolvers as `sqlite`.
#[tokio::test]
async fn sqlite3_alias_routes_like_sqlite() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(sqlite_responder)
        .mount(&server)
        .await;

    let mut cfg = base_cfg("sqlite3");
    cfg.techniques = vec!["boolean".to_owned()];
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let target = format!("{}/?id=1", server.uri());
    let state = engine.run(&target).await.expect("run stays Ok");
    assert_eq!(state, EngineState::Done);
    let confirmed = engine
        .state_handle()
        .read()
        .await
        .findings()
        .iter()
        .any(|f| {
            f.technique == injekt::session::state::TechniqueKind::Boolean
                && f.confidence >= 0.5
                && !f.evidence.contains("unconfirmed")
        });
    assert!(confirmed, "boolean finding expected via the sqlite3 alias");
}
