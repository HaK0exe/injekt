#![allow(clippy::unwrap_used, clippy::expect_used)]

//! P0.2 — paires de contrôle à arithmétique aléatoire (`checkFalsePositives`).
//!
//! - `fake_literal_page_is_vetoed_by_control_pair` : la page ne différencie
//!   les payloads que par leur TEXTE (` 1=1 ` littéral) — la paire TRUE/FALSE
//!   historique confirme, mais les entiers aléatoires du contrôle (`r=r`,
//!   `r1=r2`) sont répondus comme la baseline → veto, 0 finding.
//! - `real_oracle_keeps_finding_and_reports_control_ok` : la page évalue
//!   réellement la comparaison entière du payload → le contrôle confirme le
//!   sens de la découverte → finding conservé avec ` control=ok`.
//! - `real_oracle_survives_confirm_second_pass` : le même oracle sous
//!   `--confirm` traverse AUSSI le contrôle de la seconde passe (≥ 4 requêtes
//!   de contrôle au total) et garde son finding.

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    session::state::{Finding, TechniqueKind},
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

const BASELINE_BODY: &str = "welcome product listing page id=1 normal content row here";
const ALT_BODY: &str = "no results found nothing to show";

fn test_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(10))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

fn boolean_cfg() -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.budget.level = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg.enumeration.extract = false;
    cfg.seed = Some(42);
    cfg
}

/// Décode une URL de mock (`+` = espace, `%XX`) sans dépendance
/// supplémentaire, pour raisonner sur le payload injecté.
fn decode_url(url: &str) -> String {
    let bytes = url.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Première comparaison entière `(\d+)\s*=\s*(\d+)` d'un texte décodé.
fn first_int_comparison(text: &str) -> Option<(u64, u64)> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let lhs_end = i;
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if bytes.get(j) != Some(&b'=') {
            continue;
        }
        j += 1;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        let rhs_start = j;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j == rhs_start {
            continue;
        }
        if let (Ok(lhs), Ok(rhs)) = (
            text[start..lhs_end].parse::<u64>(),
            text[rhs_start..j].parse::<u64>(),
        ) {
            return Some((lhs, rhs));
        }
    }
    None
}

/// Vrai si `text` contient une suite de 4 chiffres — signature des entiers
/// aléatoires `1000..=9999` des payloads de contrôle (les payloads détectés
/// n'ont que des littéraux à un chiffre).
fn has_control_arithmetic(text: &str) -> bool {
    text.as_bytes()
        .windows(4)
        .any(|w| w.iter().all(u8::is_ascii_digit))
}

/// Page « fausse injection » : elle ne réagit qu'au TEXTE ` 1=1 ` (motif de
/// l'injection historique), jamais à la logique — les entiers aléatoires du
/// contrôle sont répondus comme la baseline → veto attendu.
fn literal_responder(req: &wiremock::Request) -> ResponseTemplate {
    if decode_url(req.url.as_str()).contains(" 1=1 ") {
        return ResponseTemplate::new(200).set_body_string(ALT_BODY);
    }
    ResponseTemplate::new(200).set_body_string(BASELINE_BODY)
}

/// Oracle booléen fidèle : la page évalue réellement la comparaison entière
/// du payload (`1=1` → branche différente, `1=2` → baseline).
fn oracle_responder(req: &wiremock::Request) -> ResponseTemplate {
    if let Some((lhs, rhs)) = first_int_comparison(&decode_url(req.url.as_str()))
        && lhs == rhs
    {
        return ResponseTemplate::new(200).set_body_string(ALT_BODY);
    }
    ResponseTemplate::new(200).set_body_string(BASELINE_BODY)
}

/// Lance le moteur booléen (L1, seed 42) contre la page simulée et retourne
/// `(findings, urls vues par la cible)`.
async fn run_boolean(
    responder: fn(&wiremock::Request) -> ResponseTemplate,
    confirm: bool,
) -> (Vec<Finding>, Vec<String>) {
    let server = MockServer::start().await;
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    Mock::given(method("GET"))
        .respond_with(move |req: &wiremock::Request| {
            sink.lock().expect("sink").push(req.url.to_string());
            responder(req)
        })
        .mount(&server)
        .await;
    let mut cfg = boolean_cfg();
    cfg.confirm = confirm;
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    engine
        .run(&format!("{}/?id=1", server.uri()))
        .await
        .expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let urls = seen.lock().expect("sink").clone();
    (findings, urls)
}

/// Le différentiel de cette page vient du motif textuel `1=1`, pas de la
/// logique SQL : la paire historique confirme (le seuil `1=2` est muet), mais
/// le contrôle `r=r`/`r1=r2` ne reproduit pas les deux états → veto.
#[tokio::test]
async fn fake_literal_page_is_vetoed_by_control_pair() {
    let (findings, urls) = run_boolean(literal_responder, false).await;
    let controls = urls
        .iter()
        .filter(|u| has_control_arithmetic(&decode_url(u)))
        .count();
    assert!(
        controls >= 2,
        "la paire doit avoir été confirmée puis contrôlée (2 requêtes `r=r`/`r1=r2`), vues: {urls:?}"
    );
    assert!(
        findings.is_empty(),
        "page réactive au texte seul : le contrôle doit vétér le finding, got {findings:?}"
    );
}

/// Oracle réel : le contrôle confirme la cohérence de direction (inversée ici
/// : la branche `1=1` diffère de la baseline) et le finding est conservé.
#[tokio::test]
async fn real_oracle_keeps_finding_and_reports_control_ok() {
    let (findings, urls) = run_boolean(oracle_responder, false).await;
    assert_eq!(
        findings.len(),
        1,
        "oracle sain : 1 finding, got {findings:?}"
    );
    let finding = &findings[0];
    assert_eq!(finding.technique, TechniqueKind::Boolean);
    assert!(
        finding.evidence.contains("control=ok"),
        "evidence must cite the passing control, got {}",
        finding.evidence
    );
    assert!(
        urls.iter()
            .filter(|u| has_control_arithmetic(&decode_url(u)))
            .count()
            >= 2,
        "contrôle 1st-pass envoyé (`r=r` + `r1=r2`), vues: {urls:?}"
    );
}

/// `--confirm` rejoue la paire au second passage : le contrôle y est
/// re-exécuté (+2 requêtes de contrôle) et le finding survit.
#[tokio::test]
async fn real_oracle_survives_confirm_second_pass() {
    let (findings, urls) = run_boolean(oracle_responder, true).await;
    assert_eq!(
        findings.len(),
        1,
        "oracle sain + --confirm : 1 finding conservé, got {findings:?}"
    );
    assert!(
        findings[0].evidence.contains("control=ok"),
        "evidence 1st-pass conservée, got {}",
        findings[0].evidence
    );
    assert!(
        urls.iter()
            .filter(|u| has_control_arithmetic(&decode_url(u)))
            .count()
            >= 4,
        "contrôle rejoué par la seconde passe (2 + 2 requêtes), vues: {urls:?}"
    );
}
