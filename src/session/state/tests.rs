// Fixtures : `expect` lisible — convention repo (header allow par fichier).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

fn secret_finding() -> Finding {
    Finding::new(
        "https://example.com/search?token=secret123&id=1",
        "id",
        TechniqueKind::Boolean,
        0.9,
        "boolean TRUE/FALSE split, session=secret123",
    )
}

#[test]
fn finding_debug_redacts_secrets_but_keeps_host() {
    let finding = secret_finding();
    let rendered = format!("{finding:?}");
    assert!(!rendered.contains("secret123"), "{rendered}");
    assert!(rendered.contains("example.com"), "{rendered}");
    assert!(rendered.contains("[REDACTED]"), "{rendered}");
}

#[test]
fn finding_debug_truncates_evidence() {
    let mut finding = secret_finding();
    finding.evidence = "x".repeat(10_000);
    let rendered = format!("{finding:?}");
    assert!(rendered.len() < 10_000, "{rendered}");
}

#[test]
fn session_debug_hides_extracted_values() {
    use secrecy::SecretString;
    let mut state = SessionState::new();
    state
        .extracted
        .push(SecretString::from("admin:secret123".to_owned()));
    state.increment_requests();
    let rendered = format!("{state:?}");
    assert!(!rendered.contains("secret123"), "{rendered}");
    assert!(rendered.contains("extracted_count"), "{rendered}");
}

#[test]
fn session_set_inconclusive_cause_round_trip() {
    // C14 : le setter pose/renomme le diagnostic (max 1/run, un set
    // ultérieur remplace) et le Debug ne rend que le code de cause.
    let mut state = SessionState::new();
    assert!(state.inconclusive_cause().is_none());
    let diag =
        crate::engine::diagnostics::Diagnostic::derive(&crate::engine::diagnostics::DiagSignals {
            unstable_statuses: vec![200, 500, 200],
            ..crate::engine::diagnostics::DiagSignals::default()
        })
        .expect("unstable derives");
    state.set_inconclusive_cause(Some(diag));
    assert_eq!(
        state.inconclusive_cause().map_or("", |d| d.cause.code()),
        "UnstableBaseline"
    );
    // Remplacement : le dernier set au point de dégradation gagne.
    state.set_inconclusive_cause(None);
    assert!(state.inconclusive_cause().is_none());
    let diag2 =
        crate::engine::diagnostics::Diagnostic::derive(&crate::engine::diagnostics::DiagSignals {
            count_429: 9,
            ..crate::engine::diagnostics::DiagSignals::default()
        })
        .expect("rate limited derives");
    state.set_inconclusive_cause(Some(diag2));
    assert_eq!(
        state.inconclusive_cause().map_or("", |d| d.cause.code()),
        "RateLimited"
    );
}

#[test]
fn session_debug_never_renders_the_cli_argv_in_diagnostic() {
    // La suggestion porte l'argv original (tokens possiblement secrets) :
    // le Debug de `SessionState` n'expose que le code de cause — jamais le
    // champ crû (`Diagnostic` garde la sienne redactée).
    let mut state = SessionState::new();
    let diag =
        crate::engine::diagnostics::Diagnostic::derive(&crate::engine::diagnostics::DiagSignals {
            count_429: 4,
            argv: vec![
                "--target".to_owned(),
                "https://lab.tld/?token=abcd".to_owned(),
            ],
            ..crate::engine::diagnostics::DiagSignals::default()
        })
        .expect("rate limited derives");
    state.set_inconclusive_cause(Some(diag));
    let rendered = format!("{state:?}");
    assert!(!rendered.contains("abcd"), "argv leaked: {rendered}");
    assert!(!rendered.contains("lab.tld"), "target leaked: {rendered}");
    assert!(rendered.contains("RateLimited"), "{rendered}");
}

#[test]
fn session_wipe_drops_the_diagnostic() {
    // Zero-persistence en mémoire : `wipe`/zeroize remet le diagnostic à
    // `None` (aucune trace texte restante).
    let mut state = SessionState::new();
    let diag =
        crate::engine::diagnostics::Diagnostic::derive(&crate::engine::diagnostics::DiagSignals {
            baseline_all_error: true,
            ..crate::engine::diagnostics::DiagSignals::default()
        })
        .expect("unreachable derives");
    state.set_inconclusive_cause(Some(diag));
    state.wipe();
    assert!(state.inconclusive_cause().is_none());
}
