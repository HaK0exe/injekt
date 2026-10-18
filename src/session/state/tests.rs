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
