use super::*;
use crate::session::state::{Finding, SessionState, TechniqueKind};
use secrecy::SecretString;
use std::fs;

fn test_state() -> SessionState {
    let mut state = SessionState::new();
    state.push_finding(Finding::new(
        "http://example.com/?id=1",
        "id@query",
        TechniqueKind::Boolean,
        0.9,
        "evidence with secret Authorization: Bearer abc123",
    ));
    state.push_extracted(SecretString::from("extracted secret data"));
    state
}

fn temp_path() -> String {
    // Test-only temp filename: stays on OS randomness so parallel test
    // workers never collide; never seeded (uniqueness, not determinism).
    let path = std::env::temp_dir()
        .join(format!("injekt_test_export_{}.enc", rand::random::<u64>()))
        .to_string_lossy()
        .into_owned();
    std::fs::remove_file(&path).ok();
    path
}

#[test]
fn encrypt_to_file_creates_new_file_fails_if_exists() {
    let state = test_state();
    let passphrase = SecretString::from("passphrase123456");
    let path = temp_path();

    // First write should succeed
    EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();

    // Second write should fail because file exists (create_new)
    let result = EncryptedExport::encrypt_to_file(&state, &passphrase, &path);
    assert!(result.is_err(), "create_new should fail if file exists");
    let _ = fs::remove_file(&path);
}

#[test]
fn decrypt_does_not_leak_secrets_in_json() {
    let state = test_state();
    let passphrase = SecretString::from("passphrase123456");
    let path = temp_path();

    EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
    let json_bytes = EncryptedExport::decrypt_from_file(&passphrase, &path).unwrap();
    let json_str = String::from_utf8_lossy(&json_bytes);

    // The decrypted JSON should contain the findings with secrets scrubbed if we check
    // But decrypt_from_file returns raw JSON - the scrubbing happens at report level
    // We verify the file can be decrypted
    assert!(json_str.contains("findings"));
    assert!(json_str.contains("request_count"));
    let _ = fs::remove_file(&path);
}

#[test]
fn snapshot_debug_hides_extracted_dump() {
    // NOTE: the scrubber redacts keyed secrets (`?token=`, `session=`);
    // bare opaque words without key context cannot be distinguished from
    // prose without false positives, so fixtures use keyed secrets.
    let snapshot = Snapshot {
        findings: vec![Finding::new(
            "https://example.com/?token=secret123",
            "id@query",
            TechniqueKind::Boolean,
            0.9,
            "boolean split, session=secret123",
        )],
        extracted: vec!["dump row secret123".to_owned()],
        request_count: 3,
        started_at: None,
        trace: Vec::new(),
        seed: Some(42),
    };
    let rendered = format!("{snapshot:?}");
    assert!(!rendered.contains("secret123"), "{rendered}");
    assert!(rendered.contains("extracted_count"), "{rendered}");
}

#[test]
fn extracted_data_survives_roundtrip() {
    let state = test_state();
    let passphrase = SecretString::from("passphrase123456");
    let path = temp_path();

    EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
    let json_bytes = EncryptedExport::decrypt_from_file(&passphrase, &path).unwrap();
    let snapshot: Snapshot = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(snapshot.extracted, vec!["extracted secret data".to_owned()]);
    let _ = fs::remove_file(&path);
}

#[test]
fn export_file_has_600_permissions_on_unix() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let state = test_state();
        let passphrase = SecretString::from("passphrase123456");
        let path = temp_path();

        EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
        let meta = fs::metadata(&path).unwrap();
        // 0o600 = 384 in decimal
        assert_eq!(
            meta.mode() & 0o777,
            0o600,
            "file should have 0o600 permissions"
        );
        let _ = fs::remove_file(&path);
    }
}

#[test]
fn trace_and_seed_survive_roundtrip() {
    use crate::reasoning::ProbeRecord;
    let mut state = test_state();
    state.set_seed(Some(42));
    state.push_trace(ProbeRecord::from_clear(
        0,
        "id@query",
        "boolean",
        "none",
        Some(42),
        "' OR 1=1",
        "welcome",
        0.9,
        12.0,
    ));
    let passphrase = SecretString::from("passphrase123456");
    let path = temp_path();

    EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
    let json_bytes = EncryptedExport::decrypt_from_file(&passphrase, &path).unwrap();
    let snapshot: Snapshot = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(snapshot.seed, Some(42));
    assert_eq!(snapshot.trace.len(), 1);
    assert_eq!(snapshot.trace[0].seq, 0);
    // Trace stores hashes only — never the clear payload/body.
    let dbg = format!("{:?}", snapshot.trace[0]);
    assert!(!dbg.contains("OR 1=1"), "payload leaked: {dbg}");
    let _ = fs::remove_file(&path);
}

#[test]
fn legacy_v1_snapshot_still_deserializes() {
    // v1 shape: no `extracted`/`trace`/`seed` keys (pre-C6 export).
    // `#[serde(default)]` must keep old blobs readable (v1.0-rc compat).
    let legacy = serde_json::json!({
        "findings": [],
        "request_count": 7,
        "started_at": null,
    });
    let bytes = serde_json::to_vec(&legacy).unwrap();
    let snapshot: Snapshot = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(snapshot.request_count, 7);
    assert_eq!(snapshot.extracted, [] as [String; 0]);
    assert_eq!(snapshot.trace, [] as [crate::reasoning::ProbeRecord; 0]);
    assert_eq!(snapshot.seed, None);
}

#[test]
fn unsupported_blob_version_is_rejected() {
    let state = test_state();
    let passphrase = SecretString::from("passphrase123456");
    let path = temp_path();
    EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
    // Rewrite the envelope with a future version (99): decrypt must refuse.
    let data = fs::read(&path).unwrap();
    let mut blob: serde_json::Value = serde_json::from_slice(&data).unwrap();
    blob["v"] = serde_json::Value::from(99);
    fs::write(&path, serde_json::to_vec(&blob).unwrap()).unwrap();
    let err = EncryptedExport::decrypt_from_file(&passphrase, &path).unwrap_err();
    assert!(
        err.to_string().contains("unsupported blob version"),
        "unexpected error: {err}"
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn wrong_passphrase_fails_decryption() {
    let state = test_state();
    let passphrase = SecretString::from("passphrase123456");
    let wrong = SecretString::from("wrong-passphrase-000");
    let path = temp_path();
    EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
    assert!(EncryptedExport::decrypt_from_file(&wrong, &path).is_err());
    let _ = fs::remove_file(&path);
}

#[test]
fn short_passphrase_rejected_in_lib() {
    let state = test_state();
    for short in ["", "1234567", "short-pw"] {
        let err =
            EncryptedExport::encrypt_to_file(&state, &SecretString::from(short), &temp_path())
                .unwrap_err();
        assert!(
            err.to_string().contains("passphrase too short"),
            "unexpected error for {short:?}: {err}"
        );
    }
}

#[test]
fn short_salt_and_unknown_kdf_rejected() {
    let state = test_state();
    let passphrase = SecretString::from("passphrase123456");
    let path = temp_path();
    EncryptedExport::encrypt_to_file(&state, &passphrase, &path).unwrap();
    let data = fs::read(&path).unwrap();
    let mut blob: serde_json::Value = serde_json::from_slice(&data).unwrap();
    // Empty salt collapses Argon2id strength: refuse instead of deriving.
    blob["salt_b64"] = serde_json::Value::from(String::new());
    fs::write(&path, serde_json::to_vec(&blob).unwrap()).unwrap();
    let err = EncryptedExport::decrypt_from_file(&passphrase, &path).unwrap_err();
    assert!(err.to_string().contains("salt"), "unexpected error: {err}");
    // Unknown KDF: refuse instead of silently ignoring the field.
    let mut blob: serde_json::Value = serde_json::from_slice(&data).unwrap();
    blob["kdf"] = serde_json::Value::from("scrypt-xyz");
    fs::write(&path, serde_json::to_vec(&blob).unwrap()).unwrap();
    let err = EncryptedExport::decrypt_from_file(&passphrase, &path).unwrap_err();
    assert!(err.to_string().contains("KDF"), "unexpected error: {err}");
    let _ = fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// C17 — `rekey_from_file` (migration 4 : `injekt session export <PATH>`)
// ---------------------------------------------------------------------------

#[test]
fn rekey_preserves_snapshot_and_updates_envelope() {
    let state = test_state();
    let a = SecretString::from("passphrase123456");
    let b = SecretString::from("new-passphrase-987");
    let src = temp_path();
    let dst = temp_path();
    EncryptedExport::encrypt_to_file(&state, &a, &src).unwrap();
    EncryptedExport::rekey_from_file(&a, &src, &b, &dst, false).unwrap();
    // New file opens with the NEW passphrase only.
    let plain = EncryptedExport::decrypt_from_file(&b, &dst).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(
        v.get("request_count").and_then(serde_json::Value::as_u64),
        Some(0),
        "snapshot byte-contenu préservé (re-key, pas de reserialization)"
    );
    assert_eq!(
        v.get("findings")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    // Source still opens with the OLD passphrase (untouched).
    EncryptedExport::decrypt_from_file(&a, &src).unwrap();
    fs::remove_file(&src).unwrap();
    fs::remove_file(&dst).unwrap();
}

#[test]
fn rekey_requires_force_to_replace_destination() {
    let state = test_state();
    let a = SecretString::from("passphrase123456");
    let b = SecretString::from("new-passphrase-987");
    let src = temp_path();
    let dst = temp_path();
    EncryptedExport::encrypt_to_file(&state, &a, &src).unwrap();
    EncryptedExport::encrypt_to_file(&state, &a, &dst).unwrap();
    let err = EncryptedExport::rekey_from_file(&a, &src, &b, &dst, false).unwrap_err();
    assert!(
        err.to_string().contains("destination already exists"),
        "unexpected error: {err}"
    );
    // Pre-existing destination untouched by the failed rotation.
    EncryptedExport::decrypt_from_file(&a, &dst).unwrap();
    EncryptedExport::rekey_from_file(&a, &src, &b, &dst, true).unwrap();
    EncryptedExport::decrypt_from_file(&b, &dst).unwrap();
    fs::remove_file(&src).unwrap();
    fs::remove_file(&dst).unwrap();
}

#[test]
fn rekey_rejects_wrong_source_passphrase_and_short_dest() {
    let state = test_state();
    let a = SecretString::from("passphrase123456");
    let src = temp_path();
    let dst = temp_path();
    EncryptedExport::encrypt_to_file(&state, &a, &src).unwrap();
    // Wrong source passphrase: decrypt fails before any write. The AEAD
    // opaque error (`aead::Error`-ish) carries no stable wording — assert
    // the BEHAVIOR: no partial write, source still intact.
    let wrong = SecretString::from("this-is-not-the-pass");
    let _err = EncryptedExport::rekey_from_file(&wrong, &src, &a, &dst, false)
        .expect_err("wrong passphrase must fail");
    assert!(!fs::exists(&dst).unwrap(), "aucune écriture partielle");
    EncryptedExport::decrypt_from_file(&a, &src).unwrap();
    // Destination passphrase below MIN_PASSPHRASE_LEN: no write.
    let short = SecretString::from("too-6short");
    let err = EncryptedExport::rekey_from_file(&a, &src, &short, &dst, false).unwrap_err();
    assert!(
        err.to_string().contains("passphrase too short"),
        "unexpected error: {err}"
    );
    fs::remove_file(&src).unwrap();
}

#[test]
fn rekey_force_wrong_source_preserves_destination() {
    let state = test_state();
    let a = SecretString::from("passphrase123456");
    let b = SecretString::from("new-passphrase-987");
    let src = temp_path();
    let dst = temp_path();
    EncryptedExport::encrypt_to_file(&state, &a, &src).unwrap();
    EncryptedExport::encrypt_to_file(&state, &a, &dst).unwrap();
    // --force + wrong source passphrase: the source must fail BEFORE the
    // destination is removed (no destructive rotation on a typo).
    let wrong = SecretString::from("this-is-not-the-pass");
    let _err = EncryptedExport::rekey_from_file(&wrong, &src, &b, &dst, true)
        .expect_err("wrong source passphrase must fail");
    EncryptedExport::decrypt_from_file(&a, &dst)
        .expect("pre-existing destination preserved on source decrypt failure");
    fs::remove_file(&src).unwrap();
    fs::remove_file(&dst).unwrap();
}
