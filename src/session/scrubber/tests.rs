use super::*;

#[test]
fn scrubs_authorization() {
    let sc = Scrubber::new(false);
    let out = sc.scrub("Authorization: Bearer abc123");
    assert!(out.contains("[REDACTED]"), "{out}");
}

#[test]
fn no_redact_passthrough() {
    let sc = Scrubber::new(true);
    let input = "Authorization: Bearer abc";
    assert_eq!(sc.scrub(input), input);
}

#[test]
fn hash_truncated_len() {
    assert_eq!(Scrubber::hash_truncated("secret").len(), 16);
}

#[test]
fn scrubs_bearer_with_base64_padding() {
    let sc = Scrubber::new(false);
    let out = sc.scrub("Authorization: Bearer abc");
    assert!(out.contains("[REDACTED]"), "{out}");
    // `+/=` are valid base64 token chars — no trailing leakage.
    let out = sc.scrub("token Bearer abc+def/ghi==");
    assert!(!out.contains("+def/ghi=="), "{out}");
    assert!(out.contains("Bearer [REDACTED]"), "{out}");
}

#[test]
fn scrubs_temporary_aws_keys() {
    let sc = Scrubber::new(false);
    let out = sc.scrub("key ASIAIOSFODNN7EXAMPLE");
    assert!(!out.contains("ASIAIOSFODNN7EXAMPLE"), "{out}");
}

#[test]
fn scrubs_full_pem_block() {
    let sc = Scrubber::new(false);
    let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----";
    let out = sc.scrub(pem);
    assert!(!out.contains("MIIEvgIBADANBg"), "{out}");
    assert!(!out.contains("END PRIVATE KEY"), "{out}");
}

#[test]
fn scrubs_extended_sensitive_headers() {
    let sc = Scrubber::new(false);
    for line in [
        "X-Access-Token: hunter2-value",
        "X-Session-Token: hunter2-value",
        "X-Api-Secret: hunter2-value",
        "Proxy-Authenticate: Basic hunter2-value",
        "WWW-Authenticate: Bearer hunter2-value",
    ] {
        let out = sc.scrub(line);
        assert!(!out.contains("hunter2-value"), "{line} leaked: {out}");
        assert!(out.contains("[REDACTED]"), "{line}: {out}");
    }
    assert_eq!(
        sc.scrub_header("X-Session-Token", "hunter2-value"),
        "[REDACTED]"
    );
    assert_eq!(sc.scrub_header("X-Request-Id", "req-123"), "req-123");
}

#[test]
fn scrubs_url_userinfo_but_keeps_host() {
    let sc = Scrubber::new(false);
    let out = sc.scrub("target https://admin:s3cr3t-p4ss@example.com/?id=1");
    assert!(!out.contains("s3cr3t-p4ss"), "{out}");
    assert!(!out.contains("admin:s3cr3t"), "{out}");
    assert!(out.contains("example.com/?id=1"), "{out}");
    let out = sc.scrub("proxy socks5h://user:p4ss@127.0.0.1:1080");
    assert!(!out.contains("p4ss@"), "{out}");
}

#[test]
fn scrubs_sensitive_query_values_but_keeps_benign_params() {
    let sc = Scrubber::new(false);
    let out = sc.scrub("https://example.com/?id=1&token=abc123XYZ&sessionid=sess-999");
    assert!(out.contains("id=1"), "benign param must survive: {out}");
    assert!(!out.contains("abc123XYZ"), "{out}");
    assert!(!out.contains("sess-999"), "{out}");
    assert!(out.contains("token=[REDACTED]"), "{out}");
}

#[test]
fn scrubs_json_and_form_body_secrets() {
    let sc = Scrubber::new(false);
    let out = sc.scrub(r#"body {"password": "hunter2", "user": "admin"}"#);
    assert!(!out.contains("hunter2"), "{out}");
    assert!(out.contains(r#""password": "[REDACTED]""#), "{out}");
    assert!(
        out.contains("admin"),
        "non-sensitive value must survive: {out}"
    );
    let out = sc.scrub("data password=hunter2&user=admin&api_key=AK-999");
    assert!(!out.contains("hunter2"), "{out}");
    assert!(!out.contains("AK-999"), "{out}");
    assert!(out.contains("user=admin"), "{out}");
}

#[test]
fn scrubs_provider_tokens_and_basic() {
    let sc = Scrubber::new(false);
    let fixture = "ghp_1234567890abcdefghij1234567890abcd glpat-1234567890abcdefg \
         xoxb-123-456-abc sk_live_abc123DEF456 sk-proj-abcDEF1234567890ABCDEF \
         Basic dXNlcjpwYXNz hunter BasicAuth";
    let out = sc.scrub(fixture);
    for secret in [
        "ghp_1234567890abcdefghij1234567890abcd",
        "glpat-1234567890abcdefg",
        "xoxb-123-456-abc",
        "sk_live_abc123DEF456",
        "sk-proj-abcDEF1234567890ABCDEF",
        "dXNlcjpwYXNz",
    ] {
        assert!(!out.contains(secret), "{secret} leaked: {out}");
    }
}

#[test]
fn scrubs_extended_secret_key_variants() {
    let sc = Scrubber::new(false);
    // Previously-missed variants from the audit: hyphen/underscore/camelCase.
    for secret in [
        "X-Api-Token: hunter2-value",
        "X-Api-Secret: hunter2-value",
        "Api-Secret: hunter2-value",
        "Csrf-Token: hunter2-value",
        "https://example.com/?x-api-token=abc123&api-secret=def456&csrf-token=ghi789",
        r#"{"privateKey": "hunter2", "apiSecret": "hunter2b"}"#,
        "data apiSecret=hunter2&privateKey=hunter2b&csrf-token=hunter2c",
        "proxy socks://user:p4ss@127.0.0.1:1080",
    ] {
        let out = sc.scrub(secret);
        assert!(
            !out.contains("hunter2")
                && !out.contains("abc123")
                && !out.contains("def456")
                && !out.contains("ghi789")
                && !out.contains("p4ss@"),
            "leaked: {secret} -> {out}"
        );
    }
    // Host preserved for userinfo redact.
    let out = sc.scrub("proxy socks://user:p4ss@127.0.0.1:1080");
    assert!(out.contains("127.0.0.1"), "{out}");
}

#[test]
fn scrubs_unified_sensitive_keys_across_renderers() {
    // Previously-missed keys per renderer (audit): `authorization` and
    // `private-key` in query, `cookie`/`authorization` numerics in JSON,
    // `authorization`/`client_id`/`aws_*` in form bodies.
    let sc = Scrubber::new(false);
    for secret in [
        "https://h/?authorization=secret123",
        "https://h/?private-key=abc456",
        "https://h/?client_id=cid789&aws_secret=sek012",
        "https://h/?cookie=sess999&set-cookie=sc888",
        r#"{"cookie": 12345, "user": "admin"}"#,
        r#"{"authorization": "tok111", "ok": true}"#,
        r#"{"aws_secret": "sek222", "n": 1}"#,
        "data authorization=tok333&client_id=cid444",
        "data private-key=abc555&user=admin",
    ] {
        let out = sc.scrub(secret);
        for leaked in [
            "secret123",
            "abc456",
            "cid789",
            "sek012",
            "12345",
            "sess999",
            "sc888",
            "tok111",
            "sek222",
            "tok333",
            "cid444",
            "abc555",
        ] {
            assert!(!out.contains(leaked), "{secret} leaked {leaked}: {out}");
        }
    }
    // Benign keys/values still survive in every renderer.
    assert!(sc.scrub("https://h/?id=1&q=x").contains("id=1"));
    assert!(sc.scrub(r#"{"user": "admin"}"#).contains("admin"));
    assert!(sc.scrub("data user=admin&page=2").contains("user=admin"));
}

#[test]
fn scrubs_oob_collaborator_but_keeps_seed() {
    let sc = Scrubber::new(false);
    let out = sc.scrub("callback https://abc123.oastify.com/poll?token=xyz");
    assert!(!out.contains("oastify.com"), "{out}");
    assert!(out.contains("[REDACTED-OOB]"), "{out}");
    let out = sc.scrub("oob_domain: my-collab.example.net");
    assert!(!out.contains("my-collab.example.net"), "{out}");
    // Seed is NOT a secret (replay determinism) — never redacted.
    let out = sc.scrub("seed 42 seed=42");
    assert!(out.contains("42"), "seed must survive: {out}");
}

#[test]
fn audit_fixture_all_renderers_inputs_are_scrubbed() {
    // v1.0-rc OPSEC audit fixture: every renderer input shape
    // (stdout/JSON/SARIF/JUnit/MD/trace/knowledge) goes through `scrub`.
    // Faux secrets must vanish; structure (keys, benign params, seed)
    // must survive.
    let sc = Scrubber::new(false);
    let fixture = "Authorization: Bearer faketoken123\n\
        Cookie: sess=fakesess999\n\
        https://op:s3cr3t@example.com/?id=1&token=faketoken123\n\
        {\"password\": \"fakehunter2\"} password=fakehunter2\n\
        ghp_fakesecret0123456789abcdefghij\n\
        https://xyz789.oastify.com/cb oob_poll_url=https://collab.local/poll/abc\n\
        seed 42 id=1";
    let out = sc.scrub(fixture);
    for secret in [
        "faketoken123",
        "fakesess999",
        "s3cr3t",
        "fakehunter2",
        "ghp_fakesecret0123456789abcdefghij",
        "xyz789.oastify.com",
        "https://collab.local/poll/abc",
    ] {
        assert!(!out.contains(secret), "{secret} leaked: {out}");
    }
    for survivor in ["id=1", "seed 42", "[REDACTED", "[REDACTED-OOB]"] {
        assert!(out.contains(survivor), "{survivor} missing: {out}");
    }
}
