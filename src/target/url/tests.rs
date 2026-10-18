use super::*;

#[test]
fn parse_valid() {
    let u = TargetUrl::parse("https://example.com/search?q=hello&id=1", true).unwrap();
    assert_eq!(u.query_params().len(), 2);
}

#[test]
fn debug_and_scrubbed_redact_secrets_but_keep_host() {
    let u = TargetUrl::parse("https://user:pass@example.com/search?token=secret123", true).unwrap();
    // Full URL still available for requests via Display/as_str.
    assert!(u.as_str().contains("secret123"));
    let debug = format!("{u:?}");
    assert!(!debug.contains("secret123"), "{debug}");
    assert!(!debug.contains("pass"), "{debug}");
    assert!(debug.contains("example.com"), "{debug}");
    let shown = u.scrubbed();
    assert!(!shown.contains("secret123"), "{shown}");
    assert!(shown.contains("example.com"), "{shown}");
}

#[test]
fn bare_host_defaults_to_https() {
    // `auto --target example.com` must not fail with
    // "relative URL without a base".
    let u = TargetUrl::parse("example.com", true).unwrap();
    assert_eq!(u.as_str(), "https://example.com/");
    let u = TargetUrl::parse("example.com:8080/a?id=1", true).unwrap();
    assert!(u.as_str().starts_with("https://example.com:8080/"));
    // Private bare hosts still rejected without the lab flag.
    assert!(TargetUrl::parse("127.0.0.1", false).is_err());
    assert!(TargetUrl::parse("127.0.0.1", true).is_ok());
}

#[test]
fn rejects_private_by_default() {
    assert!(TargetUrl::parse("http://127.0.0.1/admin", false).is_err());
    assert!(TargetUrl::parse("http://192.168.1.1/", false).is_err());
    assert!(TargetUrl::parse("http://10.0.0.5/", false).is_err());
}

#[test]
fn allows_private_with_flag() {
    assert!(TargetUrl::parse("http://127.0.0.1/admin", true).is_ok());
}

#[test]
fn rejects_scheme() {
    assert!(TargetUrl::parse("ftp://example.com/", true).is_err());
}

#[test]
fn rejects_loopback_variants_and_mapped() {
    // Trailing dot + case variants resolve to loopback.
    assert!(TargetUrl::parse("http://localhost./", false).is_err());
    assert!(TargetUrl::parse("http://LOCALHOST/", false).is_err());
    // IPv4-mapped IPv6 loopback/link-local bypassed the old check.
    assert!(TargetUrl::parse("http://[::ffff:127.0.0.1]/", false).is_err());
    assert!(TargetUrl::parse("http://[::ffff:169.254.169.254]/", false).is_err());
    // CGNAT + 0/8 + ULA + link-local.
    assert!(TargetUrl::parse("http://100.64.0.1/", false).is_err());
    assert!(TargetUrl::parse("http://0.1.2.3/", false).is_err());
    assert!(TargetUrl::parse("http://[fc00::1]/", false).is_err());
    assert!(TargetUrl::parse("http://[fe80::1]/", false).is_err());
    // Unified mapped check: CGNAT / 0/8 / IETF behind `::ffff:` block too.
    assert!(TargetUrl::parse("http://[::ffff:100.64.0.1]/", false).is_err());
    assert!(TargetUrl::parse("http://[::ffff:0.1.2.3]/", false).is_err());
    assert!(TargetUrl::parse("http://[::ffff:192.0.0.1]/", false).is_err());
}

#[test]
fn rejects_non_canonical_ipv4_loopback_forms() {
    // Decimal / octal / hex / short forms all resolve to 127.0.0.1 via
    // libc `inet_aton` while staying `Host::Domain` in the `url` crate.
    for host in [
        "2130706433", // 127.0.0.1 as u32
        "0x7f.0.0.1", // hex part
        "0X7F.0.0.1", // hex uppercase
        "0177.0.0.1", // octal part
        "127.0.1",    // short: 127.0.0.1
        "127.1",      // short: 127.0.0.1
        "0x7f.0x0.0x0.0x1",
        "2130706433.", // trailing dot tolerated by `url`
    ] {
        assert!(
            TargetUrl::parse(&format!("http://{host}/"), false).is_err(),
            "{host} must be rejected as loopback"
        );
    }
    // Private ranges in alt forms too.
    assert!(TargetUrl::parse("http://0xC0.0xA8.0x01.0x01/", false).is_err());
    assert!(TargetUrl::parse("http://3232235777/", false).is_err()); // 192.168.1.1
    // Public numeric forms stay allowed (no FP on e.g. 1.1.1.1 = 16843009).
    assert!(TargetUrl::parse("http://16843009/", true).is_ok());
    assert!(TargetUrl::parse("http://1.1.1.1/", false).is_ok());
    // Real hostnames untouched.
    assert!(TargetUrl::parse("http://example.com/", false).is_ok());
}

#[tokio::test]
async fn resolve_and_check_rejects_localhost_and_loopback() {
    assert!(
        TargetUrl::resolve_and_check("localhost", false)
            .await
            .is_err()
    );
    assert!(
        TargetUrl::resolve_and_check("127.0.0.1", false)
            .await
            .is_err()
    );
    assert!(
        TargetUrl::resolve_and_check("169.254.169.254", false)
            .await
            .is_err()
    );
    assert!(
        TargetUrl::resolve_and_check("127.0.0.1", true)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn validate_redirect_location_blocks_private() {
    assert!(
        TargetUrl::validate_redirect_location("http://169.254.169.254/", false)
            .await
            .is_err()
    );
    assert!(
        TargetUrl::validate_redirect_location("http://127.0.0.1/", false)
            .await
            .is_err()
    );
    assert!(
        TargetUrl::validate_redirect_location("http://127.0.0.1/", true)
            .await
            .is_ok()
    );
}
