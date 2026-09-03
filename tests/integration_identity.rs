#![allow(clippy::unwrap_used, clippy::expect_used, clippy::similar_names)]

use injekt::dbms::fingerprint::get_detector;

#[test]
fn identity_queries_per_dbms() {
    let mysql = get_detector(injekt::dbms::DbmsKind::MySql);
    assert_eq!(mysql.banner_query(), "SELECT @@version");
    assert_eq!(mysql.current_user_query(), "SELECT USER()");
    assert_eq!(mysql.current_db_query(), "SELECT DATABASE()");
    assert_eq!(mysql.hostname_query(), "SELECT @@hostname");
    assert!(mysql.length_expr("SELECT 1").contains("LENGTH"));
    assert!(
        mysql
            .ascii_cmp_expr("SELECT 1", 0, 65)
            .contains("SUBSTRING")
    );

    let pg = get_detector(injekt::dbms::DbmsKind::Postgres);
    assert_eq!(pg.banner_query(), "SELECT version()");
    assert_eq!(pg.current_db_query(), "SELECT current_database()");
    assert!(pg.length_expr("SELECT 1").contains("::text"));
    assert!(pg.ascii_cmp_expr("SELECT 1", 0, 65).contains("::text"));

    let mssql = get_detector(injekt::dbms::DbmsKind::MsSql);
    assert_eq!(mssql.current_user_query(), "SELECT SUSER_SNAME()");
    assert_eq!(mssql.current_db_query(), "SELECT DB_NAME()");
    assert_eq!(mssql.hostname_query(), "SELECT @@SERVERNAME");
    assert!(mssql.length_expr("SELECT 1").starts_with("LEN("));
    assert!(
        mssql
            .ascii_cmp_expr("SELECT 1", 1, 65)
            .contains("SUBSTRING")
    );

    let oracle = get_detector(injekt::dbms::DbmsKind::Oracle);
    assert!(oracle.banner_query().contains("v$version"));
    assert!(oracle.current_db_query().contains("DB_NAME"));
    assert!(oracle.hostname_query().contains("SERVER_HOST"));
    assert!(oracle.ascii_cmp_expr("SELECT 1", 0, 65).contains("SUBSTR"));
}

#[test]
fn engine_config_has_identity_flags() {
    let cfg = injekt::engine::orchestrator::EngineConfig::default();
    assert!(!cfg.banner);
    assert!(!cfg.current_user);
    assert!(!cfg.current_db);
    assert!(!cfg.hostname);
}
