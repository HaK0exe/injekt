use super::active::build_spec_for_context;
use super::*;
use crate::dbms::common::DbmsKind;
use crate::target::parameters::TargetParameter;

#[test]
fn test_dbms_belief_from_hint() {
    let b = DbmsBelief::from_hint("mysql");
    assert_eq!(b.mysql, 1.0);
    assert_eq!(b.postgres, 0.0);
    assert_eq!(b.top_candidate().0, DbmsKind::MySql);

    let pg = DbmsBelief::from_hint("postgres");
    assert_eq!(pg.postgres, 1.0);
    assert_eq!(pg.mysql, 0.0);
    assert_eq!(pg.top_candidate().0, DbmsKind::Postgres);

    let mssql = DbmsBelief::from_hint("mssql");
    assert_eq!(mssql.mssql, 1.0);
    assert_eq!(mssql.top_candidate().0, DbmsKind::MsSql);

    let ora = DbmsBelief::from_hint("oracle");
    assert_eq!(ora.oracle, 1.0);
    assert_eq!(ora.top_candidate().0, DbmsKind::Oracle);

    let sqlite = DbmsBelief::from_hint("sqlite");
    assert_eq!(sqlite.sqlite, 1.0);
    assert_eq!(sqlite.top_candidate().0, DbmsKind::Sqlite);

    // P5: `sqlite3` alias mirrors `sqlite` in the belief router too.
    let sqlite3 = DbmsBelief::from_hint("sqlite3");
    assert_eq!(sqlite3.sqlite, 1.0);
    assert_eq!(sqlite3.top_candidate().0, DbmsKind::Sqlite);
}

#[test]
fn test_dbms_belief_uniform_and_update() {
    let mut b = DbmsBelief::uniform();
    assert_eq!(b.mysql, 0.2);
    assert_eq!(b.postgres, 0.2);
    assert_eq!(b.sqlite, 0.2);

    b.update_with_signal(DbmsKind::Postgres, 0.9);
    assert!(b.postgres > 0.8);
    assert!(b.mysql < 0.1);
    assert_eq!(b.top_candidate().0, DbmsKind::Postgres);
}

#[test]
fn test_check_sql_errors_mysql() {
    let err = "Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version at line 1";
    let res = check_sql_errors(err);
    assert!(res.is_some());
    let (kind, _) = res.unwrap_or((DbmsKind::Unknown, String::new()));
    assert_eq!(kind, DbmsKind::MySql);
}

#[test]
fn test_check_sql_errors_postgres() {
    let err = "ERROR: syntax error at or near \"WHERE\" at character 42";
    let res = check_sql_errors(err);
    assert!(res.is_some());
    let (kind, _) = res.unwrap_or((DbmsKind::Unknown, String::new()));
    assert_eq!(kind, DbmsKind::Postgres);
}

#[test]
fn test_check_sql_errors_mssql() {
    let err = "Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark after the character string ''";
    let res = check_sql_errors(err);
    assert!(res.is_some());
    let (kind, _) = res.unwrap_or((DbmsKind::Unknown, String::new()));
    assert_eq!(kind, DbmsKind::MsSql);
}

#[test]
fn test_check_sql_errors_oracle() {
    let err = "ORA-01756: quoted string not properly terminated";
    let res = check_sql_errors(err);
    assert!(res.is_some());
    let (kind, _) = res.unwrap_or((DbmsKind::Unknown, String::new()));
    assert_eq!(kind, DbmsKind::Oracle);
}

#[test]
fn test_infer_passive_context() {
    use crate::target::parameters::ParameterLocation;

    let num_param = TargetParameter {
        name: "id".to_owned(),
        original_value: "42".to_owned(),
        location: ParameterLocation::Query,
    };
    let ctx = infer_passive_context(&num_param, None);
    assert!(ctx.numeric);
    assert_eq!(ctx.quote, QuoteContext::None);

    let sort_param = TargetParameter {
        name: "sort".to_owned(),
        original_value: "asc".to_owned(),
        location: ParameterLocation::Query,
    };
    let ctx_sort = infer_passive_context(&sort_param, None);
    assert!(ctx_sort.order_by);
}

#[test]
fn test_top_candidate_tie_break_returns_unknown() {
    // Phase 0 : uniforme (ancien `max_by` → `oracle`, dernier max)
    // doit retourner `Unknown`.
    let uniform = DbmsBelief::uniform();
    let (kind, prob) = uniform.top_candidate();
    assert_eq!(kind, DbmsKind::Unknown);
    assert!((prob - 0.20).abs() < 1e-12);
    // Near-tie sous 1e-9 → Unknown.
    let near = DbmsBelief {
        mysql: 0.200_000_000_000_5,
        postgres: 0.20,
        mssql: 0.20,
        oracle: 0.20,
        sqlite: 0.20,
    };
    assert_eq!(near.top_candidate().0, DbmsKind::Unknown);
    // Top-2 ex æquo (mysql == postgres >> autres) → Unknown.
    let duel = DbmsBelief {
        mysql: 0.4,
        postgres: 0.4,
        mssql: 0.0,
        oracle: 0.1,
        sqlite: 0.1,
    };
    assert_eq!(duel.top_candidate().0, DbmsKind::Unknown);
    // Gagnant franc inchangé.
    let mut clear = DbmsBelief::uniform();
    clear.update_with_signal(DbmsKind::Postgres, 0.9);
    assert_eq!(clear.top_candidate().0, DbmsKind::Postgres);
}

#[test]
fn test_build_spec_query_percent_encodes_payload() {
    use crate::target::{parameters::ParameterLocation, url::TargetUrl};
    let target = TargetUrl::parse("http://example.com/?id=1&other=a", true).unwrap();
    let param = TargetParameter {
        name: "id".to_owned(),
        original_value: "1".to_owned(),
        location: ParameterLocation::Query,
    };
    for payload in ["1'", "1\"-- ", "1+0", "1+999999", "a b&c=d"] {
        let spec = build_spec_for_context(&target, &param, payload, None);
        // Roundtrip : le serveur décode à l'identique.
        let parsed = url::Url::parse(&spec.url).unwrap();
        let decoded = parsed
            .query_pairs()
            .find(|(k, _)| k == "id")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        assert_eq!(decoded, payload, "roundtrip {payload}");
        // Caractères à risque encodés dans l'URL brute.
        if payload.contains('\'') {
            assert!(spec.url.contains("%27"), "quote encodée: {}", spec.url);
        }
        if payload.contains('+') {
            assert!(spec.url.contains("%2B"), "plus encodé: {}", spec.url);
        }
    }
}
