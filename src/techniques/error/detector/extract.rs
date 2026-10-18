use regex::Regex;
use secrecy::SecretString;
use std::sync::OnceLock;

/// Extract a version/error fragment as [`SecretString`].
///
/// Priority (first hit wins). Specific, quoted-value extractions run before
/// the generic legacy fallback: a body like `invalid input syntax for type
/// integer: "PostgreSQL 14.5"` matches *both* the legacy `PostgreSQL … X.Y`
/// regex (which would wrongly capture just `14.5"`, dropping the `PostgreSQL`
/// prefix and picking up the trailing quote) and the PG-specific quoted-value
/// regex (which correctly captures the full `PostgreSQL 14.5`) — the
/// specific one must win.
/// 1. `XPATH syntax error: '~…~'` quoted value (UPDATEXML/EXTRACTVALUE)
/// 2. PG `invalid input syntax for type integer: "…"` quoted value
/// 3. MSSQL `converting the varchar value '…'` quoted value (Msg 245/8114)
/// 4. bare `ORA-XXXXX…` line (ORA-01722 et al. alone)
/// 5. bare `Msg 245|8114…` line
/// 6. legacy fallback: `MySQL|PostgreSQL|Microsoft SQL Server|Oracle … X.Y…`
///    (bare version banners with no quoted/structured context)
pub(super) fn extract_version(body: &str) -> Option<SecretString> {
    static LEGACY_RE: OnceLock<Regex> = OnceLock::new();
    static XPATH_RE: OnceLock<Regex> = OnceLock::new();
    static PG_RE: OnceLock<Regex> = OnceLock::new();
    static MSSQL_VAL_RE: OnceLock<Regex> = OnceLock::new();
    static ORA_RE: OnceLock<Regex> = OnceLock::new();
    static MSG_RE: OnceLock<Regex> = OnceLock::new();

    #[allow(clippy::expect_used)]
    let xpath = XPATH_RE.get_or_init(|| {
        Regex::new(r#"XPATH syntax error:\s*['"]([^'"<]+)['"]"#).expect("xpath version regex")
    });
    if let Some(c) = xpath.captures(body)
        && let Some(m) = c.get(1)
    {
        return Some(SecretString::from(m.as_str().to_owned()));
    }

    #[allow(clippy::expect_used)]
    let pg = PG_RE.get_or_init(|| {
        Regex::new(r#"(?i)invalid input syntax for (?:type|integer)[^:]*:\s*["']([^"']+)["']"#)
            .expect("pg version regex")
    });
    if let Some(c) = pg.captures(body)
        && let Some(m) = c.get(1)
    {
        return Some(SecretString::from(m.as_str().to_owned()));
    }

    #[allow(clippy::expect_used)]
    let mssql_val = MSSQL_VAL_RE.get_or_init(|| {
        Regex::new(r#"(?i)converting the (?:varchar|nvarchar) value\s*['"]([^'"]+)['"]"#)
            .expect("mssql value regex")
    });
    if let Some(c) = mssql_val.captures(body)
        && let Some(m) = c.get(1)
    {
        return Some(SecretString::from(m.as_str().to_owned()));
    }

    #[allow(clippy::expect_used)]
    let ora =
        ORA_RE.get_or_init(|| Regex::new(r"(?i)(ORA-\d{5}[^\n<]{0,200})").expect("ora code regex"));
    if let Some(c) = ora.captures(body)
        && let Some(m) = c.get(1)
    {
        return Some(SecretString::from(m.as_str().trim().to_owned()));
    }

    #[allow(clippy::expect_used)]
    let msg = MSG_RE.get_or_init(|| {
        Regex::new(r"(?i)(Msg\s+(?:245|8114|8134)[^\n<]{0,200})").expect("msg code regex")
    });
    if let Some(c) = msg.captures(body)
        && let Some(m) = c.get(1)
    {
        return Some(SecretString::from(m.as_str().trim().to_owned()));
    }

    #[allow(clippy::expect_used)]
    let legacy = LEGACY_RE.get_or_init(|| {
        Regex::new(r"(?i)((?:MySQL|PostgreSQL|Microsoft SQL Server|Oracle).*?\d+\.\d+[^<\s]*)")
            .expect("static version regex")
    });
    if let Some(c) = legacy.captures(body)
        && let Some(m) = c.get(1)
    {
        return Some(SecretString::from(m.as_str().to_owned()));
    }

    None
}
