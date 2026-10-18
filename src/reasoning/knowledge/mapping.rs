use crate::dbms::context::InjectionContext;
use crate::session::state::TechniqueKind;

/// Classe de contexte anonyme pour la clé d'agrégat (jamais de valeur brute).
#[must_use]
pub fn context_class_for(context: &InjectionContext) -> &'static str {
    if context.json {
        return "json";
    }
    if context.order_by {
        return "order_by";
    }
    if context.numeric && context.quote == crate::dbms::context::QuoteContext::None {
        return "numeric";
    }
    match context.quote {
        crate::dbms::context::QuoteContext::SingleQuote => "single-quote",
        crate::dbms::context::QuoteContext::DoubleQuote => "double-quote",
        crate::dbms::context::QuoteContext::Parenthesis => "parenthesis",
        crate::dbms::context::QuoteContext::Unknown | crate::dbms::context::QuoteContext::None => {
            "generic"
        }
    }
}

/// Normalise un label DBMS vers le vocabulaire fermé (inconnu → `unknown`).
#[must_use]
pub fn normalize_dbms(raw: &str) -> &str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "mysql" | "mariadb" | "my" => "mysql",
        "postgres" | "postgresql" | "pg" | "pgsql" => "postgres",
        "mssql" | "sqlserver" | "sql-server" | "tsql" => "mssql",
        "oracle" | "ora" => "oracle",
        "sqlite" => "sqlite",
        _ => "unknown",
    }
}

/// Normalise une classe de contexte vers le vocabulaire fermé.
#[must_use]
pub fn normalize_context_class(raw: &str) -> &str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "numeric" => "numeric",
        "single-quote" | "single_quote" | "singlequote" => "single-quote",
        "double-quote" | "double_quote" | "doublequote" => "double-quote",
        "parenthesis" | "paren" => "parenthesis",
        "json" => "json",
        "order_by" | "order-by" | "orderby" => "order_by",
        _ => "generic",
    }
}

/// Parse strict d'un nom de technique (vocabulaire fermé, sinon `None`).
#[must_use]
pub fn parse_technique(raw: &str) -> Option<TechniqueKind> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "boolean" => Some(TechniqueKind::Boolean),
        "time" => Some(TechniqueKind::Time),
        "error" => Some(TechniqueKind::Error),
        "union" => Some(TechniqueKind::Union),
        "stacked" => Some(TechniqueKind::Stacked),
        "oob" => Some(TechniqueKind::Oob),
        "json" => Some(TechniqueKind::Json),
        "nosql" => Some(TechniqueKind::Nosql),
        "transit" => Some(TechniqueKind::Transit),
        "orm" => Some(TechniqueKind::Orm),
        "graphql" => Some(TechniqueKind::Graphql),
        "elasticsearch" => Some(TechniqueKind::Elasticsearch),
        _ => None,
    }
}

/// Toutes les techniques (expansion de `all`).
#[must_use]
pub fn all_techniques() -> Vec<TechniqueKind> {
    vec![
        TechniqueKind::Boolean,
        TechniqueKind::Time,
        TechniqueKind::Error,
        TechniqueKind::Union,
        TechniqueKind::Stacked,
        TechniqueKind::Oob,
        TechniqueKind::Json,
        TechniqueKind::Nosql,
        TechniqueKind::Transit,
        TechniqueKind::Orm,
        TechniqueKind::Graphql,
        TechniqueKind::Elasticsearch,
    ]
}

/// Expansion de la liste CLI (`all` → 8 techniques, inconnues ignorées).
#[must_use]
pub fn expand_enabled_techniques(enabled: &[String]) -> Vec<TechniqueKind> {
    if enabled.iter().any(|t| t.trim().eq_ignore_ascii_case("all")) {
        return all_techniques();
    }
    let mut out = Vec::new();
    for name in enabled {
        if let Some(kind) = parse_technique(name)
            && !out.contains(&kind)
        {
            out.push(kind);
        }
    }
    if out.is_empty() {
        return all_techniques();
    }
    out
}
