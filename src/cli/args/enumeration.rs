#![deny(unsafe_code)]

use clap::Args;

/// C17 — items valides de `--enum` (doc + tests + mapping legacy).
/// Le `value_parser` clap inline la même liste (littéraux : exigence
/// du derive) — toute évolution passe ici ET dans l'attribut.
pub const ENUM_ITEMS: [&str; 8] = [
    "dbs", "tables", "columns", "dump", "banner", "user", "db", "hostname",
];

/// C17 — item `--enum` pour un flag legacy donné (mapping warning
/// « commande équivalente ») : `--current-user` → `user`,
/// `--current-db` → `db`, `-b`/`--banner` → `banner`, le reste 1:1.
#[must_use]
pub fn legacy_item_flag(flag: &str) -> Option<&'static str> {
    match flag {
        "dbs" => Some("dbs"),
        "tables" => Some("tables"),
        "columns" => Some("columns"),
        "dump" => Some("dump"),
        "banner" | "b" => Some("banner"),
        "current-user" | "current_user" => Some("user"),
        "current-db" | "current_db" => Some("db"),
        "hostname" => Some("hostname"),
        _ => None,
    }
}

/// C17 — parsing `--scope <db[.table[.column]]>` : split sur `.` borné à
/// 3 segments (db, table, column) via `splitn(3, '.')` — un 4e segment
/// reste collé au column (`a.b.c.d` ⇒ column `c.d`) : la granularité
/// plus fine se traite via les flags historiques `--db/--table/--column`
/// (noms contenant un `.` littéral : cas identique). Segments vides
/// (`""`, `a..b`) filtrés → `None` : le moteur ignore un scope partie
/// vide (`target_table.is_empty()` → no-op). Aucune validation SQL ici —
/// la CLI ne devient pas un parseur de noms.
#[must_use]
pub fn parse_scope(scope: &str) -> (Option<String>, Option<String>, Option<String>) {
    let clean = |part: Option<&str>| part.filter(|s| !s.is_empty()).map(str::to_string);
    let mut parts = scope.splitn(3, '.');
    (
        clean(parts.next()),
        clean(parts.next()),
        clean(parts.next()),
    )
}

/// Data enumeration (opt-in extraction once a finding is confirmed).
#[derive(Debug, Clone, Args)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
pub struct EnumOpts {
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub extract: bool,

    /// C17 — compact enumeration items, comma-separated. Valid items:
    /// `dbs|tables|columns|dump|banner|user|db|hostname` (`clap value_parser`:
    /// unknown item = usage error, exit 2). Mapped onto the same internal
    /// `EnumConfig` fields as the legacy flags, which stay functional for
    /// 2 releases with a deprecation warning.
    #[arg(
        long = "enum",
        global = true,
        help_heading = "Enumeration",
        value_name = "ITEMS",
        value_delimiter = ',',
        value_parser = ["dbs", "tables", "columns", "dump", "banner", "user", "db", "hostname"]
    )]
    pub enum_items: Vec<String>,

    /// C17 — enumeration scope `db[.table[.column]]` (dot separators).
    /// Replaces the `--db/--table/--column` triple (kept functional 2
    /// releases); a database name containing a literal dot must use the
    /// legacy flags.
    #[arg(
        long,
        global = true,
        help_heading = "Enumeration",
        value_name = "DB[.TABLE[.COLUMN]]"
    )]
    pub scope: Option<String>,

    /// Enumeration flags
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub dbs: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub tables: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub columns: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub dump: bool,
    #[arg(long, short = 'b', global = true, help_heading = "Enumeration")]
    pub banner: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub current_user: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub current_db: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub hostname: bool,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub db: Option<String>,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub table: Option<String>,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub column: Option<String>,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub start: Option<usize>,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub stop: Option<usize>,
    #[arg(long, global = true, help_heading = "Enumeration")]
    pub count: bool,
}

/// C17 — items `--enum` appliqués sur les champs booléens historiques
/// (UNION : un item ne peut jamais désactiver un flag explicite).
/// Pur, sans side effect.
pub fn apply_enum_items(opts: &mut EnumOpts, items: &[String]) {
    for item in items {
        match item.as_str() {
            "dbs" => opts.dbs = true,
            "tables" => opts.tables = true,
            "columns" => opts.columns = true,
            "dump" => opts.dump = true,
            "banner" => opts.banner = true,
            "user" => opts.current_user = true,
            "db" => opts.current_db = true,
            "hostname" => opts.hostname = true,
            // clap `value_parser` garantit la validité : ce bras n'est
            // atteignable que par un appel programmatique (MCP).
            _ => {}
        }
    }
}

/// C17 — `--scope` appliqué sur le triple `db/table/column` (écrasement
/// nul : le scope ne vide jamais un flag explicite déjà posé).
pub fn apply_scope(opts: &mut EnumOpts, scope: &Option<String>) {
    if let Some(scope) = scope {
        let (db, table, column) = parse_scope(scope);
        if opts.db.is_none() {
            opts.db = db;
        }
        if opts.table.is_none() {
            opts.table = table;
        }
        if opts.column.is_none() {
            opts.column = column;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_scope_single_db() {
        let (db, table, column) = parse_scope("db1");
        assert_eq!(db.as_deref(), Some("db1"));
        assert!(table.is_none());
        assert!(column.is_none());
    }

    #[test]
    fn parse_scope_db_table_and_column() {
        let (db, table, column) = parse_scope("shop.users.password");
        assert_eq!(db.as_deref(), Some("shop"));
        assert_eq!(table.as_deref(), Some("users"));
        assert_eq!(column.as_deref(), Some("password"));
    }

    #[test]
    fn parse_scope_fourth_segment_sticks_to_column() {
        // splitn(3): `a.b.c.d` ⇒ column `c.d` — le découpage fin passe
        // par les flags historiques (cas documenté).
        let (db, table, column) = parse_scope("a.b.c.d");
        assert_eq!(db.as_deref(), Some("a"));
        assert_eq!(table.as_deref(), Some("b"));
        assert_eq!(column.as_deref(), Some("c.d"));
    }

    #[test]
    fn items_apply_union_never_downgrades() {
        let mut opts = EnumOpts {
            extract: false,
            enum_items: Vec::new(),
            scope: None,
            dbs: false,
            tables: false,
            columns: false,
            dump: true,
            banner: false,
            current_user: true,
            current_db: false,
            hostname: false,
            db: None,
            table: None,
            column: None,
            start: None,
            stop: None,
            count: false,
        };
        apply_enum_items(&mut opts, &["dbs".to_string(), "user".to_string()]);
        assert!(opts.dbs);
        assert!(opts.current_user);
        // dump/current-user déjà posés par flags : inchangés
        assert!(opts.dump);
        apply_scope(&mut opts, &Some("db1.users".to_string()));
        assert_eq!(opts.db.as_deref(), Some("db1"));
        assert_eq!(opts.table.as_deref(), Some("users"));
    }

    #[test]
    fn scope_never_overrides_explicit_flags() {
        let mut opts = EnumOpts {
            extract: false,
            enum_items: Vec::new(),
            scope: None,
            dbs: false,
            tables: false,
            columns: false,
            dump: false,
            banner: false,
            current_user: false,
            current_db: false,
            hostname: false,
            db: Some("legacy.db".to_string()),
            table: None,
            column: None,
            start: None,
            stop: None,
            count: false,
        };
        apply_scope(&mut opts, &Some("new_scope.tbl.col".to_string()));
        assert_eq!(opts.db.as_deref(), Some("legacy.db"));
        assert_eq!(opts.table.as_deref(), Some("tbl"));
        assert_eq!(opts.column.as_deref(), Some("col"));
    }

    #[test]
    fn scope_empty_value_yields_nothing() {
        let mut opts = EnumOpts {
            extract: false,
            enum_items: Vec::new(),
            scope: None,
            dbs: false,
            tables: false,
            columns: false,
            dump: false,
            banner: false,
            current_user: false,
            current_db: false,
            hostname: false,
            db: None,
            table: None,
            column: None,
            start: None,
            stop: None,
            count: false,
        };
        apply_scope(&mut opts, &Some(String::new()));
        assert!(opts.db.is_none() && opts.table.is_none() && opts.column.is_none());
        // "a..b" : la partie table vide collape en None, sans impacter
        // les parties positionnées (moteur no-op sur hiérarchie vide).
        apply_scope(&mut opts, &Some("a..b".to_string()));
        assert_eq!(opts.db.as_deref(), Some("a"));
        assert!(opts.table.is_none(), "segment vide -> None");
        assert_eq!(opts.column.as_deref(), Some("b"));
    }

    #[test]
    fn every_enum_item_maps_from_its_legacy_flag() {
        // Direction inverse du mapping warning : chaque item est
        // retrouvé depuis le flag legacy correspondant.
        for item in ENUM_ITEMS {
            let flag = match item {
                "user" => "current-user",
                "db" => "current-db",
                other => other,
            };
            assert_eq!(
                legacy_item_flag(flag),
                Some(item),
                "item `{item}` sans mapping legacy"
            );
        }
        // `b` (short déjà en place) renvoie bien l'item banner.
        assert_eq!(legacy_item_flag("b"), Some("banner"));
        // Flag inconnu : None (pas de mapping fantôme).
        assert_eq!(legacy_item_flag("unknown"), None);
    }
}
