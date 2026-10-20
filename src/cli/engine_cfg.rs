#![deny(unsafe_code)]

//! Unified `EngineConfig` builder shared by `scan`, `recon` and `auto`.
//!
//! Pure factorisation: no CLI flag, network behaviour or default changes.
//! `scan`/`auto` use [`EnumGate::Passthrough`], `recon` uses
//! [`EnumGate::Strict`] (warns when identity/enumeration flags are set
//! without `--auto-enumerate` and gates them, historical `recon` behaviour).

use crate::{cli::args::Cli, engine::orchestrator::EngineConfig};

/// Enumeration gating mode.
///
/// * `Passthrough` — `scan`/`auto` behaviour: enumeration flags pass through
///   untouched, no warning.
/// * `Strict(enumerate)` — `recon` behaviour: when `enumerate` is `false`,
///   identity/enumeration flags are ignored with a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumGate {
    Passthrough,
    Strict(bool),
}

/// C17 — legacy enumeration flags present in `EnumOpts` (bools `true`,
/// `--db/--table/--column` set) → single deprecation line with the
/// "equivalent command" mapping (`--dbs → --enum dbs`, the triple →
/// `--scope`). No values echoed (DB/table/column names carry no token but
/// the line stays flag-only, stable hashing-free). Empty string if none.
fn legacy_enum_flags(opts: &crate::cli::args::enumeration::EnumOpts) -> String {
    use crate::cli::args::enumeration::legacy_item_flag;
    let mut pairs: Vec<String> = Vec::new();
    for (flag, present) in [
        ("--dbs", opts.dbs),
        ("--tables", opts.tables),
        ("--columns", opts.columns),
        ("--dump", opts.dump),
        ("--banner", opts.banner),
        ("--current-user", opts.current_user),
        ("--current-db", opts.current_db),
        ("--hostname", opts.hostname),
    ] {
        if present {
            match flag.strip_prefix("--").and_then(legacy_item_flag) {
                Some(item) => pairs.push(format!("{flag} -> --enum {item}")),
                // unreachable with the inline table above (guard for future flags)
                None => pairs.push(flag.to_string()),
            }
        }
    }
    if opts.db.is_some() || opts.table.is_some() || opts.column.is_some() {
        pairs.push("--db/--table/--column -> --scope".to_string());
    }
    pairs.join(", ")
}

/// Build engine config from CLI detection/enumeration options.
/// Resolution honours `--profile` / config file / `INJEKT_*` via `Cli::effective_*`:
/// explicit flags always win, presets only fill gaps (non-breaking).
#[allow(clippy::too_many_lines)]
// unified scan+recon builder: one struct literal per EngineConfig section, split would reintroduce drift.
#[must_use]
pub fn build_engine_config(cli: &Cli, enum_gate: EnumGate) -> EngineConfig {
    // P0: single config-file load per build (was ~25 loads via effective_*).
    let snap = cli.resolve_snapshot();
    let tampers = if cli.detection.tamper.is_empty() {
        Vec::new()
    } else {
        crate::techniques::tamper::parse_tamper_list(Some(&cli.detection.tamper.join(",")))
    };
    let (enumerate, strict) = match enum_gate {
        EnumGate::Passthrough => (true, false),
        EnumGate::Strict(e) => (e, true),
    };
    // C17 — warning deprecated legacy flags BEFORE the mapping (only flags
    // explicitly given should appear here: `--enum`/`--scope` items will be
    // applied afterwards, an item never silences a legacy warning).
    let legacy = legacy_enum_flags(&cli.enumeration);
    if !legacy.is_empty() {
        tracing::warn!("legacy enumeration flags deprecated (2 releases left): {legacy}");
    }
    // C17 — `--enum <items>` / `--scope <db[.table[.column]]>` applied to
    // the historical fields (UNION, never a downgrade): the same internal
    // `EnumConfig`, MCP shapes (direct write of bools) untouched.
    let mut enum_local = cli.enumeration.clone();
    crate::cli::args::enumeration::apply_enum_items(&mut enum_local, &cli.enumeration.enum_items);
    crate::cli::args::enumeration::apply_scope(&mut enum_local, &cli.enumeration.scope);
    if strict
        && !enumerate
        && (enum_local.dbs
            || enum_local.tables
            || enum_local.columns
            || enum_local.dump
            || enum_local.banner
            || enum_local.current_user
            || enum_local.current_db
            || enum_local.hostname
            || enum_local.count
            || !enum_local.enum_items.is_empty()
            || enum_local.scope.is_some())
    {
        tracing::warn!(
            "identity/enumeration flags (--banner/--current-user/--current-db/--hostname/--dbs/--tables/--columns/--dump/--count, now --enum/--scope) require --auto-enumerate for recon scan; ignoring them"
        );
    }
    // C13 : lecture au boot uniquement sur opt-in explicite. OFF (`None`) =
    // aucune IO, boost 1.0 neutre, chemin byte-identique au sans-knowledge.
    let knowledge = crate::reasoning::knowledge::load_if_enabled(
        cli.knowledge_enabled(),
        cli.knowledge_path.as_deref(),
    );
    if let Some(ks) = knowledge.as_ref() {
        tracing::debug!(
            entries = ks.len(),
            enabled = true,
            "knowledge loaded (opt-in)"
        );
    }
    EngineConfig {
        budget: crate::engine::orchestrator::BudgetConfig {
            threads: cli.effective_threads_with(&snap),
            level: cli.effective_level_with(&snap),
            request_budget: cli.effective_request_budget(),
            max_duration_secs: cli.effective_max_duration(),
        },
        evasion: crate::engine::orchestrator::EvasionConfig {
            payload_opts: cli.payload_opts(),
            tampers,
            hpp: cli.evasion.hpp,
            chunked: cli.evasion.chunked,
        },
        net: crate::engine::orchestrator::NetConfig {
            allow_private: cli.http.allow_private,
            remote_dns: cli.uses_remote_dns(),
            ignore_codes: cli.detection.ignore_codes.clone(),
            method_override: cli.http.method.clone(),
        },
        oob: crate::engine::orchestrator::OobConfig {
            oob_domain: cli.detection.oob_domain.clone(),
            oob_poll_url: cli.detection.oob_poll_url.clone(),
            oob_wait_secs: cli.effective_oob_wait_secs_with(&snap),
        },
        enumeration: crate::engine::orchestrator::EnumConfig {
            extract: enum_local.extract,
            dbs: enumerate && enum_local.dbs,
            tables: enumerate && enum_local.tables,
            columns: enumerate && enum_local.columns,
            dump: enumerate && enum_local.dump,
            banner: enumerate && enum_local.banner,
            current_user: enumerate && enum_local.current_user,
            current_db: enumerate && enum_local.current_db,
            hostname: enumerate && enum_local.hostname,
            db: enum_local.db.clone(),
            table: enum_local.table.clone(),
            column: enum_local.column.clone(),
            start: enum_local.start,
            stop: enum_local.stop,
            count: enumerate && enum_local.count,
        },
        techniques: if !cli.detection.techniques.is_empty() {
            cli.detection.techniques.clone()
        } else if cli
            .detection
            .fetch_using
            .as_deref()
            .is_some_and(|v| v == "boolean" || v == "time")
        {
            // --fetch-using narrows the default technique set (explicit --techniques wins,
            // otherwise explicit --fetch-using wins over config file / profile defaults).
            match cli.detection.fetch_using.as_deref() {
                Some("boolean") => vec!["boolean".to_owned()],
                Some("time") => vec!["time".to_owned()],
                _ => cli.effective_techniques_with(&snap),
            }
        } else {
            cli.effective_techniques_with(&snap)
        },
        test_params: cli.detection.params.clone(),
        post_data: cli.detection.data.clone(),
        matcher: cli.matcher_config(),
        confirm: cli.detection.confirm,
        no_mutation: cli.evasion.no_mutation,
        seed: cli.effective_seed_with(&snap),
        quiet: cli.quiet,
        explain: cli.output_opts.explain.clone(),
        no_redact: cli.output_opts.no_redact,
        dbms_hint: cli.normalized_dbms_hint(),
        marker: cli.detection.marker.clone(),
        raw_request: cli.merged_raw_request(),
        knowledge,
        second_order: crate::engine::orchestrator::SecondOrderConfig {
            enabled: cli.evasion.second_order,
            revisit_url: cli.evasion.second_order_revisit_url.clone(),
            max_stores: cli.effective_second_order_max_stores(),
            ..crate::engine::orchestrator::SecondOrderConfig::default()
        },
        ai: crate::ai::AiSuggestConfig::from_cli(
            cli.detection.ai_suggest,
            cli.detection
                .ai_provider
                .as_deref()
                .and_then(crate::ai::AiProviderKind::from_name),
            cli.detection.ai_endpoint.clone(),
            cli.detection.ai_model.clone(),
            cli.detection
                .ai_api_key
                .clone()
                .map(secrecy::SecretString::from),
            cli.effective_ai_max_suggestions(),
            cli.effective_ai_timeout(),
        ),
        generative: crate::generation::GenerativeConfig::from_parts(
            cli.effective_generative_mode(),
            cli.effective_max_generated(),
        ),
        // C14 : argv original (binaire exclu) capturé dans `main`, matière du
        // patch de suggestion `INCONCLUSIVE`. `Zeroizing` = zéro persistance
        // (remis à zéro au drop, Debug masqué).
        argv: zeroize::Zeroizing::new(cli.captured_argv.clone()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{EnumGate, build_engine_config, legacy_enum_flags};
    use crate::cli::args::{Cli, EnumOpts};

    /// Fixture minimale : les 3 paramètres couvrent les 3 familles legacy
    /// (bool data, bool identité, triple scope).
    fn opts(dbs: bool, current_user: bool, db: Option<&str>) -> EnumOpts {
        EnumOpts {
            extract: false,
            enum_items: Vec::new(),
            scope: None,
            dbs,
            tables: false,
            columns: false,
            dump: false,
            banner: false,
            current_user,
            current_db: false,
            hostname: false,
            db: db.map(str::to_string),
            table: None,
            column: None,
            start: None,
            stop: None,
            count: false,
        }
    }

    #[test]
    fn no_legacy_flag_gives_empty_mapping() {
        assert_eq!(legacy_enum_flags(&opts(false, false, None)), "");
    }

    #[test]
    fn legacy_pairs_follow_declared_order() {
        assert_eq!(
            legacy_enum_flags(&opts(true, true, Some("shop"))),
            "--dbs -> --enum dbs, --current-user -> --enum user, \
             --db/--table/--column -> --scope"
        );
    }

    #[test]
    fn new_shapes_alone_do_not_warn_legacy() {
        let mut o = opts(false, false, None);
        o.enum_items = vec!["dbs".to_string()];
        o.scope = Some("shop.users".to_string());
        assert_eq!(legacy_enum_flags(&o), "");
    }

    #[test]
    fn enum_items_and_scope_map_onto_enum_config() {
        use clap::Parser as _;
        let cli = Cli::parse_from([
            "injekt",
            "http://t/?id=1",
            "--enum",
            "dbs,user",
            "--scope",
            "shop.users.password",
        ]);
        let cfg = build_engine_config(&cli, EnumGate::Passthrough);
        assert!(cfg.enumeration.dbs, "item dbs -> field dbs");
        assert!(
            cfg.enumeration.current_user,
            "item user -> field current_user"
        );
        assert!(!cfg.enumeration.tables, "item absent -> field untouched");
        assert_eq!(cfg.enumeration.db.as_deref(), Some("shop"));
        assert_eq!(cfg.enumeration.table.as_deref(), Some("users"));
        assert_eq!(cfg.enumeration.column.as_deref(), Some("password"));
    }

    #[test]
    fn legacy_flags_and_items_union_never_downgrade() {
        use clap::Parser as _;
        let cli = Cli::parse_from([
            "injekt",
            "http://t/?id=1",
            "--tables",
            "--enum",
            "dbs",
            "--scope",
            "db1",
        ]);
        let cfg = build_engine_config(&cli, EnumGate::Passthrough);
        assert!(cfg.enumeration.dbs, "item --enum dbs");
        assert!(
            cfg.enumeration.tables,
            "legacy --tables: union, never downgrade"
        );
        assert_eq!(
            cfg.enumeration.db.as_deref(),
            Some("db1"),
            "--scope db only"
        );
    }

    #[test]
    fn strict_gate_gates_bools_but_preserves_scope_values() {
        use clap::Parser as _;
        let cli = Cli::parse_from([
            "injekt",
            "http://t/?id=1",
            "--enum",
            "dbs",
            "--scope",
            "shop",
        ]);
        let cfg = build_engine_config(&cli, EnumGate::Strict(false));
        assert!(
            !cfg.enumeration.dbs,
            "recon sans --auto-enumerate : bools gated"
        );
        // Parité historique : les valeurs de scope (comme --db avant) restent
        // injectées pour l'usage ultérieur, seuls les bools sont gated.
        assert_eq!(cfg.enumeration.db.as_deref(), Some("shop"));
    }
}
