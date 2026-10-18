//! Check 4 — ingestion : métadonnées des sources ingestion (doctor).

use super::CheckResult;
use crate::cli::args::Cli;

// ---------------------------------------------------------------------------
// Check 4 — ingestion : métadonnées des sources (--bulk-file/--raw-file/…)
// ---------------------------------------------------------------------------

/// État d'un chemin de source, déduit de `fs::metadata` (existe + type) —
/// pas de read complet (C15 : stat lexical only, un dossier de centaines de
/// raws reste un `metadata`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceState {
    /// Existe et est un fichier.
    File,
    /// Existe et est un dossier.
    Dir,
    /// `fs::metadata` → `NotFound`.
    Missing,
    /// `fs::metadata` a échoué autrement (permissions, → `Err(e)`).
    Unreadable(String),
    /// `--bulk-file -` = alias stdin (géré tel quel par `target::ingest`).
    Stdin,
}

/// Un chemin de source ingestion et son état statique.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceItem {
    pub flag: &'static str,
    pub raw: String,
    pub expects_dir: bool,
    pub state: SourceState,
}

/// Collecte (IO fichier local only — toujours 0 socket) des sources
/// ingestion déclarées, dans l'ordre de `TargetOpts`.
#[must_use]
pub fn collect_ingestion_sources(cli: &Cli) -> Vec<SourceItem> {
    let specs: [(&str, &Option<String>, bool); 5] = [
        ("bulk-file", &cli.target_opts.bulk_file, false),
        ("raw-file", &cli.target_opts.raw_file, false),
        ("raw-dir", &cli.target_opts.raw_dir, true),
        ("openapi-file", &cli.target_opts.openapi_file, false),
        ("sitemap-file", &cli.target_opts.sitemap_file, false),
    ];
    let mut out = Vec::new();
    for (flag, value, expects_dir) in specs {
        let Some(raw) = value else { continue };
        let state = if flag == "bulk-file" && raw == "-" {
            SourceState::Stdin
        } else {
            match std::fs::metadata(raw) {
                Ok(md) if md.is_dir() => SourceState::Dir,
                Ok(_) => SourceState::File,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => SourceState::Missing,
                Err(e) => SourceState::Unreadable(e.to_string()),
            }
        };
        out.push(SourceItem {
            flag,
            raw: raw.clone(),
            expects_dir,
            state,
        });
    }
    out
}

/// Check 4 (pur) — tout chemin absent/illisible ⇒ `Fail` (le run échouerait
/// immédiatement à l'ingestion) ; type inversé (fichier ↔ dossier) ⇒ `Warn` ;
/// tout OK ⇒ résumé ; aucune source ⇒ OK neutre (usage scan direct).
#[must_use]
pub fn check_ingestion(items: &[SourceItem]) -> CheckResult {
    if items.is_empty() {
        return CheckResult::ok(
            "ingestion: aucune source (--bulk-file/--raw-file/--raw-dir/\
             --openapi-file/--sitemap-file) — usage scan direct --target",
        );
    }
    let mut hard = Vec::new();
    let mut soft = Vec::new();
    let mut good = Vec::new();
    for it in items {
        match &it.state {
            SourceState::Stdin => good.push(format!("--{} (stdin)", it.flag)),
            SourceState::File => {
                if it.expects_dir {
                    soft.push(format!(
                        "--{}={} : fichier (dossier attendu)",
                        it.flag, it.raw
                    ));
                } else {
                    good.push(format!("--{}={}", it.flag, it.raw));
                }
            }
            SourceState::Dir => {
                if it.expects_dir {
                    good.push(format!("--{}={}", it.flag, it.raw));
                } else {
                    soft.push(format!(
                        "--{}={} : dossier (fichier attendu)",
                        it.flag, it.raw
                    ));
                }
            }
            SourceState::Missing => {
                hard.push(format!("--{}={} : introuvable", it.flag, it.raw));
            }
            SourceState::Unreadable(e) => {
                hard.push(format!("--{}={} : illisible ({e})", it.flag, it.raw));
            }
        }
    }
    let total = items.len();
    if !hard.is_empty() {
        let healthy = total - hard.len();
        CheckResult::fail(format!(
            "ingestion: {healthy}/{total} sources OK — {}",
            hard.join(" · "),
        ))
    } else if !soft.is_empty() {
        CheckResult::warn(format!(
            "ingestion: type inattendu — {} (le run toucherait une source \
             du mauvais type)",
            soft.join(" · "),
        ))
    } else {
        CheckResult::ok(format!(
            "ingestion: {total}/{total} sources présentes et lisibles — {}",
            good.join(", "),
        ))
    }
}
