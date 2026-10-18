//! Check 1 — config : résolution du TOML via `file_config.rs` (doctor).

use super::{CheckLevel, CheckResult};
use crate::cli::file_config::{FileConfig, candidate_paths};
use crate::cli::profile::Profile;
use std::path::PathBuf;

fn profile_name(p: Profile) -> String {
    format!("{p:?}").to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Check 1 — config : résolution du TOML via `file_config.rs` tel quel
// ---------------------------------------------------------------------------

/// Résolution du fichier config : même boucle de candidats que
/// `file_config::load` (le premier candidat *existant et lisible* arbitre).
/// Uniquement des IO fichier local — jamais la cible, jamais le réseau.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ConfigResolution {
    /// Aucun candidat existant ; `explicit` rappelle le `--config` demandé
    /// (quand il est introuvable/illisible, la ligne le signale).
    Absent { explicit: Option<String> },
    /// Premier fichier trouvé, parse TOML OK.
    Found { path: PathBuf, cfg: FileConfig },
    /// Premier fichier trouvé mais parse KO — `error` reproduit le message
    /// `toml` (ligne/colonne) ; aucune re-parse maison.
    Broken { path: PathBuf, error: String },
}

pub(super) fn resolve_config(explicit: Option<&str>) -> ConfigResolution {
    for path in candidate_paths(explicit) {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        return match FileConfig::parse(&content) {
            Ok(cfg) => ConfigResolution::Found { path, cfg },
            Err(error) => ConfigResolution::Broken { path, error },
        };
    }
    ConfigResolution::Absent {
        explicit: explicit.map(str::to_owned),
    }
}

/// Check 1 (pur) — fichier trouvé + parse OK ⇒ résumé une ligne (profil
/// effectif, threads), `Warn` si un preset fichier est inconnu (le runtime
/// l'ignore en silence) ; absent ⇒ `Warn` « défauts intégrés » ; TOML
/// cassé ⇒ `Fail` avec l'erreur (ligne/colonne) du parse `toml`.
#[must_use]
pub fn check_config(
    res: &ConfigResolution,
    active: Option<Profile>,
    threads: usize,
) -> CheckResult {
    match res {
        ConfigResolution::Absent { explicit: None } => CheckResult::warn(
            "config: aucun fichier config (--config · ./injekt.toml · \
             ~/.config/injekt/config.toml) — défauts intégrés actifs",
        ),
        ConfigResolution::Absent { explicit: Some(p) } => CheckResult::warn(format!(
            "config: --config {p} introuvable/illisible et aucun candidat \
             auto-découvert — défauts intégrés actifs",
        )),
        ConfigResolution::Broken { path, error } => CheckResult::fail(format!(
            "config: TOML invalide ({}) — {error}",
            path.display(),
        )),
        ConfigResolution::Found { path, cfg } => {
            let mut level = CheckLevel::Ok;
            let mut note = String::new();
            let file_p = cfg.file_profile();
            // Preset effectif (+ provenance) sans ré-implémenter la
            // precedence : CLI > fichier, miroir d'`active_profile` ; un
            // preset fichier inconnu est un cas `Warn` (le runtime
            // l'ignore en silence via `file_profile` → `None`).
            let profile_seg;
            if let Some(cli_p) = active {
                if let Some(p) = file_p {
                    if cli_p == p {
                        profile_seg = format!("profil {} (fichier)", profile_name(p));
                    } else {
                        let raw = cfg.profile.as_deref().unwrap_or("?");
                        profile_seg = format!(
                            "profil {} (CLI, écrase « {raw} » du fichier)",
                            profile_name(cli_p),
                        );
                    }
                } else if let Some(raw) = cfg.profile.as_deref() {
                    level = CheckLevel::Warn;
                    note = format!(
                        " · preset fichier {raw:?} inconnu — ignoré au runtime \
                         (quick|balanced|stealth|aggressive)",
                    );
                    profile_seg = format!(
                        "profil {} (CLI, écrase le preset fichier inconnu)",
                        profile_name(cli_p),
                    );
                } else {
                    profile_seg = format!("profil {} (CLI)", profile_name(cli_p));
                }
            } else if let Some(p) = file_p {
                profile_seg = format!("profil {} (fichier)", profile_name(p));
            } else if let Some(raw) = cfg.profile.as_deref() {
                level = CheckLevel::Warn;
                note = format!(
                    " · preset fichier {raw:?} inconnu — ignoré au runtime \
                     (quick|balanced|stealth|aggressive)",
                );
                profile_seg = "profil: aucun (défauts intégrés)".to_owned();
            } else {
                profile_seg = "profil: aucun (défauts intégrés)".to_owned();
            }
            CheckResult {
                level,
                line: format!(
                    "config: {} — {profile_seg}{note} · threads {threads}",
                    path.display(),
                ),
            }
        }
    }
}
