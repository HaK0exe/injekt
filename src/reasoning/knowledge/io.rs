use super::mapping::expand_enabled_techniques;
use super::types::{KNOWLEDGE_FILE_NAME, KnowledgeError, KnowledgeStore};
use std::path::PathBuf;

/// Chemin par défaut : `INJEKT_KNOWLEDGE_PATH` > `~/.cache/injekt/knowledge.json`.
#[must_use]
pub fn default_knowledge_path() -> PathBuf {
    resolve_knowledge_path(None)
}

/// Résolution : explicite (`--knowledge-path`) > `INJEKT_KNOWLEDGE_PATH` >
/// `~/.cache/injekt/knowledge.json` (repli `$TMPDIR` si `HOME` absent).
#[must_use]
pub fn resolve_knowledge_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit
        && !p.trim().is_empty()
    {
        return PathBuf::from(p.trim());
    }
    if let Some(env) = std::env::var_os("INJEKT_KNOWLEDGE_PATH")
        && !env.is_empty()
    {
        return PathBuf::from(env);
    }
    // `HOME` on Unix, `USERPROFILE` on Windows (where `HOME` is usually unset).
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let mut p = PathBuf::from(home);
        p.push(".cache");
        p.push("injekt");
        p.push(KNOWLEDGE_FILE_NAME);
        return p;
    }
    // Last resort: same `injekt/knowledge.json` shape under the temp dir, so the
    // file name stays stable on every platform.
    let mut p = std::env::temp_dir();
    p.push("injekt");
    p.push(KNOWLEDGE_FILE_NAME);
    p
}

/// Lecture au boot : `None` + **aucune IO** quand désactivé (OFF byte-identique).
/// Activé : fichier absent → `Some(vide)` neutre ; fichier corrompu → `Some(vide)`.
#[must_use]
pub fn load_if_enabled(enabled: bool, explicit: Option<&str>) -> Option<KnowledgeStore> {
    if !enabled {
        return None;
    }
    let path = resolve_knowledge_path(explicit);
    match KnowledgeStore::load_from(&path) {
        Ok(store) => Some(store),
        Err(e) => {
            tracing::warn!(path=%path.display(), error=%e, "knowledge corrompu, cold-start neutre");
            Some(KnowledgeStore::empty())
        }
    }
}

/// Alimente `store` depuis un run terminé — **agrégats anonymes uniquement**.
///
/// Pour chaque technique activée : 1 essai (`success` = ≥1 finding de cette
/// technique). `dbms` = DBMS du finding gagnant, sinon `--dbms` hint, sinon
/// `unknown`. `context_class` = `generic` à ce niveau (l'agrégation par
/// contexte fin est faite par le moteur quand il voit `InjectionContext` ;
/// le fallback par technique garantit l'apprentissage même en `generic`).
/// `req` = part équitable du budget (`total_requests / #techniques`, ≥1).
/// Ne touche jamais à `target`/`param`/`seed`/`evidence`/secrets.
pub fn learn_from_run(
    store: &mut KnowledgeStore,
    findings: &[crate::session::state::Finding],
    enabled_techniques: &[String],
    dbms_hint: Option<&str>,
    total_requests: u64,
) {
    let kinds = expand_enabled_techniques(enabled_techniques);
    if kinds.is_empty() {
        return;
    }
    #[allow(clippy::cast_possible_truncation)]
    let per_tech_req = total_requests
        .div_ceil(kinds.len().max(1) as u64)
        .max(1)
        .min(usize::MAX as u64) as usize;
    for kind in kinds {
        let winner = findings.iter().find(|f| f.technique == kind);
        let success = winner.is_some();
        let dbms = winner
            .and_then(|f| f.dbms.as_deref())
            .or(dbms_hint)
            .unwrap_or("unknown");
        store.record(kind, dbms, "generic", success, per_tech_req);
    }
}

/// Fusion post-run + écriture : lit l'existant, fusionne `delta`, `fsync`,
/// perms `0600`. Retourne `false` sans **aucune IO** quand désactivé.
///
/// # Errors
/// Retourne une erreur si la lecture de l'existant ou l'écriture échoue.
pub fn save_delta_if_enabled(
    delta: &KnowledgeStore,
    enabled: bool,
    explicit: Option<&str>,
) -> Result<bool, KnowledgeError> {
    if !enabled {
        return Ok(false);
    }
    let path = resolve_knowledge_path(explicit);
    let mut merged = KnowledgeStore::load_from(&path).unwrap_or_else(|_| KnowledgeStore::empty());
    merged.merge(delta);
    merged.save_to(&path)?;
    Ok(true)
}
