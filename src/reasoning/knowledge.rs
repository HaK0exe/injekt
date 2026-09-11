#![deny(unsafe_code)]

//! C13 — Knowledge Engine (statistiques, pas du ML).
//!
//! Store local **opt-in** d'agrégats anonymes `~/.cache/injekt/knowledge.json`
//! (ou `INJEKT_KNOWLEDGE_PATH` / `--knowledge-path`) activé uniquement par
//! `--allow-knowledge` (défaut **OFF**).
//!
//! # Format du store (schema v1)
//!
//! ```json
//! {
//!   "version": 1,
//!   "entries": {
//!     "boolean|mysql|numeric": {"success": 12, "trials": 20, "avg_req": 14.5}
//!   }
//! }
//! ```
//!
//! Clé d'agrégat : `(technique, dbms, context_class)` — vocabulaire fermé :
//! - `technique`: `boolean|time|error|union|stacked|oob|json`
//! - `dbms`: `mysql|postgres|mssql|oracle|unknown`
//! - `context_class`: `numeric|single-quote|double-quote|parenthesis|json|order_by|generic`
//!
//! Valeurs : `{success, trials, avg_req}` (compteurs + moyenne mobile des
//! requêtes). **Jamais** de cible (`target`/URL/host), paramètre (`id@query`),
//! `seed`, cookie/header, token, body ou secret : `learn_from_run` ne consomme
//! que `(technique, dbms, succès?, req)` et toute écriture passe par le
//! [`crate::session::scrubber::Scrubber`] (redondant par construction, défense
//! en profondeur). RAM-only par défaut ; `~/.cache` uniquement sur opt-in
//! explicite.
//!
//! # Bornes du boost
//!
//! `boost(technique) = 1 + alpha` avec `alpha = success_rate_laplace - 0.5`
//! (`success_rate = (success+1)/(trials+2)`, lissage de Laplace), donc
//! `alpha ∈ [-0.5, +0.5]` et `boost ∈ [0.5, 1.5]`.
//!
//! Le [`crate::detection::scanner::scheduler`] applique ensuite son clamp
//! existant `[0.5, 2.0]` (`clamp_knowledge_boost`) : les stats conseillent,
//! l'évidence du run courant décide (jamais de veto). Cold-start
//! (`trials < MIN_SAMPLES` ou store vide/absent) → `1.0` neutre, chemin de
//! code **byte-identique** au sans-knowledge (`score == evi / cost`).
//!
//! # Protocole bench ablation (doc, pas de run live requis)
//!
//! Valider le gain sur historique rejoué (C1), sans relancer de matrice live :
//!
//! ```text
//! # 1. baseline OFF (défaut, bit-identique v0.6) :
//! bench/runner/run.py matrix --tools injekt --modes stealth,power
//! bench/runner/run.py compare --from v0.4 --to HEAD        # -> history.jsonl
//! cp bench/reports/history.jsonl /tmp/history-off.jsonl
//!
//! # 2. rejouer l'historique avec knowledge ON (même budget, mêmes seeds) :
//! #    - charger knowledge.json rempli des runs précédents (ou rejouer
//! #      N runs d'apprentissage sur A1-A7, min_samples=10)
//! #    - comparer à budget égal : detect_rate(ON) >= detect_rate(OFF),
//! #      req_p50/p95 à détection égale en baisse, fp==0 sur N1/N2 (veto)
//! bench/runner/run.py compare --from v0.4 --to HEAD   # avec knowledge ON
//!
//! # 3. verdicts : IMPROVED (detect+ ou req- à detect constant, 0 FP ajouté),
//! #    FLAT (neutre, knowledge vide -> ordre/scores identiques), REGRESSION
//! #    (detect -10pp OU tout fp>0 OU req_p50 +20% -> veto, knowledge reset).
//! ```
//!
//! Critères `DoD` v0.7 : knowledge vide → neutre (ordre/scores identiques) ;
//! rempli → `detect_rate` + à budget égal sur historique rejoué, 0 FP ajouté
//! sur N1/N2, 0 identifiant (URL/host/secret) dans le fichier.

use crate::{
    dbms::context::InjectionContext, detection::scanner::scheduler::clamp_knowledge_boost,
    session::scrubber::Scrubber, session::state::TechniqueKind,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use thiserror::Error;

/// Version du schéma du fichier knowledge (gelée en v1.0-rc).
pub const KNOWLEDGE_SCHEMA_VERSION: u8 = 1;
/// Échantillons minimum avant tout boost (cold-start neutre, anti-surconfiance).
pub const MIN_SAMPLES: u64 = 10;
/// Borne de `alpha` : `boost = 1 + alpha`, `alpha ∈ [-0.5, +0.5]`.
pub const MAX_ALPHA: f64 = 0.5;
/// Borne basse du boost knowledge (avant clamp scheduler `[0.5, 2.0]`).
pub const KNOWLEDGE_MIN_BOOST: f64 = 0.5;
/// Borne haute du boost knowledge (avant clamp scheduler `[0.5, 2.0]`).
pub const KNOWLEDGE_MAX_BOOST: f64 = 1.5;
/// Nom du fichier sous `~/.cache/injekt/`.
pub const KNOWLEDGE_FILE_NAME: &str = "knowledge.json";

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KnowledgeError {
    #[error("io error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Clé d'agrégat anonyme `(technique, dbms, context_class)`, vocabulaire fermé.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KnowledgeKey {
    pub technique: String,
    pub dbms: String,
    pub context_class: String,
}

impl KnowledgeKey {
    #[must_use]
    pub fn new(technique: TechniqueKind, dbms: &str, context_class: &str) -> Self {
        Self {
            technique: technique.to_string(),
            dbms: normalize_dbms(dbms).to_owned(),
            context_class: normalize_context_class(context_class).to_owned(),
        }
    }

    /// Clé sérialisée `technique|dbms|context_class` (format fichier v1).
    #[must_use]
    pub fn flattened(&self) -> String {
        format!("{}|{}|{}", self.technique, self.dbms, self.context_class)
    }

    /// Parse inverse de [`Self::flattened`], avec normalisation stricte.
    /// Retourne `None` si la clé n'appartient pas au vocabulaire fermé.
    #[must_use]
    pub fn parse_flattened(s: &str) -> Option<Self> {
        let (tech, rest) = s.split_once('|')?;
        let (dbms, ctx) = rest.split_once('|')?;
        let technique = parse_technique(tech)?;
        Some(Self::new(technique, dbms, ctx))
    }
}

/// Compteurs agrégés anonymes pour une clé.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KnowledgeEntry {
    pub success: u64,
    pub trials: u64,
    pub avg_req: f64,
}

impl Default for KnowledgeEntry {
    fn default() -> Self {
        Self {
            success: 0,
            trials: 0,
            avg_req: 0.0,
        }
    }
}

/// Store knowledge : agrégats seuls, aucun identifiant.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct KnowledgeStore {
    pub version: u8,
    pub entries: HashMap<KnowledgeKey, KnowledgeEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KnowledgeFile {
    #[serde(default = "default_knowledge_version")]
    version: u8,
    #[serde(default)]
    entries: HashMap<String, KnowledgeEntry>,
}

const fn default_knowledge_version() -> u8 {
    KNOWLEDGE_SCHEMA_VERSION
}

impl KnowledgeStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: KNOWLEDGE_SCHEMA_VERSION,
            entries: HashMap::new(),
        }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::new()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Enregistre une observation anonyme (1 essai).
    pub fn record(
        &mut self,
        technique: TechniqueKind,
        dbms: &str,
        context_class: &str,
        success: bool,
        req: usize,
    ) {
        let key = KnowledgeKey::new(technique, dbms, context_class);
        let entry = self.entries.entry(key).or_default();
        let new_trials = entry.trials.saturating_add(1);
        #[allow(clippy::cast_precision_loss)]
        let req_f = req as f64;
        #[allow(clippy::cast_precision_loss)]
        let old_trials_f = entry.trials as f64;
        #[allow(clippy::cast_precision_loss)]
        let new_trials_f = new_trials.max(1) as f64;
        entry.avg_req = (entry.avg_req * old_trials_f + req_f.max(0.0)) / new_trials_f;
        entry.trials = new_trials;
        if success {
            entry.success = entry.success.saturating_add(1);
        }
    }

    /// Fusionne les compteurs d'un autre store (post-run : existant + run).
    /// `success`/`trials` s'additionnent (saturant), `avg_req` est la moyenne
    /// pondérée par les essais.
    pub fn merge(&mut self, other: &Self) {
        for (key, incoming) in &other.entries {
            let entry = self.entries.entry(key.clone()).or_default();
            #[allow(clippy::cast_precision_loss)]
            let a_trials = entry.trials as f64;
            #[allow(clippy::cast_precision_loss)]
            let b_trials = incoming.trials as f64;
            let total = entry.trials.saturating_add(incoming.trials);
            #[allow(clippy::cast_precision_loss)]
            let total_f = total.max(1) as f64;
            entry.avg_req = (entry.avg_req * a_trials + incoming.avg_req * b_trials) / total_f;
            entry.success = entry.success.saturating_add(incoming.success);
            entry.trials = total;
        }
        self.version = KNOWLEDGE_SCHEMA_VERSION;
    }

    /// Compteurs agrégés par technique (tous DBMS/contextes), pour le fallback
    /// quand la clé exacte n'a pas atteint `MIN_SAMPLES`.
    #[must_use]
    pub fn aggregate_for_technique(&self, technique: TechniqueKind) -> (u64, u64) {
        let name = technique.to_string();
        let mut success = 0u64;
        let mut trials = 0u64;
        for (key, entry) in &self.entries {
            if key.technique == name {
                success = success.saturating_add(entry.success);
                trials = trials.saturating_add(entry.trials);
            }
        }
        (success, trials)
    }

    /// Boost knowledge pour `(technique, dbms, context_class)` dans
    /// `[0.5, 1.5]` (`1.0` neutre sous `MIN_SAMPLES`). Le scheduler applique
    /// ensuite `clamp_knowledge_boost` (`[0.5, 2.0]`, jamais de veto).
    #[must_use]
    pub fn boost_for(&self, technique: TechniqueKind, dbms: &str, context_class: &str) -> f64 {
        let key = KnowledgeKey::new(technique, dbms, context_class);
        if let Some(entry) = self.entries.get(&key)
            && entry.trials >= MIN_SAMPLES
        {
            return clamp_knowledge_range(boost_from_counts(entry.success, entry.trials));
        }
        let (success, trials) = self.aggregate_for_technique(technique);
        if trials >= MIN_SAMPLES {
            return clamp_knowledge_range(boost_from_counts(success, trials));
        }
        1.0
    }

    /// Boost pour une hypothèse live (`dbms` = label normalisé, `context` = C2).
    #[must_use]
    pub fn boost_for_context(
        &self,
        technique: TechniqueKind,
        dbms: &str,
        context: &InjectionContext,
    ) -> f64 {
        self.boost_for(technique, dbms, context_class_for(context))
    }

    /// Charge depuis `path`. Fichier absent → store vide (cold-start neutre).
    ///
    /// # Errors
    /// Retourne une erreur si la lecture ou le parsing échoue.
    pub fn load_from(path: &Path) -> Result<Self, KnowledgeError> {
        if !path.exists() {
            return Ok(Self::empty());
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| KnowledgeError::Io(format!("read {}: {e}", path.display())))?;
        Self::parse_str(&content)
    }

    /// Parse le JSON du fichier (clés `technique|dbms|contexte` normalisées,
    /// entrées hors vocabulaire ignorées — jamais d'identifiant accepté).
    ///
    /// # Errors
    /// Retourne une erreur si le JSON est malformé.
    pub fn parse_str(content: &str) -> Result<Self, KnowledgeError> {
        let file: KnowledgeFile = serde_json::from_str(content)
            .map_err(|e| KnowledgeError::Serialization(e.to_string()))?;
        let mut store = Self::empty();
        store.version = KNOWLEDGE_SCHEMA_VERSION;
        for (flat, entry) in file.entries {
            let Some(key) = KnowledgeKey::parse_flattened(&flat) else {
                continue;
            };
            // Bornes de bon sens : compteurs saturés, avg_req finie positive.
            if !entry.avg_req.is_finite() || entry.avg_req < 0.0 {
                continue;
            }
            if entry.success > entry.trials {
                continue;
            }
            // Le fichier ne doit contenir que des agrégats : la clé
            // re-sérialisée doit être identique (rejette toute clé exotique).
            if key.flattened() != flat.trim().to_ascii_lowercase() {
                continue;
            }
            store.entries.insert(key, entry);
        }
        Ok(store)
    }

    /// Sérialise vers le format fichier v1 (clés aplaties triées pour un
    /// diff stable). Le contenu passe par le `Scrubber` à l'écriture.
    #[must_use]
    pub fn to_file_string(&self) -> String {
        let mut flat: HashMap<String, KnowledgeEntry> = HashMap::new();
        for (key, entry) in &self.entries {
            flat.insert(key.flattened(), *entry);
        }
        let file = KnowledgeFile {
            version: KNOWLEDGE_SCHEMA_VERSION,
            entries: flat,
        };
        serde_json::to_string_pretty(&file)
            .unwrap_or_else(|_| "{\"version\":1,\"entries\":{}}".to_owned())
    }

    /// Écrit vers `path` : `mkdir -p` parents, perms `0600`, `fsync`.
    /// Le contenu est scrubbé avant écriture (no-op par construction).
    ///
    /// # Errors
    /// Retourne une erreur si la création des parents, l'écriture ou le
    /// `fsync` échoue.
    pub fn save_to(&self, path: &Path) -> Result<(), KnowledgeError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| KnowledgeError::Io(format!("mkdir {}: {e}", parent.display())))?;
        }
        let raw = self.to_file_string();
        let scrubber = Scrubber::new(false);
        let body = scrubber.scrub(&raw);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(path)
            .map_err(|e| KnowledgeError::Io(format!("open {}: {e}", path.display())))?;
        {
            use std::io::Write as _;
            file.write_all(body.as_bytes())
                .map_err(|e| KnowledgeError::Io(format!("write {}: {e}", path.display())))?;
            file.sync_all()
                .map_err(|e| KnowledgeError::Io(format!("fsync {}: {e}", path.display())))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)
                .map_err(|e| KnowledgeError::Io(format!("chmod {}: {e}", path.display())))?;
        }
        Ok(())
    }
}

/// `boost = 1 + clamp(rate_laplace - 0.5, ±0.5)` (sans le clamp scheduler).
fn boost_from_counts(success: u64, trials: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let (s, t) = (success as f64, trials.max(1) as f64);
    let rate = (s + 1.0) / (t + 2.0);
    let alpha = (rate - 0.5).clamp(-MAX_ALPHA, MAX_ALPHA);
    1.0 + alpha
}

fn clamp_knowledge_range(boost: f64) -> f64 {
    if boost.is_finite() {
        boost.clamp(KNOWLEDGE_MIN_BOOST, KNOWLEDGE_MAX_BOOST)
    } else {
        1.0
    }
}

/// Boost final vu par le scheduler : borne knowledge puis clamp `[0.5, 2.0]`
/// existant conservé (jamais de veto).
#[must_use]
pub fn scheduled_boost_for(
    store: Option<&KnowledgeStore>,
    technique: TechniqueKind,
    dbms: &str,
    context: &InjectionContext,
) -> Option<f64> {
    let ks = store?;
    let raw = ks.boost_for_context(technique, dbms, context);
    Some(clamp_knowledge_boost(raw))
}

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
    ]
}

/// Expansion de la liste CLI (`all` → 7 techniques, inconnues ignorées).
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
    if let Some(home) = std::env::var_os("HOME") {
        let mut p = PathBuf::from(home);
        p.push(".cache/injekt");
        p.push(KNOWLEDGE_FILE_NAME);
        return p;
    }
    let mut p = std::env::temp_dir();
    p.push("injekt-knowledge.json");
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::dbms::context::QuoteContext;

    fn ctx_numeric() -> InjectionContext {
        InjectionContext {
            quote: QuoteContext::None,
            numeric: true,
            json: false,
            order_by: false,
            comment: crate::dbms::context::CommentStyle::DashDash,
        }
    }

    #[test]
    fn empty_store_is_neutral() {
        let ks = KnowledgeStore::empty();
        assert!(ks.is_empty());
        for kind in all_techniques() {
            assert!((ks.boost_for(kind, "mysql", "numeric") - 1.0).abs() < 1e-12);
            assert!((ks.boost_for_context(kind, "mysql", &ctx_numeric()) - 1.0).abs() < 1e-12);
        }
    }

    #[test]
    fn cold_start_below_min_samples_stays_neutral() {
        let mut ks = KnowledgeStore::empty();
        for _ in 0..(MIN_SAMPLES - 1) {
            ks.record(TechniqueKind::Boolean, "mysql", "numeric", true, 10);
        }
        assert!((ks.boost_for(TechniqueKind::Boolean, "mysql", "numeric") - 1.0).abs() < 1e-12);
    }

    #[test]
    fn two_simulated_runs_learn_winning_technique_bounded() {
        // 2 runs simulés : 6 succès/run sur boolean/mysql/numeric (=12 essais).
        let mut ks = KnowledgeStore::empty();
        for _ in 0..6 {
            ks.record(TechniqueKind::Boolean, "mysql", "numeric", true, 12);
        }
        // Après le run 1 seul (6 < 10) : encore neutre.
        assert!((ks.boost_for(TechniqueKind::Boolean, "mysql", "numeric") - 1.0).abs() < 1e-12);
        for _ in 0..6 {
            ks.record(TechniqueKind::Boolean, "mysql", "numeric", true, 12);
        }
        let boost = ks.boost_for(TechniqueKind::Boolean, "mysql", "numeric");
        assert!(boost > 1.0, "boost={boost}");
        assert!(boost <= KNOWLEDGE_MAX_BOOST + 1e-12, "boost={boost}");
        // Clamp scheduler conservé.
        assert!(clamp_knowledge_boost(boost) >= 0.5 - 1e-12);
        assert!(clamp_knowledge_boost(boost) <= 2.0 + 1e-12);
        // Technique perdante (tout-échec) descend sous 1.0, bornée.
        let mut bad = KnowledgeStore::empty();
        for _ in 0..12 {
            bad.record(TechniqueKind::Time, "mysql", "numeric", false, 30);
        }
        let down = bad.boost_for(TechniqueKind::Time, "mysql", "numeric");
        assert!(down < 1.0, "down={down}");
        assert!(down >= KNOWLEDGE_MIN_BOOST - 1e-12, "down={down}");
    }

    #[test]
    fn boost_never_vetoes_scheduler_clamp() {
        assert!((clamp_knowledge_boost(10.0) - 2.0).abs() < 1e-12);
        assert!((clamp_knowledge_boost(0.01) - 0.5).abs() < 1e-12);
        for (s, t) in [(0, 100), (100, 100), (50, 100), (1, 10)] {
            let b = clamp_knowledge_range(boost_from_counts(s, t));
            assert!(
                (KNOWLEDGE_MIN_BOOST - 1e-12..=KNOWLEDGE_MAX_BOOST + 1e-12).contains(&b),
                "{b}"
            );
        }
    }

    #[test]
    fn merge_fuses_counters_weighted_avg() {
        let mut a = KnowledgeStore::empty();
        a.record(TechniqueKind::Boolean, "mysql", "numeric", true, 10);
        let mut b = KnowledgeStore::empty();
        b.record(TechniqueKind::Boolean, "mysql", "numeric", false, 30);
        a.merge(&b);
        let key = KnowledgeKey::new(TechniqueKind::Boolean, "mysql", "numeric");
        let e = a.entries.get(&key).expect("merged");
        assert_eq!(e.trials, 2);
        assert_eq!(e.success, 1);
        assert!((e.avg_req - 20.0).abs() < 1e-9);
    }

    #[test]
    fn file_roundtrip_and_off_creates_nothing() {
        // OFF : aucun accès disque (le caller ne doit même pas résoudre/écrire).
        assert_eq!(
            load_if_enabled(false, Some("/nonexistent-knowledge-off.json")),
            None
        );
        let delta = KnowledgeStore::empty();
        let wrote = save_delta_if_enabled(&delta, false, Some("/nonexistent-knowledge-off.json"))
            .expect("off");
        assert!(!wrote);
        assert!(!std::path::Path::new("/nonexistent-knowledge-off.json").exists());
    }

    #[test]
    fn save_sets_0600_and_loads_back() {
        let mut ks = KnowledgeStore::empty();
        for _ in 0..12 {
            ks.record(TechniqueKind::Union, "postgres", "generic", true, 14);
        }
        let dir = std::env::temp_dir().join(format!("injekt-k-{}", rand::random::<u64>()));
        let path = dir.join("knowledge.json");
        ks.save_to(&path).expect("save");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let mode = std::fs::metadata(&path).expect("meta").mode() & 0o777;
            assert_eq!(mode, 0o600, "perms={mode:o}");
        }
        let back = KnowledgeStore::load_from(&path).expect("load");
        let key = KnowledgeKey::new(TechniqueKind::Union, "postgres", "generic");
        assert_eq!(back.entries.get(&key), ks.entries.get(&key));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_contains_no_target_or_secret() {
        let mut ks = KnowledgeStore::empty();
        ks.record(TechniqueKind::Boolean, "mysql", "numeric", true, 11);
        let json = ks.to_file_string();
        // Vocabulaire fermé uniquement : aucune URL/host/param/seed/secret.
        for needle in [
            "http",
            "://",
            "example.com",
            "127.0.0.1",
            "localhost",
            "id@query",
            "id=",
            "cookie",
            "bearer",
            "authorization",
            "seed",
            "BEGIN PRIVATE",
        ] {
            assert!(
                !json.to_ascii_lowercase().contains(needle),
                "leak {needle}: {json}"
            );
        }
        // Scrubber redondant : no-op sur un fichier sain.
        let sc = Scrubber::new(false);
        assert_eq!(sc.scrub(&json), json);
    }

    #[test]
    fn learn_from_run_records_only_aggregates() {
        use crate::session::state::Finding;
        let mut ks = KnowledgeStore::empty();
        let findings = vec![Finding::new(
            "http://example.com/?id=1",
            "id@query",
            TechniqueKind::Boolean,
            0.9,
            "evidence Authorization: Bearer SECRET",
        )];
        learn_from_run(&mut ks, &findings, &["all".to_owned()], Some("mysql"), 70);
        // 7 techniques => 7 clés, la gagnante en succès.
        assert_eq!(ks.len(), 7);
        let win = KnowledgeKey::new(TechniqueKind::Boolean, "mysql", "generic");
        assert_eq!(ks.entries.get(&win).map(|e| e.success), Some(1));
        let lose = KnowledgeKey::new(TechniqueKind::Time, "mysql", "generic");
        assert_eq!(lose.flattened(), "time|mysql|generic");
        assert_eq!(ks.entries.get(&lose).map(|e| e.success), Some(0));
        // Aucune trace de la cible/du secret dans le store sérialisé.
        let json = ks.to_file_string();
        assert!(!json.contains("example.com"), "{json}");
        assert!(!json.contains("Bearer"), "{json}");
        assert!(!json.contains("id@query"), "{json}");
    }

    #[test]
    fn resolve_prefers_explicit_then_env() {
        let p = resolve_knowledge_path(Some("/tmp/custom-k.json"));
        assert_eq!(p, PathBuf::from("/tmp/custom-k.json"));
    }

    #[test]
    fn context_class_mapping() {
        assert_eq!(context_class_for(&ctx_numeric()), "numeric");
        let mut c = InjectionContext::new();
        c.json = true;
        assert_eq!(context_class_for(&c), "json");
        let mut o = InjectionContext::new();
        o.order_by = true;
        assert_eq!(context_class_for(&o), "order_by");
        assert_eq!(context_class_for(&InjectionContext::new()), "generic");
    }

    #[test]
    fn scheduled_boost_none_when_disabled() {
        assert_eq!(
            scheduled_boost_for(None, TechniqueKind::Boolean, "mysql", &ctx_numeric()),
            None
        );
        let ks = KnowledgeStore::empty();
        assert_eq!(
            scheduled_boost_for(Some(&ks), TechniqueKind::Boolean, "mysql", &ctx_numeric()),
            Some(1.0)
        );
    }
}
