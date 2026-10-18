use super::mapping::context_class_for;
use super::scoring::{boost_from_counts, clamp_knowledge_range};
use super::types::{
    KNOWLEDGE_SCHEMA_VERSION, KnowledgeEntry, KnowledgeError, KnowledgeKey, KnowledgeStore,
    MIN_SAMPLES,
};
use crate::dbms::context::InjectionContext;
use crate::session::scrubber::Scrubber;
use crate::session::state::TechniqueKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

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
