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
//! - `technique`: `boolean|time|error|union|stacked|oob|json|nosql`
//! - `dbms`: `mysql|postgres|mssql|oracle|sqlite|unknown`
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

mod io;
mod mapping;
mod scoring;
mod store;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
mod types;

pub use io::{
    default_knowledge_path, learn_from_run, load_if_enabled, resolve_knowledge_path,
    save_delta_if_enabled,
};
pub use mapping::{
    all_techniques, context_class_for, expand_enabled_techniques, normalize_context_class,
    normalize_dbms, parse_technique,
};
pub use scoring::scheduled_boost_for;
pub use types::{
    KNOWLEDGE_FILE_NAME, KNOWLEDGE_MAX_BOOST, KNOWLEDGE_MIN_BOOST, KNOWLEDGE_SCHEMA_VERSION,
    KnowledgeEntry, KnowledgeError, KnowledgeKey, KnowledgeStore, MAX_ALPHA, MIN_SAMPLES,
};
