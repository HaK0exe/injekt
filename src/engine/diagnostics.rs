#![deny(unsafe_code)]

//! C14 — Moteur de diagnostics `INCONCLUSIVE` (types purs, 0 IO, 0 réseau).
//!
//! Décision : table figée (`docs/plan-cli-ux.md` §2), max **1** diagnostic par
//! run, priorité stricte
//! `UnstableBaseline > BaselineUnreachable > WafBlocked > RateLimited >
//! NetworkTimeout > BudgetExhausted > DurationExpired`. Aucune heuristique
//! libre : chaque variante est évaluée sur un seul signal agrégé par le tail
//! de `run_internal` (statuses baseline, `baseline_all_error`, compteurs
//! detectability 403/429 drainés dans `SessionState`, budgets, cancel).
//!
//! La suggestion est un **patch déterministe de l'argv original** (capturé
//! dans `main`, descendu via `EngineConfig::argv`) : un flag n'est ajouté que
//! s'il n'est pas déjà présent. Le rendu subit `Scrubber::scrub` au moment de
//! l'affichage / sérialisation — l'argv peut porter des secrets (tokens de
//! cible, cookies), donc `Debug` reste redacté et `EngineConfig::argv` est un
//! `Zeroizing<Vec<String>>` (RAM-only, zéro persistance).

use crate::session::scrubber::Scrubber;
use serde::Serialize;
use serde::ser::SerializeStruct;
use std::fmt;
use zeroize::Zeroize;

/// Nombre minimal de sauts `403`/`406` drainés par le client avant de parler
/// d'un blocage WAF répété. Un saut isolé (une 403 ponctuelle) n'est jamais un
/// diagnostic ; s'aligne sémantiquement avec `Baseline::MIN_WAF_BLOCKS` (≥2
/// *échantillons baseline*, ici ≥3 *sauts client* qui comptent aussi les
/// retries) sans compiler les deux modules entre eux.
pub const WAF_BLOCK_COUNT_MIN: u64 = 3;

/// Nombre minimal de sauts `429` drainés avant de parler d'un rate-limit
/// répété (`429 répétés`, mapping figé). Un unique `429` re-retry est un
/// hoquet, pas une signature.
pub const RATE_LIMIT_COUNT_MIN: u64 = 3;

/// Cause racine d'un run terminé `INCONCLUSIVE`. Champ porteur = matériel de
/// preuve brut ; la sérialisation JSON rend la cause **plate** (`code()`)
/// pour un schéma stable — la preuve chiffrée vit dans `Diagnostic::evidence`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InconclusiveCause {
    /// Les échantillons baseline ne s'accordent pas (statuses ou corps
    /// différents) : l'oracle de comparaison est inutilisable. Porte les
    /// statuses observés (ordre chronologique) comme preuve.
    UnstableBaseline {
        /// Statuses des échantillons baseline collectés avant l'arrêt.
        statuses: Vec<u16>,
    },
    /// Tous les échantillons baseline sont en erreur serveur (5xx) : chaque
    /// différentiel compare une page d'erreur statique.
    BaselineUnreachable,
    /// Sauts `403`/`406` répétés : challenge / deny WAF plausibles.
    WafBlocked {
        /// Sauts `403`/`406` drainés (retries compris).
        count_403: u64,
    },
    /// Sauts `429` répétés : le limiter écrase la cadence des sondes.
    RateLimited {
        /// Sauts `429` drainés (retries compris).
        count_429: u64,
    },
    /// Transport sur timeouts : sondes jamais menées à terme. Aucun producteur
    /// live en C14 (le client ne compte pas les timeouts) ; la variante reste
    /// dans la table purement déterministe pour C15 (`doctor`) / compteurs
    /// transport futurs — brancher le signal sans retoucher la table.
    NetworkTimeout,
    /// Le budget coopératif (`--request-budget`) a stoppé la détection avant
    /// tout verdict. Info pure : pas de suggestion argv.
    BudgetExhausted,
    /// L'horloge `--max-duration` a stoppé la détection avant tout verdict.
    /// Info pure : pas de suggestion argv.
    DurationExpired,
}

impl InconclusiveCause {
    /// Identifiant stable de schéma JSON (`"UnstableBaseline"`, …) — même
    /// vocabulaire que `docs/plan-cli-ux.md` §8.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnstableBaseline { .. } => "UnstableBaseline",
            Self::BaselineUnreachable => "BaselineUnreachable",
            Self::WafBlocked { .. } => "WafBlocked",
            Self::RateLimited { .. } => "RateLimited",
            Self::NetworkTimeout => "NetworkTimeout",
            Self::BudgetExhausted => "BudgetExhausted",
            Self::DurationExpired => "DurationExpired",
        }
    }
}

impl fmt::Display for InconclusiveCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Signaux d'entrée de la table de décision — chacun face à une source unique
/// agrégée par `run_internal`. `argv` porte l'argv original du run (nom de
/// binaire exclu) pour le patch de suggestion ; vide (MCP/programmatique)
/// ⇒ pas de commande provisée.
// Chaque bool est un signal distinct derrière une source pipeline distincte
// (baseline phase × 2, tail, cancel token) — une state-machine/enum au lieu
// des 4 bools masquerait la provenance et forcerait un builder.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiagSignals {
    /// Statuses baseline quand `!Baseline::is_stable()` (vide sinon).
    pub unstable_statuses: Vec<u16>,
    /// `baseline_all_error` (tous les échantillons en 5xx).
    pub baseline_all_error: bool,
    /// Compteurs detectability `403`/`406` (déjà absorbés en `SessionState`).
    pub count_403: u64,
    /// Compteurs detectability `429` (déjà absorbés en `SessionState`).
    pub count_429: u64,
    /// Signal transport (aucun producteur live en C14, voir le variant).
    pub network_timeout: bool,
    /// `BudgetConfig::is_over_request_budget` au tail.
    pub over_request_budget: bool,
    /// `BudgetConfig::is_over_max_duration` au tail.
    pub duration_expired: bool,
    /// `cancel.is_cancelled()` : une interception opérateur ne produit jamais
    /// de diagnostic (l'état terminal est `Cancelled`, pas `INCONCLUSIVE`).
    pub cancelled: bool,
    /// Argv original capturé dans `main` (nom du binaire exclu). Non scrubbé
    /// à la construction : scrubbé à l'affichage uniquement. Vide ⇒ suggestion
    /// `None` (aucune commande provisée honnête).
    pub argv: Vec<String>,
}

/// Un diagnostic `INCONCLUSIVE` complet : cause figée + preuve textuelle +
/// suggestion (commande rejouable **avant** scrub : rede scrubbé via
/// [`Diagnostic::scrubbed`] avant toute sortie) + explication oracle.
///
/// Max 1 par run : le tail de `run_internal` appelle [`Diagnostic::derive`]
/// une seule fois au point de dégradation et stocke via
/// `SessionState::set_inconclusive_cause`.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Diagnostic {
    /// Cause racine figée (voir [`InconclusiveCause`]).
    pub cause: InconclusiveCause,
    /// Preuve textuelle déterministe (statuses, compteurs, contexte).
    pub evidence: String,
    /// Commande rejouable **avant** scrub, ou `None` (info pure / aucun
    /// ajout possible / argv vide). Texte procédural pour `NetworkTimeout`.
    pub suggestion: Option<String>,
    /// Pourquoi la run est inconclusive à ce stade (sémantique d'oracle).
    pub why: String,
}

// `Diagnostic` manuel `Debug` : la suggestion porte l'argv original (tokens
// possiblement secrets) et n'apparaît jamais dans un dump `{:?}` — elle vit
// uniquement en sortie scrubbée (console / JSON report).
impl fmt::Debug for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Diagnostic")
            .field("cause", &self.cause.code())
            .field("evidence_len", &self.evidence.len())
            .field("has_suggestion", &self.suggestion.is_some())
            .field("why_len", &self.why.len())
            .finish_non_exhaustive()
    }
}

impl Diagnostic {
    /// Constructeur canonique (tests et tail du pipeline).
    #[must_use]
    pub fn new(
        cause: InconclusiveCause,
        evidence: impl Into<String>,
        suggestion: Option<String>,
        why: impl Into<String>,
    ) -> Self {
        Self {
            cause,
            evidence: evidence.into(),
            suggestion,
            why: why.into(),
        }
    }

    /// Table de décision pure : la cause prioritaire gagne, `None` quand
    /// aucun signal n'est qualifié (ou quand l'opérateur a annulé).
    /// Déterministe : mêmes signaux ⇒ même diagnostic.
    #[must_use]
    pub fn derive(signals: &DiagSignals) -> Option<Self> {
        let cause = if signals.cancelled {
            // Ctrl+C : interruption volontaire, l'état terminal est
            // `Cancelled` — conseiller un rejeu n'a pas de sens.
            return None;
        } else if !signals.unstable_statuses.is_empty() {
            InconclusiveCause::UnstableBaseline {
                statuses: signals.unstable_statuses.clone(),
            }
        } else if signals.baseline_all_error {
            InconclusiveCause::BaselineUnreachable
        } else if signals.count_403 >= WAF_BLOCK_COUNT_MIN {
            InconclusiveCause::WafBlocked {
                count_403: signals.count_403,
            }
        } else if signals.count_429 >= RATE_LIMIT_COUNT_MIN {
            InconclusiveCause::RateLimited {
                count_429: signals.count_429,
            }
        } else if signals.network_timeout {
            InconclusiveCause::NetworkTimeout
        } else if signals.over_request_budget {
            InconclusiveCause::BudgetExhausted
        } else if signals.duration_expired {
            InconclusiveCause::DurationExpired
        } else {
            return None;
        };
        let evidence = evidence_for(&cause);
        let why = why_for(&cause);
        let suggestion = suggestion_for(&signals.argv, &cause);
        Some(Self::new(cause, evidence, suggestion, why))
    }

    /// Copie scrubbée (sortie console / JSON) : `suggestion`, `evidence`, `why`
    /// passent dans [`Scrubber::scrub`] et ne subissent jamais de Debug brut.
    #[must_use]
    pub fn scrubbed(&self, scrubber: &Scrubber) -> Self {
        Self {
            cause: self.cause.clone(),
            evidence: scrubber.scrub(&self.evidence),
            suggestion: self.suggestion.as_deref().map(|cmd| scrubber.scrub(cmd)),
            why: scrubber.scrub(&self.why),
        }
    }
}

impl Zeroize for Diagnostic {
    fn zeroize(&mut self) {
        self.evidence.zeroize();
        if let Some(s) = self.suggestion.as_mut() {
            s.zeroize();
        }
        self.why.zeroize();
    }
}

// Sérialisation schéma plan §8 : `cause` rendu plat (code), `suggestion`
// explicite (`null` quand `None`, forme figée à 4 clés). Lecture
// `#[serde(default)]` côté `JsonReport` garde les consommateurs pré-C14.
impl Serialize for Diagnostic {
    fn serialize<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Diagnostic", 4)?;
        state.serialize_field("cause", self.cause.code())?;
        state.serialize_field("evidence", &self.evidence)?;
        state.serialize_field("suggestion", &self.suggestion)?;
        state.serialize_field("why", &self.why)?;
        state.end()
    }
}

fn evidence_for(cause: &InconclusiveCause) -> String {
    match cause {
        InconclusiveCause::UnstableBaseline { statuses } => format!(
            "baseline samples disagree (statuses {statuses:?}) — comparison oracle unusable"
        ),
        InconclusiveCause::BaselineUnreachable => {
            "all baseline samples returned server errors (5xx) — origin unreachable".to_owned()
        }
        InconclusiveCause::WafBlocked { count_403 } => {
            format!("repeated denial hops ({count_403}× 403/406) — WAF challenge/deny likely")
        }
        InconclusiveCause::RateLimited { count_429 } => {
            format!("repeated throttled hops ({count_429}× 429) — rate limiter active")
        }
        InconclusiveCause::NetworkTimeout => {
            "probes ended on transport timeouts — requests never completed".to_owned()
        }
        InconclusiveCause::BudgetExhausted => {
            "cooperative request budget reached — detection stopped before a verdict".to_owned()
        }
        InconclusiveCause::DurationExpired => {
            "--max-duration clock expired — detection stopped before a verdict".to_owned()
        }
    }
}

fn why_for(cause: &InconclusiveCause) -> String {
    match cause {
        InconclusiveCause::UnstableBaseline { .. } => {
            "a TRUE/FALSE differential measured on a page that changes between samples cannot be told apart from application noise, so no finding could be trusted".to_owned()
        }
        InconclusiveCause::BaselineUnreachable => {
            "every differential compares static 5xx error pages, so any verdict (clean or finding) would be meaningless; retry the scan once the origin is reachable".to_owned()
        }
        InconclusiveCause::WafBlocked { .. } => {
            "probes were denied before reaching the application; pack tampering (space-level + case randomization) is the documented first bypass attempt".to_owned()
        }
        InconclusiveCause::RateLimited { .. } => {
            "the limiter answered probes with 429 before the database answered them; slow down the cadence and treat 429 as a negative baseline so nothing is scored on throttles".to_owned()
        }
        InconclusiveCause::NetworkTimeout => {
            "transport-level failures starved the run; check proxy, timeouts and MTU offline (run `injekt doctor`), then replay".to_owned()
        }
        InconclusiveCause::BudgetExhausted => {
            "the operator-set request budget stopped detection cooperatively before a verdict; findings would be partial — raise --request-budget (or unset it) to continue".to_owned()
        }
        InconclusiveCause::DurationExpired => {
            "the --max-duration clock stopped detection cooperatively before a verdict; raise --max-duration to continue".to_owned()
        }
    }
}

/// Patch déterministe de l'argv original : les tokens ajoutés dépendent de la
/// cause (`suggestion_command` mapping figé du plan). Rien n'est jamais
/// supprimé ni réécrit ; un flag n'est ajouté que s'il est absent de l'argv.
/// `None` quand **aucun** añadido n'est importable (tout est déjà présent),
/// quand l'argv est vide (aucune commande honnête à reconstruire), ou quand
/// la cause est de l'info pure (budget/durée).
fn suggestion_for(argv: &[String], cause: &InconclusiveCause) -> Option<String> {
    // Conseil procédural (aucun flag à injecter, rien à reconstituer) :
    // valable même sans argv — copiable tel quel.
    if matches!(cause, InconclusiveCause::NetworkTimeout) {
        return Some("run `injekt doctor`".to_owned());
    }
    // Info pure (budget/duration) : `why` l'explique, jamais de patch.
    let patchable = matches!(
        cause,
        InconclusiveCause::UnstableBaseline { .. }
            | InconclusiveCause::BaselineUnreachable
            | InconclusiveCause::WafBlocked { .. }
            | InconclusiveCause::RateLimited { .. }
    );
    if !patchable {
        return None;
    }
    // argv vide (MCP, constructions programmatiques) : reconstituer une
    // commande sans cible serait mensongère — pas de suggestion, la cause
    // reste affichée.
    if argv.is_empty() {
        return None;
    }
    let extra: Option<Vec<String>> = match cause {
        InconclusiveCause::UnstableBaseline { .. } | InconclusiveCause::BaselineUnreachable => {
            let mut extra = Vec::new();
            if !argv_has_flag(argv, "--fetch-using") {
                extra.extend(["--fetch-using".to_owned(), "direct".to_owned()]);
            }
            if !argv_techniques_include_time(argv) {
                extra.extend(["--techniques".to_owned(), "time".to_owned()]);
            }
            maybe(extra)
        }
        InconclusiveCause::WafBlocked { .. } => {
            // Chaîne complète uniquement si l'opérateur n'a PAS déjà pris la
            // main sur `--tamper` (les auto-tampers s'effacent devant un choix
            // explicite) — ajouter une seconde occurrence remplacerait la sienne.
            if argv_has_flag(argv, "--tamper") {
                None
            } else {
                Some(vec![
                    "--tamper".to_owned(),
                    "space2comment,randomcase".to_owned(),
                ])
            }
        }
        InconclusiveCause::RateLimited { .. } => {
            let mut extra = Vec::new();
            // `--ignore-code` répété remplacerait la liste opérateur (clap
            // last-wins) : n'ajouter que si absent. Idem `--rate-limit`.
            if !argv_has_flag(argv, "--ignore-code") {
                extra.extend(["--ignore-code".to_owned(), "429".to_owned()]);
            }
            if !argv_has_flag(argv, "--rate-limit") {
                extra.extend(["--rate-limit".to_owned(), "2".to_owned()]);
            }
            maybe(extra)
        }
        // `NetworkTimeout` est déjà traité au-dessus (conseil procédural) et
        // les causes info pure sont retournées plus haut ; armée wildcard
        // pour le `#[non_exhaustive]`.
        _ => None,
    };
    extra.map(|tokens| {
        let mut all: Vec<&str> = argv.iter().map(String::as_str).collect();
        all.extend(tokens.iter().map(String::as_str));
        suggestion_command(&all)
    })
}

fn maybe(extra: Vec<String>) -> Option<Vec<String>> {
    if extra.is_empty() { None } else { Some(extra) }
}

/// `injekt [argv] [extra]` — chaîne rejouable telle quelle. Tokens portant un
/// métacaractère shell sont double-quotés (échappement `"` `$` `` ` `` `\`) :
/// une URL `?id=1&x=2` non-quotée serait *découpée* par le shell.
fn suggestion_command(tokens: &[&str]) -> String {
    const SUGGESTION_BIN: &str = "injekt";
    let mut out = String::from(SUGGESTION_BIN);
    for token in tokens {
        out.push(' ');
        out.push_str(&shell_quote(token));
    }
    out
}

/// Double-quote minimaliste, déterministe : quote uniquement le nécessaire
/// (métacaractères / espaces), échappe `"`, `$`, `` ` ``, `\` à l'intérieur.
fn shell_quote(token: &str) -> String {
    // Caractères passables sans quote dans un shell POSIX/bash/zsh (aucun ne
    // divise le mot ni ne déclenche d'expansion) : tout le reste force le
    // double-quote. `&` `?` `|` `;` espace, guillemets, `$`, glob — tous
    // arrivent de l'URL/argv utilisateur.
    const SAFE_UNQUOTED: &str = "-_.:/@%+=,~";
    let needs = token.is_empty()
        || token
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || SAFE_UNQUOTED.contains(c)));
    if !needs {
        return token.to_owned();
    }
    let mut quoted = String::with_capacity(token.len() + 2);
    quoted.push('"');
    for c in token.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '$' | '`' => {
                quoted.push('\\');
                quoted.push(c);
            }
            _ => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

/// `true` quand le flag long est déjà présent (forme `--flag value`, `--flag`,
/// `--flag=value`). Formes courtes ignorées : la patch ne cible que les longs.
#[must_use]
pub fn argv_has_flag(argv: &[String], flag: &str) -> bool {
    debug_assert!(flag.starts_with("--"), "long flag expected");
    argv.iter()
        .any(|token| token == flag || startswith_flag(token, flag))
}

// tok starts with `flag` + `=` (inline value form).
fn startswith_flag(token: &str, flag: &str) -> bool {
    let Some(rest) = token.strip_prefix(flag) else {
        return false;
    };
    rest.starts_with('=')
}

/// `true` quand le set des `--techniques` de l'argv embarque déjà `time`
/// (séparateur `,`, plusieurs occurrences, forme `--techniques=…` ou
/// `--techniques …`). `all` couvre time.
#[must_use]
pub fn argv_techniques_include_time(argv: &[String]) -> bool {
    argv_values_of(argv, "--techniques").any(|value| {
        value
            .split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("time") || t.trim().eq_ignore_ascii_case("all"))
    })
}

fn argv_values_of<'a>(argv: &'a [String], flag: &str) -> impl Iterator<Item = &'a str> {
    argv.iter().enumerate().filter_map(move |(idx, token)| {
        if token == flag {
            argv.get(idx + 1).map(String::as_str)
        } else {
            startswith_flag(token, flag)
                .then(|| token.split_once('=').map_or(token.as_str(), |(_, v)| v))
        }
    })
}

// Tests : 1 plante par variante de cause + priorités + surfaces scrub/serialize
// (fichier séparé convention repo, sous la barre 500L de docs/REFACTOR_PLAN.md).
#[cfg(test)]
mod tests;
