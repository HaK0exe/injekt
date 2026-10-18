#![deny(unsafe_code)]

//! P0.2 — paires de contrôle à arithmétique aléatoire (`checkFalsePositives`).
//!
//! Après qu'une paire TRUE/FALSE a confirmé une injection booléenne, sqlmap
//! re-teste le même point avec des paires de contrôle « logiquement vraie »
//! (`r=r`) et « logiquement fausse » (`r1=r2`, `r1≠r2`) : si la page ne réagit
//! pas à ces paires comme elle a réagi aux payloads injectés, le différentiel
//! venait du payload lui-même (filtrage d'un motif, reflet, instabilité), pas
//! de la logique SQL → faux positif.
//!
//! Module pur (aucune I/O) :
//! - [`derive_control_pair`] construit les deux payloads de contrôle à partir
//!   des payloads finaux confirmés, sans toucher aux autres chiffres ;
//! - [`control_verdict`] tranche entre « cohérent » ([`ControlVerdict::Keep`]),
//!   « contredit » ([`ControlVerdict::Veto`]) et « non mesuré »
//!   ([`ControlVerdict::Neutral`], jamais de veto) ; sa variante
//!   [`control_verdict_with_match_ratio`] accepte le plancher de bruit appris
//!   (P1.2, `Baseline::match_ratio`) et rescapce un côté baseline-like dont la
//!   similarité Jaccard retombe dans la bande `DIFF_TOLERANCE` autour de ce
//!   plancher.
//!
//! Le budget est borné par construction : une paire dérivée coûte exactement
//! 2 requêtes, et un payload dont le motif arithmétique manque coûte 0 requête.

mod control;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

pub use control::{
    ControlPair, ControlVerdict, control_verdict, control_verdict_with_match_ratio,
    derive_control_pair,
};
