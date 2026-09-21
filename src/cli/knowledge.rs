#![deny(unsafe_code)]

//! Post-run knowledge learning shared by `scan`, `recon` and `auto`.
//!
//! Pure factorisation: aggregates anonymous `(technique, dbms, generic,
//! succès?, req)` counters via `learn_from_run` then merges + writes
//! (`fsync`, perms 0600) via `save_delta_if_enabled`. OFF = aucune IO.

use crate::cli::args::Cli;

/// Learn from a finished run and persist the anonymous delta (opt-in only).
///
/// * `findings` — findings of the run (anonymised, never stored raw).
/// * `techniques` — enabled techniques for fair per-tech request sharing.
/// * `dbms_hint` — `--dbms` hint fallback when no winner finding carries one.
/// * `req_count` — total requests of the run.
/// * `cli` — gates IO (`knowledge_enabled`) and provides path + redaction.
///
/// OFF (`!knowledge_enabled`) = return immédiat, aucune IO.
pub fn learn_and_save(
    findings: &[crate::session::state::Finding],
    techniques: &[String],
    dbms_hint: Option<&str>,
    req_count: u64,
    cli: &Cli,
) {
    // C13 post-run (opt-in uniquement) : fusion des compteurs anonymes puis
    // écriture (`fsync`, perms 0600). OFF = aucune IO. Le delta ne contient
    // que `(technique, dbms, generic, succès?, req)` — jamais de cible,
    // param, seed, evidence ou secret.
    if !cli.knowledge_enabled() {
        return;
    }
    let mut delta = crate::reasoning::knowledge::KnowledgeStore::empty();
    crate::reasoning::knowledge::learn_from_run(
        &mut delta, findings, techniques, dbms_hint, req_count,
    );
    let scrubber = crate::session::scrubber::Scrubber::new(cli.output_opts.no_redact);
    match crate::reasoning::knowledge::save_delta_if_enabled(
        &delta,
        true,
        cli.knowledge_path.as_deref(),
    ) {
        Ok(true) => tracing::info!(
            path = %scrubber.scrub(&cli.effective_knowledge_path().display().to_string()),
            entries = delta.len(),
            "knowledge updated (opt-in, aggregates only)"
        ),
        Ok(false) => {}
        Err(e) => tracing::warn!(error=%e, "knowledge save failed (run results kept in RAM)"),
    }
}
