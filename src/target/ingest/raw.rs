//! `--raw-dir` loader: Burp/ZAP raw-request files -> target URLs (P5 split).

use super::MAX_RAW_FILE_BYTES;
use crate::target::raw_request::RawRequest;

/// Load every `*.txt`/`*.req` file from `dir` as a Burp/ZAP raw request and
/// return the reconstructed target URLs (`https` preferred, `http` fallback).
///
/// Only files with a `txt`/`req` extension **and** regular-file type are
/// considered (`&&`, not `||`); symlinks are rejected via `symlink_metadata`
/// and each file is capped at [`MAX_RAW_FILE_BYTES`].
///
/// # Errors
/// Returns an error when the directory cannot be listed.
pub fn load_raw_dir_targets(dir: &str) -> anyhow::Result<Vec<String>> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| anyhow::anyhow!("cannot list raw dir '{dir}': {e}"))?;
    let mut out = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        // Reject symlinks first (TOCTOU-safe: `symlink_metadata`, not `metadata`).
        let symlink_meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(path = %path.display(), error=%e, "skipping raw file (stat failed)");
                continue;
            }
        };
        if symlink_meta.file_type().is_symlink() {
            tracing::warn!(path = %path.display(), "skipping raw file (symlink rejected)");
            continue;
        }
        // `&&`: extension must match AND entry must be a regular file.
        let has_valid_ext = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("txt") || e.eq_ignore_ascii_case("req"));
        if !(has_valid_ext && symlink_meta.is_file()) {
            continue;
        }
        if symlink_meta.len() > MAX_RAW_FILE_BYTES {
            tracing::warn!(
                path = %path.display(),
                len = symlink_meta.len(),
                "skipping raw file (exceeds 2 MiB cap)"
            );
            continue;
        }
        // Hard cap on the read itself (`take`): the file can grow between
        // the `symlink_metadata` size check above and the read (TOCTOU).
        let content = {
            use std::io::Read as _;
            let file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error=%e, "skipping unreadable raw file");
                    continue;
                }
            };
            let mut limited = file.take(MAX_RAW_FILE_BYTES.saturating_add(1));
            let mut buf = String::new();
            match limited.read_to_string(&mut buf) {
                Ok(_) => buf,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error=%e, "skipping unreadable raw file");
                    continue;
                }
            }
        };
        if u64::try_from(content.len()).unwrap_or(u64::MAX) > MAX_RAW_FILE_BYTES {
            tracing::warn!(
                path = %path.display(),
                "skipping raw file (exceeds 2 MiB cap)"
            );
            continue;
        }
        let req = match RawRequest::parse(&content) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(path = %path.display(), error=%e, "skipping unparseable raw file");
                continue;
            }
        };
        // Scheme by explicit port: `Host: x:80` is plain HTTP — trying
        // `https://x:80` first would fail closed on a valid target.
        // Absolute-form targets carry their own scheme already.
        // Shared with `--raw-file` via `RawRequest::to_url_with_port_hint`.
        if let Some(url) = req.to_url_with_port_hint() {
            out.push(url);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}
