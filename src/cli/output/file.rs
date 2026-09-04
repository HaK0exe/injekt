#![deny(unsafe_code)]

//! Secure opt-in disk writes for `--output` reports.
//!
//! Model follows [`crate::session::export::EncryptedExport`] (`create_new` +
//! `0o600` on Unix, never overwrite) and [`crate::mcp::tools`] path
//! validation (relative-only, no `..` traversal unless `--force`).

use std::path::{Component, PathBuf};

/// Maximum JSON report size accepted for `--output` writes (same cap as
/// ingestion reads: fail fast instead of filling disk).
pub const MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;

/// Validate a CLI `--output` path.
///
/// * Empty paths are rejected.
/// * Absolute paths and `..` components are rejected unless `force` is true
///   (explicit opt-in, warns at call site).
/// * The parent directory (or `.` for bare filenames) is canonicalized so
///   symlink escapes and missing parents fail fast instead of writing to an
///   unexpected location.
///
/// Returns the canonicalized full destination path.
///
/// # Errors
/// Returns an error if `path` is empty, has no file name, escapes the
/// current directory via an absolute path or `..` without `force`, or its
/// parent directory cannot be canonicalized.
pub fn validate_output_path(path: &str, force: bool) -> anyhow::Result<PathBuf> {
    if path.is_empty() {
        anyhow::bail!("output path is empty");
    }
    let p = std::path::Path::new(path);
    if !force {
        if p.is_absolute() {
            anyhow::bail!(
                "output must be a relative path (absolute '{path}' rejected; use --force to override)"
            );
        }
        if p.components().any(|c| matches!(c, Component::ParentDir)) {
            anyhow::bail!(
                "output must not contain '..' (path traversal rejected; use --force to override)"
            );
        }
    } else if p.is_absolute() || p.components().any(|c| matches!(c, Component::ParentDir)) {
        tracing::warn!(
            path = %path,
            "output traversal override via --force (absolute or '..' allowed explicitly)"
        );
    }
    // Canonicalize parent to pin the write location (symlink-safe).
    let parent = p.parent().unwrap_or_else(|| std::path::Path::new(""));
    let file_name = p
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("output path '{path}' has no file name"))?;
    let canonical_parent = if parent.as_os_str().is_empty() {
        std::fs::canonicalize(".")
            .map_err(|e| anyhow::anyhow!("cannot canonicalize current dir: {e}"))?
    } else {
        std::fs::canonicalize(parent).map_err(|e| {
            anyhow::anyhow!("cannot canonicalize parent '{}': {e}", parent.display())
        })?
    };
    Ok(canonical_parent.join(file_name))
}

/// Async variant for `scan` / `auto` (`tokio::fs`, `create_new` + `0o600`).
///
/// When `force` is false (default): `create_new` (no overwrite) + refuse
/// absolute/`..` paths. When `force` is true (explicit `--force` opt-in):
/// absolute/`..` allowed with a warning and existing files may be truncated
/// (still `0o600`).
///
/// # Errors
/// Returns an error when validation fails, the payload exceeds
/// [`MAX_OUTPUT_BYTES`], the destination already exists (no overwrite without
/// `--force`), or the write/sync fails.
pub async fn write_output_file_async(
    path: &str,
    json: &str,
    force: bool,
    scrubbed_for_log: &str,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt as _;
    if json.len() > MAX_OUTPUT_BYTES {
        anyhow::bail!(
            "output report too large ({} bytes > {MAX_OUTPUT_BYTES})",
            json.len()
        );
    }
    let dest = validate_output_path(path, force)?;
    tracing::warn!(
        path=%scrubbed_for_log,
        "output requested — opt-in disk write (sensitive report, 0o600{})",
        if force { ", --force overwrite" } else { ", no overwrite" }
    );
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let mut file = opts.open(&dest).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "output '{}' already exists (no overwrite for OPSEC; remove it or choose another path)",
                dest.display()
            )
        } else {
            anyhow::anyhow!("output write failed '{}': {e}", dest.display())
        }
    })?;
    file.write_all(json.as_bytes())
        .await
        .map_err(|e| anyhow::anyhow!("output write failed: {e}"))?;
    file.write_all(b"\n")
        .await
        .map_err(|e| anyhow::anyhow!("output write failed: {e}"))?;
    file.sync_all()
        .await
        .map_err(|e| anyhow::anyhow!("output sync failed: {e}"))?;
    Ok(())
}

/// Sync variant for `recon` (`std::fs`, `create_new` + `0o600`).
///
/// # Errors
/// Same contract as [`write_output_file_async`].
pub fn write_output_file_sync(
    path: &str,
    json: &str,
    force: bool,
    scrubbed_for_log: &str,
) -> anyhow::Result<()> {
    use std::io::Write as _;
    if json.len() > MAX_OUTPUT_BYTES {
        anyhow::bail!(
            "output report too large ({} bytes > {MAX_OUTPUT_BYTES})",
            json.len()
        );
    }
    let dest = validate_output_path(path, force)?;
    tracing::warn!(
        path=%scrubbed_for_log,
        "output requested — opt-in disk write (sensitive report, 0o600{})",
        if force { ", --force overwrite" } else { ", no overwrite" }
    );
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts.open(&dest).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "output '{}' already exists (no overwrite for OPSEC; remove it or choose another path)",
                dest.display()
            )
        } else {
            anyhow::anyhow!("output write failed '{}': {e}", dest.display())
        }
    })?;
    file.write_all(json.as_bytes())
        .map_err(|e| anyhow::anyhow!("output write failed: {e}"))?;
    file.write_all(b"\n")
        .map_err(|e| anyhow::anyhow!("output write failed: {e}"))?;
    file.sync_all()
        .map_err(|e| anyhow::anyhow!("output sync failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert!(validate_output_path("", false).is_err());
    }

    #[test]
    fn rejects_absolute_without_force() {
        assert!(validate_output_path("/tmp/x.json", false).is_err());
    }

    #[test]
    fn rejects_parent_dir_without_force() {
        assert!(validate_output_path("../x.json", false).is_err());
        assert!(validate_output_path("a/../b.json", false).is_err());
    }

    #[test]
    fn bare_filename_canonicalizes() {
        let dest = validate_output_path("injekt-test-output.json", false);
        assert!(dest.is_ok());
    }
}
