#![deny(unsafe_code)]

use anyhow::Context as _;

use std::collections::HashSet;

use crate::target::url::TargetUrl;

/// Maximum number of targets accepted from a bulk file.
pub const MAX_BULK_TARGETS: usize = 1000;

/// Load and validate bulk targets from a text file (one URL per line).
///
/// Blank lines and comment lines (`#`, `//`) are skipped, duplicates are
/// removed, and lines that fail [`TargetUrl::parse`] are skipped with a
/// warning instead of failing the whole file.
///
/// # Errors
///
/// Returns an error if the file cannot be read, if more than
/// [`MAX_BULK_TARGETS`] valid targets are found, or if no valid target
/// remains after filtering.
pub fn load_targets(path: &str, allow_private: bool) -> anyhow::Result<Vec<String>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("cannot read bulk file '{path}'"))?;
    let targets = collect_valid_targets(&content, allow_private);
    if targets.len() > MAX_BULK_TARGETS {
        anyhow::bail!("bulk file exceeds {MAX_BULK_TARGETS} targets: '{path}'");
    }
    if targets.is_empty() {
        anyhow::bail!("no valid targets in bulk file '{path}'");
    }
    Ok(targets)
}

/// Parse bulk targets from raw text (one URL per line), without file I/O.
///
/// Same filtering as [`load_targets`]: blank/comment lines skipped,
/// duplicates removed, invalid lines skipped. The result is truncated to
/// [`MAX_BULK_TARGETS`] entries so callers reusing this helper stay within
/// the cap; use [`load_targets`] to get a hard error instead.
#[must_use]
pub fn parse_targets_text(content: &str, allow_private: bool) -> Vec<String> {
    let mut targets = collect_valid_targets(content, allow_private);
    targets.truncate(MAX_BULK_TARGETS);
    targets
}

fn collect_valid_targets(content: &str, allow_private: bool) -> Vec<String> {
    let mut seen = HashSet::<String>::new();
    let mut targets = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        if !seen.insert(trimmed.to_owned()) {
            continue;
        }
        if TargetUrl::parse(trimmed, allow_private).is_err() {
            tracing::warn!(line=%trimmed, "skipping invalid bulk target");
            continue;
        }
        targets.push(trimmed.to_owned());
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn skips_comments_and_blank_lines() {
        let content =
            "# comment\n\n   \n// other comment\n  # indented\nhttps://example.com/?id=1\n";
        let targets = parse_targets_text(content, false);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0], "https://example.com/?id=1");
    }

    #[test]
    fn deduplicates_targets() {
        let content = "https://example.com/?id=1\nhttps://example.com/?id=1\n  https://example.com/?id=1  \nhttps://example.com/?id=2\n";
        let targets = parse_targets_text(content, false);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0], "https://example.com/?id=1");
        assert_eq!(targets[1], "https://example.com/?id=2");
    }

    #[test]
    fn rejects_invalid_scheme_and_private_by_default() {
        let content = "ftp://example.com/\nhttp://127.0.0.1/admin\nhttps://example.com/\n";
        let strict = parse_targets_text(content, false);
        assert_eq!(strict.len(), 1);
        assert_eq!(strict[0], "https://example.com/");
        let permissive = parse_targets_text(content, true);
        assert_eq!(permissive.len(), 2);
        assert!(permissive.contains(&"http://127.0.0.1/admin".to_owned()));
        assert!(permissive.contains(&"https://example.com/".to_owned()));
    }

    #[test]
    fn returns_empty_when_no_valid_targets() {
        let targets = parse_targets_text("# only comments\n\n// nothing usable\n", false);
        assert!(targets.is_empty());
    }

    #[test]
    fn truncates_at_cap() {
        let mut content = String::new();
        for i in 0..=MAX_BULK_TARGETS {
            let _ = writeln!(content, "https://example{i}.com/?id=1");
        }
        let targets = parse_targets_text(&content, false);
        assert_eq!(targets.len(), MAX_BULK_TARGETS);
    }

    #[test]
    fn load_targets_missing_file_errors() {
        let result = load_targets("/nonexistent/injekt-bulk-missing.txt", false);
        assert!(result.is_err());
    }

    #[test]
    fn load_targets_rejects_over_cap() {
        let mut content = String::new();
        for i in 0..=MAX_BULK_TARGETS {
            let _ = writeln!(content, "https://example{i}.com/?id=1");
        }
        let path = std::env::temp_dir().join(format!("injekt-bulk-cap-{}.txt", std::process::id()));
        let path_str = path.to_string_lossy().into_owned();
        assert!(std::fs::write(&path, content).is_ok());
        let result = load_targets(&path_str, false);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err());
    }
}
