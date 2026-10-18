use crate::target::parameters::{ParameterLocation, TargetParameter};

/// Filter testable parameters by `-p` selection (case-insensitive).
/// Accepts bare names (`id`), `location:name` (`body:user`,
/// `cookie:PHPSESSID`, `header:X-Forwarded-For`) or full keys (`id@query`).
/// Empty filter returns all params. Marker synthetics are always preserved
/// when markers are present.
#[must_use]
pub fn filter_params(params: Vec<TargetParameter>, filter: &[String]) -> Vec<TargetParameter> {
    if filter.is_empty() {
        return params;
    }
    let lowered: Vec<String> = filter
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if lowered.is_empty() {
        return params;
    }
    params
        .into_iter()
        .filter(|p| {
            if p.name.starts_with("marker_") {
                return true;
            }
            let name_l = p.name.to_ascii_lowercase();
            let key_l = p.key().to_ascii_lowercase();
            lowered.iter().any(|f| {
                // Bare name (`id`) or full key (`id@query`, `x@header:y`).
                if f == &name_l || f == &key_l {
                    return true;
                }
                // `location:name` form (e.g. `body:user`, `cookie:PHPSESSID`).
                let Some((loc, n)) = f.split_once(':') else {
                    return false;
                };
                match &p.location {
                    ParameterLocation::Header(h) => {
                        // `header:X-Forwarded-For` matches header params by
                        // header name; full `header:h` display also accepted.
                        loc == "header" && (name_l == n || h.to_ascii_lowercase() == n)
                    }
                    other => other.to_string().to_ascii_lowercase() == loc && name_l == n,
                }
            })
        })
        .collect()
}

/// Number of base payloads to try per technique for a tuning `--level`.
/// L1 is the historical budget (byte-identical default), L2 doubles it,
/// L3+ exhausts the whole list. Pure and unit-testable.
#[must_use]
pub fn payload_budget(level: u8, default_take: usize, total: usize) -> usize {
    match level {
        // 0 is unreachable via CLI (clap range 1..=5); treated as L1 defensively.
        0 | 1 => default_take.min(total),
        2 => (default_take * 2).min(total),
        _ => total,
    }
}

/// `--ignore-code`: a response status listed in `codes` is treated as a
/// negative probe (never a finding). The baseline (including WAF detection)
/// runs before this filter and is never ignored.
#[must_use]
pub fn is_ignored(status: u16, codes: &[u16]) -> bool {
    codes.contains(&status)
}

/// App-level signature filter status (e.g. bench A1 `400 {"error":"invalid
/// parameter"}` on spaced keywords). Distinct from WAF `403`/`406` (see
/// `Baseline::is_waf_blocked`): the baseline sees clean `200`s so no
/// auto-tamper fires, yet every spaced boolean payload returns `400`/`400`.
/// Callers use this to prune the payload loop early instead of burning the
/// full L3 matrix on an obviously filtered sink. Narrow to `400`/`400` only
/// so N1/N2 (`200`) and WAF blocks (`403`/`406`) never trip it.
pub const APP_FILTER_STATUS: u16 = 400;
/// Consecutive fully-filtered `(payload, tamper-set)` probes before pruning.
pub const FILTER_STREAK_LIMIT: usize = 3;

#[must_use]
pub const fn is_app_filter_block(true_status: u16, false_status: u16) -> bool {
    true_status == APP_FILTER_STATUS && false_status == APP_FILTER_STATUS
}

/// `true` when every baseline sample is a server error (5xx: origin down,
/// CF 520–524, …). Detection differentials against error pages are
/// meaningless (static pages refute everything), so the caller warns loudly
/// instead of burning hundreds of probes silently. Empty = `false`
/// (no samples is a different failure, handled upstream). Pure and
/// unit-testable.
#[must_use]
pub fn baseline_all_error(statuses: &[u16]) -> bool {
    !statuses.is_empty() && statuses.iter().all(|s| (500..600).contains(s))
}
