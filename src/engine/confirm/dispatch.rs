use super::boolean::confirm_boolean_second_pass;
use super::error::confirm_error_second_pass;
use super::stacked::confirm_stacked_second_pass;
use super::time::confirm_time_second_pass;
use super::union::confirm_union_second_pass;
use crate::dbms::context::InjectionContext;
use crate::detection::baseline;
use crate::http::client::HttpClient;
use crate::session::state::{Finding, SessionState, TechniqueKind};
use crate::target::{
    injection::ProbeOpts, markers::MarkerSet, parameters::TargetParameter, raw_request::RawRequest,
    url::TargetUrl,
};
use crate::techniques::{payload_opts::PayloadOpts, tamper::Tamper};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// Dispatch `--confirm` re-validation per technique (OOB excluded by the
/// caller). Each branch sends fresh payloads built with the derived seed RNG
/// and records hashes-only trace entries. Returns `true` when the differential
/// still holds (keep), `false` when it clearly disappeared (drop).
/// Inconclusive (transport error, `--ignore-code`, cancel) returns `true`
/// (keep): the first pass stays authoritative, the second pass only vetoes on
/// positive evidence of absence — never invents findings.
///
/// Robustness (C5-tardif fix): every branch retries a bounded set of fresh
/// payloads (mirroring the first-pass `payload_budget`, capped) instead of a
/// single `.first()`. The first-pass may have confirmed on the 2nd L1 payload
/// (e.g. `' OR 1=1` after a polyglot miss, or a numeric pair after
/// quote-ordering); re-validating only the head polyglot would drop a true
/// positive on conclusive-but-wrong-family evidence. Keep iff ANY candidate
/// re-confirms; drop only when ALL candidates conclusively fail.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn confirm_finding_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    level: u8,
) -> bool {
    match finding.technique {
        TechniqueKind::Boolean
        | TechniqueKind::Json
        | TechniqueKind::Nosql
        | TechniqueKind::Transit
        | TechniqueKind::Orm
        | TechniqueKind::Graphql
        | TechniqueKind::Elasticsearch => {
            confirm_boolean_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                context,
                level,
            )
            .await
        }
        TechniqueKind::Error => {
            confirm_error_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                context,
                level,
            )
            .await
        }
        TechniqueKind::Time => {
            confirm_time_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                level,
            )
            .await
        }
        TechniqueKind::Union => {
            confirm_union_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                level,
            )
            .await
        }
        TechniqueKind::Stacked => {
            confirm_stacked_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                level,
            )
            .await
        }
        TechniqueKind::Oob => true,
    }
}
