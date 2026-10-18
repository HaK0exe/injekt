//! Candidate-build phase of the boolean/JSON/NoSQL second pass (P2),
//! split out of `confirm_boolean_second_pass`: the `SecondPassCand`
//! catalogue + boolean-safe tampers + `NoSQL` `JSON` operator path + error
//! channel flag + baseline comparator body, as a relay bundle.

use super::super::dbms_label_from_finding;
use crate::dbms::context::InjectionContext;
use crate::detection::baseline;
use crate::engine::schedule::order_boolean_by_context;
use crate::session::state::{Finding, TechniqueKind};
use crate::target::injection::payload_budget;
use crate::target::parameters::{ParameterLocation, TargetParameter};
use crate::target::raw_request::RawRequest;
use crate::techniques::tamper::Tamper;

/// Second-pass candidate: the historical boolean TRUE/FALSE base pair
/// (quote-aware) or the full JSON/NoSQL payload — error probe included — so a
/// finding confirmed through either channel re-probes the SAME channel with
/// first-pass parity.
pub(crate) enum SecondPassCand {
    Boolean {
        true_base: String,
        false_base: String,
    },
    Json(crate::techniques::json::payloads::JsonPayload),
    Nosql(crate::techniques::nosql::payloads::NosqlPayload),
}

/// Relay bundle produced by the candidate-build phase of the second
/// pass: everything the confirmation loop consumes. P2 extraction; the
/// builder is pure (no probe, no effect), so hoisting the empty-guard
/// after it is observation-free.
pub(crate) struct BooleanSecondPassSetup {
    pub(crate) candidates: Vec<SecondPassCand>,
    pub(crate) safe: Vec<Tamper>,
    pub(crate) json_operator_path: Option<String>,
    pub(crate) error_channel: bool,
    pub(crate) baseline_body: String,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_second_pass_setup(
    finding: &Finding,
    param: &TargetParameter,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    matcher: &crate::detection::matcher::MatcherConfig,
    effective_tampers: &[Tamper],
    context: &InjectionContext,
    level: u8,
) -> BooleanSecondPassSetup {
    let label = dbms_label_from_finding(finding);
    // Candidates in first-pass order: boolean keeps its quote-aware pairs
    // (unchanged behaviour); JSON mirrors `test_json_bounded`
    // (`json_scan_payloads`: direct sweep + GraphQL `variables` envelope);
    // NoSQL mirrors `test_nosql_bounded` (full catalogue, same budget).
    let candidates: Vec<SecondPassCand> = if finding.technique == TechniqueKind::Json {
        let payloads = crate::engine::schedule::json_scan_payloads(label);
        let take = payload_budget(level, 2, payloads.len());
        payloads
            .into_iter()
            .take(take)
            .map(SecondPassCand::Json)
            .collect()
    } else if finding.technique == TechniqueKind::Nosql {
        let payloads = crate::techniques::nosql::payloads::nosql_payloads();
        let take = payload_budget(level, 2, payloads.len());
        payloads
            .into_iter()
            .take(take)
            .map(SecondPassCand::Nosql)
            .collect()
    } else {
        let mut payloads = crate::techniques::boolean::payloads::boolean_payloads_for(label);
        order_boolean_by_context(&mut payloads, context);
        let take = payload_budget(level, 2, payloads.len()).clamp(1, 3);
        payloads
            .iter()
            .take(take)
            .map(|p| SecondPassCand::Boolean {
                true_base: p.true_payload.clone(),
                false_base: p.false_payload.clone(),
            })
            .collect()
    };
    // Boolean-safe only: opaque tampers would collapse the differential.
    let safe: Vec<Tamper> = effective_tampers
        .iter()
        .filter(|t| t.is_boolean_safe())
        .cloned()
        .collect();
    // NoSQL JSON-body operator path: same detection as `test_nosql_bounded`
    // (`param` body + JSON sniff) — the injected shape is an operator object,
    // not the generic string form, and string tampers don't apply there.
    let json_operator_path: Option<String> = match &param.location {
        ParameterLocation::Body => {
            let body_opt = raw.and_then(|r| r.body.as_deref());
            let ct = raw.and_then(|r| r.content_type());
            body_opt
                .filter(|body| {
                    crate::target::structured::sniff_kind(ct, body)
                        == crate::target::structured::StructuredKind::Json
                })
                .map(str::to_owned)
        }
        _ => None,
    };
    // Error-channel findings (JSON `__bad__` / NoSQL `$where`) carry their
    // differential in the error probe, not the boolean pair: re-probe the
    // error payload (1 request/candidate), mirroring the first pass.
    let error_channel = finding.evidence.contains("channel=error");
    // P1.1 — purge des zones dynamiques marquées avant comparaison.
    let baseline_body =
        matcher.pre_process(&baseline.strip_dynamic_content(&baseline.representative_body_str()));
    BooleanSecondPassSetup {
        candidates,
        safe,
        json_operator_path,
        error_channel,
        baseline_body,
    }
}
