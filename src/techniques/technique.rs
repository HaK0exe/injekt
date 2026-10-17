//! Technique abstraction (P2): the shared, dyn-safe [`Technique`] trait and
//! the [`TechniqueCtx`] built once per (param, technique) dispatch by the
//! `engine::detection` executor. Adding a technique only touches its
//! `scan.rs` module and the [`technique_for`] registry below.

use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    detection::{baseline::Baseline, matcher::MatcherConfig},
    engine::fetch::{fetch_for_payload, fetch_for_payload_with_class},
    generation::GenerativeMode,
    http::{client::HttpClient, timeouts::RequestClass},
    session::state::{SessionState, TechniqueKind},
    target::{
        injection::ProbeOpts, markers::MarkerSet, parameters::TargetParameter,
        raw_request::RawRequest, url::TargetUrl,
    },
    techniques::{payload_opts::PayloadOpts, tamper::Tamper},
};
use futures::future::BoxFuture;
use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// All immutable inputs a detection probe needs, built once per
/// (param, technique) dispatch. Extra fields cover the per-technique options
/// so the trait signature stays stable when a technique gains an input.
pub(crate) struct TechniqueCtx<'a> {
    pub(crate) client: &'a HttpClient,
    pub(crate) state: &'a Arc<RwLock<SessionState>>,
    pub(crate) cancel: &'a CancellationToken,
    pub(crate) target: &'a TargetUrl,
    pub(crate) target_str: &'a str,
    pub(crate) param: &'a TargetParameter,
    pub(crate) baseline: &'a Baseline,
    pub(crate) marker_set: &'a MarkerSet,
    pub(crate) raw: Option<&'a RawRequest>,
    pub(crate) tampers: &'a [Tamper],
    pub(crate) opts: ProbeOpts,
    pub(crate) popts: &'a PayloadOpts,
    pub(crate) matcher: &'a MatcherConfig,
    pub(crate) level: u8,
    pub(crate) ignore_codes: &'a [u16],
    pub(crate) seed: Option<u64>,
    pub(crate) context: &'a InjectionContext,
    pub(crate) dbms_belief: &'a DbmsBelief,
    /// `--max-duration` deadline for the long per-technique loops
    /// (`None` = unlimited, historical behaviour byte-identical).
    pub(crate) deadline: Option<Instant>,
    /// Error probe: the boolean pair confirmation is enabled.
    pub(crate) boolean_enabled: bool,
    /// Boolean probe: `--generative` mode + payload cap.
    pub(crate) generative_mode: GenerativeMode,
    pub(crate) max_generated: u8,
    /// OOB probe: collaborator config (`None` = probes skipped).
    pub(crate) oob_domain: Option<&'a String>,
    pub(crate) oob_poll_url: Option<&'a String>,
    pub(crate) oob_wait_secs: u64,
}

impl TechniqueCtx<'_> {
    /// Send `payload` through the shared injection path (same arguments as
    /// [`fetch_for_payload`]) and return `(body, ms, status)`.
    pub(crate) async fn fetch(&self, payload: &str) -> (String, f64, u16) {
        fetch_for_payload(
            self.client,
            self.state,
            self.cancel,
            self.target,
            self.target_str,
            self.param,
            payload,
            self.marker_set,
            self.raw,
            self.opts,
            self.popts,
        )
        .await
    }

    /// Same as [`Self::fetch`] with an explicit [`RequestClass`] (boolean,
    /// time, OOB probes have their own timeout pools).
    pub(crate) async fn fetch_with_class(
        &self,
        payload: &str,
        class: RequestClass,
    ) -> (String, f64, u16) {
        fetch_for_payload_with_class(
            self.client,
            self.state,
            self.cancel,
            self.target,
            self.target_str,
            self.param,
            payload,
            self.marker_set,
            self.raw,
            self.opts,
            self.popts,
            class,
        )
        .await
    }
}

/// One detection technique. `probe` sends the bounded payload sweep for a
/// single (param, technique) pair and records its own `Finding`s/trace probes;
/// hypothesis folding stays in the engine executor.
pub(crate) trait Technique: Send + Sync {
    fn kind(&self) -> TechniqueKind;
    fn probe<'a>(&'a self, ctx: &'a TechniqueCtx<'a>) -> BoxFuture<'a, ()>;
}

/// Registry: one entry per [`TechniqueKind`], matched via
/// [`Technique::kind`]. Adding a technique = new `scan.rs` module + one entry
/// here.
pub(crate) fn technique_for(kind: TechniqueKind) -> Option<&'static dyn Technique> {
    const ALL: [&dyn Technique; 8] = [
        &crate::techniques::boolean::scan::BooleanTechnique,
        &crate::techniques::error::scan::ErrorTechnique,
        &crate::techniques::time::scan::TimeTechnique,
        &crate::techniques::union::scan::UnionTechnique,
        &crate::techniques::stacked::scan::StackedTechnique,
        &crate::techniques::json::scan::JsonTechnique,
        &crate::techniques::nosql::scan::NosqlTechnique,
        &crate::techniques::oob::scan::OobTechnique,
    ];
    ALL.iter().copied().find(|t| t.kind() == kind)
}
