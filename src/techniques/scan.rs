#![deny(unsafe_code)]

//! P2 scaffold (additive, no behaviour change).
//!
//! Target contract for unifying the 8 `test_*_bounded` loops currently in
//! `engine::orchestrator` behind one [`Technique`] trait + a generic
//! [`ProbeExecutor`]. This module only defines types + the trait today;
//! migration of each technique body happens in P2-1..P2-6.

use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    error::InjektError,
    http::timeouts::RequestClass,
    session::state::TechniqueKind,
    target::parameters::TargetParameter,
    techniques::{payload_opts::PayloadOpts, tamper::Tamper},
};

/// Read-only context for one technique on one parameter.
/// What the 8 prologues recompute today (belief + context + budget + tampers).
#[derive(Debug)]
#[non_exhaustive]
pub struct TechniqueCtx<'a> {
    pub param: &'a TargetParameter,
    pub belief: &'a DbmsBelief,
    pub context: &'a InjectionContext,
    pub level: u8,
    pub seed: Option<u64>,
    pub tampers: &'a [Tamper],
    pub popts: &'a PayloadOpts,
}

/// One probe ready to send (final wire payload already built with RNG).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReadyProbe {
    pub wire_payload: String,
    pub tamper_label: String,
    pub base_index: usize,
}

/// Minimal scored response (what `fetch_for_payload_with_class` returns).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProbeResponse {
    pub body: String,
    pub ms: f64,
    pub status: u16,
}

/// Detector decision, no side effects.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TechniqueVerdict {
    pub vulnerable: bool,
    pub confidence: f64,
    pub dbms: Option<String>,
    pub evidence: String,
    pub false_positive_prob: Option<f64>,
}

/// Injectable fetch for `confirm` second shots (mockable without HTTP).
pub trait ConfirmFetch: Send + Sync {
    fn fetch_boxed(
        &self,
        wire_payload: String,
    ) -> std::pin::Pin<
        Box<dyn core::future::Future<Output = Result<ProbeResponse, InjektError>> + Send + '_>,
    >;
}

/// Common contract for the 8 techniques.
/// `Send + Sync` for `buffer_unordered` + `CancellationToken` use.
pub trait Technique: Send + Sync + core::fmt::Debug {
    fn kind(&self) -> TechniqueKind;
    /// Historical L1 budget (`boolean 2, error 2, time 4, union 1, ...`).
    fn default_take(&self) -> usize;
    /// `true` for boolean-family (boolean/json/nosql-bool): use
    /// `boolean_safe_transformation_sets`, else full sets.
    fn uses_boolean_safe_tampers(&self) -> bool {
        false
    }
    /// Timeout/pool class (`Boolean/Time/Oob/Default`).
    fn request_class(&self) -> RequestClass;
    /// Ordered base payload list (context ordering already applied).
    ///
    /// # Errors
    /// Returns an error when no payload applies (never `expect` on `.first()`).
    fn payloads(&self, ctx: &TechniqueCtx<'_>) -> Result<Vec<String>, InjektError>;
    /// Score one response. Pure, no I/O (current `*_Detector::evaluate*` move here).
    fn probe(
        &self,
        baseline_body: &str,
        baseline_ms: f64,
        resp: &ProbeResponse,
        wire_payload: &str,
    ) -> TechniqueVerdict;
    /// Confirming second shot(s). Returns `Some` when confirmed.
    fn confirm(
        &self,
        ctx: &TechniqueCtx<'_>,
        baseline_body: &str,
        baseline_ms: f64,
        first: &ProbeResponse,
        wire_payload: &str,
        fetch: &dyn ConfirmFetch,
    ) -> std::pin::Pin<
        Box<
            dyn core::future::Future<Output = Result<Option<TechniqueVerdict>, InjektError>>
                + Send
                + '_,
        >,
    >;
    /// `true` for custom loops (union ORDER BY enum, OOB token/poll/wait).
    fn needs_custom_loop(&self) -> bool {
        false
    }
}
