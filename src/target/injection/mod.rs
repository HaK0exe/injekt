#![deny(unsafe_code)]

mod filters;
mod headers;
mod inject;
mod opts;
mod raw;
mod spec;
mod tampers;

pub use filters::{
    APP_FILTER_STATUS, FILTER_STREAK_LIMIT, baseline_all_error, filter_params, is_app_filter_block,
    is_ignored, payload_budget,
};
pub use headers::{headers_preserving_raw, headers_preserving_raw_keep_ct};
pub use inject::{
    inject_body_param, inject_multipart_field, inject_param, inject_param_or_marker,
    inject_with_marker,
};
pub use opts::ProbeOpts;
pub use raw::synthetic_raw_from_data;
pub use spec::{build_injection_spec_with_raw, request_spec_from_raw};
pub use tampers::{resolve_effective_tampers, waf_auto_tampers};
