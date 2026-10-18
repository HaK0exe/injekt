use super::{InjectionContext, QuoteContext};
use crate::target::{parameters::TargetParameter, raw_request::RawRequest};

/// Passive inference from parameter name, value, and request content type (0 HTTP request).
#[must_use]
pub fn infer_passive_context(
    param: &TargetParameter,
    raw: Option<&RawRequest>,
) -> InjectionContext {
    let mut ctx = InjectionContext::new();

    // 1. JSON context
    if let Some(r) = raw {
        if r.headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("application/json"))
        {
            ctx.json = true;
        }
        if let Some(body) = &r.body {
            let trimmed = body.trim();
            if (trimmed.starts_with('{') && trimmed.ends_with('}'))
                || (trimmed.starts_with('[') && trimmed.ends_with(']'))
            {
                ctx.json = true;
            }
        }
    }

    // 2. Order by context from parameter name
    let name_l = param.name.to_ascii_lowercase();
    if name_l == "order"
        || name_l == "orderby"
        || name_l == "sort"
        || name_l == "sort_by"
        || name_l == "dir"
        || name_l == "direction"
        || name_l == "by"
    {
        ctx.order_by = true;
    }

    // 3. Numeric context hint from value
    let val_trimmed = param.original_value.trim();
    if !val_trimmed.is_empty() && val_trimmed.chars().all(|c| c.is_ascii_digit()) {
        ctx.numeric = true;
        ctx.quote = QuoteContext::None;
    }

    ctx
}
