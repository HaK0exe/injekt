//! `auto` escalation planner: L1 as-configured, L2 widened, L3 evasive
//! (pure over [`EngineConfig`], no I/O). `base64encode` is never
//! auto-enabled: it breaks boolean TRUE/FALSE differentials.

use crate::engine::orchestrator::EngineConfig;

/// One escalation step: label + mutated engine config.
#[derive(Debug, Clone)]
pub struct EscalationStep {
    /// Short label shown in logs (`L1-baseline`, `L2-tamper`, `L3-evasion`).
    pub label: &'static str,
    /// Engine config for this pass.
    pub config: EngineConfig,
}

/// Pure escalation plan: L1 as-configured, L2 widened, L3 evasive.
/// Returns a single step when `escalate` is false.
#[must_use]
pub fn escalation_plan(base: &EngineConfig, escalate: bool) -> Vec<EscalationStep> {
    if !escalate {
        return vec![EscalationStep {
            label: "L1-baseline",
            config: base.clone(),
        }];
    }
    let mut steps = vec![EscalationStep {
        label: "L1-baseline",
        config: base.clone(),
    }];

    let mut l2 = base.clone();
    l2.budget.level = base.budget.level.max(2);
    if l2.evasion.tampers.is_empty() {
        l2.evasion.tampers = crate::techniques::tamper::parse_tamper_list(Some(
            "space2comment,randomcase,versionedfuzz",
        ));
    }
    l2.confirm = false;
    steps.push(EscalationStep {
        label: "L2-tamper",
        config: l2,
    });

    let mut l3 = base.clone();
    l3.budget.level = base.budget.level.max(3);
    // 6 tampers → 8 transformation sets (`t.len()+2` bound): adds `equaltolike`
    // (`=`-signature WAFs) plus `numericobfuscate`/`linecomment` (numeric and
    // terminator signatures) orthogonal to the space/encoding coverage. Opaque
    // tampers (`base64encode`) stay opt-in only — never auto-escalated.
    if l3.evasion.tampers.len() < 6 {
        l3.evasion.tampers = crate::techniques::tamper::parse_tamper_list(Some(
            "space2comment,randomcase,charencode,equaltolike,numericobfuscate,linecomment",
        ));
    }
    l3.matcher.text_only = true;
    l3.evasion.hpp = true;
    steps.push(EscalationStep {
        label: "L3-evasion",
        config: l3,
    });
    steps
}
