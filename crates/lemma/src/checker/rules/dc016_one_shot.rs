//! DC-016: One-shot instruction without already-executed guard.
//!
//! Trigger: an instruction whose name contains "initialize", "init",
//! "create", "claim", or "consume" that does not use Anchor's `init`
//! constraint (which provides automatic reinitialization protection).
//!
//! Why: instructions that should only execute once must verify they have
//! not already executed. Without a guard the instruction can be called
//! repeatedly, allowing reinitialization or double-claiming.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

const ONE_SHOT_PATTERNS: &[&str] = &["initialize", "init_", "_init", "create_", "claim_", "consume_"];

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        let handler_lower = handler.name.to_ascii_lowercase();
        if !ONE_SHOT_PATTERNS.iter().any(|p| handler_lower.contains(p)) {
            continue;
        }
        let has_anchor_init = handler.accounts.iter().any(|a| {
            a.raw_constraint.as_deref()
                .map(|c| c.contains("init"))
                .unwrap_or(false)
        });
        if has_anchor_init {
            continue; 
        }
        gaps.push(gap(
            &handler.name,
            VulnClass::InsecureInitialisation,
            Severity::High,
            format!(
                "Handler `{}` appears to be a one-shot instruction but does not use \
                 Anchor's `init` constraint for reinitialization protection. Without \
                 it the instruction can be called multiple times. Either use \
                 `#[account(init, ...)]` or add an explicit check that the account \
                 has not already been initialised.",
                handler.name,
            ),
            "DC-016",
        ));
    }
    gaps
}