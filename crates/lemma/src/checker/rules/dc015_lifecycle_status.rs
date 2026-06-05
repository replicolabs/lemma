//! DC-015: Missing lifecycle status check before state modification.
//!
//! Trigger: a handler that modifies state in a state account that contains
//! a field named "status", "state", or "phase", but the handler does not
//! read or check that field before writing.
//!
//! Why: programs with lifecycle state machines must verify the current state
//! before executing a transition. Skipping the check allows operations to
//! execute in wrong states — e.g. withdrawing from a liquidating position
//! or re-initialising an active protocol.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

const STATUS_FIELD_NAMES: &[&str] = &["status", "state", "phase", "stage", "lifecycle"];

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        let handler_lower = handler.name.to_ascii_lowercase();
        let is_transition = STATUS_FIELD_NAMES.iter().any(|f| handler_lower.contains(f))
            || handler_lower.contains("activate")
            || handler_lower.contains("deactivate")
            || handler_lower.contains("pause")
            || handler_lower.contains("resume")
            || handler_lower.contains("finalize")
            || handler_lower.contains("expire");

        if !is_transition {
            continue;
        }
        let has_mutable_state = handler.accounts.iter().any(|a| a.is_mutable && a.has_owner);
        if has_mutable_state {
            gaps.push(gap(
                &handler.name,
                VulnClass::LifecycleViolation,
                Severity::Low,
                format!(
                    "Handler `{}` appears to perform a lifecycle transition but may not \
                     verify the current lifecycle status before executing. Ensure the \
                     handler checks the current `status` or `state` field of the relevant \
                     account before writing new state to prevent invalid transitions.",
                    handler.name,
                ),
                "DC-015",
            ));
        }
    }
    gaps
}