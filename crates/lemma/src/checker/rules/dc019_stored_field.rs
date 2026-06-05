//! DC-019: Stored field written only at init, never updated.
//!
//! Trigger: analysis across all handlers to find state fields that
//! appear to be written only in initialisation handlers and only read
//! (never updated) in subsequent handlers.
//!
//! Why: if a validation field is never written after init, it always
//! contains the initialisation value. A field intended to gate access
//! that is never updated after init may always equal a permissive value,
//! making the validation vacuous.
//!
//! Note: this rule operates on handler names and account patterns since
//! we do not have full data flow analysis. It flags patterns for review.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let init_handlers: Vec<&InstructionHandler> = handlers
        .iter()
        .filter(|h| {
            let lower = h.name.to_ascii_lowercase();
            lower.contains("init") || lower.contains("create") || lower.contains("setup")
        })
        .collect();

    let non_init_handlers: Vec<&InstructionHandler> = handlers
        .iter()
        .filter(|h| {
            let lower = h.name.to_ascii_lowercase();
            !lower.contains("init") && !lower.contains("create") && !lower.contains("setup")
        })
        .collect();

    if init_handlers.is_empty() || non_init_handlers.is_empty() {
        return Vec::new();
    }
    let mut gaps = Vec::new();
    for init_h in &init_handlers {
        for account in &init_h.accounts {
            if !account.is_mutable || !account.has_owner {
                continue;
            }
            let updated_later = non_init_handlers.iter().any(|h| {
                h.accounts.iter().any(|a| {
                    a.name == account.name && a.is_mutable
                })
            });
            if !updated_later && non_init_handlers.len() > 1 {
                gaps.push(gap(
                    &init_h.name,
                    VulnClass::StoredFieldNeverWritten,
                    Severity::Low,
                    format!(
                        "State account `{}` is written during `{}` but does not appear \
                         as mutable in any other handler. If this account stores fields \
                         used in validation, verify they are updated correctly when the \
                         program state changes. Static validation fields always retain \
                         their initialisation value.",
                        account.name, init_h.name,
                    ),
                    "DC-019",
                ));
            }
        }
    }
    gaps
}