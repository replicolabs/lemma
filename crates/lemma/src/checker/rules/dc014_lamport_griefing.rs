//! DC-014: Lamport griefing on PDA initialisation.
//!
//! Trigger: an init handler for a PDA that does not appear to check for
//! existing lamports before transferring the rent-exempt minimum.
//!
//! Why: an attacker can send lamports to a PDA address before the program
//! initialises it. The system program's Allocate instruction fails if the
//! account already has lamports. Transferring exactly the rent-exempt
//! minimum without accounting for existing lamports can leave the account
//! in an uninitialised but funded state.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        let handler_name_lower = handler.name.to_ascii_lowercase();
        let is_init_handler = handler_name_lower.contains("init")
            || handler_name_lower.contains("create")
            || handler_name_lower.contains("initialize");
        if !is_init_handler {
            continue;
        }
        for account in &handler.accounts {
            if !account.is_pda {
                continue;
            }
            let uses_anchor_init = account
                .raw_constraint.as_deref()
                .map(|c| c.contains("init"))
                .unwrap_or(false);
            if uses_anchor_init {
                continue; 
            }
            gaps.push(gap(
                &handler.name,
                VulnClass::InsecureInitialisation,
                Severity::Medium,
                format!(
                    "Handler `{}` initialises PDA `{}` without using Anchor's `init` \
                     constraint. If an attacker pre-funds the PDA address with lamports, \
                     the initialisation may fail or behave unexpectedly. When initialising \
                     manually, calculate the rent-exempt minimum, check existing lamports, \
                     and transfer only the deficit: \
                     `transfer(required.saturating_sub(existing))`.",
                    handler.name, account.name,
                ),
                "DC-014",
            ));
        }
    }
    gaps
}