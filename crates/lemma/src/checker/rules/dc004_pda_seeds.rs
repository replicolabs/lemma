//! DC-004: PDA seeds without user-specific identifier.
//!
//! Trigger: a PDA account whose seeds contain only program-level string
//! literals without any account key or variable reference.
//!
//! Why: PDAs derived only from constant seeds are shared across all users.
//! Any user who interacts with the program addresses the same PDA.
//! An attacker can manipulate another user's state by calling instructions
//! that modify the shared PDA.

use crate::{
    checker::rules::gap,
    types::{InstructionHandler, SecurityGap, Severity, VulnClass},
};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        for account in &handler.accounts {
            if !account.is_pda {
                continue;
            }
            let constraint = account.raw_constraint.as_deref().unwrap_or("");
            if !has_user_specific_seed(constraint) {
                gaps.push(gap(
                    &handler.name,
                    VulnClass::InsecureInitialisation,
                    Severity::Medium,
                    format!(
                        "PDA account `{}` appears to use only constant seeds with no \
                         user-specific identifier. All users will derive the same PDA, \
                         enabling one user to interfere with another's state. Include a \
                         user pubkey or unique identifier in the seeds.",
                        account.name,
                    ),
                    "DC-004",
                ));
            }
        }
    }
    gaps
}

fn has_user_specific_seed(constraint: &str) -> bool {
    constraint.contains(".key()")
        || constraint.contains(".as_ref()")
        || has_non_literal_seed(constraint)
}

fn has_non_literal_seed(constraint: &str) -> bool {
    let Some(seeds_start) = constraint.find("seeds = [") else {
        return false;
    };
    let after = &constraint[seeds_start + 9..];
    let seeds_end = after.find(']').unwrap_or(after.len());
    let seeds = &after[..seeds_end];

    seeds
        .split(',')
        .map(|s| s.trim())
        .any(|s| !s.is_empty() && !s.starts_with("b\"") && !s.starts_with("b'"))
}
