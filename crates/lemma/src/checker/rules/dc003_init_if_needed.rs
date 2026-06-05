//! DC-003: init_if_needed usage.
//!
//! Trigger: any account constraint that contains "init_if_needed".
//!
//! Why: init_if_needed permits reinitialisation attacks. An attacker can
//! call any instruction that uses init_if_needed on an account they control,
//! reinitialising it to a state that benefits them (e.g. becoming the new
//! authority).

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        for account in &handler.accounts {
            let uses_init_if_needed = account
                .raw_constraint.as_deref()
                .map(|c| c.contains("init_if_needed"))
                .unwrap_or(false);
            if uses_init_if_needed {
                gaps.push(gap(
                    &handler.name,
                    VulnClass::InsecureInitialisation,
                    Severity::High,
                    format!(
                        "Account `{}` uses `init_if_needed` which permits reinitialisation. \
                         An attacker can call this instruction on an already-initialised \
                         account and overwrite its state. Use `init` instead and add an \
                         explicit is-already-initialised check if conditional initialisation \
                         is required.",
                        account.name,
                    ),
                    "DC-003",
                ));
            }
        }
    }
    gaps
}