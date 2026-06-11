//! DC-003: init_if_needed usage.
//!
//! Trigger: any account constraint that contains "init_if_needed".
//!
//! Why: init_if_needed permits reinitialisation attacks. An attacker can
//! call any instruction that uses init_if_needed on an account they control,
//! reinitialising it to a state that benefits them (e.g. becoming the new
//! authority).

use crate::{
    checker::rules::gap,
    types::{InstructionHandler, SecurityGap, Severity, VulnClass},
};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        for account in &handler.accounts {
            let c = account.raw_constraint.as_deref().unwrap_or("");
            if !c.contains("init_if_needed") {
                continue;
            }
            let is_token_like = account.type_str.contains("TokenAccount")
                || account.type_str.contains("InterfaceAccount")
                || account.type_str.contains("Mint")
                || c.contains("associated_token");
            if is_token_like {
                continue;
            }

            gaps.push(gap(
                &handler.name,
                VulnClass::InsecureInitialisation,
                Severity::Medium,
                format!(
                    "State account `{}` uses `init_if_needed`. If it holds authority or \
                     configuration, an attacker may call this handler on an existing account \
                     and reset it. Confirm there is a reinitialisation guard, or use `init`.",
                    account.name,
                ),
                "DC-003",
            ));
        }
    }
    gaps
}
