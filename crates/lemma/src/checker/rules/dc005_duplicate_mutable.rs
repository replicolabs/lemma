//! DC-005: Duplicate mutable accounts without key check.
//!
//! Trigger: instruction with two or more mutable accounts of the same
//! Anchor type without a constraint verifying they have different keys.
//!
//! Why: if the same account is passed for two mutable parameters, sequential
//! writes to both cancel each other out. The second write overwrites the
//! first, producing incorrect final state.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        let mutable: Vec<_> = handler.accounts.iter().filter(|a| a.is_mutable).collect();
        if mutable.len() < 2 {
            continue;
        }
        for i in 0..mutable.len() {
            for j in (i + 1)..mutable.len() {
                let a = mutable[i];
                let b = mutable[j];
                // Same base type (strip lifetime params for comparison).
                let base_a = strip_lifetime(&a.type_str);
                let base_b = strip_lifetime(&b.type_str);
                if base_a != base_b {
                    continue;
                }
                let a_has_key_check = a.raw_constraint.as_deref()
                    .map(|c| c.contains("address =") || c.contains(&format!("key = {}", b.name)))
                    .unwrap_or(false);
                let b_has_key_check = b.raw_constraint.as_deref()
                    .map(|c| c.contains("address =") || c.contains(&format!("key = {}", a.name)))
                    .unwrap_or(false);
                if !a_has_key_check && !b_has_key_check {
                    gaps.push(gap(
                        &handler.name,
                        VulnClass::MissingOwnershipCheck,
                        Severity::Medium,
                        format!(
                            "Accounts `{}` and `{}` are both mutable with the same type `{}`. \
                             If the same account is passed for both parameters, writes will \
                             overwrite each other. Add a `constraint = {}.key() != {}.key()` \
                             check.",
                            a.name, b.name, base_a, a.name, b.name,
                        ),
                        "DC-005",
                    ));
                }
            }
        }
    }
    gaps
}

fn strip_lifetime(type_str: &str) -> &str {
    type_str.split('<').next().unwrap_or(type_str).trim()
}