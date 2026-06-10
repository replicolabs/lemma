//! DC-017: Permissionless state write.
//!
//! Trigger: a handler that has mutable state accounts but no signer
//! constraint on any account and no has_one binding.
//!
//! Why: a handler that writes to program state without any access control
//! can be called by anyone. Any caller can write arbitrary data to
//! program-owned state accounts.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        let has_mutable_state = handler.accounts.iter().any(|a| {
            a.is_mutable && a.has_owner && !a.is_pda && !a.is_unchecked
        });
        if !has_mutable_state {
            continue;
        }
        let has_access_control = handler.accounts.iter().any(|a| {
            a.has_signer || a.has_has_one
        });
        if has_access_control {
            continue;
        }

        let handler_lower = handler.name.to_ascii_lowercase();
        let intentionally_permissionless = handler_lower.contains("permissionless")
            || handler_lower.contains("crank")
            || handler_lower.contains("settle")
            || handler_lower.contains("refresh");
        if intentionally_permissionless {
            continue;
        }

        gaps.push(gap(
            &handler.name,
            VulnClass::PermissionlessStateWrite,
            Severity::High,
            format!(
                "Handler `{}` writes to mutable state accounts but has no signer \
                 constraint or authority binding. Any account can call this instruction \
                 and modify program state. If this is intentionally permissionless, \
                 add `lemma acknowledge gap-XXX --reason \"permissionless by design\"` \
                 to suppress this warning.",
                handler.name,
            ),
            "DC-017",
        ));
    }
    gaps
}