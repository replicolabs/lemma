//! DC-020: Authority not revoked on account close.
//!
//! Trigger: a close handler that closes state accounts but does not
//! also revoke token delegate approvals or program authority delegations
//! that reference the closed account.
//!
//! Why: when a position, vault, or authority account is closed, any
//! delegate approvals granted by that account remain active on-chain.
//! An attacker can exploit these dangling approvals after the account
//! is gone to drain associated token accounts.

use crate::{
    checker::rules::gap,
    types::{InstructionHandler, SecurityGap, Severity, VulnClass},
};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        let handler_lower = handler.name.to_ascii_lowercase();
        let is_close = handler_lower.contains("close")
            || handler_lower.contains("delete")
            || handler_lower.contains("terminate");
        if !is_close {
            continue;
        }
        let has_token_account = handler.accounts.iter().any(|a| {
            let name_lower = a.name.to_ascii_lowercase();
            name_lower.contains("token")
                || name_lower.contains("vault")
                || a.type_str.to_ascii_lowercase().contains("tokenaccount")
        });

        if !has_token_account {
            continue;
        }
        let has_revoke = handler.cpi_calls.iter().any(|c| {
            c.program_account.to_ascii_lowercase().contains("revoke")
                || c.program_account.to_ascii_lowercase().contains("token")
        });

        if !has_revoke {
            gaps.push(gap(
                &handler.name,
                VulnClass::AuthorityNotRevokedOnClose,
                Severity::High,
                format!(
                    "Handler `{}` closes accounts including token accounts but does not \
                     appear to revoke token delegate approvals. Dangling delegates on \
                     closed accounts can be exploited. Add a `revoke` CPI call to the \
                     SPL Token program before closing the token accounts.",
                    handler.name,
                ),
                "DC-020",
            ));
        }
    }
    gaps
}
