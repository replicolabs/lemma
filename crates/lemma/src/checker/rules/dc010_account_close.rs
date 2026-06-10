//! DC-010: Account not properly closed (data not zeroed / discriminator not cleared).
//!
//! Trigger: a handler that closes an account (transfers lamports to a
//! destination) without using Anchor's `close` constraint or explicitly
//! zeroing the account data.
//!
//! Why: a closed account that still has its discriminator byte set can be
//! revived within the same transaction by refunding lamports. The attacker
//! drains the account in instruction N, refunds lamports in instruction N+1,
//! and the account is alive again in instruction N+2 with attacker-chosen data.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        let lower = handler.name.to_ascii_lowercase();
        if !lower.contains("close") && !lower.contains("delete")
            && !lower.contains("destroy") && !lower.contains("terminate")
        {
            continue;
        }
        let has_anchor_close = handler.accounts.iter().any(|a| {
            a.raw_constraint.as_deref().map(|c| c.contains("close =")).unwrap_or(false)
        });
        if has_anchor_close { continue; }

        let has_typed_mutable = handler.accounts.iter().any(|a| {
            a.is_mutable && a.has_owner && !a.is_unchecked
        });
        if !has_typed_mutable { continue; }

        gaps.push(gap(
            &handler.name,
            VulnClass::LifecycleViolation,
            Severity::Medium,
            format!(
                "Handler `{}` closes an account but no account uses Anchor's \
                 `close = <destination>` constraint. Without it the discriminator \
                 is not cleared and the account can be revived within the same \
                 transaction. Add `#[account(mut, close = destination)]` to the \
                 account being closed.",
                handler.name,
            ),
            "DC-010",
        ));
    }
    gaps
}