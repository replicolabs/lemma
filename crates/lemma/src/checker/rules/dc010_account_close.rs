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
        for account in &handler.accounts {
            let uses_close = account
                .raw_constraint.as_deref()
                .map(|c| c.contains("close ="))
                .unwrap_or(false);
            if !account.is_mutable || uses_close {
                continue;
            }
            let handler_name_lower = handler.name.to_ascii_lowercase();
            let is_close_handler = handler_name_lower.contains("close")
                || handler_name_lower.contains("delete")
                || handler_name_lower.contains("destroy")
                || handler_name_lower.contains("terminate");

            if is_close_handler {
                gaps.push(gap(
                    &handler.name,
                    VulnClass::LifecycleViolation,
                    Severity::High,
                    format!(
                        "Handler `{}` appears to close accounts but account `{}` does \
                         not use Anchor's `close` constraint. Without `close`, the \
                         account discriminator is not cleared and the account can be \
                         revived in a multi-instruction transaction. Use \
                         `#[account(mut, close = destination)]`.",
                        handler.name, account.name,
                    ),
                    "DC-010",
                ));
            }
        }
    }
    gaps
}