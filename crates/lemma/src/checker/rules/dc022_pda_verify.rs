//! DC-022: PDA accepted without seeds+bump verification in non-init handler.
//!
//! Trigger: a non-init handler that accepts a PDA account without a seeds
//! constraint to verify it was derived from the expected seeds and bump.
//!
//! Why: without seeds verification, an attacker can pass any account at
//! the PDA position. The account may have the correct owner (if it is a
//! program-owned account) but be at a different address than expected.
//! This allows substituting a different program-owned account in the PDA
//! position, potentially accessing another user's state.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        let handler_lower = handler.name.to_ascii_lowercase();
        let is_init = handler_lower.contains("init")
            || handler_lower.contains("create")
            || handler_lower.contains("initialize");
        if is_init {
            continue;
        }

        for account in &handler.accounts {
            let looks_like_pda = {
                let lower = account.name.to_ascii_lowercase();
                lower.contains("pda") || lower.contains("escrow")
                    || lower.contains("vault") || lower.contains("pool_state")
                    || lower.contains("market_state")
            };

            if !looks_like_pda {
                continue;
            }
            if account.is_pda {
                continue;
            }
            if account.has_owner && !account.is_unchecked {
                gaps.push(gap(
                    &handler.name,
                    VulnClass::InitWithoutPda,
                    Severity::High,
                    format!(
                        "Account `{}` in handler `{}` appears to be a PDA but has no \
                         `seeds` constraint to verify its derivation. Without seeds \
                         verification, an attacker can pass a different program-owned \
                         account at this position. Add \
                         `#[account(seeds = [...], bump = state.bump)]`.",
                        account.name, handler.name,
                    ),
                    "DC-022",
                ));
            }
        }
    }
    gaps
}