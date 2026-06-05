//! DC-001: Missing owner check on UncheckedAccount.
//!
//! Trigger: any account declared as UncheckedAccount<'info> or raw
//! AccountInfo<'info> that has no owner constraint and no address constraint.
//!
//! Why: UncheckedAccount bypasses Anchor's automatic owner verification.
//! An attacker can pass any account owned by any program. Without an
//! explicit owner constraint the program will accept and deserialise data
//! from accounts controlled by the attacker.

use crate::{
    checker::rules::gap,
    types::{InstructionHandler, SecurityGap, Severity, VulnClass},
};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();

    for handler in handlers {
        for account in &handler.accounts {
            if !account.is_unchecked {
                continue;
            }
            let has_owner_constraint = account.has_owner
                || account.raw_constraint.as_deref()
                    .map(|c| c.contains("owner =") || c.contains("address ="))
                    .unwrap_or(false);

            if !has_owner_constraint {
                gaps.push(gap(
                    &handler.name,
                    VulnClass::MissingOwnershipCheck,
                    Severity::High,
                    format!(
                        "Account `{}` is declared as `{}` (unchecked) with no owner or \
                         address constraint. An attacker can pass any account in this \
                         position. Add `#[account(owner = expected_program_id)]` or use \
                         a typed account like `Account<'info, T>`.",
                        account.name, account.type_str,
                    ),
                    "DC-001",
                ));
            }
        }
    }

    gaps
}