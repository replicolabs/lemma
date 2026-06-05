//! DC-009: Missing canonical bump storage.
//!
//! Trigger: a PDA account uses `seeds` in its constraint but does not
//! store the canonical bump in the account state (no `bump` field visible).
//!
//! Why: if the canonical bump is not stored, subsequent handlers must call
//! find_program_address to validate the PDA, which costs ~8000 CU per call.
//! Worse, using a non-canonical bump stored by the user allows deriving
//! addresses that differ under certain seed conditions.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        for account in &handler.accounts {
            if !account.is_pda {
                continue;
            }
            if !account.has_bump {
                gaps.push(gap(
                    &handler.name,
                    VulnClass::InsecureInitialisation,
                    Severity::Medium,
                    format!(
                        "PDA account `{}` uses seeds but does not include a `bump` \
                         field in its constraint. Store the canonical bump from \
                         `find_program_address` in the account data during init. \
                         In subsequent handlers, use `create_program_address` with \
                         the stored bump instead of calling `find_program_address` again.",
                        account.name,
                    ),
                    "DC-009",
                ));
            }
        }
    }
    gaps
}