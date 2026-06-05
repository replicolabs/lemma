//! DC-008: Arbitrary CPI with unvalidated program account.
//!
//! Trigger: any CPI call where the program account is unchecked and
//! the program's key is not verified before the call.
//!
//! Why: an unvalidated CPI target allows an attacker to substitute a
//! malicious program that accepts the same instruction discriminator.
//! The malicious program executes with the signed accounts and
//! writable authority the calling program passed to it.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        for cpi in &handler.cpi_calls {
            if cpi.program_verified {
                continue;
            }
            gaps.push(gap(
                &handler.name,
                VulnClass::ArbitraryCpi,
                Severity::Critical,
                format!(
                    "CPI call using program account `{}` in handler `{}` does not \
                     verify the program's identity before invocation. An attacker can \
                     substitute a malicious program. Use a typed `Program<'info, T>` \
                     account or add an explicit key check: \
                     `require_keys_eq!(ctx.accounts.{}.key(), expected_program::ID);`",
                    cpi.program_account, handler.name, cpi.program_account,
                ),
                "DC-008",
            ));
        }
    }
    gaps
}