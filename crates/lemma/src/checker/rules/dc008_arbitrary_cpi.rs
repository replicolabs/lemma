//! DC-008: Arbitrary CPI with unvalidated program account.
//!
//! Trigger: any CPI call where the program account is unchecked and
//! the program's key is not verified before the call.
//!
//! Why: an unvalidated CPI target allows an attacker to substitute a
//! malicious program that accepts the same instruction discriminator.
//! The malicious program executes with the signed accounts and
//! writable authority the calling program passed to it.

use crate::{
    checker::rules::gap,
    types::{InstructionHandler, SecurityGap, Severity, VulnClass},
};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        for cpi in &handler.cpi_calls {
            if cpi.program_verified {
                continue;
            }
            if cpi.program_account.as_ref() == "unknown" {
                continue;
            }
            if is_known_safe(&cpi.program_account) {
                continue;
            }

            gaps.push(gap(
                &handler.name,
                VulnClass::ArbitraryCpi,
                Severity::High,
                format!(
                    "CPI to `{}` in handler `{}` does not verify the program's identity. \
                     An attacker can substitute a malicious program. Use a typed \
                     `Program<'info, T>` account or add: \
                     `require_keys_eq!({}.key(), MyProgram::ID, ErrorCode::InvalidProgram);`",
                    cpi.program_account, handler.name, cpi.program_account,
                ),
                "DC-008",
            ));
        }
    }
    gaps
}

fn is_known_safe(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("system_program")
        || lower.contains("token_program")
        || lower.contains("spl_token")
        || lower.contains("associated_token")
        || lower.contains("associated_token_program")
        || lower.contains("rent")
        || lower.contains("clock")
}
