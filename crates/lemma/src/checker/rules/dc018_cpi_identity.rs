//! DC-018: CPI without program identity verification.
//!
//! Trigger: any CPI call where the callee program account is not verified
//! against a known program ID before the call. Similar to DC-008 but
//! focuses on cases where the account is typed but its key is not
//! explicitly verified against the expected constant.
//!
//! This is distinct from DC-008 which catches completely unvalidated
//! UncheckedAccount CPI targets. DC-018 catches typed accounts where
//! the type provides some safety but the specific program ID is not
//! pinned to a known constant.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        for cpi in &handler.cpi_calls {
            if cpi.program_verified {
                continue;
            }
            let known_program = is_known_system_program(&cpi.program_account);
            if known_program {
                continue;
            }
            gaps.push(gap(
                &handler.name,
                VulnClass::ArbitraryCpi,
                Severity::High,
                format!(
                    "CPI to `{}` in handler `{}` does not verify the program identity \
                     against a known program ID constant. Add \
                     `require_keys_eq!({}.key(), MyProgram::ID, ErrorCode::InvalidProgram);` \
                     before the CPI call.",
                    cpi.program_account, handler.name, cpi.program_account,
                ),
                "DC-018",
            ));
        }
    }
    gaps
}

fn is_known_system_program(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("system_program")
        || lower.contains("token_program")
        || lower.contains("rent")
        || lower.contains("spl_token")
        || lower.contains("spl_associated")
}