//! DC-011: Sysvar account not validated (Pinocchio programs).
//!
//! Trigger: in Pinocchio programs, any account whose name contains
//! "clock", "rent", or "slot_hashes" that is accessed via direct data
//! read rather than the safe `Clock::get()` / `Rent::get()` accessors.
//!
//! Why: Pinocchio does not implicitly validate sysvar accounts. A sysvar
//! passed as an account parameter can be a fake account with the correct
//! data layout but incorrect address, allowing the attacker to feed the
//! program manipulated timestamps or rent values.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

const SYSVAR_NAMES: &[&str] = &["clock", "rent", "slot_hashes", "sysvar"];

pub fn check(handlers: &[InstructionHandler], source: &str) -> Vec<SecurityGap> {
    let is_pinocchio = source.contains("pinocchio") || source.contains("solana_nostd");
    if !is_pinocchio {
        return Vec::new();
    }
    let uses_safe_accessor = source.contains("Clock::get()")
        || source.contains("Rent::get()")
        || source.contains("SlotHashes::get()");

    let mut gaps = Vec::new();
    for handler in handlers {
        for account in &handler.accounts {
            let name_lower = account.name.to_ascii_lowercase();
            if !SYSVAR_NAMES.iter().any(|s| name_lower.contains(s)) {
                continue;
            }
            if uses_safe_accessor {
                continue;
            }
            gaps.push(gap(
                &handler.name,
                VulnClass::MissingOwnershipCheck,
                Severity::High,
                format!(
                    "Pinocchio program accesses sysvar account `{}` as a direct account \
                     parameter without using the safe accessor `{}::get()`. An attacker \
                     can pass a fake sysvar with manipulated data. Use \
                     `pinocchio::sysvars::clock::Clock::get()` instead.",
                    account.name,
                    if name_lower.contains("clock") { "Clock" }
                    else if name_lower.contains("rent") { "Rent" }
                    else { "Sysvar" },
                ),
                "DC-011",
            ));
        }
    }
    gaps
}