//! DC-013: Missing has_one constraint binding authority to stored field.
//!
//! Trigger: a handler has an authority-named signer account but no
//! `has_one` constraint binding it to the corresponding field in a
//! state account.
//!
//! Why: a signer check alone only verifies the account signed the
//! transaction. It does not verify the signer is the specific authority
//! stored in the program's state. Any account can sign — the check only
//! confirms they signed, not that they are the right signer.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

const AUTHORITY_PATTERNS: &[&str] = &["authority", "admin", "owner", "manager"];

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        for account in &handler.accounts {
            if !account.has_signer {
                continue;
            }
            let name_lower = account.name.to_ascii_lowercase();
            if !AUTHORITY_PATTERNS.iter().any(|p| name_lower.contains(p)) {
                continue;
            }
            if account.has_has_one {
                continue;
            }
            let has_state_account = handler.accounts.iter().any(|a| {
                !a.has_signer && a.has_owner && !a.is_pda
            });
            if !has_state_account {
                continue;
            }
            gaps.push(gap(
                &handler.name,
                VulnClass::MissingSignerCheck,
                Severity::High,
                format!(
                    "Authority account `{}` is required to sign but is not bound to a \
                     stored authority field via `has_one`. Any account can sign — the check \
                     only confirms the transaction was signed, not that the signer is the \
                     correct authority for this program state. Add \
                     `#[account(has_one = {})]` to the state account.",
                    account.name, account.name,
                ),
                "DC-013",
            ));
        }
    }
    gaps
}