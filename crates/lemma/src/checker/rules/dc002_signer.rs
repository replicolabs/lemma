//! DC-002: Missing signer check on authority-named accounts.
//!
//! Trigger: any account whose name suggests it is an authority (contains
//! "authority", "admin", "owner", "manager", "operator") that is not
//! declared as Signer<'info> and has no signer constraint.
//!
//! Why: authority accounts that are not required to sign allow any account
//! to impersonate the authority. The attacker passes the real authority's
//! pubkey in the accounts list without that account's signature.

use crate::{
    checker::rules::gap,
    types::{InstructionHandler, SecurityGap, Severity, VulnClass},
};

const AUTHORITY_PATTERNS: &[&str] = &[
    "authority",
    "admin",
    "owner",
    "manager",
    "operator",
    "governor",
    "controller",
    "supervisor",
];

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();

    for handler in handlers {
        for account in &handler.accounts {
            if !looks_like_authority(&account.name) {
                continue;
            }
            if account.has_signer {
                continue;
            }
            let severity = if handler_transfers_value(handler) {
                Severity::Critical
            } else {
                Severity::High
            };

            gaps.push(gap(
                &handler.name,
                VulnClass::MissingSignerCheck,
                severity,
                format!(
                    "Account `{}` appears to be an authority but is not required to sign \
                     the transaction. Any account can be passed in this position without \
                     the real authority's signature. Use `Signer<'info>` or add \
                     `#[account(signer)]`.",
                    account.name,
                ),
                "DC-002",
            ));
        }
    }

    gaps
}

fn looks_like_authority(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    AUTHORITY_PATTERNS.iter().any(|p| lower.contains(p))
}

fn handler_transfers_value(handler: &InstructionHandler) -> bool {
    let name = handler.name.to_ascii_lowercase();
    [
        "withdraw",
        "transfer",
        "burn",
        "drain",
        "swap",
        "borrow",
        "liquidate",
        "claim",
        "redeem",
        "send",
        "pay",
    ]
    .iter()
    .any(|kw| name.contains(kw))
}
