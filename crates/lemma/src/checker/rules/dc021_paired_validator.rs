//! DC-021: Paired validator mismatch.
//!
//! Trigger: an instruction accepts both a token account and a mint account
//! but does not cross-validate them (no constraint binding the token
//! account's mint field to the mint account's key).
//!
//! Why: a token account validated as owned by the SPL Token program and a
//! mint validated as a valid SPL mint can still be for different assets.
//! Without cross-validation, an attacker passes a valid token account for
//! one asset alongside a mint for a different asset, enabling asset
//! confusion and potential fund drains.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        let token_accounts: Vec<_> = handler.accounts.iter().filter(|a| {
            let lower = a.name.to_ascii_lowercase();
            lower.contains("token") || lower.contains("vault")
                || a.type_str.to_ascii_lowercase().contains("tokenaccount")
        }).collect();

        let mint_accounts: Vec<_> = handler.accounts.iter().filter(|a| {
            let lower = a.name.to_ascii_lowercase();
            lower.contains("mint") || a.type_str.to_ascii_lowercase().contains("mint")
        }).collect();

        if token_accounts.is_empty() || mint_accounts.is_empty() {
            continue;
        }
        let has_cross_validation = handler.accounts.iter().any(|a| {
            a.has_has_one && a.has_one_field.as_deref()
                .map(|f| f.contains("mint"))
                .unwrap_or(false)
        }) || handler.accounts.iter().any(|a| {
            a.raw_constraint.as_deref()
                .map(|c| c.contains("mint") && c.contains("constraint"))
                .unwrap_or(false)
        });

        if !has_cross_validation {
            let token_names: Vec<&str> = token_accounts.iter().map(|a| a.name.as_ref()).collect();
            let mint_names: Vec<&str> = mint_accounts.iter().map(|a| a.name.as_ref()).collect();
            gaps.push(gap(
                &handler.name,
                VulnClass::PairedValidatorMismatch,
                Severity::High,
                format!(
                    "Handler `{}` accepts token accounts [{}] and mint accounts [{}] \
                     but does not cross-validate that the token accounts belong to the \
                     expected mint. An attacker can pass a valid token account for a \
                     different asset. Add `#[account(has_one = mint)]` to the relevant \
                     token account.",
                    handler.name,
                    token_names.join(", "),
                    mint_names.join(", "),
                ),
                "DC-021",
            ));
        }
    }
    gaps
}