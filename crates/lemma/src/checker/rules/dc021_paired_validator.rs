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

use crate::{
    checker::rules::gap,
    types::{InstructionHandler, SecurityGap, Severity, VulnClass},
};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        let token_accounts: Vec<_> = handler
            .accounts
            .iter()
            .filter(|a| {
                a.type_str.to_ascii_lowercase().contains("tokenaccount")
                    || a.type_str.contains("InterfaceAccount")
            })
            .collect();
        let has_mint = handler
            .accounts
            .iter()
            .any(|a| a.type_str.contains("Mint") || a.name.to_ascii_lowercase().contains("mint"));
        if token_accounts.is_empty() || !has_mint {
            continue;
        }
        let cross_validated = handler.accounts.iter().any(|a| {
            if a.has_one_field
                .as_deref()
                .map(|f| f.contains("mint"))
                .unwrap_or(false)
            {
                return true;
            }
            a.raw_constraint
                .as_deref()
                .map(|c| {
                    c.contains("token::mint")
                        || c.contains("associated_token::mint")
                        || c.contains("mint::")
                        || c.contains("mint =")
                })
                .unwrap_or(false)
        });
        if cross_validated {
            continue;
        }

        let names: Vec<&str> = token_accounts.iter().map(|a| a.name.as_ref()).collect();
        gaps.push(gap(
            &handler.name,
            VulnClass::PairedValidatorMismatch,
            Severity::Medium,
            format!(
                "Handler `{}` takes token account(s) [{}] alongside a mint but does not bind \
                 them with `token::mint = <mint>`. An attacker could pass a token account for \
                 a different asset. Add a `token::mint` (or `has_one = mint`) constraint.",
                handler.name,
                names.join(", "),
            ),
            "DC-021",
        ));
    }
    gaps
}
