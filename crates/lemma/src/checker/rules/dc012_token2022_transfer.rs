//! DC-012: Token-2022 using deprecated `transfer` instead of `transfer_checked`.
//!
//! Trigger: a program imports anchor_spl::token::transfer (or the equivalent)
//! while also interacting with Token-2022 token accounts.
//!
//! Why: the old `transfer` instruction is deprecated in Token-2022. If the
//! token account has a Transfer Hook or Transfer Fee extension, calling
//! `transfer` returns `MintRequiredForTransfer` and the instruction fails
//! silently. Use `transfer_checked` or `anchor_spl::token_interface`.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

pub fn check(_handlers: &[InstructionHandler], source: &str) -> Vec<SecurityGap> {
    let uses_token_interface = source.contains("token_interface")
        || source.contains("token_2022")
        || source.contains("Token2022");

    if !uses_token_interface {
        return Vec::new();
    }

    let uses_old_transfer = source.contains("anchor_spl::token::transfer")
        || (source.contains("use anchor_spl::token") && source.contains("::transfer("));

    if !uses_old_transfer {
        return Vec::new();
    }
    vec![gap(
        "program",
        VulnClass::ArbitraryCpi,
        Severity::High,
        "Program uses Token-2022 accounts but calls the deprecated `anchor_spl::token::transfer` \
         instruction. For Token-2022 tokens with Transfer Hook or Transfer Fee extensions, \
         this call returns `MintRequiredForTransfer`. Replace with `transfer_checked` from \
         `anchor_spl::token_interface` which handles all Token-2022 extensions.",
        "DC-012",
    )]
}