use crate::{
    checker::rules::gap,
    types::{InstructionHandler, SecurityGap, Severity, VulnClass},
};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        for account in &handler.accounts {
            if !account.is_unchecked {
                continue;
            }
            if account.is_pda {
                continue;
            }

            let lower = account.name.to_ascii_lowercase();
            if lower.contains("system_program")
                || lower.contains("token_program")
                || lower.contains("rent")
                || lower.contains("clock")
                || lower.contains("instructions")
                || lower.contains("sysvar")
            {
                continue;
            }

            let c = account.raw_constraint.as_deref().unwrap_or("");
            let has_constraint = c.contains("owner =")
                || c.contains("address =")
                || c.contains("seeds")
                || c.contains("associated_token")
                || c.contains("token::")
                || c.contains("mint::");
            if has_constraint {
                continue;
            }

            gaps.push(gap(
                &handler.name,
                VulnClass::MissingOwnershipCheck,
                Severity::Medium,
                format!(
                    "Account `{}` is declared unchecked (`{}`) with no owner, address, or \
                     seeds constraint. An attacker can pass any account here. A `/// CHECK:` \
                     comment satisfies the compiler but does not validate ownership — confirm \
                     the program checks the owner, or use `Account<'info, T>`.",
                    account.name, account.type_str,
                ),
                "DC-001",
            ));
        }
    }
    gaps
}
