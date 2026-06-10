use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

const AUTHORITY_PATTERNS: &[&str] = &["authority", "admin", "owner", "manager"];

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        for account in &handler.accounts {
            if !account.has_signer { continue; }
            let name_lower = account.name.to_ascii_lowercase();
            if !AUTHORITY_PATTERNS.iter().any(|p| name_lower.contains(p)) { continue; }
            let already_bound = handler.accounts.iter().any(|a| {
                a.has_one_field.as_deref() == Some(account.name.as_ref())
            });
            if already_bound { continue; }

            let has_state_account = handler.accounts.iter()
                .any(|a| !a.has_signer && a.has_owner && !a.is_pda);
            if !has_state_account { continue; }

            gaps.push(gap(
                &handler.name,
                VulnClass::MissingSignerCheck,
                Severity::Low,
                format!(
                    "Signer `{}` is not bound to a stored field via `has_one`. If it must \
                     match a value in program state, add `#[account(has_one = {})]` to the \
                     state account. If `{}` is simply the user initiating the action, no \
                     change is needed.",
                    account.name, account.name, account.name,
                ),
                "DC-013",
            ));
        }
    }
    gaps
}