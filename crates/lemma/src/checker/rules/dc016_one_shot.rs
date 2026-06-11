use crate::{
    checker::rules::gap,
    types::{InstructionHandler, SecurityGap, Severity, VulnClass},
};

const ONE_SHOT_PATTERNS: &[&str] = &["initialize", "init_", "_init", "create_"];

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        let handler_lower = handler.name.to_ascii_lowercase();
        if !ONE_SHOT_PATTERNS.iter().any(|p| handler_lower.contains(p)) {
            continue;
        }

        let has_init = handler.accounts.iter().any(|a| {
            a.raw_constraint
                .as_deref()
                .map(|c| c.contains("init"))
                .unwrap_or(false)
        });
        if has_init {
            continue;
        }

        gaps.push(gap(
            &handler.name,
            VulnClass::InsecureInitialisation,
            Severity::Medium,
            format!(
                "Handler `{}` looks like a one-shot initialiser but no account uses Anchor's \
                 `init` constraint. Without it the instruction may be callable more than \
                 once. Use `#[account(init, ...)]` or add an already-initialised check.",
                handler.name,
            ),
            "DC-016",
        ));
    }
    gaps
}
