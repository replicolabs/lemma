use crate::{
    checker::rules::gap,
    types::{AccountDecl, InstructionHandler, SecurityGap, Severity, VulnClass},
};

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        let candidates: Vec<&AccountDecl> = handler
            .accounts
            .iter()
            .filter(|a| a.is_mutable && !is_pinned(a))
            .collect();
        if candidates.len() < 2 {
            continue;
        }

        let mut by_type: std::collections::HashMap<String, Vec<&str>> = Default::default();
        for a in &candidates {
            let ty = normalize_type(&a.type_str);
            if ty == "UncheckedAccount" || ty == "AccountInfo" || ty.is_empty() {
                continue;
            }
            by_type.entry(ty).or_default().push(a.name.as_ref());
        }
        for (ty, names) in by_type {
            if names.len() < 2 {
                continue;
            }
            gaps.push(gap(
                &handler.name,
                VulnClass::MissingOwnershipCheck,
                Severity::Low,
                format!(
                    "Handler `{}` has {} mutable `{}` accounts ({}) with no address-pinning \
                     constraint. If the same account is passed for two of them, writes \
                     overwrite each other. Add `constraint = {}.key() != {}.key()`.",
                    handler.name,
                    names.len(),
                    ty,
                    names.join(", "),
                    names[0],
                    names[1],
                ),
                "DC-005",
            ));
        }
    }
    gaps
}

fn is_pinned(a: &AccountDecl) -> bool {
    if a.is_pda || a.has_has_one {
        return true;
    }
    a.raw_constraint
        .as_deref()
        .map(|c| {
            c.contains("address =")
                || c.contains("associated_token")
                || c.contains("seeds")
                || c.contains("token::authority")
        })
        .unwrap_or(false)
}

fn normalize_type(type_str: &str) -> String {
    let s = type_str.trim();
    let Some(open) = s.find('<') else {
        return s.to_string();
    };
    let base = &s[..open];
    let inner = s[open + 1..].trim_start();
    if inner.starts_with('\'') {
        if let Some(comma) = inner.find(", ") {
            format!("{}<{}", base, inner[comma + 2..].trim_start())
        } else {
            base.to_string()
        }
    } else {
        format!("{}<{}", base, inner)
    }
}
