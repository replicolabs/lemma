//! DC-006: Unchecked arithmetic on token-amount variables.
//!
//! Trigger: arithmetic operations (+, -, *) on variables whose names
//! contain token-related keywords without using checked variants.
//! Only fires when Cargo.toml does NOT have overflow-checks = true
//! in the release profile (DC-007 covers that case separately).
//!
//! Why: unchecked arithmetic on u64 token amounts silently wraps on
//! overflow in release builds, producing incorrect balances, fees,
//! or output amounts.

use crate::{checker::rules::gap, types::{InstructionHandler, SecurityGap, Severity, VulnClass}};

const TOKEN_KEYWORDS: &[&str] = &[
    "amount", "balance", "fee", "collateral", "reserve",
    "debt", "lamport", "token", "liquidity", "price",
    "supply", "vault", "deposit", "withdraw",
];

pub fn check(handlers: &[InstructionHandler]) -> Vec<SecurityGap> {
    let mut gaps = Vec::new();
    for handler in handlers {
        for op in &handler.arithmetic {
            if op.is_checked {
                continue;
            }
            if op.op == '/' {
                continue; 
            }
            if involves_token_variable(&op.lhs) || involves_token_variable(&op.rhs) {
                let severity = if op.op == '*' {
                    Severity::High // Multiplication has the largest overflow potential.
                } else {
                    Severity::Medium
                };
                gaps.push(gap(
                    &handler.name,
                    VulnClass::ArithmeticError,
                    severity,
                    format!(
                        "Unchecked `{}` operation on `{}` and `{}` in handler `{}`. \
                         In release builds without overflow-checks this silently wraps. \
                         Use `checked_{}` or `saturating_{}`, or enable \
                         `overflow-checks = true` in [profile.release].",
                        op.op, op.lhs, op.rhs, handler.name,
                        op_name(op.op), op_name(op.op),
                    ),
                    "DC-006",
                ));
            }
        }
    }
    gaps
}

fn involves_token_variable(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    TOKEN_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

fn op_name(op: char) -> &'static str {
    match op { '+' => "add", '-' => "sub", '*' => "mul", _ => "div" }
}