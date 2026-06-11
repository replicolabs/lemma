//! DC-007: Missing overflow-checks = true in release profile.
//!
//! Trigger: the raw source text (which includes Cargo.toml content when
//! loaded from a directory) does not contain `overflow-checks = true`
//! under `[profile.release]`.
//!
//! Why: Rust release builds disable integer overflow checks by default
//! for performance. Every arithmetic operation in the program is silently
//! wrapping. A single missing check can drain a vault.
//!
//! This is a program-level gap rather than a per-handler gap.

use crate::{
    checker::rules::gap,
    types::{SecurityGap, Severity, VulnClass},
};

pub fn check(source: &str) -> Vec<SecurityGap> {
    let has_overflow_checks =
        source.contains("overflow-checks = true") || source.contains("overflow_checks = true");

    if has_overflow_checks {
        return Vec::new();
    }
    let has_profile_release = source.contains("[profile.release]");
    let has_cargo_toml = source.contains("[package]") || source.contains("[workspace]");

    if !has_profile_release && !has_cargo_toml {
        return Vec::new();
    }

    vec![gap(
        "program",
        VulnClass::ArithmeticError,
        Severity::Medium,
        "The release profile does not set `overflow-checks = true`. All integer \
         arithmetic in release builds wraps silently on overflow instead of \
         panicking. Add `overflow-checks = true` under `[profile.release]` in \
         Cargo.toml. This is especially important for a security tool or a \
         program handling token amounts.",
        "DC-007",
    )]
}
