pub mod dc001_owner;
pub mod dc002_signer;
pub mod dc003_init_if_needed;
pub mod dc004_pda_seeds;
pub mod dc005_duplicate_mutable;
pub mod dc006_arithmetic;
pub mod dc007_cargo_overflow;
pub mod dc008_arbitrary_cpi;
pub mod dc009_canonical_bump;
pub mod dc010_account_close;
pub mod dc011_sysvar;
pub mod dc012_token2022_transfer;
pub mod dc013_has_one;
pub mod dc014_lamport_griefing;
pub mod dc016_one_shot;
pub mod dc017_permissionless_write;
pub mod dc019_stored_field;
pub mod dc020_authority_revoke;
pub mod dc021_paired_validator;
pub mod dc022_pda_verify;

use crate::types::{GapSource, SecurityGap, Severity, VulnClass};

pub(super) fn gap(
    handler_name:   &str,
    vuln_class:     VulnClass,
    severity:       Severity,
    description:    impl Into<String>,
    source_rule_id: &str,
) -> SecurityGap {
    SecurityGap {
        id:             Box::from(""),        
        handler_name:   Box::from(handler_name),
        vuln_class,
        severity,
        description:    description.into().into_boxed_str(),
        source_rule_id: Box::from(source_rule_id),
        source:         GapSource::Deterministic,
        acknowledged:   false,
        ack_reason:     None,
    }
}