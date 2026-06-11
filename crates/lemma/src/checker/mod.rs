pub mod rules;

use crate::types::{GapSource, InstructionHandler, SecurityGap};

use rules::{
    dc001_owner, dc002_signer, dc003_init_if_needed, dc004_pda_seeds, dc005_duplicate_mutable,
    dc006_arithmetic, dc007_cargo_overflow, dc008_arbitrary_cpi, dc009_canonical_bump,
    dc010_account_close, dc011_sysvar, dc012_token2022_transfer, dc013_has_one,
    dc014_lamport_griefing, dc016_one_shot, dc017_permissionless_write, dc019_stored_field,
    dc020_authority_revoke, dc021_paired_validator, dc022_pda_verify,
};

pub fn run_all(
    handlers: &[InstructionHandler],
    source: &str,
    gap_id_offset: usize,
) -> Vec<SecurityGap> {
    let mut gaps: Vec<SecurityGap> = Vec::new();

    macro_rules! run_rule {
        ($rule:expr) => {
            gaps.extend($rule);
        };
    }
    run_rule!(dc001_owner::check(handlers));
    run_rule!(dc002_signer::check(handlers));
    run_rule!(dc003_init_if_needed::check(handlers));
    run_rule!(dc004_pda_seeds::check(handlers));
    run_rule!(dc005_duplicate_mutable::check(handlers));
    run_rule!(dc006_arithmetic::check(handlers, source));
    run_rule!(dc007_cargo_overflow::check(source));
    run_rule!(dc008_arbitrary_cpi::check(handlers));
    run_rule!(dc009_canonical_bump::check(handlers));
    run_rule!(dc010_account_close::check(handlers));
    run_rule!(dc011_sysvar::check(handlers, source));
    run_rule!(dc012_token2022_transfer::check(handlers, source));
    run_rule!(dc013_has_one::check(handlers));
    run_rule!(dc014_lamport_griefing::check(handlers));
    run_rule!(dc016_one_shot::check(handlers));
    run_rule!(dc017_permissionless_write::check(handlers));
    run_rule!(dc019_stored_field::check(handlers));
    run_rule!(dc020_authority_revoke::check(handlers));
    run_rule!(dc021_paired_validator::check(handlers));
    run_rule!(dc022_pda_verify::check(handlers));

    for (i, gap) in gaps.iter_mut().enumerate() {
        gap.id = format!("gap-{:03}", gap_id_offset + i + 1).into_boxed_str();
        gap.source = GapSource::Deterministic;
    }

    gaps
}
