# Audit Finding Extraction Prompt

Paste this prompt into any chat interface, followed by the audit report
content you want to extract from. The model will produce a JSON file
ready for submission to solana-audit-kb.

---

You are extracting security findings from a Solana program audit report
into structured JSON for the Lemma knowledge base.

Read the provided audit report content. For each security finding that
meets the criteria below, produce one finding object. Collect all findings
into a single JSON object following the schema.

Output only valid JSON. No preamble, no explanation, no markdown fences.

INCLUDE findings that:
- Affect a specific instruction handler or are clearly program-level
- Have a concrete vulnerability with real impact
- Can be expressed as a verifiable formal property
- Are severity medium, high, or critical

SKIP findings that are:
- Informational only with no security impact
- Documentation or code style suggestions
- Test coverage recommendations
- Performance optimizations
- Already fixed before publication (if clearly noted in the report)

OUTPUT FORMAT:

```json
{
  "firm": "exact firm name from report",
  "program_name": "program name",
  "audit_year": 2024,
  "program_type": "amm|lending|bridge|staking|nft|multisig|token_program|governance|oracle|other",
  "source_type": "professional_audit",
  "source_url": "https://direct-url-to-report or null",
  "deprecated": false,
  "deprecation_reason": null,
  "deprecation_date": null,
  "findings": [
    {
      "id": "FIRM-PROGRAM-NUMBER from report",
      "title": "exact title from report",
      "description": "full description quoted accurately from report",
      "affected_instruction": "instruction_name or null",
      "affected_accounts": ["account_name_1"],
      "abstract_pattern_id": "see PATTERN LIST below",
      "abstract_pattern_description": "one sentence describing the abstract class",
      "vulnerability_class": "see CLASS LIST below",
      "severity": "critical|high|medium|low|informational",
      "recommendation": "recommendation from report",
      "derived_property": {
        "natural_language": "The {instruction} instruction must verify that {account} {property} before {action}.",
        "kani_assertion": "kani::assert!(ctx.accounts.{account}.is_signer, \"{instruction}: {account} must sign\");",
        "qedspec_forms": [
          {
            "clause_type": "guard|requires|ensures|invariant|establishes",
            "expression": "expression here"
          }
        ]
      }
    }
  ]
}
```

VALID PATTERN IDs:
priv-ix-no-authority-signer
admin-ix-no-admin-signer
user-action-no-user-signer
multisig-threshold-bypass
upgrade-authority-not-checked
ix-signer-not-matched-to-state
data-account-owner-not-checked
token-vault-owner-not-checked
pool-state-owner-not-checked
mint-account-owner-not-checked
config-account-owner-not-checked
token-account-mint-not-matched
token-amount-overflow-unchecked
amm-formula-intermediate-overflow
pool-invariant-not-maintained
ratio-calculation-precision-loss
missing-cargo-overflow-checks
zero-amount-not-checked
debt-balance-underflow
initialise-no-authority-check
reinitialisation-not-prevented
state-account-discriminator-not-set
config-field-not-validated-on-init
admin-cannot-be-transferred
authority-duplication-not-prevented
oracle-account-identity-not-checked
oracle-account-owner-not-checked
oracle-staleness-not-checked
oracle-confidence-not-checked
oracle-price-plausibility-not-checked
arbitrary-cpi-unchecked-program
lifecycle-one-shot-not-enforced
permissionless-state-writer
init-without-pda-verification
stored-field-never-written
authority-not-revoked-on-close
paired-validator-mismatch
pda-sharing-across-users
non-canonical-bump-stored
lamport-griefing-on-init
sysvar-account-not-validated
token2022-transfer-not-checked
token2022-permanent-delegate-not-validated
token2022-fee-accounting-delta-ignored
account-revival-not-prevented
duplicate-mutable-accounts-not-checked

VALID VULNERABILITY CLASSES:
missing_signer_check
missing_ownership_check
arithmetic_error
insecure_initialisation
oracle_validation
arbitrary_cpi
lifecycle_violation
permissionless_state_write
init_without_pda
stored_field_never_written
paired_validator_mismatch
authority_not_revoked_on_close
other

CLAUSE TYPE RULES:
guard — precondition on account properties (signer, owner, key equality)
requires — precondition on value properties (amount > 0, fee < 10000)
ensures — postcondition on state (new_balance == old_balance - amount)
invariant — throughout execution (collateral_ratio >= minimum)
establishes — first creation by this instruction (vault.owner == authority.key())

NATURAL LANGUAGE RULES:
Must start with "The {instruction} instruction"
Must name the specific account or value
Must state the property in verifiable terms

KANI ASSERTION RULES:
Must start with kani::assert!(
Must reference only variables that exist in a real handler context
Must be syntactically valid Rust

SELF-REVIEW before output:
1. Every kani_assertion starts with kani::assert!( and has valid syntax
2. Every natural_language names the specific instruction and property
3. Every clause_type matches the semantic timing rules
4. Every id comes from the actual report, not invented
5. Every abstract_pattern_id is from the PATTERN LIST
6. source_url links to the actual public report