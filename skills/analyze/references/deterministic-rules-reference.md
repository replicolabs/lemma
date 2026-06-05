# Deterministic Rules Reference

These 22 rules run before any LLM reasoning. Results are definitive for
the patterns they check. When presenting these gaps, state they were found
by a deterministic checker — not estimated or inferred.

---

| Rule | What it checks | Vulnerability class | Base severity |
|---|---|---|---|
| DC-001 | UncheckedAccount with no owner or address constraint | missing_ownership_check | High |
| DC-002 | Authority-named account not required to sign | missing_signer_check | High/Critical |
| DC-003 | `init_if_needed` constraint usage | insecure_initialisation | High |
| DC-004 | PDA seeds with no user-specific identifier | insecure_initialisation | Medium |
| DC-005 | Two mutable accounts of same type without key inequality check | missing_ownership_check | Medium |
| DC-006 | Unchecked arithmetic on token-amount variables | arithmetic_error | High/Medium |
| DC-007 | Missing `overflow-checks = true` in Cargo.toml release profile | arithmetic_error | Medium |
| DC-008 | CPI to program account not verified as the expected program | arbitrary_cpi | Critical |
| DC-009 | PDA uses seeds but bump not stored | insecure_initialisation | Medium |
| DC-010 | Close handler without Anchor `close` constraint | lifecycle_violation | High |
| DC-011 | Pinocchio sysvar accessed as account parameter not via safe accessor | missing_ownership_check | High |
| DC-012 | Token-2022 program using deprecated `transfer` not `transfer_checked` | arbitrary_cpi | High |
| DC-013 | Signer authority not bound to stored field via `has_one` | missing_signer_check | High |
| DC-014 | PDA init without accounting for existing lamports | insecure_initialisation | Medium |
| DC-015 | Lifecycle-transition handler may not check current status field | lifecycle_violation | Low |
| DC-016 | One-shot instruction without init protection | insecure_initialisation | High |
| DC-017 | Handler writes state with no signer and no authority binding | permissionless_state_write | Critical |
| DC-018 | CPI target not verified against a known program ID constant | arbitrary_cpi | High |
| DC-019 | State account written only in init, never updated in other handlers | stored_field_never_written | Low |
| DC-020 | Close handler does not revoke token delegate approvals | authority_not_revoked_on_close | High |
| DC-021 | Token account and mint account not cross-validated | paired_validator_mismatch | High |
| DC-022 | PDA-named account in non-init handler has no seeds constraint | init_without_pda | High |

---

## Severity Adjustment Rules

DC-002 fires at **Critical** when the handler name contains withdraw,
transfer, burn, drain, swap, borrow, liquidate, claim, redeem, send, or pay.
Otherwise it fires at **High**.

DC-006 fires at **High** for multiplication (`*`). At **Medium** for
addition and subtraction.

DC-017 fires at **Critical** unless the handler name contains permissionless,
crank, settle, or refresh, in which case it is suppressed entirely.

---

## Rules That Take Program-Level Inputs

DC-007 reads the raw source text looking for Cargo.toml content. It fires
a single program-level gap rather than a per-handler gap.

DC-011 only fires for Pinocchio programs (detected by pinocchio or
solana_nostd in imports).

DC-012 only fires when Token-2022 imports are detected alongside the
deprecated transfer call.

---

## How to Present Deterministic Gaps

When presenting a deterministic gap, say:

"This gap was found by **[rule ID]** — a deterministic checker rule that
has zero false positives for this specific pattern. The checker verified
that [specific account] is declared as [specific type] with no [specific
constraint] in handler [handler name]."

This is more credible than saying "the analysis suggests" or "there may be".
The deterministic checker does not suggest. It confirms.