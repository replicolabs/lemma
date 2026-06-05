# Compute Unit Optimization Guide

When multiple fix options exist for a security gap, use this guide to
estimate the CU cost of each option and present them to the developer.

Solana programs have a 1.4M CU per transaction limit. Programs close to
this limit need to choose the most efficient fix option.

---

## CU Cost Estimates by Operation

### Account validation

| Operation | Approximate CU cost |
|---|---|
| `Signer<'info>` type (Anchor) | ~30 CU |
| `Account<T>` deserialization | ~100-200 CU depending on struct size |
| `UncheckedAccount` with manual owner check | ~50 CU |
| `has_one` constraint | ~80 CU |
| `constraint = expr` | ~60-100 CU depending on expression |
| `Program<'info, T>` key check | ~40 CU |
| Manual `require_keys_eq!` | ~60 CU |

### Arithmetic

| Operation | Approximate CU cost |
|---|---|
| `checked_add` / `checked_sub` | ~10 CU overhead vs unchecked |
| `checked_mul` | ~15 CU overhead |
| u64 → u128 promotion + checked_mul | ~25 CU overhead |
| `saturating_add` | ~8 CU overhead |

### CPI

| Operation | Approximate CU cost |
|---|---|
| Base CPI overhead | ~1000 CU |
| `invoke_signed` additional | ~200 CU |
| Program key verification before CPI | ~60 CU |

---

## Presenting Fix Options With CU Costs

When two fix options exist, present them like this:

```
Fix Option A — Typed Signer account (Anchor idiomatic)
  Change: pub authority: AccountInfo<'info> → pub authority: Signer<'info>
  CU cost: ~30 CU per transaction
  Note: Anchor handles the check at account loading time before the
        handler body runs. No handler body change required.

Fix Option B — Explicit require! check
  Change: add require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
          at the start of the handler body
  CU cost: ~85 CU per transaction
  Note: Less idiomatic. Only use if you need the authority as AccountInfo
        for other operations after the check.

Recommendation: Option A — lower CU cost and more idiomatic for Anchor.
```

---

## Redundancy Detection

When the deterministic checker identifies a redundant check, present the
CU savings clearly:

```
Redundant check identified in `update_config`:

  Current code:
    // Manual signer check (line 47)
    require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
    // Anchor Signer type (accounts struct, line 103)
    pub authority: Signer<'info>,

  The Anchor Signer type already verifies the signer before the handler
  body runs. The manual require! on line 47 is redundant.

  Removing the redundant check saves: ~85 CU per transaction
  Safety: The Signer type constraint catches unsigned transactions
          before the handler body executes. Removal is safe.

  Suggested removal:
  - require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
```

---

## When NOT to Optimize for CU

Do not suggest CU optimization when:
- The program is far below the 1.4M CU limit
- The redundant check provides defense-in-depth for a critical operation
- Removing the check would make the code harder to understand
- The savings are less than 100 CU and the program is not CU-constrained

Always prioritize correctness and clarity over minor CU savings.