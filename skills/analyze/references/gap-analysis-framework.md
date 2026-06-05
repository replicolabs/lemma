# Gap Analysis Framework

This document explains how to interpret Lemma gap output and how to
present each gap to the developer.

---

## Gap Structure

Every gap has these fields:

- `id` — stable identifier within this run (`gap-001`, `gap-002`…)
- `handler_name` — the instruction handler affected
- `vuln_class` — the vulnerability class (see table below)
- `severity` — critical, high, medium, low, informational
- `description` — what is missing and why it matters
- `source_rule_id` — the deterministic rule (e.g. `DC-002`) or KB finding ID
- `source` — `deterministic` or `llm`

---

## Severity Interpretation

### Critical

Immediate, irreversible financial loss or permanent protocol takeover with
no preconditions. Fix before any further development. These gaps mean the
program **cannot be safely deployed**.

Common examples:
- Missing signer check on a withdrawal or transfer instruction
- Arbitrary CPI where an attacker substitutes a malicious program
- Permissionless write to a balance or vault account

### High

Significant financial loss or privilege escalation possible but requires
specific conditions. Fix before mainnet deployment.

Common examples:
- Missing signer check on an admin configuration instruction
- Arithmetic overflow in token amount calculations
- Oracle validation missing on a price-dependent instruction
- Missing ownership check on a vault account

### Medium

Meaningful risk but exploitation requires significant effort or has
bounded impact. Should be fixed before mainnet but not immediately blocking.

Common examples:
- PDA sharing across users
- Missing lifecycle check
- Lamport griefing on PDA init
- Duplicate mutable accounts without key check

### Low

Security weakness that is difficult to exploit in practice. Fix in the
next development cycle.

### Informational

Best practice violation. No immediate security impact. Fix when convenient.

---

## Gap Source: Deterministic vs LLM

**Deterministic gaps** (source: `deterministic`) were found by one of the
22 built-in checker rules. These are 100% reliable for the specific pattern
the rule checks. Zero false positives for what they claim to check.

**LLM gaps** (source: `llm`) were identified by the agent reasoning over
retrieved knowledge base evidence. These require human judgment to confirm.
They may be false positives depending on program context. Always explain
the uncertainty when presenting LLM gaps.

---

## Presenting Each Gap

When you present a gap to the developer, follow this structure:

1. **Lead with the severity badge and a one-line summary.**
   "🔴 CRITICAL — gap-001: Missing signer check on `withdraw`"

2. **Explain the specific risk in one to two sentences.**
   Do not use generic language. Name the specific handler, the specific
   account, and the specific outcome for the attacker.
   "Any account can call `withdraw` without the depositor's signature,
   allowing an attacker to drain the depositor's vault by passing the
   depositor's pubkey without their signature."

3. **Name the evidence.**
   For deterministic gaps: "Caught by DC-002 (missing signer on
   authority-named account)."
   For KB gaps: "This pattern matches HAL-GFXHAL-01, a finding from
   the Halborn GooseFX audit where the same vulnerability allowed
   unauthorized fee configuration changes."

4. **Show the fix.**
   Show the specific code change for the specific framework the program
   uses. See the framework-specific patch patterns in the fix skill's
   references.

---

## Vulnerability Class Reference

| Class | What it means |
|---|---|
| `missing_signer_check` | Authority account not required to sign |
| `missing_ownership_check` | Account not verified as owned by expected program |
| `arithmetic_error` | Overflow, underflow, or precision loss in calculations |
| `insecure_initialisation` | Init allows reinitialisation or accepts unsafe parameters |
| `oracle_validation` | Oracle price feed not validated for staleness, identity, or confidence |
| `arbitrary_cpi` | CPI target not verified before call |
| `lifecycle_violation` | State transition executed without lifecycle status check |
| `permissionless_state_write` | State modified without any access control |
| `init_without_pda` | PDA accepted without seeds+bump verification |
| `stored_field_never_written` | Validation field never updated, always at init value |
| `paired_validator_mismatch` | Token account and mint not cross-validated |
| `authority_not_revoked_on_close` | Delegate approvals not revoked when account closed |

---

## Framework-Specific Fix Patterns

### Anchor

Missing signer:
```rust
// Before
pub authority: AccountInfo<'info>,

// After — Option 1: typed account (preferred)
pub authority: Signer<'info>,

// After — Option 2: explicit constraint
#[account(signer)]
pub authority: UncheckedAccount<'info>,
```

Missing ownership:
```rust
// Before
pub pool: AccountInfo<'info>,

// After
pub pool: Account<'info, Pool>,
```

Missing has_one:
```rust
// Before
#[account(mut)]
pub pool: Account<'info, Pool>,
pub authority: Signer<'info>,

// After
#[account(mut, has_one = authority)]
pub pool: Account<'info, Pool>,
pub authority: Signer<'info>,
```

Arbitrary CPI:
```rust
// Before
pub token_program: AccountInfo<'info>,

// After
pub token_program: Program<'info, Token>,
```

### Pinocchio

Missing signer:
```rust
// Before — no check
let authority = accounts[0];

// After
let authority = accounts[0];
if !authority.is_signer() {
    return Err(ProgramError::MissingRequiredSignature);
}
```

Missing ownership:
```rust
// After
if !authority.is_owned_by(&crate::ID) {
    return Err(ProgramError::InvalidAccountOwner);
}
```