# Invariant Generation Guide

This document explains how to generate correct formal invariants from
the Lemma analysis output. Read this before generating any invariants.

---

## What an Invariant Is

An invariant is a formal property that must hold for a program to be
considered correct and secure. Lemma generates invariants grounded in
documented vulnerability evidence — not guesses.

Every invariant has three representations:

1. **Natural language** — a precise English statement of the property
2. **Kani assertion** — a Rust expression for bounded model checking
3. **QEDSpec clause** — a formal clause for the QEDGen verification pipeline

---

## The Generation Process

### Step 1: Read the retrieved evidence

Check `.lemma/analysis-context.md` for the retrieved KB entries for each
handler. Each retrieved entry has a `natural_language` field that describes
the formal property that should hold. This is your primary evidence source.

Do not generate invariants from general security knowledge alone. Always
ground them in the retrieved evidence.

### Step 2: Map evidence to handlers

For each instruction handler, collect all retrieved entries relevant to it.
Group entries by vulnerability class.

### Step 3: Generate the natural language statement

For each retrieved entry, produce a natural language invariant that:
- Starts with "The {handler_name} instruction"
- Names the specific account or value involved
- States the property in verifiable terms
- Ends by stating what must happen or what must not happen

Good: "The `withdraw` instruction must verify that the `depositor` account
has signed the transaction before transferring any lamports from the vault."

Bad: "The program should check signers."

### Step 4: Generate the Kani assertion

Map the natural language property to a `kani::assert!` expression.

Rules:
- Every variable you reference must exist in the handler's account context
- The expression must be syntactically valid Rust inside a function body
- Use `ctx.accounts.{name}.is_signer` for signer checks
- Use `ctx.accounts.{name}.key() == expected` for key checks
- Use `amount.checked_add(fee).is_some()` for arithmetic checks
- Use `ctx.accounts.{name}.owner == &program_id` for ownership checks

### Step 5: Generate the QEDSpec clause

Read `references/qedspec-clause-guide.md` to determine the correct
`clause_type` for each property.

---

## Invariant Quality Checklist

Before finalising an invariant, verify:

- [ ] The natural language names the specific instruction
- [ ] The natural language names the specific account or value
- [ ] The Kani assertion compiles — every variable is defined in context
- [ ] The clause_type matches the semantic timing (pre vs post execution)
- [ ] The invariant is grounded in a specific retrieved KB finding
- [ ] The confidence score reflects the quality of the evidence match

---

## Confidence Scoring

Assign confidence on a 0.0 to 1.0 scale:

- **0.9 - 1.0**: Retrieved entry is from a program of the same type with
  the same vulnerability class. The property is directly applicable.

- **0.7 - 0.9**: Retrieved entry is from a similar program type. The
  property is applicable with minor adaptation.

- **0.5 - 0.7**: Retrieved entry is from a different program type but the
  same vulnerability class. The property applies in principle.

- **Below 0.5**: The invariant is generated from general security knowledge
  without strong KB evidence. Mark clearly in the output.

---

## Example: Complete Invariant Set for a Swap Handler

**Context:** AMM swap handler with retrieved entry HAL-GFXHAL-02
(arithmetic overflow in AMM formula).

**Natural language:**
"The `swap` instruction must use u128 intermediate values when calculating
the output amount to prevent overflow, and the final output amount must not
exceed the available liquidity in the destination vault."

**Kani assertion:**
```rust
let numerator = (amount_in as u128)
    .checked_mul(reserve_out as u128)
    .ok_or(ErrorCode::ArithmeticOverflow)?;
let denominator = (reserve_in as u128)
    .checked_add(amount_in as u128)
    .ok_or(ErrorCode::ArithmeticOverflow)?;
let amount_out = numerator / denominator;
kani::assert!(
    amount_out <= reserve_out as u128,
    "swap: output cannot exceed available reserve"
);
```

**QEDSpec clauses:**
```
requires amount_in > 0
ensures swap_output <= vault_balance(token_vault_out)
invariant reserve_a * reserve_b >= initial_k
```

**Confidence:** 0.92 (same program type, direct evidence from HAL-GFXHAL-02)