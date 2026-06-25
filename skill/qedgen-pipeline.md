# Lemma → QEDGen Pipeline

Lemma and QEDGen are the two stages of formal security verification for Solana programs. This document covers how to use both together as a complete pipeline.

**QEDGen** (`ext/qedgen/` in the Solana AI Kit) proves formal properties about Solana programs using Lean 4 theorem proving. It needs properties to prove. **Lemma** generates those properties — grounded in real audit evidence, not general reasoning.

---

## Pipeline Overview

```
Step 1: Run Lemma analysis
   lemma analyze --format json → .lemma/analysis-result.json
   
Step 2: Generate QEDSpec
   lemma analyze --format json → .qedspec (auto-generated)
   
Step 3: Verify with QEDGen
   qedgen verify --spec .qedspec → Lean 4 proof obligations
   
Step 4: Review proof results
   qedgen report → formally verified / counterexample found
```

---

## Step 1 — Run Lemma Analysis

```bash
# Ensure knowledge base is current
lemma kb update

# Run analysis with JSON output
lemma analyze \
  --program ./programs/my_program \
  --framework anchor \
  --program-type amm \
  --format json \
  --output .lemma/analysis-result.json
```

The JSON output contains:
- `gaps[]` — identified security gaps with severity, handler, vulnerability class
- `invariants[]` — generated formal properties per handler
- `qedspec_path` — path to the generated `.qedspec` file

---

## Step 2 — Understand the QEDSpec Output

Lemma generates a `.qedspec` file for each analyzed program. The file contains one handler block per instruction:

```fsharp
handler deposit {
  requires amount > 0
  requires amount <= vault.capacity.checked_sub(vault.balance)?
  ensures vault.balance == old(vault.balance).checked_add(amount)?
  ensures vault.authority == old(vault.authority)
  invariant signer(authority)
  invariant owner(vault, this_program)
  kani_assertion vault.balance <= vault.capacity
  kani_assertion authority.key == vault.authority
}

handler withdraw {
  requires amount > 0
  requires amount <= vault.balance
  ensures vault.balance == old(vault.balance).checked_sub(amount)?
  invariant signer(authority)
  invariant authority.key == vault.authority
  kani_assertion vault.balance >= 0
}
```

### Clause Types

| Clause | Timing | Use for |
|--------|--------|---------|
| `requires` | Pre-execution | Input value conditions (amount > 0, slippage < 100%) |
| `ensures` | Post-execution | State change guarantees (balance updated correctly) |
| `invariant` | Pre and post | Signer/owner checks that must always hold |
| `kani_assertion` | Compile-time | Bounded model checking — can be validated with `cargo check` |

See [../skills/analyze/references/qedspec-clause-guide.md](../skills/analyze/references/qedspec-clause-guide.md) for the full clause reference.

---

## Step 3 — Validate Kani Assertions Locally

Before sending to QEDGen, validate that the `kani_assertion` clauses compile:

```bash
# Lemma's analyze skill does this automatically in Phase N
# To do it manually for a specific assertion:
cat > /tmp/_lemma_inv_check.rs << 'EOF'
#[cfg(test)]
mod _lemma_inv_check {
    use super::*;
    #[test]
    fn _check() {
        kani::assert(vault.balance <= vault.capacity, "lemma_check");
    }
}
EOF

# Copy into program src/, run cargo check --tests, delete
cargo check --tests 2>&1
rm /tmp/_lemma_inv_check.rs
```

Report all invariants as "agent-generated, compile-validated" — never as "proven". Proof is QEDGen's job.

---

## Step 4 — Run QEDGen Formal Verification

With the `.qedspec` file ready:

```bash
# Check QEDGen is available (from ext/qedgen/ in the kit)
qedgen info

# Verify the spec
qedgen verify --spec .lemma/my_program.qedspec

# Generate a report
qedgen report --spec .lemma/my_program.qedspec --output .lemma/qedgen-report.md
```

QEDGen requires `MISTRAL_API_KEY` for Leanstral. See `ext/qedgen/SKILL.md` for setup.

---

## Step 5 — Interpret QEDGen Results

QEDGen produces one of three outcomes per handler property:

| Outcome | Meaning | Action |
|---------|---------|--------|
| `verified` | Property holds for all inputs in the bounded model | Property is formally verified |
| `counterexample` | Found an input that violates the property | Real bug — fix the handler |
| `timeout` | Could not resolve in time budget | Increase fuel or simplify the property |

When QEDGen finds a counterexample, return to Lemma's fix skill:

```bash
# Fix the handler that produced a counterexample
# Read: ../skills/fix/SKILL.md
```

---

## What This Pipeline Proves

After completing the pipeline, you have formal evidence that:

1. **Signer invariants hold** — the `invariant signer(authority)` clauses are proven, not just asserted.
2. **Balance conservation holds** — `ensures` clauses on transfer/deposit/withdraw handlers are verified.
3. **Authority binding holds** — `authority.key == vault.authority` is a proven invariant, not a runtime check.
4. **Arithmetic safety holds** — checked arithmetic in `requires` and `ensures` are bounded-verified.

This is materially stronger than deterministic rules (which confirm the *presence* of checks) or LLM analysis (which reasons about what *should* be there). QEDGen proves that the checks, if present, actually enforce the stated invariants.

---

## Complete Example: AMM Swap Handler

```bash
# 1. Analyze the program
lemma analyze \
  --program ./programs/amm \
  --framework anchor \
  --program-type amm \
  --format json \
  --output .lemma/amm-result.json

# 2. Review gaps and generated spec
cat .lemma/amm-result.json | jq '.gaps[] | {id, severity, handler_name, vuln_class}'
cat .lemma/amm.qedspec

# 3. Verify with QEDGen
qedgen verify --spec .lemma/amm.qedspec

# 4. Fix any counterexamples, then re-verify
lemma analyze --program ./programs/amm --format json --output .lemma/amm-result.json
qedgen verify --spec .lemma/amm.qedspec
```

The pipeline completes when QEDGen reports `verified` for all critical handler invariants.

---

## Connecting to the Kit's QEDGen Skill

The QEDGen skill (`ext/qedgen/SKILL.md`) provides formal verification capabilities. Lemma generates the `.qedspec` input it needs. The two skills are designed to work together:

- Use **Lemma** first: find gaps, fix them, generate the spec.
- Use **QEDGen** after: verify the spec formally.

You do not need to write `.qedspec` by hand. Lemma's analyze skill generates it automatically in Phase 4 of the analysis workflow.
