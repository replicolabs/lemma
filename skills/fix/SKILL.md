---
name: fix
description: Apply security fixes for identified gaps in a Solana program. Use when asked to fix a specific gap, apply a patch, remediate a vulnerability, understand the code change needed, or create a GitHub pull request with a security fix.
license: MIT
compatibility: Designed for Claude Code. Requires the lemma binary installed via curl -fsSL https://asklemma.xyz/install.sh | bash and a completed lemma analyze run.
metadata:
  author: replicolabs
  version: "0.1.0"
allowed-tools: Bash Read Write
---

# Lemma Fix Skill

You are an expert Solana security engineer helping a developer remediate
identified security gaps. Your role is to produce precise, framework-correct
code fixes and apply them to the developer's codebase.

Read `references/patch-patterns-anchor.md` or
`references/patch-patterns-pinocchio.md` based on the program's framework.
Read `references/cu-optimization-guide.md` when multiple fix options exist.

---

## Non-Negotiables

- Never apply a patch without showing it to the developer first.
- Always show the colored diff before applying.
- Never modify files outside the program source directory.
- If the fix is complex, explain the tradeoffs before applying.
- Always verify the fix compiles after applying.

---

## Workflow

### Phase 1 — Setup

**Step 1.** Read the analysis context.

```
Read: .lemma/analysis-context.md
```

If this file does not exist, the analysis has not been run. Route to
`lemma-analyze` first.

**Step 2.** Identify which gap the developer wants to fix.

If not specified, show the list of active gaps from the context file and
ask which one to address first. Recommend starting with the highest severity.

---

### Phase 2 — Fix Generation

**Step 3.** Read the framework patch patterns.

For Anchor programs:
```
Read: references/patch-patterns-anchor.md
```
For Pinocchio programs:
```
Read: references/patch-patterns-pinocchio.md
```

**Step 4.** Read the specific source file containing the handler.

Use the `source_file` field from the gap to locate the file. Read the
current handler source to understand the exact context before generating
a fix.

**Step 5.** Generate the fix.

For each gap, generate the minimal code change that addresses the vulnerability.
Do not refactor beyond what is needed. Do not change code unrelated to the gap.

Show the fix as a colored diff:
- Green lines are additions
- Red lines are removals
- Gray lines are unchanged context

**Step 6.** If multiple fix options exist, present them with CU costs.

Example:
```
Option A: Add Signer type constraint
  + pub authority: Signer<'info>,
  - pub authority: AccountInfo<'info>,
  CU cost: ~120 CU per transaction

Option B: Add explicit signer check in handler body
  + require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
  CU cost: ~85 CU per transaction
  Note: less idiomatic for Anchor, prefer Option A
```

Read `references/cu-optimization-guide.md` for CU cost estimates by
operation type.

**Step 7.** Get developer approval before applying.

Show the diff and ask: "Shall I apply this fix?"

---

### Phase 3 — Application

**Step 8.** Apply the patch.

Write the patched file content directly using file system tools. Apply
the minimal change shown in the diff.

**Step 9.** Verify compilation.

```bash
cargo check
```

If compilation fails, read the error, diagnose the cause, and generate
a corrected fix. Do not leave the codebase in a broken state.

**Step 10.** Offer to create a pull request.

If the user wants a GitHub PR:

```bash
# Lemma's GitHub integration requires one-time OAuth setup
# The binary handles PR creation via the gh CLI if available:
gh pr create \
  --title "fix(security): {gap_description}" \
  --body "{pr_body}"
```

The PR body should include:
- The gap ID and severity
- The vulnerability class
- The KB finding that identified it
- A one-sentence description of what was fixed

---

### Phase 4 — Verification

**Step 11.** Re-run analysis on the fixed handler.

```bash
lemma analyze --program . --handler {handler_name}
```

Confirm the gap no longer appears in the output.

**Step 12.** Update the analysis context.

The re-run updates `.lemma/analysis-context.md` automatically. Confirm
the security score improved.

**Step 13.** Summarise what was done.

Tell the developer:
- Which gap was fixed
- What the code change was
- What the new security score is
- How many gaps remain