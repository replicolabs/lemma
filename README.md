# Lemma

**Catch what auditors catch, before you ship.**

Lemma is an automated security analysis tool for Solana programs. It runs as a compiled Rust binary — not a prompt. It executes 22 deterministic security rules, retrieves findings from a knowledge base of professional audit reports, and generates formal QEDSpec properties ready for the [QEDGen](https://github.com/QEDGen/qedgen) verification pipeline.

Works inside Claude Code, Cursor, Codex, and any agent that supports the [Agent Skills](https://agentskills.dev) spec.

---

## Why Lemma Is Different

Every other security skill tells the LLM to reason about vulnerabilities. Lemma runs a binary first.

**Deterministic checker** — 22 compiled rules that run on your parsed program source before any LLM reasoning. When Lemma reports a missing signer check, it verified deterministically that the account is declared without a `Signer` type or `is_signer` assertion — it did not infer, estimate, or guess. Zero false positives for the patterns they check.

**Evidence-grounded retrieval** — each instruction handler is embedded and searched against a structured knowledge base of findings from named professional audits (Halborn, Zellic, Neodyme, OtterSec). Every gap report cites a real documented case, not general security principles.

**Formal property generation** — Lemma generates `.qedspec` output for each handler, compatible with [QEDGen](https://github.com/QEDGen/qedgen) (already bundled in the Solana AI Kit as `ext/qedgen`). Lemma is the pre-stage that generates the properties; QEDGen is the back-stage that proves them. Together they form a complete formal verification pipeline.

---

## Install

```bash
curl -fsSL https://asklemma.xyz/install.sh | bash
```

Installs the `lemma` binary and the agent skills into your Claude Code or Cursor environment. After installation, open Claude Code in your project and say:

```
analyze my program for security vulnerabilities
```

Requires: a [Voyage AI](https://dashboard.voyageai.com) API key (free tier sufficient) and Rust (for building from source) or a prebuilt binary.

---

## Install as a Solana AI Kit Submodule

Lemma ships as a standalone tool but is also designed to slot into the [Solana AI Kit](https://github.com/solanabr/solana-ai-kit) as a security submodule:

```bash
# From your solana-ai-kit root
git submodule add https://github.com/replicolabs/lemma .claude/skills/ext/lemma
```

Then add to your kit's `SKILL.md` routing table:

```markdown
## Security Auditing

From [Lemma](ext/lemma/skill/):

- [ext/lemma/skill/SKILL.md](ext/lemma/skill/SKILL.md) — Deterministic security analysis + KB retrieval + QEDSpec generation
```

The skill entry point at `skill/SKILL.md` follows the standard Agent Skills progressive disclosure pattern and routes to the four focused skill files.

---

## What It Does

### Three Analysis Layers

**1. Deterministic checker**

22 rules compiled into the binary. They run first, before any LLM call.

| Rule | What it checks |
|------|----------------|
| DC-001 | Missing account ownership check |
| DC-002 | Authority account not required to sign (Critical on withdraw/transfer) |
| DC-003 | `init_if_needed` usage |
| DC-004 | PDA seeds with no user identifier |
| DC-005 | Duplicate mutable accounts without key inequality |
| DC-006 | Unchecked arithmetic on token amounts |
| DC-007 | Missing `overflow-checks = true` in release profile |
| DC-008 | Arbitrary CPI — program not verified |
| DC-009 | PDA bump not stored |
| DC-010 | Account close without Anchor `close` constraint |
| DC-011 | Pinocchio sysvar via account parameter instead of safe accessor |
| DC-012 | Token-2022 using deprecated `transfer` instead of `transfer_checked` |
| DC-013 | Signer not bound to stored field via `has_one` |
| DC-014 | Lamport griefing on PDA initialization |
| DC-016 | One-shot instruction without init protection |
| DC-017 | Permissionless state write (Critical) |
| DC-018 | CPI target not validated against known program ID |
| DC-019 | State field written only in init, never updated |
| DC-020 | Close handler does not revoke token delegate |
| DC-021 | Token account and mint not cross-validated |
| DC-022 | PDA account in non-init handler has no seeds constraint |

**2. Knowledge base retrieval**

The binary embeds each instruction handler using Voyage AI and performs cosine similarity search over a knowledge base of structured findings from professional Solana audit reports. Retrieved findings are included in the gap report alongside the deterministic results.

The knowledge base is maintained in [replicolabs/kb](https://github.com/replicolabs/kb).

**3. Formal invariant generation**

From the combined deterministic + retrieved results, Lemma generates a `.qedspec` file with `requires`, `ensures`, `invariant`, and `kani_assertion` clauses for each handler — ready for QEDGen.

---

## The Lemma → QEDGen Pipeline

```
Your Solana program
        ↓
lemma analyze → gap report + .qedspec file
        ↓
qedgen verify → Lean 4 proof obligations (Leanstral)
        ↓
Formally verified invariants
```

The `ext/qedgen` skill in the Solana AI Kit provides the formal verification back-end. Lemma provides the front-end: deterministic discovery, evidence grounding, and property generation. They are designed as a pipeline, not as competing tools.

See [skill/qedgen-pipeline.md](skill/qedgen-pipeline.md) for the complete workflow.

---

## CLI Reference

```bash
lemma init                          # first-time setup (configure API key)
lemma kb update                     # download latest knowledge base
lemma analyze --program ./programs/my_program
lemma analyze --program . --framework anchor --program-type amm
lemma analyze --program . --format json --output .lemma/result.json
lemma search "missing signer check on withdrawal"
lemma info
```

---

## Sample Output

Running `lemma analyze` on an Anchor AMM program produces structured output like this:

```
Lemma v0.1.0 — security analysis

  Program:   programs/amm/src/lib.rs
  Framework: Anchor (auto-detected)
  Handlers:  4 found (swap, deposit, withdraw, initialize)

  Embedding handlers... [4/4]
  Searching knowledge base... [12 findings retrieved]
  Running deterministic checker... [22 rules]

  ─────────────────────────────────────────────────────────
  CRITICAL  gap-001  withdraw — missing_signer_check
  Rule DC-002 confirmed: `authority` is declared as
  UncheckedAccount with no Signer constraint. An attacker
  can call withdraw for any vault by passing any pubkey as
  authority.

  KB match: Halborn SOL-2023-001 — "Missing signer check
  on withdrawal handler allowed unauthorized draining of
  user vaults." Confidence: 0.91

  Fix: Change authority account type to Signer<'info>

  ─────────────────────────────────────────────────────────
  HIGH      gap-002  swap — arithmetic_error
  Rule DC-006 confirmed: multiplication of token amounts
  with no checked arithmetic on line 47 of swap.rs.
  Integer overflow could produce incorrect swap output.

  KB match: Zellic 2022 — "Unchecked multiplication in
  AMM pool fee calculation." Confidence: 0.87

  Fix: Replace `*` with .checked_mul().ok_or(Error::Overflow)?

  ─────────────────────────────────────────────────────────

  Summary: 1 critical, 1 high, 0 medium, 0 low
  QEDSpec written to: .lemma/amm.qedspec
  Context written to: .lemma/analysis-context.md

  Next: fix critical gap first, then run `lemma analyze` again.
  Or say: "fix gap-001" to apply the patch.
```

The agent then reads `.lemma/analysis-result.json` and walks you through each gap with the source context, the KB evidence, and the exact code fix.

---

## Supported Frameworks

- Anchor
- Quasar
- Pinocchio
- Native Rust

---

## Agent Skill Files

```
skill/
├── SKILL.md              ← kit-compliant entry point (router)
└── qedgen-pipeline.md    ← complete Lemma → QEDGen workflow

skills/
├── SKILL_ROUTER.md       ← standalone router for direct installs
├── analyze/
│   ├── SKILL.md          ← full analysis workflow
│   └── references/       ← rules, gap framework, QEDSpec guide, invariant guide
├── fix/
│   ├── SKILL.md          ← fix workflow with diff preview
│   └── references/       ← patch patterns (Anchor, Pinocchio), CU guide
├── review/
│   ├── SKILL.md          ← full review session + report generation
│   └── references/       ← report template, review workflow
├── contribute/
│   ├── SKILL.md          ← KB contribution workflow
│   └── references/       ← extraction and curation prompts
└── data/
    ├── security-knowledge/   ← per-framework security references
    ├── guides/               ← QEDSpec guide, severity methodology, deploy runbook
    └── catalogs/             ← clonable repos, MCP catalog, skills catalog
```

---

## Skill Registry Entry

For adding Lemma to the Solana AI Kit skill registry:

```json
{
  "id": "lemma-auditor",
  "name": "Lemma — Solana Security Auditor",
  "type": "skill",
  "domain": "solana-security",
  "description": "Deterministic security analysis for Solana programs: 22 binary-checked rules + professional audit KB retrieval + QEDSpec formal property generation. The pre-stage to ext/qedgen — generates properties for formal verification rather than competing with it.",
  "source": "https://github.com/replicolabs/lemma",
  "install": {
    "method": "submodule",
    "command": "git submodule add https://github.com/replicolabs/lemma .claude/skills/ext/lemma",
    "env": ["VOYAGE_API_KEY"]
  },
  "license": "MIT",
  "maintainer": "replicolabs",
  "default_installed": false,
  "tags": ["security", "audit", "solana", "deterministic", "formal-verification", "qedspec"]
}
```

---

## Knowledge Base

The knowledge base is maintained in [replicolabs/kb](https://github.com/replicolabs/kb). It contains structured security findings extracted from professional Solana audit reports. Contributions are welcome — see the [contribution guide](https://github.com/replicolabs/kb/blob/main/CONTRIBUTING.md) and the `lemma-contribute` skill.

---

## License

MIT
