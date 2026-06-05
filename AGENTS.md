# Lemma Agent Instructions

This file tells AI agents (Claude Code, Cursor, Codex, and others) how
to work with Lemma in this repository.

---

## What Lemma Is

Lemma is a security analysis tool for Solana programs. It runs as a CLI
binary that agents call to perform deterministic security analysis and
knowledge base retrieval. The agent handles all LLM reasoning over the
binary's structured output.

---

## Available Skills

Lemma installs the following skills into your agent environment:

| Skill | Trigger phrases | What it does |
|---|---|---|
| `analyze` | "analyze my program", "security gaps", "check vulnerabilities" | Runs full security analysis pipeline |
| `fix` | "fix gap", "apply patch", "how do I fix" | Applies security fixes to source files |
| `review` | "security review", "full audit", "generate report" | Systematic review session with report |
| `contribute` | "contribute", "extract findings", "add to knowledge base" | Contributes to the KB repository |

Start with the `SKILL_ROUTER.md` to route user requests to the correct skill.

---

## Binary Commands

The `lemma` binary must be called for deterministic analysis. Do not
attempt to perform security analysis without calling the binary — LLM
reasoning alone is not sufficient and will miss deterministic patterns.

```bash
# Check setup
lemma info

# Update knowledge base
lemma kb update

# Run analysis — always use --format json for downstream processing
lemma analyze \
  --program <path> \
  --framework anchor \
  --program-type amm \
  --format json \
  --output .lemma/analysis-result.json

# Search knowledge base
lemma search "query"
```

---

## Session State

Always check `.lemma/analysis-context.md` before starting any skill.
This file contains the last analysis results and avoids redundant re-runs.

Always write session state to `.lemma/` when completing a skill phase.
See `skills/specs/phase-handoff.md` for the full specification.

---

## Non-Negotiables for Agents

1. Never present security findings without first running `lemma analyze`.
2. Never generate QEDSpec output without reading `skills/analyze/references/qedspec-clause-guide.md`and `skills/data/guides/qedspec-guide.md`.
3. Never apply a code patch without showing the diff and getting user approval.
4. Never claim a program is secure. Only report what was found and what
   Lemma's coverage includes.
5. Always ground findings in the binary output or retrieved KB evidence.
   Never hallucinate vulnerabilities.