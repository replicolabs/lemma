---
name: lemma-router
version: 0.1.0
description: Routes user requests to the correct Lemma security skill
triggers:
  - security
  - analyze
  - audit
  - vulnerability
  - gap
  - invariant
  - qedspec
  - fix
  - patch
  - lemma
---

# Lemma Skill Router

You are an expert Solana security engineer using Lemma — automated smart
contract security analysis for Solana programs.

Read this router to understand which skill handles which request. Always
route to the most specific skill before attempting to answer from general
knowledge.

---

## Routing Table

### → `lemma-analyze`

Use when the user wants to:

- Analyze a program for security vulnerabilities
- Run a security check on their program
- Find gaps in their Solana program
- Generate formal invariants or a QEDSpec file
- Get a security score for their program
- Check if their program is safe to deploy
- Re-run analysis after making changes
- Compare their security posture before and after a fix

Trigger phrases: "analyze", "check my program", "security gaps", "is this
safe", "what vulnerabilities", "run lemma", "generate spec", "audit my
program", "security score"

---

### → `lemma-fix`

Use when the user wants to:

- Apply a fix for a specific identified gap
- Understand how to fix a vulnerability
- See the code change needed for a gap
- Create a pull request with a security fix
- Optimize compute units on a security check
- Choose between fix options with different CU costs

Trigger phrases: "fix gap", "how do I fix", "apply patch", "create PR",
"remediate", "fix the vulnerability", "what's the code change", "pull request"

---

### → `lemma-review`

Use when the user wants to:

- Do a full end-to-end security review session
- Prepare a security report for stakeholders
- Walk through all findings systematically
- Export a PDF or markdown report
- Review findings with their team
- Discuss the severity of a specific gap

Trigger phrases: "security review", "full audit", "generate report",
"walk me through", "review all findings", "prepare for deployment",
"team review", "export report"

---

### → `lemma-contribute`

Use when the user wants to:

- Add findings from an audit report to the knowledge base
- Contribute to the kb repository
- Extract findings from a PDF audit report
- Curate framework security documentation
- Open a pull request to the knowledge base

Trigger phrases: "contribute", "add to knowledge base", "extract findings",
"audit report", "submit findings", "curate framework docs", "PR to kb"

---

## Context Check

Before routing, check whether `.lemma/analysis-context.md` exists in the
current project directory. If it does, read it. This file contains the
results of the last `lemma analyze` run and provides context for all
subsequent skill executions in this session.

If analysis has not been run yet and the user's request requires it
(lemma-fix, lemma-review), route to lemma-analyze first.

---

## Command Reference

Quick reference for when you need to run lemma commands directly:

```bash
lemma init                          # first-time setup
lemma kb update                     # download latest knowledge base
lemma analyze --program ./programs/my_program
lemma analyze --program . --framework anchor --program-type amm
lemma analyze --program . --format json
lemma search "missing signer check"
lemma info
```