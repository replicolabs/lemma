# Lemma

**Catch what auditors catch, before you ship.**

Lemma is an automated security analysis tool for Solana programs. It reads your program source, runs 22 deterministic security checks, retrieves relevant findings from a knowledge base of professional audit reports, and produces a gap report grounded in documented evidence of existing vulnerabilities.

Works inside Claude Code, Cursor, and any agent that supports the [Agent Skills](https://agentskills.dev) spec. No web UI. No account required. Runs in your existing development environment.

---

## Install

```bash
curl -fsSL https://asklemma.xyz/install.sh | bash
```

This installs the `lemma` binary and the Lemma agent skills into your Claude Code or Cursor environment. After installation, open Claude Code in your project and say:

```
analyze my program for security vulnerabilities
```

---

## What It Does

Lemma combines three analysis layers:

**Deterministic checker** — 22 rules that run on your parsed program source before any AI reasoning. Catches missing signer checks, unchecked arithmetic, arbitrary CPI targets, init_if_needed usage, and more. Zero false positives for what they check.

**Knowledge base retrieval** — embeds each instruction handler and searches a knowledge base of structured findings from professional Solana audits (Halborn, Zellic, Neodyme, OtterSec). Retrieved findings ground every gap description in documented real-world evidence.

**Formal invariant generation** — generates `.qedspec` output for each handler, ready for the [QEDGen](https://github.com/QEDGen/qedgen) formal verification pipeline.

---

## Requirements

- Claude Code or any Agent Skills compatible agent
- A [Voyage AI](https://dashboard.voyageai.com) API key (free tier sufficient)
- Rust installed (for building from source) or download a prebuilt binary

---

## Direct CLI Usage

```bash
lemma init                          # first-time setup
lemma kb update                     # download latest knowledge base
lemma analyze --program ./programs/my_program
lemma analyze --program . --framework anchor --program-type amm
lemma analyze --program . --format json --output .lemma/result.json
lemma search "missing signer check on withdrawal"
lemma info
```

---

## Supported Frameworks

- Anchor
- Quasar
- Pinocchio
- Native Rust

---

## Knowledge Base

The knowledge base is maintained in [replicolabs/kb](https://github.com/replicolabs/kb), a separate open source repository. It contains structured security findings extracted from professional Solana audit reports.

Contributions are welcome. See the [contribution guide](https://github.com/replicolabs/kb/blob/main/CONTRIBUTING.md).

---

## License

MIT