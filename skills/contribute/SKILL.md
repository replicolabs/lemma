---
name: contribute
description: Contribute security findings to the Lemma knowledge base. Use when asked to add findings from an audit report, extract findings from a PDF audit report, contribute to the replicolabs/kb repository, or curate framework security documentation.
license: MIT
compatibility: Designed for Claude Code. Requires git and access to the internet to open pull requests.
metadata:
  author: replicolabs
  version: "0.1.0"
allowed-tools: Bash Read Write
---

# Lemma Contribute Skill

You are a Solana security researcher helping to expand the Lemma knowledge
base. Your role is to extract structured security findings from audit
reports and contribute them to the kb repository.

---

## Non-Negotiables

- Every finding must come from a publicly available, named audit report.
- The source_url must link to the actual document.
- Never invent finding IDs — use the IDs from the original report.
- Every kani_assertion must be syntactically valid Rust.
- Run `make validate-file` before opening a PR.

---

## Workflow

### Audit Report Extraction

**Step 1.** Receive the audit report content.

The user pastes text from an audit report or provides a URL. If a URL
is provided, read the document.

**Step 2.** Read the extraction prompt.

```
Read: references/extraction-prompt.md
```

**Step 3.** Extract findings.

Follow the extraction prompt exactly. Produce a JSON object for each
finding following the kb schema.

**Step 4.** Validate locally.

```bash
cd ~/kb
make validate-file FILE=raw/professional_audits/{firm}/{filename}.json
```

Fix any errors before proceeding.

**Step 5.** Open a pull request.

Guide the user through opening a PR to the kb repository
with the new JSON file.

---

### Framework Documentation Curation

**Step 1.** Receive the framework source material.

The user provides an llms.txt file or framework documentation.

**Step 2.** Read the curation prompt.

```
Read: references/curation-prompt.md
```

**Step 3.** Produce the curated security reference.

Follow the curation prompt to produce:
1. A human-readable security reference document
2. An embedding-optimized version with Framework: chunk headers

**Step 4.** Save both versions.

- Human-readable → `lemma/skills/data/security-knowledge/{framework}-security-reference.md`
- Embedding-optimized → `kb/raw/framework_docs/{framework}/security-reference.md`