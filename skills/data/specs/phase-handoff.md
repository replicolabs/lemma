# Phase Handoff Specification

This document defines the `.lemma/` directory and the context files written
by Lemma skills. These files persist state between agent sessions so analysis
results are available without re-running the full pipeline.

---

## The .lemma/ Directory

Created automatically by `lemma analyze` in the current project directory.
Should be added to `.gitignore` unless the team wants to track analysis
history in version control.

```
.lemma/
├── analysis-context.md      # last analysis summary — read by all skills
├── analysis-result.json     # full AnalysisResult JSON — read by lemma-fix
├── kb.lock                  # KB version pin for reproducibility
└── session-context.md       # active review session state
```

---

## analysis-context.md

Written by `lemma analyze` after every run. Read by all skills at the
start of a session to understand the current security posture without
re-running analysis.

### Format

```markdown
# Lemma Analysis Context

**Program:** my_program
**Framework:** anchor
**Program type:** amm
**Security score:** 74/100
**Lemma version:** 0.1.0
**KB version:** 2026.06.01.982ebd3
**Timestamp:** 2026-06-01T10:00:00Z

## Gap Summary

- Total active gaps: 5
- Critical: 1
- High: 3

## Gaps

- `gap-001` [critical / missing_signer_check] Missing signer on `withdraw`... (handler: `withdraw`)
- `gap-002` [high / arithmetic_error] Unchecked multiplication in `swap`... (handler: `swap`)
- `gap-003` [high / arbitrary_cpi] CPI to `token_program` not verified... (handler: `swap`)

## Retrieved Evidence

### Handler: `withdraw`

- `HAL-GFXHAL-01` [0.91] The update_fee_config instruction must verify...
- `NEO-STAKEPOOL-02` [0.84] The withdraw instruction must verify...

### Handler: `swap`

- `HAL-GFXHAL-02` [0.92] The swap output amount calculation must use u128...
```

### When to Write

The binary writes this file automatically after every `lemma analyze` run.
If the binary is not available, a skill can write it manually using the
format above.

### When to Read

Every skill reads this file at the start of Phase 1 before doing anything
else. If the file is missing or older than 24 hours, the skill should
ask the user whether to re-run analysis.

---

## analysis-result.json

The full `AnalysisResult` JSON written by `lemma analyze --format json`.
Contains complete gap data, retrieved entries, and invariants.

Read by `lemma-fix` to get exact gap details, handler names, and
source rule IDs needed for patch generation.

---

## kb.lock

Written by `lemma kb update`. Records the exact KB version used for
analysis reproducibility.

```toml
[knowledge_base]
version = "2026.06.01.982ebd3"
url = "https://github.com/replicolabs/kb/releases/download/kb-2026.06.01.982ebd3/knowledge_base.json"
sha256 = "8be9ab5454776f8c16b886d1535803720f369aec08d33ef289079b00ca8eac33"
downloaded_at = "2026-06-01T10:00:00Z"
```

Commit this file to your repository if you want reproducible analysis
(running on the same commit with the same kb.lock produces the same results).

---

## session-context.md

Written by `lemma-review` during an active review session. Records which
gaps have been reviewed, their triage decisions, and any notes.

```markdown
# Lemma Review Session

**Started:** 2026-06-01T14:00:00Z
**Reviewer:** (agent session)

## Gap Triage

| Gap ID | Decision | Notes |
|---|---|---|
| gap-001 | fix — in progress | DC-002 missing signer on withdraw |
| gap-002 | fix — completed | arithmetic overflow fixed |
| gap-003 | acknowledged | permissionless by design — public crank |
| gap-004 | defer | low severity, next sprint |

## Review Status

- [ ] All critical gaps triaged
- [ ] All high gaps triaged
- [ ] Report generated
- [ ] Developer approval received
```

---

## .gitignore Recommendation

Add to project `.gitignore`:

```gitignore
# Lemma analysis context — local only
.lemma/analysis-context.md
.lemma/analysis-result.json
.lemma/session-context.md

# Keep these for reproducibility if desired:
# .lemma/kb.lock
# .lemma-suppress.toml
```