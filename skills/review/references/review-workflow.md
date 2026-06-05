# Security Review Workflow Reference

This document provides detailed guidance for conducting a systematic
security review session with a developer.

---

## Review Session Goals

1. Ensure the developer understands every critical and high gap.
2. Ensure every gap is either fixed, acknowledged, or triaged.
3. Produce a written record of the security posture and decisions made.
4. Give the developer a clear deployment readiness assessment.

---

## Handling Developer Pushback

Developers sometimes resist security findings. Handle common objections:

**"This code path is never called with untrusted input."**
Respond: "On-chain programs are public interfaces. Any account or value
can be passed by any transaction. The assumption that certain inputs
are trusted must be enforced by code, not by convention."

**"This is just a test program."**
Respond: "If the program will ever be deployed with real funds or real
accounts, it needs real security. The patterns established in test
programs often persist to production."

**"Our auditor already checked this."**
Respond: "A previous audit is valuable. This analysis may catch things
that were added since the audit, or patterns the auditor's tooling
missed. Would you like to acknowledge this gap with the reason
'reviewed by auditor' so it is recorded but not counted in the score?"

---

## Triage Framework

For each gap, one of four outcomes:

1. **Fix now** — critical or high, straightforward fix, developer has time
2. **Fix before deployment** — high or medium, requires more thought
3. **Acknowledge** — intentional design, developer understands the risk
4. **Defer** — low or informational, tracked for future sprint

Record the outcome for every gap. Do not leave gaps without a decision.

---

## Evidence Quality Tiers

When presenting a gap's evidence, state the quality tier:

**Tier 1 — Deterministic:** "This was found by the Lemma checker rule
DC-002. The checker verified that [account] has no signer constraint.
Zero false positives for this specific pattern."

**Tier 2 — Professional audit evidence:** "This pattern matches HAL-GFXHAL-01,
a finding from the Halborn audit of GooseFX Swap in 2023. Halborn found
the same vulnerability class in a structurally similar instruction."

**Tier 3 — Framework documentation evidence:** "The Anchor security
reference documents this as a common mistake in programs using
UncheckedAccount. Multiple protocol hacks have involved this pattern."

**Tier 4 — Heuristic:** "This is flagged as a potential concern based on
the handler name and account structure. Human review is recommended
to confirm whether this is actually a vulnerability in this context."

---

## Writing a Good Acknowledgment

When the developer acknowledges a gap, record a clear reason:

Good acknowledgment reasons:
- "Permissionless by design — this instruction is a public crank"
- "Mitigated by upstream check in the calling program"
- "Accepted risk — protected by off-chain monitoring"
- "Not applicable — this account is always the System Program"

Bad acknowledgment reasons:
- "OK" — not specific enough to be useful in a future audit
- "Known" — does not explain why the risk is accepted
- "Will fix later" — use the defer triage outcome instead