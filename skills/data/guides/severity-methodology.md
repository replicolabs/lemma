# Lemma Severity Methodology

This document defines how Lemma assigns severity scores to identified
security gaps. The methodology is public so developers understand exactly
why a gap received its severity rating and what they need to fix first.

---

## Core Principle

Severity is not inherited from the vulnerability class alone. It is
adjusted based on what the affected instruction actually does. A missing
signer check on a withdrawal instruction is critical. The same check
missing on a read-only view instruction is low. Context determines
severity.

---

## Severity Levels

### Critical

The gap allows an attacker to cause immediate, irreversible financial
loss or take permanent control of the protocol with no preconditions
other than submitting a transaction.

Examples:
- Missing signer check on an instruction that transfers tokens or lamports
- Arbitrary CPI where an attacker can substitute a malicious program
  that drains vaults
- Missing ownership check on a vault account in a withdrawal instruction
- Permissionless instruction that allows any caller to drain protocol
  reserves

### High

The gap allows an attacker to cause significant financial loss or
privilege escalation but requires specific conditions, timing, or
knowledge to exploit.

Examples:
- Missing signer check on an instruction that modifies fee rates,
  collateral ratios, or other protocol parameters
- Arithmetic overflow in token amount calculations that can be triggered
  with large inputs
- Missing oracle validation that allows price manipulation to cause
  undercollateralized borrows
- Missing ownership check on a state account that controls access to
  funds

### Medium

The gap creates a meaningful security risk but exploitation requires
significant effort, specific market conditions, or insider knowledge.
The impact is bounded or reversible.

Examples:
- Missing signer check on an instruction that modifies non-financial
  configuration
- Arithmetic precision loss in fee calculations that creates a slow
  drain over many transactions
- PDA sharing vulnerability that allows users to interfere with each
  other's positions
- Missing lifecycle check that allows duplicate initialization

### Low

The gap represents a security weakness that is difficult to exploit
in practice or has limited impact when exploited. The developer should
fix it but it does not represent an immediate threat.

Examples:
- Missing signer check on a read-only or view instruction
- Non-canonical bump storage that creates a theoretical PDA confusion
  risk
- Redundant security check whose removal would be safe but whose
  presence is not harmful
- Missing writable enforcement on an account that is not modified in
  practice

### Informational

The gap is a best practice violation or a pattern that resembles a
vulnerability class but does not represent an exploitable weakness in
this specific program context. Developers should be aware of it but
it does not require immediate remediation.

---

## Severity Adjustment Rules

These rules are applied in order. The first matching rule determines
the severity adjustment.

### Rule 1: Financial Impact Escalation

If the affected instruction transfers tokens, transfers lamports, burns
tokens, or modifies a balance field, escalate the base vulnerability
class severity by one level.

Trigger: instruction name contains withdraw, drain, transfer, burn,
swap, borrow, liquidate, claim, redeem, or the instruction body writes
to a field named balance, amount, reserve, vault, or collateral.

### Rule 2: Administrative Control Escalation

If the affected instruction sets or modifies an authority, owner, admin,
or upgrade authority field, escalate by one level. Control over
administrative accounts is equivalent to control over funds in most
protocols.

### Rule 3: One-Way State Transition Escalation

If the affected instruction performs a state transition that cannot be
reversed such as closing an account, finalizing a position, or consuming
a one-time token, escalate by one level. Irreversible operations have
higher impact when they go wrong.

### Rule 4: Read-Only Downgrade

If the affected instruction only reads state and emits no events,
transfers no tokens, and modifies no accounts, downgrade the severity
by two levels. Read-only instructions have limited attack surface.

Trigger: instruction has no mutable accounts other than the fee payer,
or all mutable accounts are the fee payer.

### Rule 5: Configuration Parameter Downgrade

If the affected instruction modifies a configuration parameter with
a bounded input range and the parameter change takes effect gradually
or can be overridden by a timelock, downgrade by one level.

### Rule 6: CU Cost Consideration

Severity is not adjusted for compute unit cost alone. A gap that costs
more CUs to exploit is not less severe. CU costs are reported alongside
suggested fixes as a separate concern from security severity.

---

## Base Severity by Vulnerability Class

These are the starting severity values before adjustments. The rules
above modify them based on context.

| Vulnerability Class | Base Severity |
|---|---|
| missing_signer_check | high |
| missing_ownership_check | high |
| arithmetic_error | high |
| arbitrary_cpi | critical |
| insecure_initialisation | medium |
| oracle_validation | high |
| lifecycle_violation | medium |
| permissionless_state_write | critical |
| init_without_pda | medium |
| stored_field_never_written | medium |
| paired_validator_mismatch | high |
| authority_not_revoked_on_close | high |
| other | medium |

---

## Security Score Formula

The security score is a number from 0 to 100 representing the overall
security posture of the analyzed program. Higher is better.

Starting score: 100

Deductions:
- Each critical gap: subtract 20 points (maximum deduction from
  critical gaps: 60 points)
- Each high gap: subtract 10 points (maximum deduction from high
  gaps: 30 points)
- Each medium gap: subtract 5 points (maximum deduction from medium
  gaps: 20 points)
- Each low gap: subtract 1 point (maximum deduction from low gaps:
  5 points)
- Each informational gap: no deduction
- Each critical or high architectural recommendation: subtract 5
  points

The score cannot go below 0.

Acknowledged gaps do not contribute to deductions. A gap acknowledged
with a reason of intentional design, mitigated elsewhere, or accepted
risk is excluded from score calculation.

### Score Interpretation

| Score | Interpretation |
|---|---|
| 90-100 | Strong security posture. Minor gaps only. |
| 70-89 | Good posture. Some gaps requiring attention. |
| 50-69 | Moderate risk. Multiple gaps present. Review before deployment. |
| 30-49 | Significant risk. Critical or multiple high gaps present. Do not deploy. |
| 0-29 | Severe risk. Critical gaps present. Requires immediate remediation. |

---

## Deterministic vs LLM-Generated Gaps

Lemma produces two categories of gaps.

Deterministic gaps are found by the 22 built-in checker rules. These
run on the parsed program representation before any LLM call. They
are 100% reliable for what they check. If the deterministic checker
flags a gap, it is a real gap with no false positives possible for
the specific pattern being checked.

LLM-generated gaps are found by the agent reasoning over the retrieved
audit findings. These are probabilistic. The agent may flag patterns
that do not represent real vulnerabilities in the specific program
context. Developers should review LLM-generated gaps with the
understanding that they require human judgment to confirm.

The security report clearly distinguishes deterministic gaps from
LLM-generated gaps. The security score counts both but the gap report
labels each one with its source.

---

## Changelog

This methodology is versioned alongside the Lemma binary. Changes to
the scoring formula or severity rules are documented here so developers
can understand why their score changed between versions.

v0.1.0 — Initial methodology. 22 deterministic rules. Base severity
table above. Five adjustment rules.