# Framework Security Document Curation Prompt

Paste this prompt into any chat interface along with the framework source
code, documentation, or llms.txt to produce a curated security reference
document for the Lemma knowledge base.

---

You are a senior Solana security researcher with deep expertise in formal
verification and smart contract auditing. Produce a curated security
reference document for a specific Solana development framework.

This document will be embedded in a vector database and retrieved when a
program using this framework is being analyzed by Lemma. Every sentence
must be directly security-relevant. Do not include anything about
installation, performance, CLI usage, or general development workflow.

THE FRAMEWORK: [INSERT: Anchor / Quasar / Pinocchio / Native Rust]

SOURCE MATERIAL: [PASTE FRAMEWORK SOURCE CODE OR DOCUMENTATION]

Produce the following document structure exactly.

## 1. Automatic Security Enforcement

For each property the framework enforces automatically without the
developer writing any explicit check:
- Property name
- What it enforces precisely and completely
- What it does NOT enforce (the exact boundary)
- Which type, decorator, or constraint triggers enforcement
- What happens if the developer uses UncheckedAccount or equivalent

## 2. Developer Responsibilities

For each commonly needed property NOT provided automatically:
- Property name
- Why the framework does not handle it
- The correct code pattern with a complete example
- The incorrect pattern developers commonly write thinking it provides
  protection but does not

## 3. Framework-Specific Vulnerability Patterns

For each pattern unique to or especially common in this framework:
- Pattern name
- What the developer writes that creates the vulnerability
- Why this framework makes this mistake more likely
- The formal property that should hold
- Vulnerable code example (minimal, compilable)
- Correct code example (minimal, compilable)
- kani::assert! expression catching this vulnerability
- QEDSpec clause (guard, requires, ensures, invariant, or establishes)

## 4. Trust Boundaries

- What attacker inputs bypass automatic protections?
- What assumptions must the developer verify?
- CPI trust boundaries?
- What does using UncheckedAccount leave unprotected?

## 5. Discriminator and Type Safety

- How are account types distinguished?
- What prevents type confusion?
- Where does the discriminator check happen? Can it be bypassed?

## 6. Initialization and Lifecycle

- How does the framework prevent reinitialization?
- What must the developer do that the framework does not handle?
- Safe account closure procedure?

## 7. Arithmetic Safety

- Does the framework enable overflow-checks in release builds?
- What arithmetic is safe by default?
- What requires explicit checked variants?

## 8. QEDSpec Clause Mapping

For each property from Sections 1 and 2, state the correct clause_type:
guard, requires, ensures, invariant, or establishes

## 9. Common Audit Findings

Top five vulnerability classes for this framework. For each:
- Class name (use the exact enum values from the Lemma schema)
- Why it is common in this framework specifically
- How a gap analysis tool should detect it

QUALITY REQUIREMENTS:
Every claim must be specific and verifiable.
Every kani::assert! must be valid Rust that compiles in a function body.
Every QEDSpec clause_type must follow semantic timing rules exactly.

After the main document, produce a SECOND VERSION optimized for vector
database embedding. In this version, rewrite each section as standalone
chunks where every chunk begins with:

Framework: [name]
Topic: [property or vulnerability name]
Applies to: [instruction types or account types]

Each chunk must be independently understandable without surrounding context.