# Contributing to Lemma

Thank you for your interest in contributing. There are two ways to contribute
to the Lemma ecosystem.

---

## Contributing to the Knowledge Base

The knowledge base lives in a separate repository:
[replicolabs/kb](https://github.com/replicolabs/kb)

The most impactful contribution is adding structured security findings from
public Solana audit reports. See the
[KB contribution guide](https://github.com/replicolabs/kb/blob/main/CONTRIBUTING.md)
for the full process.
---

## Contributing to the Binary and Skills

### Setting Up

```bash
git clone https://github.com/replicolabs/lemma
cd lemma
cargo build
```

### Making Changes

- Bug fixes and improvements to existing checker rules: open a PR with a
  clear description of the bug, the fix, and how you verified it.

- New checker rules: open an issue first to discuss the rule before
  implementing it. New rules must have zero false positives for the specific
  pattern they check.

- Skill file improvements: edit the relevant skill in `skills/` and open a PR.

### Code Standards

- No `unwrap()`, use `?` and proper error handling
- `Box<str>` for string fields that are set once and never mutated
- Run `cargo clippy` before opening a PR and fix all warnings

### Pull Request Process

1. Fork the repository
2. Create a branch: `git checkout -b fix/description` or `feat/description`
3. Make your changes
4. Run `cargo check` and `cargo clippy`
5. Open a pull request with a description of what changed and why

---

## Reporting Bugs

Open a GitHub issue 