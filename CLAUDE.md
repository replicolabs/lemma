# Claude Code Instructions for Lemma

This file is read by Claude Code when working in this repository.

---

## This Repository

This is the Lemma source repository. It contains:

- `crates/lemma/` — the Rust binary source
- `skills/` — agent skills for Claude Code and Codex
- `install.sh` — the curl-installable setup script

---

## Building

```bash
cargo build                    # debug build
cargo build --release          # release build
cargo check                    # type check without building
cargo clippy                   # lints
```

The binary is at `target/debug/lemma` or `target/release/lemma`.

---

## Testing the Binary

```bash
# After building, test with the local binary
./target/debug/lemma info
./target/debug/lemma kb update
./target/debug/lemma analyze --program /path/to/test/program
```

---

## Repository Structure

```
crates/lemma/src/
  main.rs          — entry point, command dispatch
  cli.rs           — CLI command definitions
  config.rs        — ~/.lemma/config.toml management
  types.rs         — all shared data types
  kb/              — knowledge base download and loading
  retrieval/       — Voyage AI embedding and cosine search
  parser/          — Anchor, Quasar, Pinocchio, Native parsers
  checker/         — 22 deterministic security rules
  output/          — gap report, QEDSpec, markdown, patch writers
  github/          — OAuth and pull request creation
```

---

## Code Standards

- No `#[cfg(test)]` blocks — tests are written separately when needed
- `Box<str>` for string fields set once, `String` only where mutation needed
- All async code uses tokio
- Error messages must be user-friendly with actionable suggestions
- `overflow-checks = true` in release profile — this is a security tool
- Idiomatic Rust throughout — no unnecessary clones, no unwrap in non-test code

---

## Adding a New Checker Rule

1. Create `crates/lemma/src/checker/rules/dc0XX_name.rs`
2. Implement a `check` function returning `Vec<SecurityGap>`
3. Use the `gap()` helper from `rules/mod.rs`
4. Add the module to `rules/mod.rs`
5. Add the call to `checker/mod.rs` `run_all` function

---

## The Knowledge Base

The knowledge base lives at `https://github.com/replicolabs/kb`. It is
a separate repository. The binary downloads `knowledge_base.json` from
its GitHub Releases. Do not attempt to embed the KB in this repository.

---

## When Working on This Repository

If asked to analyze a Solana program, use the built binary at
`./target/debug/lemma analyze` — do not use the installed system binary.

If asked to add a security rule, follow the pattern in existing rule files
in `crates/lemma/src/checker/rules/`.