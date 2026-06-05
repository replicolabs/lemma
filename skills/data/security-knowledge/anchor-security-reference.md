# Anchor Framework — Security Reference Document (Lemma Edition)

> Framework: Anchor (Solana)
> Source material: otter-sec/anchor source, coral-xyz/sealevel-attacks, official Anchor documentation
> Purpose: Embedded in a vector database; retrieved during static analysis of Anchor programs by Lemma.
> Every sentence is directly security-relevant. No installation, CLI, or performance content.

---

## 1. Automatic Security Enforcement

### 1.1 Account Ownership Verification

**Property name:** Account ownership check

**What it enforces precisely:** When an account is declared as `Account<'info, T>`, Anchor verifies `account.info.owner == T::owner()` before deserializing the account data. For structs marked with `#[account]`, `T::owner()` returns the `crate::ID` declared by `declare_id!` in the same program. Anchor additionally rejects accounts where the owner is the System Program AND lamports == 0, preventing the use of uninitialised system-owned accounts.

**What it does NOT enforce:** It does not verify the account's address (pubkey). An account owned by the correct program but at a completely different address will still pass this check. It does not verify the account contents beyond ownership and discriminator. It does not enforce that the account address matches any expected PDA derivation unless a `seeds`/`bump` constraint is also present.

**Trigger:** Using `Account<'info, T>` as the field type in a `#[derive(Accounts)]` struct.

**If UncheckedAccount is used instead:** `UncheckedAccount<'info>` (and the deprecated `AccountInfo<'info>`) perform zero ownership checks. The Anchor CLI enforces that any field typed as `UncheckedAccount` or `AccountInfo` must have a `/// CHECK:` doc comment explaining why it is safe, and `anchor build` will emit a compile error otherwise. The runtime does not reject the transaction; the developer is fully responsible for manual ownership validation.

---

### 1.2 Account Discriminator Verification

**Property name:** Discriminator check on deserialization

**What it enforces precisely:** The `#[account]` macro prepends an 8-byte discriminator to each account on serialization and verifies it on deserialization via `try_deserialize`. The discriminator is `sha256("account:<TypeName>")[..8]` by default. If the discriminator bytes in the stored account data do not match the expected discriminator, Anchor returns `ErrorCode::AccountDiscriminatorMismatch` and aborts the instruction. This prevents an account of type `Metadata` from being passed where an account of type `Vault` is expected, even if both have the same data layout.

**What it does NOT enforce:** It does not enforce discriminator correctness when using `try_deserialize_unchecked`, which skips the check. It does not protect against two types that happen to have colliding discriminators (SHA-256 collision is negligible in practice). All-zero discriminators are explicitly unsupported for account types; Anchor refuses to compile `#[account(discriminator = 0)]` or `#[account(discriminator = [0,0,0])]` because zeroed data is indistinguishable from a newly allocated account.

**Trigger:** Any field typed as `Account<'info, T>` where `T` is annotated with `#[account]`.

**If UncheckedAccount is used instead:** No discriminator check is performed. An attacker can supply any account at the correct address without triggering a type-safety rejection.

---

### 1.3 Signer Verification

**Property name:** Transaction signer check

**What it enforces precisely:** When a field is typed as `Signer<'info>`, Anchor verifies that `account_info.is_signer == true` before the instruction handler runs. This check is enforced at the framework constraint layer during `try_accounts`, before any handler logic executes.

**What it does NOT enforce:** It does not verify that the signer is the correct authority for the operation — only that the account signed the transaction. A valid signer who is not the stored authority on an account will pass this check. Business-logic authority matching requires a separate `has_one` or `constraint` expression.

**Trigger:** `Signer<'info>` field type, or `#[account(signer)]` on an `UncheckedAccount`.

**If UncheckedAccount is used instead:** No signer check. Any account may be passed in the signer position and the instruction will proceed.

---

### 1.4 Program Identity Verification

**Property name:** Program account check

**What it enforces precisely:** `Program<'info, T>` verifies that `account_info.key == T::id()` and that `account_info.executable == true`. For `Program<'info, System>`, this checks the System Program address. For `Program<'info, Token>`, this checks the SPL Token program address.

**What it does NOT enforce:** It does not verify that the program has not been upgraded to a malicious version (upgradeable programs can change). It does not verify the behaviour or logic of the CPI target — only its address.

**Trigger:** `Program<'info, T>` field type.

**If UncheckedAccount is used instead:** No program ID or executability check. An attacker can substitute a malicious program with the same interface.

---

### 1.5 PDA Derivation Verification

**Property name:** PDA seeds and bump check

**What it enforces precisely:** `#[account(seeds = [...], bump)]` instructs Anchor to call `Pubkey::find_program_address` with the provided seeds and verify that the result matches the account's key. When `bump = expr` is provided, Anchor uses `Pubkey::create_program_address` with that explicit bump and verifies the result. Both forms reject any account whose key does not match the derivation.

**What it does NOT enforce:** It does not verify that the bump stored in account data was derived canonically unless the developer explicitly stores and reuses `ctx.bumps.<field_name>`. When `bump` is used without a stored value, Anchor calls `find_program_address` on every invocation (which returns the canonical bump), costing extra compute units.

**Trigger:** `#[account(seeds = [...], bump)]` or `#[account(seeds = [...], bump = account.bump)]`.

**If UncheckedAccount is used instead:** No PDA derivation check. Any account key is accepted.

---

### 1.6 Mutable Account Gating

**Property name:** Writable-flag enforcement

**What it enforces precisely:** `#[account(mut)]` tells Anchor to serialize account state back to chain after the handler exits (via `AccountsExit::exit`). Without `mut`, modified in-memory state is discarded silently.

**What it does NOT enforce:** Anchor does not enforce that an account is NOT writable when no `mut` constraint is present. The runtime enforces actual write privileges, but Anchor does not prevent a caller from passing a writable account into a non-mutable slot.

**Trigger:** `#[account(mut)]` on any account field.

**If omitted:** State changes will not be persisted to the account. This is a logic bug, not a security enforcement failure per se, but it can cause invariant violations when developers assume writes were persisted.

---

### 1.7 `has_one` Relationship Enforcement

**Property name:** Cross-account field equality check

**What it enforces precisely:** `#[account(has_one = target)]` verifies that `self_account.target == ctx.accounts.target.key()`. It confirms that a public key stored as a field inside an account matches the key of another account in the instruction context.

**What it does NOT enforce:** It does not verify the type, ownership, or contents of the `target` account. It only checks key equality.

**Trigger:** `#[account(has_one = field_name)]`.

**If omitted:** A caller can substitute a different account in the `target` position (e.g., a different authority or different vault), and the program will accept it silently.

---

### 1.8 Account Closure

**Property name:** Safe account closure

**What it enforces precisely:** `#[account(mut, close = destination)]` instructs Anchor to: (1) transfer all lamports from the closed account to `destination` after the handler exits; (2) zero the account's data; (3) write `CLOSED_ACCOUNT_DISCRIMINATOR` (8 bytes of `0xff`) into the account's data buffer; (4) reassign the owner to the System Program. This prevents revival attacks within the same transaction because the discriminator check on any subsequent use of this account will fail.

**What it does NOT enforce:** It does not prevent the destination from being an attacker-controlled address. The developer must ensure `destination` is a trusted account (e.g., constrained by `has_one` or `address`).

**Trigger:** `close = destination` constraint.

**If developer closes manually (only draining lamports):** A partial manual close that only transfers lamports but does not zero data and write the CLOSED discriminator leaves the account vulnerable to revival attacks within the same transaction.

---

### 1.9 Reinitialization Prevention via `init`

**Property name:** Single-use initialisation guard

**What it enforces precisely:** `#[account(init, payer = ..., space = ...)]` invokes the System Program to allocate a new account. If the account already exists (non-zero lamports or non-zero data), the System Program CPI fails, aborting the instruction. This prevents reinitialisation of existing accounts through the `init` path.

**What it does NOT enforce:** `init` does not prevent a developer from inadvertently writing an `initialize` instruction that doesn't use `init` and manually zeroes or overwrites data. The `init_if_needed` feature (behind a Cargo feature flag) disables reinitialization protection for that field; when used, the developer must add their own check that already-initialized accounts cannot have their state reset.

**Trigger:** `#[account(init, payer = <payer>, space = <n>)]`.

---

### 1.10 Overflow Checks in Release Builds

**Property name:** Integer overflow detection

**What it enforces precisely:** Anchor's `anchor init` scaffolding creates a workspace `Cargo.toml` with `[profile.release] overflow-checks = true`, which causes integer overflow in release builds to panic (same as debug mode) rather than wrap silently. The Anchor CLI also enforces that `overflow-checks` is explicitly stated in the workspace `Cargo.toml`; if absent, `anchor build` emits: `Error: overflow-checks is not enabled`.

**What it does NOT enforce:** This is a workspace-level Cargo configuration. Programs that do not originate from `anchor init`, or that override the profile, may not have this flag. The flag does not apply to explicit wrapping arithmetic (`wrapping_add`, etc.) or to programs that deliberately use `#[allow(arithmetic_overflow)]`.

**Trigger:** `overflow-checks = true` in `[profile.release]` of workspace `Cargo.toml`.

---

## 2. Developer Responsibilities

### 2.1 Authority Matching (Business Logic)

**Property name:** Authority-to-account binding

**Why the framework does not handle it:** Anchor can enforce that a signer signed the transaction and that a field named `authority` in an account equals another account's key. But it cannot infer which field inside an account is the authority — that is a business-logic decision.

**Correct pattern:**
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
```
`has_one = authority` checks that `vault.authority == ctx.accounts.authority.key()`, and `Signer` checks the transaction signature. Both constraints together confirm that the signer is the stored authority.

**Incorrect pattern developers commonly write:**
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>, // Signer check only — no binding to vault.authority!
}
```
This accepts any signer, not just the vault's stored authority. An attacker who signs with their own key can drain any vault.

---

### 2.2 Duplicate Mutable Account Detection

**Property name:** Distinct-account check for mutable pairs

**Why the framework does not handle it:** Anchor validates individual account constraints but does not compare accounts against each other for key equality unless the developer adds an explicit check.

**Correct pattern:**
```rust
pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    require_keys_neq!(
        ctx.accounts.from.key(),
        ctx.accounts.to.key(),
        ErrorCode::SameAccount
    );
    // ... transfer logic
    Ok(())
}
```

**Incorrect pattern:**
```rust
pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    // Missing identity check — from and to can be the same account.
    ctx.accounts.from.amount -= amount;
    ctx.accounts.to.amount += amount;
    Ok(())
}
```
When `from == to`, the first write is overwritten by the second, silently producing a spurious balance increase.

---

### 2.3 PDA Bump Storage and Reuse

**Property name:** Canonical bump persistence

**Why the framework does not handle it:** Anchor derives the canonical bump during `init` via `find_program_address`, but does not automatically store it in account data. If subsequent instructions re-derive the bump using `find_program_address` on every call, they spend unnecessary compute units. If they accept a user-supplied bump via instruction arguments, they expose a canonicalization attack.

**Correct pattern:**
```rust
// During init: store the canonical bump
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    ctx.accounts.state.bump = ctx.bumps.state; // store canonical bump
    Ok(())
}

// During subsequent use: supply stored bump to avoid re-derivation
#[derive(Accounts)]
pub struct UseState<'info> {
    #[account(seeds = [b"state"], bump = state.bump)]
    pub state: Account<'info, State>,
}
```

**Incorrect pattern:**
```rust
// Accepting user-supplied bump: allows non-canonical bump attacks
pub fn set_value(ctx: Context<BumpSeed>, key: u64, bump: u8) -> ProgramResult {
    let address = Pubkey::create_program_address(
        &[key.to_le_bytes().as_ref(), &[bump]], ctx.program_id
    )?;
    require_keys_eq!(address, ctx.accounts.data.key());
    // ... proceeds with non-canonical bump accepted
    Ok(())
}
```
`create_program_address` accepts any valid bump, not just the canonical one, allowing an attacker to supply a non-canonical bump that derives to the same address but may open future attack surfaces.

---

### 2.4 Post-CPI State Re-validation

**Property name:** State consistency after cross-program invocation

**Why the framework does not handle it:** After a CPI call, Anchor re-loads modified accounts that were passed by reference. However, Anchor cannot know which invariants the developer expects to hold after the CPI; invariant re-checking is the developer's responsibility.

**Correct pattern:**
```rust
pub fn complex_op(ctx: Context<ComplexOp>, amount: u64) -> Result<()> {
    let balance_before = ctx.accounts.vault.amount;
    // ... CPI call ...
    ctx.accounts.vault.reload()?; // reload after CPI
    let balance_after = ctx.accounts.vault.amount;
    require!(balance_after == balance_before - amount, ErrorCode::InvariantViolation);
    Ok(())
}
```

**Incorrect pattern:**
```rust
pub fn complex_op(ctx: Context<ComplexOp>, amount: u64) -> Result<()> {
    // CPI call that modifies vault
    token::transfer(ctx.accounts.transfer_ctx(), amount)?;
    // Reading vault.amount here may use stale in-memory data
    msg!("Vault balance: {}", ctx.accounts.vault.amount);
    Ok(())
}
```

---

### 2.5 SPL Token Mint-Account Binding

**Property name:** Token account mint verification

**Why the framework does not handle it:** Anchor's `#[account(token::mint = mint)]` constraint validates the mint field when the `token` constraint group is present, but developers who validate token accounts manually via `Account<'info, TokenAccount>` without the `token::mint` sub-constraint do not get this check.

**Correct pattern:**
```rust
#[account(
    mut,
    token::mint = expected_mint,
    token::authority = authority
)]
pub user_token_account: Account<'info, TokenAccount>,
pub expected_mint: Account<'info, Mint>,
```

**Incorrect pattern:**
```rust
// Accepts any token account regardless of which mint it holds
pub user_token_account: Account<'info, TokenAccount>,
```
An attacker can supply a token account for a worthless token, causing the program to operate on the wrong asset.

---

### 2.6 Sysvar Address Validation

**Property name:** Sysvar authenticity check

**Why the framework does not handle it:** Anchor's `Sysvar<'info, Clock>` type checks that the account key equals the canonical sysvar address. However, if a developer uses `UncheckedAccount` for a sysvar and reads data from it directly, no address check is performed.

**Correct pattern:**
```rust
pub clock: Sysvar<'info, Clock>,
// OR
let clock = Clock::get()?; // reads directly from runtime, no account needed
```

**Incorrect pattern:**
```rust
/// CHECK: clock account
pub clock: UncheckedAccount<'info>,
// ...
let clock: Clock = Clock::try_from_slice(&ctx.accounts.clock.data.borrow())?;
// No key check — attacker can supply a fake clock account
```

---

## 3. Framework-Specific Vulnerability Patterns

### 3.1 Missing `has_one` — Account Data Matching Vulnerability

**Pattern name:** Missing authority binding (`account_data_matching`)

**What the developer writes:** The developer uses `Account<'info, T>` for ownership and discriminator, and `Signer<'info>` for the transaction signer, but omits `has_one = authority`, relying on the handler to compare manually — which is then forgotten or incorrectly implemented.

**Why this framework makes it more likely:** Anchor's type system automatically handles ownership and discriminator. Developers come to trust the framework to handle "account safety" and forget that business-logic field equality (stored authority vs. signer) is not checked by any account type.

**Formal property that should hold but does not:**
`guard: vault.authority == authority.key()`

**Vulnerable code:**
```rust
use anchor_lang::prelude::*;
declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod insecure {
    use super::*;
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // No check that authority == vault.authority
        ctx.accounts.vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
```

**Correct code:**
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
```

**kani::assert! expression:**
```rust
kani::assert!(
    ctx.accounts.vault.authority == ctx.accounts.authority.key(),
    "vault authority must match signer"
);
```

**QEDSpec clause:**
```
guard: vault.authority == authority.key()
```

---

### 3.2 Type Cosplay via Non-Anchor Deserialization

**Pattern name:** Type cosplay through raw deserialization (`missing_ownership_check`)

**What the developer writes:** The developer uses `AccountInfo<'info>` or `UncheckedAccount<'info>` and calls `T::try_from_slice` directly, without checking the discriminator.

**Why this framework makes it more likely:** Anchor provides `Account<'info, T>` which does discriminator + ownership checks automatically. When developers bypass this for performance or legacy compatibility, they silently lose both checks.

**Formal property that should hold but does not:**
`guard: account.owner == program_id AND account.data[..8] == discriminator_of(T)`

**Vulnerable code:**
```rust
use anchor_lang::prelude::*;
use borsh::BorshDeserialize;
declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod type_cosplay_insecure {
    use super::*;
    pub fn update_user(ctx: Context<UpdateUser>) -> ProgramResult {
        // No discriminator check — Metadata can be passed as User
        let user = User::try_from_slice(&ctx.accounts.user.data.borrow()).unwrap();
        if ctx.accounts.user.owner != ctx.program_id {
            return Err(ProgramError::IllegalOwner);
        }
        if user.authority != ctx.accounts.authority.key() {
            return Err(ProgramError::InvalidAccountData);
        }
        msg!("GM {}", user.authority);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdateUser<'info> {
    user: AccountInfo<'info>,
    authority: Signer<'info>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct User { authority: Pubkey }

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Metadata { account: Pubkey } // same layout as User — can be confused
```

**Correct code:**
```rust
#[derive(Accounts)]
pub struct UpdateUser<'info> {
    #[account(has_one = authority)]
    user: Account<'info, User>, // discriminator + ownership automatic
    authority: Signer<'info>,
}

#[account]
pub struct User { authority: Pubkey }
```

**kani::assert! expression:**
```rust
let disc = &ctx.accounts.user.try_borrow_data()?[..8];
kani::assert!(disc == User::discriminator(), "discriminator must match User type");
kani::assert!(ctx.accounts.user.owner == ctx.program_id, "owner must be this program");
```

**QEDSpec clause:**
```
guard: user.discriminator == sha256("account:User")[..8] AND user.owner == program_id
```

---

### 3.3 Bump Seed Canonicalization

**Pattern name:** Non-canonical bump acceptance (`init_without_pda`)

**What the developer writes:** The developer accepts a `bump: u8` instruction argument and calls `create_program_address` with that bump rather than using `find_program_address` to derive (and enforce) the canonical bump.

**Why this framework makes it more likely:** Anchor's `#[account(seeds = [...], bump)]` macro hides `find_program_address` internally and surfaces the canonical bump via `ctx.bumps`. When developers implement PDA validation manually (especially in older code pre-Anchor constraints), they replicate only part of the validation.

**Formal property that should hold but does not:**
`guard: bump == find_program_address(seeds, program_id).1`

**Vulnerable code:**
```rust
use anchor_lang::prelude::*;
declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod bump_seed_canonicalization_insecure {
    use super::*;
    pub fn set_value(ctx: Context<BumpSeed>, key: u64, new_value: u64, bump: u8) -> ProgramResult {
        let address = Pubkey::create_program_address(
            &[key.to_le_bytes().as_ref(), &[bump]], ctx.program_id
        )?;
        if address != ctx.accounts.data.key() {
            return Err(ProgramError::InvalidArgument);
        }
        ctx.accounts.data.value = new_value;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct BumpSeed<'info> {
    data: Account<'info, Data>,
}

#[account]
pub struct Data { value: u64 }
```

**Correct code:**
```rust
#[derive(Accounts)]
#[instruction(key: u64)]
pub struct BumpSeed<'info> {
    #[account(seeds = [key.to_le_bytes().as_ref()], bump)]
    data: Account<'info, Data>,
}
```

**kani::assert! expression:**
```rust
let (expected_addr, canonical_bump) =
    Pubkey::find_program_address(&[key.to_le_bytes().as_ref()], ctx.program_id);
kani::assert!(ctx.accounts.data.key() == expected_addr, "PDA must be canonical");
kani::assert!(bump == canonical_bump, "bump must be canonical");
```

**QEDSpec clause:**
```
guard: data.key() == find_program_address([key_bytes], program_id).address
```

---

### 3.4 PDA Sharing

**Pattern name:** Over-broad PDA seeds (shared pool authority) (`permissionless_state_write`)

**What the developer writes:** A pool or vault PDA is derived using only global seeds (e.g., just the token mint address), causing all users to share one PDA authority.

**Why this framework makes it more likely:** Anchor's `seeds` constraint makes PDA derivation ergonomic, leading developers to choose minimal seed sets without considering that uniqueness per user/entity is required for isolated control.

**Formal property that should hold but does not:**
`guard: forall u1 != u2, pda(u1) != pda(u2)` (each user must have a unique PDA)

**Vulnerable code:**
```rust
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};
declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod pda_sharing_insecure {
    use super::*;
    pub fn withdraw_tokens(ctx: Context<WithdrawTokens>, bump: u8, amount: u64) -> ProgramResult {
        let seeds = &[ctx.accounts.pool.mint.as_ref(), &[bump]];
        // All users for this mint share the same PDA signer
        let signer = &[&seeds[..]];
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.pool_token_account.to_account_info(),
                to: ctx.accounts.withdrawal_destination.to_account_info(),
                authority: ctx.accounts.pool.to_account_info(),
            },
            signer,
        );
        token::transfer(cpi_ctx, amount)
    }
}

#[derive(Accounts)]
pub struct WithdrawTokens<'info> {
    #[account(seeds = [pool.mint.as_ref()], bump)]
    pool: Account<'info, TokenPool>,
    // ...
    pool_token_account: Account<'info, TokenAccount>,
    withdrawal_destination: Account<'info, TokenAccount>,
    token_program: Program<'info, Token>,
}

#[account]
pub struct TokenPool {
    pub vault: Pubkey,
    pub mint: Pubkey,
    pub withdraw_destination: Pubkey,
    pub bump: u8,
}
```

**Correct code:**
```rust
#[derive(Accounts)]
pub struct WithdrawTokens<'info> {
    // Include the specific vault and owner in seeds for user isolation
    #[account(
        seeds = [pool.mint.as_ref(), pool.withdraw_destination.as_ref()],
        bump = pool.bump,
        has_one = withdraw_destination,
        has_one = vault
    )]
    pool: Account<'info, TokenPool>,
    vault: Account<'info, TokenAccount>,
    withdraw_destination: Account<'info, TokenAccount>,
    token_program: Program<'info, Token>,
}
```

**kani::assert! expression:**
```rust
kani::assert!(
    ctx.accounts.pool.withdraw_destination == ctx.accounts.withdrawal_destination.key(),
    "withdrawal destination must match stored destination"
);
```

**QEDSpec clause:**
```
guard: pool.withdraw_destination == withdrawal_destination.key()
      AND pool.vault == pool_token_account.key()
```

---

### 3.5 Arbitrary CPI

**Pattern name:** Unvalidated program target in CPI (`arbitrary_cpi`)

**What the developer writes:** The developer performs a CPI using an `AccountInfo`-typed program account without checking its key, allowing an attacker to supply a malicious substitute program.

**Why this framework makes it more likely:** Anchor's `invoke` and raw CPI paths accept `AccountInfo`, which performs no program ID check. The safer `Program<'info, Token>` wrapper is available but not enforced, so developers using raw CPI helpers may omit the check.

**Formal property that should hold but does not:**
`guard: token_program.key() == spl_token::ID`

**Vulnerable code:**
```rust
use anchor_lang::prelude::*;
use anchor_lang::solana_program;
declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod arbitrary_cpi_insecure {
    use super::*;
    pub fn cpi(ctx: Context<Cpi>, amount: u64) -> ProgramResult {
        solana_program::program::invoke(
            &spl_token::instruction::transfer(
                ctx.accounts.token_program.key, // attacker-controlled program key!
                ctx.accounts.source.key,
                ctx.accounts.destination.key,
                ctx.accounts.authority.key,
                &[], amount,
            )?,
            &[
                ctx.accounts.source.clone(),
                ctx.accounts.destination.clone(),
                ctx.accounts.authority.clone(),
            ],
        )
    }
}

#[derive(Accounts)]
pub struct Cpi<'info> {
    source: AccountInfo<'info>,
    destination: AccountInfo<'info>,
    authority: AccountInfo<'info>,
    token_program: AccountInfo<'info>, // no program ID check
}
```

**Correct code:**
```rust
use anchor_spl::token::{self, Token, TokenAccount};

#[derive(Accounts)]
pub struct Cpi<'info> {
    source: Account<'info, TokenAccount>,
    destination: Account<'info, TokenAccount>,
    authority: Signer<'info>,
    token_program: Program<'info, Token>, // enforces spl_token::ID
}
```

**kani::assert! expression:**
```rust
kani::assert!(
    ctx.accounts.token_program.key() == &anchor_spl::token::ID,
    "token_program must be SPL Token"
);
```

**QEDSpec clause:**
```
guard: token_program.key() == spl_token::ID AND token_program.executable == true
```

---

### 3.6 Insecure Account Closure (Revival Attack)

**Pattern name:** Incomplete account close leaving revival window (`lifecycle_violation`)

**What the developer writes:** The developer manually closes an account by draining lamports but does not zero the data or write the `CLOSED_ACCOUNT_DISCRIMINATOR`, leaving the discriminator intact and the account revivable within the same transaction.

**Why this framework makes it more likely:** Anchor's `close` constraint handles all steps atomically. Developers who implement closure manually often only copy the lamport-draining step from examples, missing the discriminator overwrite that prevents same-transaction revival.

**Formal property that should hold but does not:**
`ensures: account.lamports == 0 AND account.data[..8] == CLOSED_ACCOUNT_DISCRIMINATOR`

**Vulnerable code (insecure — only drains lamports):**
```rust
pub fn close(ctx: Context<Close>) -> ProgramResult {
    let dest_starting_lamports = ctx.accounts.destination.lamports();
    **ctx.accounts.destination.lamports.borrow_mut() = dest_starting_lamports
        .checked_add(ctx.accounts.account.to_account_info().lamports())
        .unwrap();
    **ctx.accounts.account.to_account_info().lamports.borrow_mut() = 0;
    // Data not zeroed — discriminator intact — revivable by re-funding lamports
    Ok(())
}

#[derive(Accounts)]
pub struct Close<'info> {
    account: Account<'info, Data>,
    destination: AccountInfo<'info>,
}
```

**Correct code:**
```rust
#[derive(Accounts)]
pub struct Close<'info> {
    #[account(mut, close = destination)]
    account: Account<'info, Data>,
    #[account(mut)]
    destination: SystemAccount<'info>,
}
// close constraint handles: lamport transfer + data zeroing + CLOSED discriminator write
```

**kani::assert! expression:**
```rust
// After handler exits:
let data = ctx.accounts.account.to_account_info().try_borrow_data()?;
kani::assert!(ctx.accounts.account.to_account_info().lamports() == 0, "lamports must be zero");
kani::assert!(&data[..8] == anchor_lang::__private::CLOSED_ACCOUNT_DISCRIMINATOR, "closed discriminator must be set");
```

**QEDSpec clause:**
```
ensures: account.lamports == 0
ensures: account.data[..8] == CLOSED_ACCOUNT_DISCRIMINATOR
```

---

### 3.7 `init_if_needed` Reinitialization Attack

**Pattern name:** Reinitialization via `init_if_needed` (`insecure_initialisation`)

**What the developer writes:** The developer uses `init_if_needed` without adding a guard that rejects already-initialized accounts or prevents re-setting of critical fields (e.g., authority).

**Why this framework makes it more likely:** `init_if_needed` is explicitly a framework opt-in feature (behind the `init-if-needed` Cargo feature) that disables the single-use initialisation guarantee of `init`. Developers enable it for UX convenience without realizing it allows attackers to call the instruction again on an existing account.

**Formal property that should hold but does not:**
`ensures: IF account existed before THEN account.authority is unchanged`

**Vulnerable code:**
```rust
// With init_if_needed, an attacker calls initialize() again on an existing account
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    ctx.accounts.data.authority = ctx.accounts.authority.key(); // overwrites existing authority!
    ctx.accounts.data.balance = 0;
    Ok(())
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init_if_needed, payer = authority, space = 8 + 40)]
    pub data: Account<'info, Data>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

**Correct code:**
```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Guard: reject if already initialized
    require!(!ctx.accounts.data.is_initialized, ErrorCode::AlreadyInitialized);
    ctx.accounts.data.is_initialized = true;
    ctx.accounts.data.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**kani::assert! expression:**
```rust
kani::assert!(!ctx.accounts.data.is_initialized, "account must not be already initialized");
```

**QEDSpec clause:**
```
requires: data.is_initialized == false
establishes: data.authority == authority.key()
establishes: data.is_initialized == true
```

---

## 4. Trust Boundaries

### Attacker-Controlled Inputs That Can Bypass Automatic Protections

- **Account keys:** The attacker supplies every account in the instruction. Any account not validated by type, constraint, or address check is fully attacker-controlled.
- **Instruction data / arguments:** All instruction arguments are attacker-controlled. Anchor does not validate argument values; only account constraints are automatically checked.
- **Account ordering:** The Solana runtime passes accounts in the order the client provides. If an instruction accepts variable-count or `remaining_accounts`, the attacker controls position and content of those accounts.
- **CPI targets:** Any program account typed as `AccountInfo` rather than `Program<'info, T>` is attacker-controlled. The attacker can substitute a malicious program at a different address.
- **Bump seeds supplied as instruction arguments:** If a bump is passed in instruction data and used in `create_program_address` directly, it is attacker-controlled. The framework constraint `bump` (no argument) is safe; `bump = user_supplied_value` is not.

### Framework Assumptions the Developer Must Verify

- Anchor assumes `T::owner()` is the correct owner to check. For cross-program accounts, the developer must ensure the correct program's `declare_id!` is referenced in `T`'s owner implementation.
- Anchor assumes that the `has_one` field name on a constraint matches a field of the same name in both the account struct and the `Accounts` struct. Typos compile silently and produce incorrect checks.
- The `close` constraint assumes the `destination` account is trusted. The developer must constrain it.
- `init_if_needed` disables the reinitialization guard. The developer must add their own guard.

### CPI Trust Boundaries

**What Anchor verifies about CPI targets:** When `Program<'info, T>` is used as the CPI target type, Anchor verifies the program key and executability before the handler runs. Anchor's generated CPI module functions (from `declare_program!`) build the instruction with the correct discriminator and typed accounts.

**What the developer must verify:**
- That the CPI target program has not been upgraded to a malicious version (upgrade authority is external to Anchor).
- That the accounts passed in the CPI `Context` are the accounts the callee expects — Anchor does not validate account ordering within the CPI call.
- That re-entrant CPI state changes are accounted for — account data modified by the callee must be reloaded with `.reload()` before being read again in the caller.
- When using raw `invoke` or `invoke_signed` instead of Anchor's CPI module, no program ID or account validation is performed; the developer is fully responsible.

### What `UncheckedAccount` Leaves Unprotected

Using `UncheckedAccount<'info>` removes all of the following checks:
- Account ownership (program ID equality)
- Account discriminator (type safety)
- Signer status
- PDA derivation

The only enforcement remaining is that a `/// CHECK:` doc comment must exist or `anchor build` will fail. This is a compile-time documentation requirement, not a runtime safety guarantee.

---

## 5. Discriminator and Type Safety

### How Account Types Are Distinguished

Every struct annotated with `#[account]` receives an 8-byte discriminator computed as `sha256("account:<TypeName>")[..8]`. This discriminator is prepended to the serialized account data by `try_serialize` and verified at the start of `try_deserialize` before any field data is read.

### What Prevents Type Confusion Attacks

`Account<'info, T>` calls `T::try_deserialize`, which checks the discriminator against the expected bytes before reading any data. This means a `Metadata` account (with its own discriminator) cannot be passed where a `Vault` account is expected, even if both structs have identical field layouts.

### Where the Discriminator Check Happens and Whether It Can Be Bypassed

The check occurs inside `AccountDeserialize::try_deserialize`, called during `Accounts::try_accounts` before the instruction handler runs. It can be bypassed by:
- Calling `try_deserialize_unchecked` directly (skips the discriminator read).
- Using `AccountInfo<'info>` or `UncheckedAccount<'info>` and performing manual deserialization without checking the discriminator.
- Using zero-copy accounts (`AccountLoader<'info, T>`) with `load_unchecked` instead of `load` (which does not verify the discriminator).
- Setting a custom discriminator with `#[account(discriminator = ...)]` — all-zero custom discriminators are rejected by the compiler, but non-zero custom discriminators are the developer's responsibility to keep consistent.

### Developer Responsibility Beyond Framework Enforcement

- When interacting with accounts from foreign programs (not annotated with Anchor's `#[account]`), the developer must verify the discriminator or schema manually, since `T::owner()` from a foreign crate may not match expectations.
- When adding fields to an existing account struct, the discriminator is unchanged, but account data layout changes require a migration — existing accounts on-chain have old field sizes and will fail deserialization silently if the new struct is incompatible.
- Events use a different discriminator namespace: `sha256("event:<TypeName>")[..8]`. Event discriminators and account discriminators do not collide by design.

---

## 6. Initialization and Lifecycle

### How Anchor Prevents Reinitialization Attacks

`#[account(init, ...)]` emits a CPI to the System Program to create the account. The System Program rejects creation of an account that already has non-zero lamports or data, aborting the transaction. Anchor then writes the discriminator on first serialization, establishing type identity.

### What the Developer Must Do During Initialization That Anchor Does Not

- Store the canonical bump if the account is a PDA: `account.bump = ctx.bumps.account_field_name;`
- Set any authority or owner fields to the intended values. Anchor does not infer which fields are authority fields.
- Validate that the `payer` account has sufficient lamports for rent exemption. Anchor delegates this to the System Program CPI, which will fail if insufficient, but the developer should handle this gracefully in the client.
- When using `init_if_needed`, add an explicit `is_initialized` flag and reject re-initialisation of already-initialized accounts.

### How Anchor Handles Account Closure

The `#[account(mut, close = destination)]` constraint:
1. Runs the handler body first.
2. In `AccountsExit::exit`, transfers all lamports from the account to `destination`.
3. Zeroes all bytes of the account data.
4. Writes `CLOSED_ACCOUNT_DISCRIMINATOR` (`[0xff; 8]`) at offset 0.
5. Reassigns the account owner to the System Program.

This means any instruction that subsequently attempts to deserialize the account with `Account<'info, T>` will fail because `[0xff; 8]` does not match `T`'s discriminator.

### What the Developer Must Do During Closure

- Constrain the `destination` account to prevent an attacker from redirecting lamports.
- If the account holds associated token accounts, close those token accounts before closing the parent, or account for the lamports separately.
- Ensure no other instruction in the same transaction reads the account after closure, as the data and lamports are already transferred at `exit` time.

### Lifecycle Transitions Tracked vs. Developer-Managed

**Anchor tracks:** account exists / does not exist (via `init`); account is closed (via `close`).

**Developer must track:** whether an account is in a specific application lifecycle state (e.g., `Draft → Active → Settled`); multi-step state machines; whether a field like `did_execute` has been flipped; whether a timelock has expired.

---

## 7. Arithmetic Safety

### Default Behavior

Anchor's `anchor init` workspace sets `[profile.release] overflow-checks = true`. With this flag, integer overflow in release builds panics (same as debug). The Anchor CLI enforces this flag is explicitly present; its absence causes `anchor build` to fail.

### What Is Safe by Default

All primitive integer arithmetic (`+`, `-`, `*`) will panic on overflow in both debug and release builds when `overflow-checks = true` is set. This includes arithmetic on `u64`, `u128`, `i64`, and all other integer primitives.

### What Requires Explicit Checked Variants

- **Explicit wrapping arithmetic:** `wrapping_add`, `wrapping_sub`, `wrapping_mul` intentionally bypass the overflow check and always wrap. These must be reviewed for intent.
- **Casting:** `as` casts (e.g., `u128 as u64`) silently truncate in all modes regardless of the overflow flag. Use `u64::try_from(value)?` instead.
- **Division:** Division by zero panics regardless of overflow settings. The overflow check flag does not help here; use `.checked_div()` where the divisor may be zero.
- **Floating-point arithmetic:** Solana programs should not use floating-point; the BPF target does not guarantee IEEE 754 behaviour. Use integer or fixed-point arithmetic instead.

### Framework-Specific Arithmetic Utilities

Anchor does not provide its own checked math utilities beyond enabling the Rust overflow flag. Developers should use Rust's standard `.checked_add()`, `.checked_sub()`, `.checked_mul()`, `.checked_div()`, and `.saturating_*` variants when expressing intent around edge cases, even with the overflow flag enabled, to make correctness explicit and auditable.

---

## 8. QEDSpec Clause Mapping

| Property | Section | QEDSpec Clause Type | Rationale |
|---|---|---|---|
| Account ownership (`Account<T>`) | 1.1 | `guard` | Pre-execution, account property: owner == program_id |
| Discriminator check | 1.2 | `guard` | Pre-execution, account property: data[..8] == discriminator |
| Signer check (`Signer<T>`) | 1.3 | `guard` | Pre-execution, account property: is_signer == true |
| Program identity (`Program<T>`) | 1.4 | `guard` | Pre-execution, account property: key == T::id() |
| PDA derivation (`seeds`, `bump`) | 1.5 | `guard` | Pre-execution, account key derived from seeds |
| `has_one` equality | 1.7 | `guard` | Pre-execution, field equality between account data and another account key |
| Authority binding (business logic) | 2.1 | `guard` | Pre-execution: stored authority == signer key |
| Distinct mutable accounts | 2.2 | `requires` | Pre-execution, value property: from.key != to.key |
| Canonical bump | 2.3 | `guard` | Pre-execution: stored bump == find_program_address canonical bump |
| Post-CPI state consistency | 2.4 | `invariant` | Throughout execution: vault balance invariant maintained across CPI |
| Token mint-account binding | 2.5 | `guard` | Pre-execution: token_account.mint == expected_mint.key() |
| Sysvar authenticity | 2.6 | `guard` | Pre-execution: clock.key() == Clock::id() |
| Reinitialization guard | 6 | `requires` | Pre-execution, value property: is_initialized == false |
| Closure lamport drain | 6 | `ensures` | Post-execution: account.lamports == 0 |
| Closure discriminator overwrite | 6 | `ensures` | Post-execution: account.data[..8] == CLOSED_ACCOUNT_DISCRIMINATOR |
| Authority established on init | 6 | `establishes` | First creation: account.authority == authority.key() |
| Balance invariant | 7 | `invariant` | Throughout: sum of all balances == constant (no creation from air) |
| Overflow-free arithmetic | 7 | `invariant` | Throughout: all arithmetic results within type bounds |

---

## 9. Common Audit Findings in This Framework

### 9.1 `missing_signer_check`

**Why common in Anchor:** Anchor's `Account<'info, T>` provides ownership and discriminator automatically, giving developers false confidence that all necessary checks are handled. They add `Signer<'info>` to the correct field for the transaction signature but omit binding the signer to the stored authority field in the account. The program accepts any signer, not just the account owner.

**Framework feature contributing:** The separation between type-level checks (`Account`, `Signer`) and business-logic checks (`has_one`, `constraint`) is not visually obvious in a constraint block. Developers focus on making the types compile rather than cross-referencing stored authority fields.

**Gap analysis detection:** Any instruction that mutates state controlled by an `authority: Pubkey` field inside an account must have a corresponding `has_one = authority` constraint AND that `authority` must be typed as `Signer<'info>`. Flag any handler that writes to a field under authority control where either check is missing.

---

### 9.2 `arbitrary_cpi`

**Why common in Anchor:** Anchor provides a safe `Program<'info, Token>` wrapper and typed CPI module functions. However, developers who use raw `invoke()` from `solana_program`, or who pass a generic `AccountInfo` as the program target, bypass the program ID check entirely. This is particularly common in programs that want to support multiple token programs (SPL Token vs Token-2022) and use an `AccountInfo` for the token program to allow both.

**Framework feature contributing:** Anchor does not enforce that CPI targets use `Program<'info, T>`. The `Interface<'info, T>` type exists for multi-program interfaces (e.g., `TokenInterface`) but requires explicit use; `AccountInfo` is silently accepted everywhere.

**Gap analysis detection:** Any `invoke()` or `invoke_signed()` call where the first argument's program key comes from an `AccountInfo`-typed account field (rather than a `Program` or `Interface` typed field) is a candidate for arbitrary CPI. Flag if no `require_keys_eq!` or `constraint` on the program key is present.

---

### 9.3 `insecure_initialisation`

**Why common in Anchor:** The `init_if_needed` feature is intended for convenience but disables reinitialization protection. Developers enable it without adding compensating guards. Additionally, some programs implement initialization via custom logic that doesn't use `init`, relying on a boolean flag — and either forget the flag or check it after modifying state.

**Framework feature contributing:** `init_if_needed` requires an opt-in Cargo feature, suggesting it is "fine to use when you need it," without making the security implications explicit at the call site.

**Gap analysis detection:** Any `#[account(init_if_needed, ...)]` field without a corresponding `require!(!account.is_initialized, ...)` or equivalent guard in the handler body is vulnerable. Also flag any handler named `initialize` that uses `Account<'info, T>` without `init` and lacks a discriminator check or initialized-flag check.

---

### 9.4 `lifecycle_violation` (Account Revival / Zombie Accounts)

**Why common in Anchor:** Developers who implement account closure manually (outside of the `close` constraint) often only drain lamports without writing the `CLOSED_ACCOUNT_DISCRIMINATOR`. The account appears closed (zero lamports) but its data and discriminator remain intact. Within the same transaction, another instruction can deposit lamports and re-use the "closed" account as if it were live.

**Framework feature contributing:** The `close` constraint is the correct idiomatic approach, but its multi-step atomic behavior (lamport transfer + zero + discriminator overwrite + owner reassign) is not obvious. The intermediate "insecure" patterns (zero lamports, zero data but no discriminator) fail silently.

**Gap analysis detection:** Any instruction that manually transfers lamports from an account to zero without also writing `CLOSED_ACCOUNT_DISCRIMINATOR` at offset 0 is vulnerable. Flag account-draining patterns that do not use the `close` constraint or do not call the equivalent atomic sequence.

---

### 9.5 `permissionless_state_write` (PDA Sharing)

**Why common in Anchor:** Anchor's ergonomic `seeds` constraint makes PDA derivation simple. Developers choose seed sets that are convenient (e.g., just the mint address for a pool) without reasoning about uniqueness per user. The resulting shared PDA can be used by any user to authorize withdrawals from a shared pool.

**Framework feature contributing:** Anchor does not validate that seed sets are user-unique or that the same PDA cannot be used to authorize access across multiple distinct entities. The framework only checks that the provided seeds derive the provided account — not that the seeds are adequately scoped.

**Gap analysis detection:** Any pool, vault, or authority PDA where the seeds do not include a user-specific component (user pubkey, wallet address, unique identifier) and where the PDA is used to sign a token transfer or privileged mutation should be flagged as a potential PDA sharing vulnerability.

---

---

# EMBEDDING-OPTIMIZED VERSION

*Each chunk below is independently understandable and begins with framework, topic, and applies-to fields for semantic retrieval.*

---

```
Framework: Anchor
Topic: Account Ownership Verification (Account<T>)
Applies to: All instructions using Account<'info, T> typed fields

Account<'info, T> verifies account.info.owner == T::owner() before deserializing account data. T::owner() returns the program ID declared by declare_id! in the same crate when T uses #[account]. This check runs during Accounts::try_accounts before any instruction handler logic executes. It also rejects accounts owned by the System Program with zero lamports (uninitialized). What it does NOT check: the account's pubkey/address. A differently-addressed but correctly-owned account passes this check. Using UncheckedAccount<'info> removes ownership enforcement entirely. The Anchor CLI requires a /// CHECK: comment on any UncheckedAccount field or anchor build fails, but this is a documentation gate, not a runtime safety gate.
```

---

```
Framework: Anchor
Topic: Account Discriminator and Type Safety (#[account] macro)
Applies to: All instructions using Account<'info, T> where T is annotated with #[account]

The #[account] macro computes an 8-byte discriminator as sha256("account:<TypeName>")[..8] and prepends it to serialized account data. try_deserialize verifies this discriminator before reading any field data, returning AccountDiscriminatorMismatch if they differ. This prevents type confusion: an account of type Metadata cannot be passed where Vault is expected even if both structs have identical field layouts. The discriminator check can be bypassed by: (1) calling try_deserialize_unchecked; (2) using UncheckedAccount with manual deserialization; (3) calling AccountLoader::load_unchecked on zero-copy accounts. All-zero custom discriminators (#[account(discriminator = 0)]) are explicitly rejected by the compiler as they are indistinguishable from newly allocated accounts.
```

---

```
Framework: Anchor
Topic: Signer Verification (Signer<'info>)
Applies to: All instructions requiring transaction signature from a specific account

Signer<'info> verifies account_info.is_signer == true at constraint time before the handler runs. #[account(signer)] on an UncheckedAccount performs the same check. What Signer does NOT check: whether the signer is the correct authority for the operation. Business-logic authority binding requires a separate has_one = authority constraint that verifies the signer's key matches a stored authority field in another account. Missing the has_one constraint while only having Signer means any signer can trigger the instruction, not just the account owner.
```

---

```
Framework: Anchor
Topic: Program Identity Verification (Program<'info, T>)
Applies to: All instructions that perform CPI or interact with known on-chain programs

Program<'info, T> verifies account.key == T::id() and account.executable == true before the handler. This prevents arbitrary CPI by ensuring the program passed as a parameter is actually the expected program. Typed CPI module functions generated from declare_program! use this enforcement automatically. Using AccountInfo<'info> as the program type instead removes this check. Interface<'info, T> is the multi-program equivalent (e.g., TokenInterface for SPL Token / Token-2022 compatibility) and should be preferred over AccountInfo when supporting multiple program variants.
```

---

```
Framework: Anchor
Topic: PDA Derivation Verification (seeds, bump constraints)
Applies to: All instructions accessing Program Derived Addresses

#[account(seeds = [...], bump)] calls Pubkey::find_program_address with the given seeds, verifies the result matches the account's key, and surfaces the canonical bump via ctx.bumps.<field_name>. #[account(seeds = [...], bump = account.bump)] uses Pubkey::create_program_address with the stored bump — more compute-efficient and avoids the find_program_address loop. The canonical bump is the numerically highest valid bump (the one find_program_address returns). Accepting a user-supplied bump via instruction arguments and calling create_program_address directly (without find_program_address comparison) is a canonicalization attack vector — an attacker may supply a non-canonical bump that still derives to the target address. Store the canonical bump in account data during init: account.bump = ctx.bumps.account_field; and use it in all subsequent validations.
```

---

```
Framework: Anchor
Topic: has_one Constraint — Cross-Account Field Equality
Applies to: Any instruction where stored authority, mint, or other relational fields must match accounts in context

#[account(has_one = target)] verifies self_account.target == ctx.accounts.target.key(). This binds a public key stored inside an account's data to another account present in the instruction context. It is the primary mechanism for authority binding: to ensure that the Signer in the instruction is the stored authority on the account, both has_one = authority AND authority: Signer<'info> must be present. has_one alone does not check signer status. Signer alone does not check authority binding. Omitting has_one while keeping only Signer<'info> allows any signer to perform authority-gated operations.
```

---

```
Framework: Anchor
Topic: Missing Authority Binding — Account Data Matching Vulnerability
Applies to: Withdraw, transfer, update, and any state-mutating instructions

The most common Anchor audit finding. A developer declares authority: Signer<'info> (enforces transaction signature) but omits has_one = authority on the account (does not enforce that the signer is the stored authority). Any valid Solana keypair can then sign the transaction and trigger the instruction against any account. Correct pattern: #[account(mut, has_one = authority)] on the account and authority: Signer<'info> in the struct. QEDSpec: guard: account.authority == authority.key(). Kani assertion: kani::assert!(ctx.accounts.account.authority == ctx.accounts.authority.key(), "authority mismatch");
```

---

```
Framework: Anchor
Topic: Arbitrary CPI — Unvalidated Program Target
Applies to: Any instruction that performs a CPI to a token program, DEX, or other external program

When the CPI target is typed as AccountInfo<'info>, Anchor performs no program ID check. An attacker can substitute a malicious program at a different address. Prevention: use Program<'info, Token> for SPL Token CPIs (enforces spl_token::ID), use Interface<'info, TokenInterface> for Token-2022 compatible CPIs. For non-standard programs: add #[account(address = EXPECTED_PROGRAM_ID)] or require_keys_eq!(ctx.accounts.program.key(), &EXPECTED_ID). Anchor's CPI module functions (generated via declare_program!) build instructions with correct discriminators and enforce typed accounts; prefer these over raw invoke(). QEDSpec: guard: token_program.key() == spl_token::ID.
```

---

```
Framework: Anchor
Topic: Bump Seed Canonicalization Vulnerability
Applies to: Any instruction that validates or creates PDAs using user-supplied bump values

Pubkey::create_program_address accepts any valid bump (0-255); Pubkey::find_program_address returns only the canonical (highest valid) bump. If a developer accepts a bump as an instruction argument and uses create_program_address without comparing the result to find_program_address, the canonical constraint is lost. The correct Anchor pattern: use #[account(seeds = [...], bump)] which calls find_program_address internally. During init, store the canonical bump: account.bump = ctx.bumps.field_name. For later validations, use #[account(seeds = [...], bump = account.bump)] to avoid the find loop and enforce the stored canonical value. QEDSpec: guard: pda.key() == find_program_address(seeds, program_id).address.
```

---

```
Framework: Anchor
Topic: PDA Sharing — Over-Broad Seed Sets
Applies to: Pool, vault, and any PDA used as a shared authority

A PDA derived from seeds that do not include a user-specific component (e.g., seeds = [b"pool", mint.key().as_ref()]) creates a shared authority for all users of that mint. Any user who knows the derivation can satisfy the seeds constraint and authorize operations on any user's assets. Prevention: include user-specific identifiers in seeds: seeds = [b"pool", mint.key().as_ref(), owner.key().as_ref()]. Add has_one constraints to bind the PDA's stored withdraw_destination and vault to the accounts in context. QEDSpec: guard: pool.withdraw_destination == withdrawal_destination.key() AND pool.vault == pool_token_account.key().
```

---

```
Framework: Anchor
Topic: Type Cosplay via Raw Deserialization
Applies to: Any instruction using AccountInfo or UncheckedAccount with manual borsh deserialization

When a developer uses AccountInfo and calls T::try_from_slice directly instead of Account<'info, T>, no discriminator check is performed. Two structs with the same field layout (e.g., User { authority: Pubkey } and Metadata { account: Pubkey }) are interchangeable. An attacker can pass a Metadata account where a User account is expected, pass the owner check (same program), pass the layout deserialization (same bytes), and falsify authority. Prevention: always use Account<'info, T> which calls try_deserialize with the discriminator check. QEDSpec: guard: account.data[..8] == sha256("account:User")[..8].
```

---

```
Framework: Anchor
Topic: Insecure Account Closure — Revival Attack
Applies to: Any instruction that closes or "burns" an account

A manual account closure that only drains lamports (sets lamports to 0) without zeroing data and writing CLOSED_ACCOUNT_DISCRIMINATOR ([0xff; 8]) is vulnerable to revival. Within the same transaction, another instruction can re-fund the account with lamports and use it as if it were live, since the discriminator is intact. Anchor's close constraint atomically: (1) transfers lamports to destination; (2) zeroes all data; (3) writes CLOSED_ACCOUNT_DISCRIMINATOR; (4) reassigns owner to System Program. Use #[account(mut, close = destination)] on the field. Any manual closure that skips the discriminator overwrite step is incomplete. QEDSpec: ensures: account.lamports == 0; ensures: account.data[..8] == CLOSED_ACCOUNT_DISCRIMINATOR.
```

---

```
Framework: Anchor
Topic: init_if_needed — Reinitialization Attack
Applies to: Any instruction using #[account(init_if_needed, ...)]

init_if_needed disables the reinitialization protection of init. An account that already exists passes through the init_if_needed path, allowing the instruction handler to overwrite authority, owner, or other critical fields. This is intentional by design but dangerous without a compensating guard. Required compensating pattern: check an is_initialized boolean flag at the start of the handler and reject the instruction if the flag is already true. The flag must be set to true during the first initialization. Avoid init_if_needed in security-sensitive contexts; prefer separate initialize and use instructions. QEDSpec: requires: data.is_initialized == false; establishes: data.authority == authority.key(); establishes: data.is_initialized == true.
```

---

```
Framework: Anchor
Topic: Duplicate Mutable Accounts
Applies to: Any instruction that accepts two mutable accounts of the same type (e.g., from/to, source/destination)

Anchor does not compare accounts against each other for key equality. If a caller passes the same account in two mutable slots (e.g., from and to in a transfer), the instruction will write the second mutation over the first, producing incorrect state. This is especially dangerous in token transfer instructions where from.amount -= x is then overwritten by to.amount += x. Detection: any instruction with two Account<'info, T> fields both marked mut where one is used as a source and one as a destination must include require_keys_neq!(from.key(), to.key(), ErrorCode::SameAccount). QEDSpec: requires: from.key() != to.key().
```

---

```
Framework: Anchor
Topic: Overflow Checks and Arithmetic Safety
Applies to: All arithmetic operations in instruction handlers

Anchor's anchor init scaffolding adds overflow-checks = true under [profile.release] in the workspace Cargo.toml, causing integer overflow to panic in release builds (matching debug behavior). The Anchor CLI enforces this flag is explicitly present; anchor build fails if absent. What is NOT protected: wrapping_add/wrapping_sub/wrapping_mul intentionally bypass the flag. as casts (e.g., u128 as u64) silently truncate regardless of the flag — use u64::try_from(value)? instead. Division by zero panics regardless. Floating-point arithmetic is unsupported on BPF; use integer or fixed-point instead. Use .checked_div() when divisor may be zero. QEDSpec: invariant: all arithmetic results within type bounds.
```

---

```
Framework: Anchor
Topic: Sysvar Authenticity — Anchor vs Manual Deserialization
Applies to: Instructions that read Clock, Rent, SlotHashes, or other sysvars

Anchor's Sysvar<'info, Clock> verifies that the account key equals the canonical sysvar address (Clock::id()) before allowing access. If a developer uses UncheckedAccount and manually deserializes a sysvar, no address check is performed. An attacker can supply a fake account with the correct data layout but a wrong address, feeding the program a falsified timestamp or rent schedule. Prevention: use Sysvar<'info, Clock> typed field, or use Clock::get() which reads directly from the runtime without an account argument. QEDSpec: guard: clock_account.key() == Clock::id().
```

---

```
Framework: Anchor
Topic: CPI Trust Boundaries — What Anchor Verifies vs Developer Responsibility
Applies to: All instructions performing cross-program invocations

Anchor verifies (via Program<'info, T>): CPI target key == T::id() AND target.executable == true, before the instruction handler runs. Anchor does NOT verify: the CPI target has not been upgraded to a malicious version; accounts passed within the CPI are correctly ordered or typed for the callee; state changes made by the callee to shared accounts are re-read after the CPI. Developer must: use .reload() on any account modified by a CPI before reading its state again; validate all program IDs for programs not covered by typed Program<'info, T>; never pass extra signer privileges (with_signer seeds) that grant more authority than the specific operation requires.
```

---

```
Framework: Anchor
Topic: Account Lifecycle — init, init_if_needed, close, and State Machines
Applies to: All instructions that create, use, or close Anchor accounts

Anchor tracks two lifecycle states: account exists (init creates it) and account is closed (close constraint destroys it). Application-level state machines (e.g., Draft → Active → Settled) are entirely the developer's responsibility. Common findings: (1) reinitialization — use init (not init_if_needed) and never allow authority fields to be overwritten; (2) zombie accounts — accounts closed by draining lamports but not discriminator-zeroed can be revived; (3) missing state guards — an instruction valid only in Active state but callable in Draft state because no enum/flag check guards the transition. Store lifecycle state as an enum field and use require!(account.state == ExpectedState, ...) at the start of each handler.
```

---

```
Framework: Anchor
Topic: Common Audit Finding — missing_signer_check
Applies to: All state-mutating instructions

Root cause in Anchor: Account<'info, T> provides ownership + discriminator but NOT signer enforcement. Developers add Signer<'info> for the transaction signature but omit has_one = authority to bind the signer to the stored authority field. Detection: find every account struct field typed Account<'info, T> where T has an authority: Pubkey field. Check that the instruction context has a corresponding Signer<'info> field AND a has_one = authority constraint on the account. If either is missing, flag missing_signer_check.
```

---

```
Framework: Anchor
Topic: Common Audit Finding — arbitrary_cpi
Applies to: All instructions calling external programs

Root cause in Anchor: AccountInfo<'info> is accepted anywhere as a program parameter with no ID check. Common scenario: supporting both SPL Token and Token-2022 by using AccountInfo for the token program instead of Interface<'info, TokenInterface>. Detection: scan for any account field typed AccountInfo or UncheckedAccount used as the first argument to invoke(), invoke_signed(), or as the program in a CpiContext::new(). Flag if no address = ..., require_keys_eq!, or constraint on that field's key exists.
```

---

```
Framework: Anchor
Topic: Common Audit Finding — insecure_initialisation
Applies to: All initialization instructions

Root cause in Anchor: init_if_needed disables single-use guarantee. Also: custom init handlers that don't use init constraint and forget the initialized-flag guard. Detection: (1) any #[account(init_if_needed)] field without a matching require!(!account.is_initialized) in the handler; (2) any handler named initialize or init that uses Account<'info, T> without init constraint and does not check a boolean or enum initialization flag; (3) any handler that sets account.authority = ... without first verifying the account was not previously initialized.
```

---

```
Framework: Anchor
Topic: Common Audit Finding — lifecycle_violation (Account Revival)
Applies to: All instructions that close accounts

Root cause in Anchor: developers copy the lamport-draining pattern from examples but omit the discriminator overwrite. Three progressive insecure patterns exist: (1) drain lamports only; (2) drain + zero data but no discriminator write; (3) drain + zero + zero discriminator (all-zero discriminator is also bypassed by zeroed new accounts). Only #[account(mut, close = destination)] or the full manual sequence (drain + zero + write CLOSED_ACCOUNT_DISCRIMINATOR + reassign owner to System Program) is safe. Detection: any manual lamport transfer setting account lamports to zero without a subsequent write of [0xff;8] at data offset 0.
```

---

```
Framework: Anchor
Topic: Common Audit Finding — permissionless_state_write (PDA Sharing)
Applies to: Pool, vault, staking, and any shared-authority PDA instructions

Root cause in Anchor: ergonomic seeds constraint encourages minimal seed sets. A PDA seeded only on a global identifier (e.g., mint address) becomes a shared authority for all users. Detection: for any PDA used to sign token transfers or privileged mutations, inspect the seeds. If no user-specific component (owner pubkey, wallet, unique ID) is present in the seeds, flag as pda_sharing / permissionless_state_write. Also check that has_one constraints bind all stored relationship fields (vault, withdraw_destination) to the accounts in the instruction context.
```