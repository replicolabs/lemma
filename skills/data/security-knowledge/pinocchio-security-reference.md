# Pinocchio Framework — Security Reference Document (Lemma Edition)

> Framework: Pinocchio (Solana)
> Source material: anza-xyz/pinocchio source, vict0rcarvalh0 Pinocchio guide, helius-pinocchio-blog, account-patterns.md, edge-cases.md, SKILL.md, SKILL_ONE.md, migration-from-anchor.md, en.mdx, README.md
> Purpose: Embedded in a vector database; retrieved during static analysis of Pinocchio programs by Lemma.
> Every sentence is directly security-relevant. No installation, CLI, or performance content.

---

## 1. Automatic Security Enforcement

Pinocchio provides **zero automatic security enforcement** on accounts. Unlike Anchor, there are no procedural macros, no `Account<T>` wrapper types, no constraint attributes, and no derive-based validation. Every security property — ownership, signer status, discriminator, PDA derivation, writability, program identity, sysvar addresses — must be checked explicitly by the developer in their `TryFrom` implementation or instruction handler. The framework's only automatic behavior is delivering the raw account slice to the entrypoint.

### 1.1 Entrypoint Input Parsing (Not a Security Guarantee)

**Property name:** Raw byte delivery

**What it enforces precisely:** Pinocchio's `entrypoint!` macro delivers three arguments to `process_instruction`: `program_id: &Pubkey`, `accounts: &[AccountInfo]`, and `instruction_data: &[u8]`. The accounts are presented in the order the client provided them. The runtime's own account model enforces that writable accounts are flagged as writable by the transaction, and that signer accounts have valid signatures on the transaction — but Pinocchio does not surface these as type-level checks.

**What it does NOT enforce:** Pinocchio does not check ownership, discriminator, signer status (beyond the runtime's signature validation), PDA derivation, account size, or any relationship between accounts. All of these are the developer's responsibility.

**Which account type triggers this enforcement:** None — `AccountInfo` is the sole account type in Pinocchio and carries no automatic enforcement.

**What happens if `AccountInfo` is used without checks:** The program will operate on any account the caller supplies. An attacker who controls all supplied accounts can feed the program arbitrary data, leading to ownership bypass, type confusion, signer bypass, and PDA spoofing simultaneously.

---

### 1.2 Runtime-Level Signature Verification (External to Framework)

**Property name:** Transaction signature validity

**What it enforces precisely:** The Solana runtime verifies that every account marked `is_signer = true` in the transaction has a valid Ed25519 signature covering the transaction. This is enforced before the program entrypoint is called. Pinocchio exposes this flag via `account.is_signer()`.

**What it does NOT enforce:** The runtime does not verify that the correct account is the signer — only that whoever is marked as a signer did sign. Whether that signer is the expected authority for the operation is a business-logic check the developer must perform explicitly.

**Trigger:** Automatic, runtime-level.

---

### 1.3 Runtime-Level Writability Enforcement

**Property name:** Write flag enforcement

**What it enforces precisely:** The Solana runtime prevents programs from writing to an account that was not marked writable in the transaction. An attempt to borrow mutable data on a non-writable account will fail at the runtime level.

**What it does NOT enforce:** Pinocchio does not check that mutable accounts ARE marked writable before the handler tries to write them. Failing to assert `account.is_writable()` in the `TryFrom` validation means a malformed instruction that passes a read-only account in a mutable position will be caught only when the write occurs, not at the validation boundary where the error should surface.

**Trigger:** Automatic, runtime-level — but the developer should assert writability explicitly in `TryFrom` for defense-in-depth and early error reporting.

---

### 1.4 `invoke_signed_unchecked` — Explicit Unsafe CPI

**Property name:** CPI borrow safety

**What it enforces precisely:** Pinocchio's internal CPI implementations (e.g., `Transfer::invoke_signed`, `CreateAccount::invoke_signed`) check `account.is_borrowed()` before building the CPI instruction view. If an account is currently mutably borrowed, these implementations return `ProgramError::AccountBorrowFailed` before the CPI is issued.

**What it does NOT enforce:** This check guards against re-entrant borrow conflicts only. It does not validate the program ID being invoked, the account ordering, or whether the accounts being passed have the correct properties for the callee. When `invoke_signed_unchecked` is called directly (used internally in low-level Pinocchio CPI structs with safety comments), all borrow and memory safety guarantees are the caller's responsibility.

**Trigger:** `invoke_signed_unchecked` is explicitly `unsafe` and used with `// SAFETY:` comments in the anza-xyz/pinocchio source. Developer-facing CPI helpers (e.g., `Transfer { ... }.invoke()`) expose the safe variant.

---

## 2. Developer Responsibilities

### 2.1 Account Ownership Check

**Property name:** Program ownership verification

**Why the framework does not handle it:** Pinocchio has no `Account<T>` wrapper. `AccountInfo` is a raw view of account metadata. Any account can be passed in any position.

**Correct pattern:**
```rust
impl<'a> TryFrom<&'a [AccountInfo]> for DepositAccounts<'a> {
    type Error = ProgramError;
    fn try_from(accounts: &'a [AccountInfo]) -> Result<Self, Self::Error> {
        let [owner, vault, _system_program, ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        // Ownership check: vault must be owned by this program
        if vault.owner() != &crate::ID {
            return Err(ProgramError::IllegalOwner);
        }
        // ...
        Ok(Self { owner, vault })
    }
}
```

**Incorrect pattern developers commonly write:**
```rust
// Missing ownership check — any account passes
fn process_deposit(accounts: &[AccountInfo]) -> ProgramResult {
    let vault = &accounts[0]; // Assumed to be owned by this program
    let data = vault.try_borrow_data()?;
    // Attacker supplied a fake account with identical data layout
    // Program proceeds with malicious data
    Ok(())
}
```

---

### 2.2 Signer Check

**Property name:** Authority signature enforcement

**Why the framework does not handle it:** There is no `Signer<'info>` type. `AccountInfo.is_signer()` is a getter that must be called explicitly.

**Correct pattern:**
```rust
if !authority.is_signer() {
    return Err(ProgramError::MissingRequiredSignature);
}
// AND: bind the signer to the stored authority field
let data = vault.try_borrow_data()?;
if data[AUTHORITY_OFFSET..AUTHORITY_OFFSET + 32] != authority.key().to_bytes() {
    return Err(ProgramError::InvalidAccountData);
}
```

**Incorrect pattern:**
```rust
// Signer check exists but authority binding is missing
if !authority.is_signer() {
    return Err(ProgramError::MissingRequiredSignature);
}
// Missing: does this signer match vault.authority?
// Any valid signer can perform this privileged operation
```

---

### 2.3 Discriminator Check (Type Safety)

**Property name:** Account type discrimination

**Why the framework does not handle it:** Pinocchio has no `#[account]` macro and no automatic discriminator. The developer must define and enforce their own discriminator scheme.

**Correct pattern (single-byte discriminator — the idiomatic Pinocchio approach):**
```rust
pub const VAULT_DISCRIMINATOR: u8 = 1;

pub fn from_account_info(account: &AccountInfo) -> Result<&Self, ProgramError> {
    let data = account.try_borrow_data()?;
    if data.len() < Self::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    if data[0] != VAULT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(bytemuck::from_bytes(&data[..Self::LEN]))
}
```

**Incorrect pattern:**
```rust
// No discriminator check — any account with the right size passes
pub fn from_account_info(account: &AccountInfo) -> Result<&Self, ProgramError> {
    let data = account.try_borrow_data()?;
    if data.len() < Self::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(bytemuck::from_bytes(&data[..Self::LEN])) // Type confusion possible
}
```

---

### 2.4 PDA Derivation Verification

**Property name:** PDA address authenticity

**Why the framework does not handle it:** There is no `seeds`/`bump` constraint attribute. PDA validation must use `Pubkey::find_program_address` or `Pubkey::create_program_address` manually.

**Correct pattern:**
```rust
// Verify PDA using stored canonical bump (preferred — avoids find loop)
let expected = Pubkey::create_program_address(
    &[b"vault", owner.key().as_ref(), &[vault_data.bump]],
    &crate::ID,
).map_err(|_| ProgramError::InvalidSeeds)?;
if vault.key() != &expected {
    return Err(ProgramError::InvalidSeeds);
}
```

**Incorrect pattern:**
```rust
// Accepting user-supplied bump directly — canonicalization bypass
pub fn process(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let user_bump = data[0];
    let vault = &accounts[0];
    let owner = &accounts[1];
    // Attacker supplies non-canonical bump that still derives to vault address
    let addr = Pubkey::create_program_address(
        &[b"vault", owner.key().as_ref(), &[user_bump]], &crate::ID
    )?;
    if vault.key() != &addr { return Err(ProgramError::InvalidSeeds); }
    // Proceeds with non-canonical bump — future exploits possible
    Ok(())
}
```

---

### 2.5 Sysvar Address Validation

**Property name:** Sysvar authenticity

**Why the framework does not handle it:** Pinocchio does NOT implicitly validate sysvar account addresses. Unlike Anchor's `Sysvar<'info, Clock>`, passing a `Clock`-shaped account at the wrong address is not caught by any framework type. The safe pattern is to use `Clock::get()` / `Rent::get()` which read directly from the runtime without accepting an account argument.

**Correct pattern:**
```rust
use pinocchio::sysvars::{clock::Clock, rent::Rent, Sysvar};
let clock = Clock::get()?;     // runtime syscall — no account needed, no spoofing possible
let rent = Rent::get()?;       // same
```

**Incorrect pattern:**
```rust
// Accepting sysvar as AccountInfo without address check
let clock_account = &accounts[2]; // Could be any account
let clock: Clock = unsafe { *(clock_account.try_borrow_data()?.as_ptr() as *const Clock) };
// Attacker-supplied fake clock with manipulated timestamp
```

---

### 2.6 Program Identity Check for CPI

**Property name:** CPI target authenticity

**Why the framework does not handle it:** Pinocchio provides no `Program<'info, T>` type. All CPI targets are raw `AccountInfo` or `Address` values.

**Correct pattern:**
```rust
// Check token program key before any CPI
if token_program.key() != &pinocchio_token::ID {
    return Err(ProgramError::IncorrectProgramId);
}
// OR: use the typed CPI struct which embeds the program ID
Transfer {
    from: source,
    to: destination,
    authority: owner,
    amount,
}.invoke()?; // pinocchio_token::Transfer always CPIs to pinocchio_token::ID
```

**Incorrect pattern:**
```rust
// Passing program AccountInfo directly to raw invoke without ID check
pinocchio::program::invoke(
    &instruction,
    &[source, destination, authority, token_program], // token_program unchecked
)?;
```

---

### 2.7 Canonical Bump Storage and Reuse

**Property name:** Canonical bump persistence

**Why the framework does not handle it:** Pinocchio has no `ctx.bumps` accessor. The canonical bump must be derived via `find_program_address` during initialization, stored in account data, and used in subsequent validations via `create_program_address`.

**Correct pattern:**
```rust
// During init: derive canonical bump and store it
let (expected_pda, canonical_bump) =
    Pubkey::find_program_address(&[b"vault", owner.key().as_ref()], &crate::ID);
if vault.key() != &expected_pda { return Err(ProgramError::InvalidSeeds); }
vault_data.bump = canonical_bump; // store for later

// During use: validate using stored bump (no find loop)
let expected = Pubkey::create_program_address(
    &[b"vault", owner.key().as_ref(), &[vault_data.bump]], &crate::ID
)?;
if vault.key() != &expected { return Err(ProgramError::InvalidSeeds); }
```

**Incorrect pattern:**
```rust
// Calling find_program_address on every invocation (expensive) OR
// not storing the bump and re-deriving with a user-supplied value
```

---

### 2.8 Account Closure (Revival Attack Prevention)

**Property name:** Safe account closure with discriminator invalidation

**Why the framework does not handle it:** Pinocchio has no `close = destination` constraint. Account closure must be implemented manually in three steps: (1) drain lamports, (2) set the first byte to `0xff` (sentinel "closed" discriminator), (3) resize to 1 byte via `realloc` and call `account.close()`.

**Correct pattern (from en.mdx / pinocchio guide):**
```rust
pub fn close(account: &AccountInfo, destination: &AccountInfo) -> ProgramResult {
    // 1. Mark as closed BEFORE draining lamports to prevent revival reads
    {
        let mut data = account.try_borrow_mut_data()?;
        data[0] = 0xff; // sentinel "closed" discriminator
    }
    // 2. Transfer lamports to destination
    *destination.try_borrow_mut_lamports()? += *account.try_borrow_lamports()?;
    // 3. Resize and close (zeroes remaining data)
    account.realloc(1, true)?;
    account.close()
}
```

**Incorrect patterns (three levels of insecurity):**
```rust
// Insecure 1: Only lamport drain — data and discriminator intact, revivable
**destination.try_borrow_mut_lamports()? += account.lamports();
**account.try_borrow_mut_lamports()? = 0;
// Discriminator still valid — account can be "reopened" in same transaction

// Insecure 2: Drain + zero data — but no sentinel discriminator
// An all-zero discriminator can be confused with a fresh uninitialized account

// Insecure 3: Lamports drained but realloc/close not called
// Account data persists on-chain with stale state
```

---

### 2.9 Reinitialization Prevention

**Property name:** Single-use initialization guard

**Why the framework does not handle it:** Pinocchio has no `init` constraint. The developer must manually check the discriminator byte before initializing to ensure the account is not already in use.

**Correct pattern:**
```rust
pub fn process_initialize(accounts: &[AccountInfo]) -> ProgramResult {
    let vault = &accounts[0];
    // Check: if discriminator is already set, account is initialized
    {
        let data = vault.try_borrow_data()?;
        if !data.is_empty() && data[0] == VAULT_DISCRIMINATOR {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
    }
    // Proceed with initialization via CreateAccount CPI
    // ...
    Ok(())
}
```

**Incorrect pattern:**
```rust
// No initialization guard — attacker calls initialize() on existing account
pub fn process_initialize(accounts: &[AccountInfo]) -> ProgramResult {
    let vault = &accounts[0];
    let vault_data = Vault::from_account_mut(vault)?; // overwrites existing data!
    vault_data.authority = authority.key().to_bytes();
    Ok(())
}
```

---

### 2.10 Lamport Griefing on PDA Init

**Property name:** Pre-funded PDA initialization safety

**Why the framework does not handle it:** Pinocchio performs no automatic lamport reconciliation. If an attacker sends lamports to a PDA before initialization, and the program attempts to create the account with an exact rent-exempt amount, the `Allocate` + `Assign` CPI will fail because the account already has lamports.

**Correct pattern:**
```rust
let required = Rent::get()?.minimum_balance(space);
let existing = vault.lamports();
if existing < required {
    Transfer {
        from: payer,
        to: vault,
        lamports: required - existing, // deficit only
    }.invoke()?;
}
Allocate { account: vault, space: space as u64 }.invoke_signed(signers)?;
Assign { account: vault, owner: &crate::ID }.invoke_signed(signers)?;
```

**Incorrect pattern:**
```rust
// Always transfers full rent-exempt amount — fails if account already has lamports
Transfer { from: payer, to: vault, lamports: required }.invoke()?;
```

---

### 2.11 Writability / Read-Only Enforcement

**Property name:** Explicit mutability assertion

**Why the framework does not handle it:** Pinocchio makes no assertion that mutable accounts have `is_writable = true`. The runtime will reject writes, but the error will surface deep in the instruction rather than at the account validation boundary.

**Correct pattern (in TryFrom):**
```rust
if !vault.is_writable() {
    return Err(ProgramError::InvalidAccountData);
}
// Optionally also assert authority is NOT writable (defense-in-depth)
if authority.is_writable() {
    return Err(ProgramError::InvalidArgument);
}
```

**Incorrect pattern:**
```rust
// No mutability check — the runtime will catch it eventually,
// but validation boundary is unclear and error messages are harder to debug
```

---

### 2.12 Duplicate Mutable Account Detection

**Property name:** Distinct account identity for mutable pairs

**Why the framework does not handle it:** Pinocchio performs no comparison between accounts for key equality.

**Correct pattern:**
```rust
if from.key() == to.key() {
    return Err(ProgramError::InvalidArgument);
}
```

**Incorrect pattern:**
```rust
// Missing identity check — from and to can be the same account
// Sequential mutations cancel each other, producing incorrect balances
**from.try_borrow_mut_lamports()? -= amount;
**to.try_borrow_mut_lamports()? += amount;
```

---

### 2.13 Batch Instruction — Per-Instruction Ownership Checks

**Property name:** Ownership re-verification per inner instruction in batch mode

**Why the framework does not handle it:** In Pinocchio's batch instruction pattern (discriminator `0xFF`), the runtime enforces ownership only at the end of the batch, not between inner instructions. Some inner instructions that modify accounts without explicit program ownership checks can be exploited by an attacker who constructs a batch with accounts they own.

**Correct pattern:**
```rust
// In each inner instruction handler:
if account.owner() != &crate::ID {
    return Err(ProgramError::IllegalOwner);
}
```

**Incorrect pattern:**
```rust
// Inner instruction omits ownership check assuming the outer batch validated it
// Attacker constructs a batch where account ownership changes mid-batch
```

---

## 3. Framework-Specific Vulnerability Patterns

### 3.1 Missing TryFrom Validation — Silent Acceptance of Any Account

**Pattern name:** Empty validation context (`missing_ownership_check`, `missing_signer_check`)

**What the developer writes:** A `TryFrom` implementation that only destructures the account slice without performing any checks, treating the accounts as validated.

**Why this framework makes it more likely:** Pinocchio's ergonomic `TryFrom` pattern for accounts appears to be a structural safeguard, causing developers to believe that the act of writing a `TryFrom` impl provides security. In Anchor, the struct types enforce checks. In Pinocchio, the struct is only as secure as the checks inside the `TryFrom` body.

**Formal property that should hold but does not:**
`guard: vault.owner == program_id AND authority.is_signer == true AND vault.discriminator == VAULT_DISC`

**Vulnerable code:**
```rust
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};

pub struct WithdrawAccounts<'a> {
    pub vault: &'a AccountInfo,
    pub authority: &'a AccountInfo,
}

impl<'a> TryFrom<&'a [AccountInfo]> for WithdrawAccounts<'a> {
    type Error = ProgramError;
    fn try_from(accounts: &'a [AccountInfo]) -> Result<Self, Self::Error> {
        let [vault, authority, ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        // No checks — any accounts accepted
        Ok(Self { vault, authority })
    }
}
```

**Correct code:**
```rust
impl<'a> TryFrom<&'a [AccountInfo]> for WithdrawAccounts<'a> {
    type Error = ProgramError;
    fn try_from(accounts: &'a [AccountInfo]) -> Result<Self, Self::Error> {
        let [vault, authority, ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        if vault.owner() != &crate::ID { return Err(ProgramError::IllegalOwner); }
        if !authority.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
        {
            let data = vault.try_borrow_data()?;
            if data.len() < Vault::LEN || data[0] != VAULT_DISCRIMINATOR {
                return Err(ProgramError::InvalidAccountData);
            }
            if &data[AUTHORITY_OFFSET..AUTHORITY_OFFSET+32] != authority.key().as_ref() {
                return Err(ProgramError::InvalidAccountData);
            }
        }
        Ok(Self { vault, authority })
    }
}
```

**kani::assert! expression:**
```rust
kani::assert!(vault.owner() == &crate::ID, "vault must be owned by this program");
kani::assert!(authority.is_signer(), "authority must be a signer");
kani::assert!(
    &vault.try_borrow_data().unwrap()[0..1] == &[VAULT_DISCRIMINATOR],
    "vault discriminator must be correct"
);
```

**QEDSpec clause:**
```
guard: vault.owner == program_id
guard: authority.is_signer == true
guard: vault.data[0] == VAULT_DISCRIMINATOR
```

---

### 3.2 Sysvar Spoofing

**Pattern name:** Fake sysvar account (`oracle_validation`)

**What the developer writes:** An `AccountInfo` accepted from the instruction for a sysvar (e.g., `Clock`) and read directly without verifying the account's key.

**Why this framework makes it more likely:** Pinocchio has no `Sysvar<'info, Clock>` type that checks the canonical address. Developers who pass sysvar accounts into instruction handlers are responsible for the address check, but it is non-obvious that this check is needed.

**Formal property that should hold but does not:**
`guard: clock_account.key() == Clock::id()`

**Vulnerable code:**
```rust
use pinocchio::account_info::AccountInfo;
use pinocchio::program_error::ProgramError;

pub fn check_expiry(accounts: &[AccountInfo], expiry_ts: i64) -> ProgramResult {
    let clock_account = &accounts[2]; // No address check!
    // Attacker supplies a fake account at any address with manipulated timestamp
    let timestamp = i64::from_le_bytes(
        clock_account.try_borrow_data()?[32..40].try_into().unwrap()
    );
    if timestamp > expiry_ts {
        return Err(ProgramError::Custom(0)); // bypassed by fake clock
    }
    Ok(())
}
```

**Correct code:**
```rust
use pinocchio::sysvars::{clock::Clock, Sysvar};

pub fn check_expiry(expiry_ts: i64) -> ProgramResult {
    let clock = Clock::get()?; // runtime syscall — no account, no spoofing
    if clock.unix_timestamp > expiry_ts {
        return Err(ProgramError::Custom(0));
    }
    Ok(())
}
```

**kani::assert! expression:**
```rust
// Not applicable to the correct pattern (no account argument)
// For auditing the incorrect pattern:
let clock_key = accounts[2].key();
kani::assert!(
    clock_key == &pinocchio::sysvars::clock::Clock::id(),
    "clock account must be the canonical sysvar address"
);
```

**QEDSpec clause:**
```
guard: clock_account.key() == pinocchio::sysvars::clock::Clock::id()
```

---

### 3.3 Bump Canonicalization via User-Supplied Bump

**Pattern name:** Non-canonical PDA bump (`init_without_pda`)

**What the developer writes:** The developer accepts a `bump: u8` in instruction data and passes it directly to `Pubkey::create_program_address` without calling `find_program_address` to verify it is the canonical bump.

**Why this framework makes it more likely:** Pinocchio has no `bump` constraint that calls `find_program_address` internally. The developer must call it manually. The "optimization" pattern of using `create_program_address` (cheaper than `find`) is valid only when using a previously-stored canonical bump, not a user-supplied one.

**Formal property that should hold but does not:**
`guard: bump == find_program_address(seeds, program_id).1`

**Vulnerable code:**
```rust
pub fn process(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let bump = data[0]; // user-supplied bump
    let vault = &accounts[0];
    let owner = &accounts[1];
    // create_program_address accepts any valid bump — not just canonical
    let addr = Pubkey::create_program_address(
        &[b"vault", owner.key().as_ref(), &[bump]], &crate::ID
    ).map_err(|_| ProgramError::InvalidSeeds)?;
    if vault.key() != &addr { return Err(ProgramError::InvalidSeeds); }
    Ok(())
}
```

**Correct code:**
```rust
// During init: derive and store canonical bump
let (expected, canonical_bump) =
    Pubkey::find_program_address(&[b"vault", owner.key().as_ref()], &crate::ID);
if vault.key() != &expected { return Err(ProgramError::InvalidSeeds); }
vault_data.bump = canonical_bump;

// During use: validate with stored bump only
let expected = Pubkey::create_program_address(
    &[b"vault", owner.key().as_ref(), &[vault_data.bump]], &crate::ID
).map_err(|_| ProgramError::InvalidSeeds)?;
if vault.key() != &expected { return Err(ProgramError::InvalidSeeds); }
```

**kani::assert! expression:**
```rust
let (canonical_addr, canonical_bump) =
    Pubkey::find_program_address(&[b"vault", owner.key().as_ref()], &crate::ID);
kani::assert!(vault.key() == &canonical_addr, "PDA must match canonical derivation");
kani::assert!(stored_bump == canonical_bump, "stored bump must be canonical");
```

**QEDSpec clause:**
```
guard: vault.key() == find_program_address([b"vault", owner.key()], program_id).address
```

---

### 3.4 Incomplete Account Closure — Revival Attack

**Pattern name:** Partial closure leaving valid discriminator (`lifecycle_violation`)

**What the developer writes:** Only draining lamports (setting them to zero) without invalidating the discriminator byte and shrinking/closing the account.

**Why this framework makes it more likely:** Pinocchio has no `close` constraint equivalent. The three-step closure pattern (lamport drain + `data[0] = 0xff` + `realloc(1)` + `close()`) is idiomatic Pinocchio but not enforced by any framework primitive. Developers who implement only the lamport step leave the account revivable.

**Formal property that should hold but does not:**
`ensures: account.data[0] == 0xff AND account.lamports == 0`

**Vulnerable code:**
```rust
pub fn close(accounts: &[AccountInfo]) -> ProgramResult {
    let account = &accounts[0];
    let destination = &accounts[1];
    // Only lamport drain — discriminator intact, account revivable
    **destination.try_borrow_mut_lamports()? += account.lamports();
    **account.try_borrow_mut_lamports()? = 0;
    Ok(())
}
```

**Correct code:**
```rust
pub fn close(accounts: &[AccountInfo]) -> ProgramResult {
    let account = &accounts[0];
    let destination = &accounts[1];
    {
        let mut data = account.try_borrow_mut_data()?;
        data[0] = 0xff; // sentinel — prevents any future discriminator match
    }
    *destination.try_borrow_mut_lamports()? += *account.try_borrow_lamports()?;
    account.realloc(1, true)?;
    account.close()
}
```

**kani::assert! expression:**
```rust
// After handler:
let data = account.try_borrow_data().unwrap();
kani::assert!(account.lamports() == 0, "lamports must be zero after close");
kani::assert!(data[0] == 0xff, "first byte must be sentinel closed discriminator");
```

**QEDSpec clause:**
```
ensures: account.lamports == 0
ensures: account.data[0] == 0xff
```

---

### 3.5 PDA Sharing — Over-Broad Seeds

**Pattern name:** Shared pool authority via non-unique seeds (`permissionless_state_write`)

**What the developer writes:** A vault or pool PDA is derived using only global seeds (e.g., token mint address alone), meaning all users share the same PDA as authority.

**Why this framework makes it more likely:** Pinocchio's manual PDA derivation requires the developer to consciously choose seed sets. Without Anchor's `has_one` constraint reinforcing uniqueness, developers optimizing for minimal seeds may inadvertently create a shared authority PDA.

**Formal property that should hold but does not:**
`guard: forall users u1 != u2: pda(u1) != pda(u2)`

**Vulnerable code:**
```rust
// Seeds only include mint — all users of this mint share one PDA
let (pool_pda, bump) = Pubkey::find_program_address(
    &[b"pool", mint.key().as_ref()],
    &crate::ID,
);
```

**Correct code:**
```rust
// Seeds include owner — each user has a unique PDA
let (pool_pda, bump) = Pubkey::find_program_address(
    &[b"pool", mint.key().as_ref(), owner.key().as_ref()],
    &crate::ID,
);
// AND verify stored withdraw_destination matches the destination account
if pool_data.withdraw_destination != destination.key().to_bytes() {
    return Err(ProgramError::InvalidAccountData);
}
```

**kani::assert! expression:**
```rust
kani::assert!(
    pool_data.withdraw_destination == destination.key().to_bytes(),
    "withdrawal destination must match stored field"
);
kani::assert!(
    pool_data.owner == owner.key().to_bytes(),
    "pool owner must match"
);
```

**QEDSpec clause:**
```
guard: pool.withdraw_destination == destination.key()
guard: pool.owner == owner.key()
```

---

### 3.6 Arbitrary CPI — Unvalidated Program Key

**Pattern name:** CPI to attacker-controlled program (`arbitrary_cpi`)

**What the developer writes:** A CPI using a raw `invoke()` or `invoke_signed()` call where the program key comes from an `AccountInfo` supplied by the caller without any key validation.

**Why this framework makes it more likely:** Pinocchio has no `Program<'info, T>` type. All program accounts are raw `AccountInfo`. The typed CPI helpers (`pinocchio_token::Transfer`, `pinocchio_system::Transfer`) embed the program ID internally, but raw `invoke()` calls take an `AccountInfo` for the program with no key check.

**Formal property that should hold but does not:**
`guard: token_program.key() == pinocchio_token::ID`

**Vulnerable code:**
```rust
use pinocchio::program::invoke;

pub fn process_transfer(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let token_program = &accounts[3]; // No check — attacker controls this
    let ix = spl_token::instruction::transfer(
        token_program.key, source.key, destination.key, authority.key, &[], amount
    )?;
    invoke(&ix, &[source.clone(), destination.clone(), authority.clone()])
}
```

**Correct code:**
```rust
use pinocchio_token::instructions::Transfer;

// Typed CPI: always CPIs to pinocchio_token::ID
Transfer {
    from: source,
    to: destination,
    authority: owner,
    amount,
}.invoke()?;
// OR: explicit check before raw invoke
if token_program.key() != &pinocchio_token::ID {
    return Err(ProgramError::IncorrectProgramId);
}
```

**kani::assert! expression:**
```rust
kani::assert!(
    token_program.key() == &pinocchio_token::ID,
    "token_program must be SPL Token"
);
```

**QEDSpec clause:**
```
guard: token_program.key() == pinocchio_token::ID
```

---

### 3.7 `unsafe` in Zero-Copy Data Access

**Pattern name:** Unsound `bytemuck` / raw pointer cast on unverified data (`missing_ownership_check`)

**What the developer writes:** Using `bytemuck::from_bytes` or a raw pointer cast on account data without first verifying account ownership, length, and discriminator.

**Why this framework makes it more likely:** Pinocchio's performance-oriented design encourages zero-copy data access. The `bytemuck::from_bytes` call is Pinocchio's idiomatic deserialization pattern. Without the preceding ownership and discriminator checks, the resulting reference may alias attacker-controlled data with program struct types.

**Formal property that should hold but does not:**
`guard: account.owner == program_id AND account.data.len >= T::LEN AND account.data[0] == DISCRIMINATOR`

**Vulnerable code:**
```rust
// Raw cast without any ownership or discriminator check
let data = account.try_borrow_data()?;
let vault: &Vault = bytemuck::from_bytes(&data[..Vault::LEN]); // may be attacker data
let authority = Pubkey::from(vault.authority); // potentially forged
```

**Correct code:**
```rust
// Ownership check first
if account.owner() != &crate::ID { return Err(ProgramError::IllegalOwner); }
let data = account.try_borrow_data()?;
// Size check
if data.len() < Vault::LEN { return Err(ProgramError::InvalidAccountData); }
// Discriminator check
if data[0] != VAULT_DISCRIMINATOR { return Err(ProgramError::InvalidAccountData); }
// Safe to cast now
let vault: &Vault = bytemuck::from_bytes(&data[..Vault::LEN]);
```

**kani::assert! expression:**
```rust
kani::assert!(account.owner() == &crate::ID, "must be program-owned before bytemuck cast");
kani::assert!(data.len() >= Vault::LEN, "data must be at least Vault::LEN bytes");
kani::assert!(data[0] == VAULT_DISCRIMINATOR, "discriminator must match Vault");
```

**QEDSpec clause:**
```
guard: account.owner == program_id
guard: account.data.len >= Vault::LEN
guard: account.data[0] == VAULT_DISCRIMINATOR
```

---

## 4. Trust Boundaries

### Attacker-Controlled Inputs That Bypass Protections

Every account in the instruction is attacker-controlled. In Pinocchio, there is no framework layer between the raw runtime delivery and the program logic — every `AccountInfo` in the slice can be forged (wrong owner, wrong data, wrong address) unless the developer explicitly validates each property. Specifically:

- **Account position:** The attacker controls which account appears at which index. If a `TryFrom` destructuring expects `[vault, authority, ..]`, the attacker can put any account at index 0 and any account at index 1.
- **Instruction data:** All instruction data is attacker-controlled. Enum discriminators must be compared before trusting any parsed fields. Lengths and offsets must be validated before any `get_unchecked` calls.
- **CPI targets:** Any program `AccountInfo` that is not validated by key comparison is attacker-controlled. The attacker can substitute a malicious program.
- **Sysvar accounts:** Any `AccountInfo` accepted as a sysvar without address validation is attacker-controlled (fake `Clock`, fake `Rent`, fake `SlotHashes`).
- **Bump seeds in instruction data:** Any bump value in instruction data is attacker-controlled. Using `create_program_address` with it without a canonical bump comparison is a canonicalization bypass.

### Assumptions the Framework Makes That the Developer Must Verify

- Pinocchio makes no assumptions. The framework delivers a raw byte slice. Every security assumption must be written as explicit code.
- The developer must verify: account ordering matches documentation; account count is sufficient (slice destructuring check); every account has the expected owner, discriminator, signer flag, writability flag, and address.

### CPI Trust Boundaries

**What Pinocchio verifies about CPI targets:** Pinocchio's typed CPI instruction structs (e.g., `pinocchio_system::Transfer`, `pinocchio_token::Transfer`) embed the target program ID internally and use `invoke_signed_unchecked` with a fixed `program_id: &crate::ID` field. Calling `Transfer { ... }.invoke()` from `pinocchio_system` will always target the System Program.

**What the developer must verify when using typed CPI helpers:** That the accounts being passed into the struct are the correct ones (the struct does not validate account ownership or ordering, only the program ID).

**What the developer must verify when using raw `invoke()` or `invoke_signed()`:** Everything — the program ID, the account ordering, the account properties. No checks are automatic.

**Re-entrant state:** After any CPI, account state visible through previously-borrowed `AccountInfo` may be stale. Re-borrow the account data after any CPI that could have modified it.

### What Using `AccountInfo` Without Checks Leaves Unprotected

Using `AccountInfo` without validation leaves the following unprotected: account ownership, account discriminator (type identity), signer status (beyond runtime signature), PDA derivation correctness, sysvar address authenticity, program ID in CPI, account size, and authority field binding.

---

## 5. Discriminator and Type Safety

### How Account Types Are Distinguished

Pinocchio has no framework-level discriminator system. The standard Pinocchio idiom is a **single-byte discriminator** as the first byte of account data, with values `0x01`–`0xFE` for account types and `0xFF` reserved as the sentinel "closed" value. Some programs use a `u8` enum for the discriminator.

Instruction routing uses a single-byte discriminator on `instruction_data.split_first()` at the entrypoint, matching up to 255 instruction types (`0x00`–`0xFE`; `0xFF` is reserved for batch instructions).

### What Prevents Type Confusion Attacks

Nothing automatic. The developer must:
1. Define a unique discriminator constant per account type (e.g., `VAULT_DISCRIMINATOR: u8 = 1`, `CONFIG_DISCRIMINATOR: u8 = 2`).
2. Check `data[0] == EXPECTED_DISCRIMINATOR` in every account deserialization function.
3. Check account ownership alongside the discriminator (ownership alone does not prevent confusion between two types owned by the same program).

### Where the Discriminator Check Happens and Whether It Can Be Bypassed

The discriminator check happens wherever the developer writes it — typically in `from_account_info` or inside `TryFrom`. It can be bypassed by:
- Calling `bytemuck::from_bytes` directly without the discriminator check.
- Using `get_unchecked` on the data slice with an assumed offset.
- Missing the discriminator check entirely in a `TryFrom` that only validates ownership and size.

### Developer Responsibility Beyond Framework Enforcement

The developer is entirely responsible for: defining discriminator constants, writing discriminator checks in all deserialization paths, ensuring no two account types have the same discriminator, and using the sentinel value `0xFF` for closed accounts exclusively.

---

## 6. Initialization and Lifecycle

### How Pinocchio Prevents Reinitialization Attacks

It does not — automatically. The developer must check the discriminator before initializing. The secure initialization sequence is:
1. Verify the account has zero lamports (uninitialized system account) or check that `data[0] != EXPECTED_DISCRIMINATOR`.
2. Invoke `CreateAccount` via CPI with the correct `space` and `owner`.
3. Set `data[0] = EXPECTED_DISCRIMINATOR` and populate all fields.

If the account already exists (non-zero lamports), step 2 (the `CreateAccount` System Program CPI) will fail naturally. However, the developer should add an explicit discriminator check as an additional guard.

### What the Developer Must Do During Initialization

- Check that the target account is uninitialized (discriminator byte not set).
- Handle lamport griefing: check for existing lamports and transfer only the deficit.
- Derive and store the canonical bump from `find_program_address`.
- Set the discriminator byte **before** setting other fields to ensure the account is immediately recognizable as initialized.
- Verify that the payer is a signer and is writable.

### How Pinocchio Handles Account Closure

The idiomatic Pinocchio closure sequence:
1. Borrow mutable data and set `data[0] = 0xff`.
2. Transfer all lamports to the destination account.
3. Call `account.realloc(1, true)` to shrink the account to 1 byte (the sentinel).
4. Call `account.close()` to return the account to the System Program.

This prevents revival because: `0xff` is not a valid discriminator for any account type; the 1-byte size prevents any valid struct from being deserialized; and the closed account is owned by the System Program so `account.owner() != &crate::ID` checks will reject it.

### Which Lifecycle Transitions the Developer Must Track

All of them. Pinocchio tracks no lifecycle. The developer must implement: uninitialized → initialized (discriminator set), initialized → closed (sentinel written), and any application-level transitions (e.g., `Active → Settled`) as enum fields in the account data.

---

## 7. Arithmetic Safety

### Default Behavior

Pinocchio's recommended `Cargo.toml` (`[profile.release] overflow-checks = true`) enables integer overflow panics in release builds, matching debug behavior. This is a Cargo profile setting, not enforced by the Pinocchio crate itself. Programs not using the recommended template may lack this setting.

### What Is Safe by Default

When `overflow-checks = true` is set: all primitive integer arithmetic (`+`, `-`, `*`) will panic on overflow in both debug and release builds.

### What Requires Explicit Checked Variants

- **`as` casts** (e.g., `u128 as u64`) silently truncate regardless of the overflow flag. Use `u64::try_from(value)?` instead.
- **Wrapping arithmetic** (`wrapping_add`, etc.) intentionally bypasses the overflow check.
- **Division by zero** panics regardless. Use `.checked_div()` when the divisor may be zero.
- **Direct lamport manipulation** (`**account.try_borrow_mut_lamports()? += amount`) is arithmetic that is not protected by the overflow flag if expressed as raw addition. Prefer `.checked_add()` and propagate the error.

### Framework-Specific Arithmetic Utilities

Pinocchio provides no arithmetic helpers beyond enabling the Rust overflow flag. Use Rust's standard `.checked_add()`, `.checked_sub()`, `.checked_mul()`, `.checked_div()`. For lamport arithmetic specifically:
```rust
let new_balance = vault_balance
    .checked_add(amount)
    .ok_or(ProgramError::ArithmeticOverflow)?;
```

---

## 8. QEDSpec Clause Mapping

| Property | Section | QEDSpec Clause Type | Rationale |
|---|---|---|---|
| Account ownership (`account.owner() == program_id`) | 2.1 | `guard` | Pre-execution, account property |
| Signer check (`account.is_signer()`) | 2.2 | `guard` | Pre-execution, account property |
| Authority binding (stored auth == signer key) | 2.2 | `guard` | Pre-execution, field equality |
| Discriminator check (`data[0] == DISC`) | 2.3 | `guard` | Pre-execution, account property |
| PDA derivation (key == derived address) | 2.4 | `guard` | Pre-execution, account key |
| Sysvar address (`Clock::get()` used) | 2.5 | `guard` | Pre-execution, canonical runtime read |
| CPI program identity | 2.6 | `guard` | Pre-execution, account key |
| Canonical bump stored | 2.7 | `establishes` | First creation: vault.bump == find_program_address().bump |
| Account closed: sentinel set | 2.8 | `ensures` | Post-execution: account.data[0] == 0xff |
| Account closed: lamports zero | 2.8 | `ensures` | Post-execution: account.lamports == 0 |
| Not already initialized | 2.9 | `requires` | Pre-execution value: data[0] != DISCRIMINATOR |
| Lamport griefing: deficit-only transfer | 2.10 | `requires` | Pre-execution: lamports_to_transfer == max(0, required - existing) |
| Writability assertion | 2.11 | `guard` | Pre-execution, account property |
| Distinct mutable accounts | 2.12 | `requires` | Pre-execution: from.key != to.key |
| Batch: per-instruction ownership | 2.13 | `guard` | Pre-execution (per inner ix): account.owner == program_id |
| Overflow-free arithmetic | 7 | `invariant` | Throughout: all arithmetic within type bounds |
| Balance invariant post-operation | 7 | `ensures` | Post: new_balance == old_balance ± amount |

---

## 9. Common Audit Findings in This Framework

### 9.1 `missing_ownership_check`

**Why common in Pinocchio:** There is no `Account<T>` type performing automatic ownership verification. Every `AccountInfo` in the slice is identical at the type level regardless of which program owns it. Developers who are unfamiliar with the Pinocchio security model or who are migrating from Anchor may not add the ownership check because they expect it to come "for free" from the account type system.

**Framework feature contributing:** The absence of any typed account wrapper. `AccountInfo` carries no ownership invariant.

**Gap analysis detection:** For every mutable account field in a `TryFrom` implementation, check for a preceding `if account.owner() != &crate::ID { return Err(ProgramError::IllegalOwner); }`. Any mutable account without this check is a candidate for `missing_ownership_check`.

---

### 9.2 `missing_signer_check`

**Why common in Pinocchio:** There is no `Signer<'info>` type. Developers must write `if !account.is_signer() { ... }` explicitly. The check is trivial but easy to omit, especially during rapid prototyping when the `TryFrom` body is populated incrementally. Additionally, developers may add the signer check but omit the authority-binding check (comparing the signer's key to a stored authority field).

**Framework feature contributing:** No type-level enforcement of signer status. The pattern of verifying both `is_signer()` AND authority field equality must be consistently applied.

**Gap analysis detection:** Any instruction that modifies state behind an authority field must have both `is_signer()` and `stored_authority == signer.key()` checks. Flag any handler that modifies authority-controlled state where either is absent.

---

### 9.3 `lifecycle_violation` (Account Revival)

**Why common in Pinocchio:** The three-step closure sequence (sentinel write + lamport drain + `realloc(1)` + `close()`) is less obvious than Anchor's single `close = destination` constraint. Developers who implement closure often omit the sentinel write, leaving the discriminator byte intact and the account revivable within the same transaction by re-funding lamports.

**Framework feature contributing:** No equivalent of the `close` constraint. The closure sequence must be manually implemented and tested. The sentinel value `0xFF` and `realloc(1)` are conventions, not framework enforcement.

**Gap analysis detection:** Any instruction whose name or logic suggests account closure (e.g., `close`, `withdraw_and_close`, `settle`) should be checked for: (1) `data[0] = 0xff` before lamport transfer; (2) lamports set to zero; (3) `realloc(1)` and `close()` called. Any missing step is a finding.

---

### 9.4 `insecure_initialisation`

**Why common in Pinocchio:** The developer must manually check that the account is not already initialized. The pattern `if data[0] == DISCRIMINATOR { return Err(AccountAlreadyInitialized); }` is not part of any framework template. Developers who implement initialization without this guard allow attackers to call the instruction on an existing account, potentially overwriting the authority field.

**Framework feature contributing:** No `init` constraint. The System Program CPI in `CreateAccount` will fail if the account already has lamports, providing partial protection, but this does not catch the case where the account was initialized with exact rent-exempt lamports and then partly drained. An explicit discriminator check is required.

**Gap analysis detection:** Any initialization instruction that calls `CreateAccount` or sets `data[0] = DISCRIMINATOR` without first checking that the existing discriminator byte is zero (or `!= DISCRIMINATOR`) is a candidate for `insecure_initialisation`.

---

### 9.5 `arbitrary_cpi`

**Why common in Pinocchio:** There is no `Program<'info, T>` type. CPI program targets are raw `AccountInfo` or `Address` values. When developers use raw `invoke()` for flexibility (e.g., supporting multiple token programs), they often omit the program key validation. Even when using typed CPI helpers, developers may pass accounts in incorrect positions because the helper struct performs no account-level validation.

**Framework feature contributing:** The absence of a typed program wrapper. The only safe path is to use the Pinocchio-specific typed CPI instruction structs (`pinocchio_token::Transfer`, `pinocchio_system::CreateAccount`) which embed the program ID, or to add explicit key checks before raw `invoke()` calls.

**Gap analysis detection:** Any call to `pinocchio::program::invoke()` or `pinocchio::program::invoke_signed()` where the first argument's program ID is derived from an `AccountInfo` field without a preceding key equality check. Flag as `arbitrary_cpi`.

---

---

# EMBEDDING-OPTIMIZED VERSION

*Each chunk is independently understandable and begins with framework, topic, and applies-to fields for semantic retrieval.*

---

```
Framework: Pinocchio
Topic: Zero Automatic Security Enforcement — Everything Is Manual
Applies to: All instructions in every Pinocchio program

Pinocchio provides zero automatic security enforcement. There are no typed account wrappers, no constraint attributes, no discriminator system, no PDA derivation checks, and no sysvar address verification. Every security property — ownership, signer, discriminator, PDA, writability, program identity, authority binding — must be written as explicit code in the TryFrom implementation or instruction handler. The framework delivers a raw &[AccountInfo] slice and does nothing further. This is the fundamental trust boundary: the entire account slice is attacker-controlled until the developer's explicit checks reject it.
```

---

```
Framework: Pinocchio
Topic: Account Ownership Check — Manual is_owned_by / owner() Check
Applies to: All instructions accessing program-owned accounts

There is no Account<T> type. Ownership must be checked by the developer: if account.owner() != &crate::ID { return Err(ProgramError::IllegalOwner); }. This check must appear in every TryFrom implementation for every account that is expected to be owned by the program, before any data access. Omitting this check allows an attacker to supply a foreign account with an identical data layout, causing the program to deserialize and act on attacker-controlled data. QEDSpec: guard: account.owner == program_id.
```

---

```
Framework: Pinocchio
Topic: Signer Check — Manual is_signer() Verification
Applies to: All instructions requiring an authority or payer signature

There is no Signer<'info> type. Signer status must be checked with: if !account.is_signer() { return Err(ProgramError::MissingRequiredSignature); }. This check is necessary but not sufficient. The signer's key must also be compared to the stored authority field in the relevant account: if data[AUTHORITY_OFFSET..AUTHORITY_OFFSET+32] != signer.key().as_ref() { return Err(ProgramError::InvalidAccountData); }. Signer check alone (without authority binding) allows any valid Solana keypair to trigger the instruction. QEDSpec: guard: authority.is_signer == true AND account.authority == authority.key().
```

---

```
Framework: Pinocchio
Topic: Account Discriminator — Developer-Defined Single-Byte Scheme
Applies to: All instructions deserializing program-owned accounts

Pinocchio has no automatic discriminator. The idiomatic pattern is a single-byte discriminator as data[0], with unique values per account type (e.g., VAULT_DISC = 1, CONFIG_DISC = 2) and 0xFF reserved as the sentinel closed value. The discriminator check must appear in every deserialization function before bytemuck::from_bytes or any field access: if data[0] != EXPECTED_DISCRIMINATOR { return Err(ProgramError::InvalidAccountData); }. Without this check, two structs with identical field layouts are interchangeable — a type confusion attack. QEDSpec: guard: account.data[0] == EXPECTED_DISCRIMINATOR.
```

---

```
Framework: Pinocchio
Topic: PDA Derivation Verification — Manual find_program_address / create_program_address
Applies to: All instructions using Program Derived Addresses

There is no seeds/bump constraint. PDA validation: during init, call find_program_address to get the canonical bump and store it in account data (vault_data.bump = canonical_bump). During subsequent use, validate with create_program_address using the stored bump — not a user-supplied one. Never accept a bump from instruction data and pass it directly to create_program_address; this is a canonicalization attack where the attacker supplies a non-canonical bump that still derives to the same address. Always: let (addr, bump) = find_program_address(seeds, &crate::ID); verify addr == account.key(). QEDSpec: guard: account.key() == find_program_address(seeds, program_id).address.
```

---

```
Framework: Pinocchio
Topic: Sysvar Spoofing — Use Clock::get() not AccountInfo
Applies to: All instructions reading Clock, Rent, SlotHashes, or other sysvars

Pinocchio does not validate sysvar account addresses. An AccountInfo accepted for a sysvar without address validation can be a fake account with a manipulated timestamp or rent schedule. The safe pattern: use Clock::get()? and Rent::get()? which are runtime syscalls that do not accept an account argument and cannot be spoofed. Never read sysvar data from an AccountInfo without verifying: if clock_account.key() != &Clock::id() { return Err(ProgramError::InvalidArgument); }. QEDSpec: guard: clock_account.key() == Clock::id() (or use Clock::get() instead of an account parameter).
```

---

```
Framework: Pinocchio
Topic: CPI Program Identity — Manual Key Check Required
Applies to: All instructions performing cross-program invocations

There is no Program<'info, T> type. For token CPIs, use pinocchio_token::Transfer { ... }.invoke()? which always targets the SPL Token program ID internally. For system CPIs, use pinocchio_system::Transfer { ... }.invoke()?. For raw invoke() calls, always check the program key first: if token_program.key() != &pinocchio_token::ID { return Err(ProgramError::IncorrectProgramId); }. An unchecked program AccountInfo in CPI position is an arbitrary_cpi vulnerability where the attacker substitutes a malicious program. QEDSpec: guard: token_program.key() == pinocchio_token::ID.
```

---

```
Framework: Pinocchio
Topic: Account Closure — Three-Step Pattern with Sentinel Discriminator
Applies to: Any instruction that closes or finalizes an account

Pinocchio has no close constraint. The full correct closure sequence: (1) set data[0] = 0xff before draining lamports; (2) transfer all lamports to destination; (3) call account.realloc(1, true)? to shrink to 1 byte; (4) call account.close() to return to System Program. The sentinel 0xff prevents revival: discriminator checks (data[0] != 0xff) will always reject the closed account. Draining lamports alone (without sentinel + realloc + close) is a lifecycle_violation — the account is revivable within the same transaction by re-funding lamports. QEDSpec: ensures: account.lamports == 0; ensures: account.data[0] == 0xff.
```

---

```
Framework: Pinocchio
Topic: Reinitialization Prevention — Manual Discriminator Check Before Init
Applies to: All initialization instructions

Pinocchio has no init constraint. Before creating an account, check that it is not already initialized: let data = account.try_borrow_data()?; if !data.is_empty() && data[0] == DISCRIMINATOR { return Err(ProgramError::AccountAlreadyInitialized); }. The CreateAccount System Program CPI provides partial protection (fails if account has non-zero lamports) but does not catch all cases. An explicit discriminator check is required. During initialization, set the discriminator byte first, before setting authority or other fields, to make the initialized state immediately detectable. QEDSpec: requires: account.data[0] != DISCRIMINATOR.
```

---

```
Framework: Pinocchio
Topic: Lamport Griefing — Deficit-Only Lamport Transfer on PDA Init
Applies to: All instructions that initialize PDAs by creating new accounts

An attacker can send lamports to a PDA before the program initializes it, causing CreateAccount CPI to fail if the program transfers the full rent-exempt amount (the account is no longer empty). The correct pattern: let required = Rent::get()?.minimum_balance(space); let existing = vault.lamports(); if existing < required { Transfer { from: payer, to: vault, lamports: required - existing }.invoke()?; }. Transfer only the deficit, then Allocate + Assign. QEDSpec: requires: lamports_transferred == max(0, required_lamports - existing_lamports).
```

---

```
Framework: Pinocchio
Topic: Batch Instruction — Per-Inner-Instruction Ownership Checks Required
Applies to: Programs implementing batch instructions (discriminator 0xFF)

In Pinocchio's batch instruction pattern, multiple inner instructions are processed sequentially in a single CPI. The runtime enforces account ownership only at the end of the batch, not between inner instructions. Any inner instruction handler that modifies an account without an explicit ownership check (account.owner() != &crate::ID) can be exploited by an attacker who supplies an account they own. Each inner instruction handler must independently verify ownership of every account it modifies, even when the outer batch entrypoint has already validated the discriminator. QEDSpec: guard (per inner instruction): account.owner == program_id.
```

---

```
Framework: Pinocchio
Topic: TryFrom Pattern — Security Depends Entirely on Check Completeness
Applies to: All Pinocchio instructions using the TryFrom account validation pattern

The TryFrom trait is Pinocchio's idiomatic account validation mechanism. It provides structural organization but no automatic security. The appearance of a TryFrom implementation does not guarantee any checks are performed — the developer must write every check explicitly. A complete TryFrom body for a privileged account must include: (1) slice length check; (2) ownership check; (3) discriminator check; (4) size check; (5) signer check if applicable; (6) authority field equality if applicable; (7) PDA derivation if applicable; (8) writability assertion if applicable. Any omitted check is a potential vulnerability. QEDSpec: guard: all checks listed above hold before Ok(Self {...}) is returned.
```

---

```
Framework: Pinocchio
Topic: Common Audit Finding — missing_ownership_check
Applies to: All instructions, all account types

Root cause: No Account<T> type enforces ownership automatically. Detection: in every TryFrom or account handler, find all AccountInfo fields that are used to read program-controlled data (e.g., bytemuck::from_bytes, try_borrow_data with field access). Check that account.owner() != &crate::ID is tested before any data access. Any account used as a data source without this check is missing_ownership_check. Special attention: accounts from remaining_accounts or dynamically-indexed account slices that skip TryFrom validation.
```

---

```
Framework: Pinocchio
Topic: Common Audit Finding — lifecycle_violation (Revival Attack)
Applies to: Any instruction closing accounts

Root cause: No close constraint. Developers often implement only the lamport drain without the sentinel write and realloc. Detection: any instruction that sets account lamports to zero without also writing data[0] = 0xff AND calling account.realloc(1, true) AND account.close(). Three-level check: (1) lamports drained? (2) data[0] set to 0xff before drain? (3) account.close() called? Any step missing is lifecycle_violation.
```

---

```
Framework: Pinocchio
Topic: Common Audit Finding — arbitrary_cpi
Applies to: All instructions performing CPIs

Root cause: No Program<'info, T> type. Detection: search for calls to pinocchio::program::invoke() or invoke_signed() where the program_id argument is derived from an AccountInfo field. Check whether a preceding key equality assertion exists: if program_account.key() != &EXPECTED_ID { return Err(...); }. If absent, flag as arbitrary_cpi. Also check that typed CPI structs (Transfer, CreateAccount) are used where possible rather than manual InstructionView construction.
```

---

```
Framework: Pinocchio
Topic: Common Audit Finding — missing_signer_check
Applies to: All state-mutating instructions

Root cause: No Signer<'info> type. Detection: for every instruction that modifies program-owned state behind an authority: verify (1) is_signer() is checked on the authority account; (2) the authority account's key is compared to a stored authority field in the account being modified. Both checks are required — signer without authority binding allows any signer; authority binding without signer check allows replay without a signature. Flag any mutating instruction where either is absent.
```

---

```
Framework: Pinocchio
Topic: Common Audit Finding — insecure_initialisation
Applies to: All initialization instructions

Root cause: No init constraint. Detection: any instruction that writes the account discriminator byte (data[0] = DISCRIMINATOR) without first checking that the existing value is not already set. Also flag: any instruction that sets an authority field (data[AUTHORITY_OFFSET..] = authority.key()) without first verifying that data[0] != DISCRIMINATOR (i.e., the account is not already initialized). The CreateAccount CPI provides partial protection but is not sufficient in all cases.
```

---

```
Framework: Pinocchio
Topic: Common Audit Finding — permissionless_state_write (PDA Sharing)
Applies to: Pool, vault, and shared-authority PDA instructions

Root cause: Manual PDA derivation encourages minimal seed sets for simplicity. Detection: for any PDA used to authorize token transfers or privileged operations, inspect the seeds. If no user-specific component (owner pubkey, wallet address, unique counter) appears in the seeds, flag as potential PDA sharing / permissionless_state_write. Also verify that stored relationship fields (e.g., pool.withdraw_destination) are compared to the actual accounts in context: if pool_data.withdraw_destination != destination.key() { return Err(...); }.
```