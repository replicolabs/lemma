# Native Rust (solana_program) — Security Reference Document (Lemma Edition)

> Framework: Native Rust (`solana_program` crate)
> Source material: native_rust_1.md, native_rust_2.md, edge-cases.md, account-patterns.md, SKILL_ONE.md
> Purpose: Embedded in a vector database; retrieved during static analysis of Native Rust Solana programs by Lemma.
> Every sentence is directly security-relevant. No installation, CLI, or performance content.

---

## 1. Automatic Security Enforcement

Native Rust programs using `solana_program` provide **extremely minimal automatic security enforcement**. The crate is a low-level wrapper around Solana's BPF syscall interface. It provides the `entrypoint!` macro, `AccountInfo`, `ProgramResult`, and helpers for serialization (Borsh), but performs no automatic ownership checks, signer verification, discriminator enforcement, PDA validation, or type safety on accounts. All of these are the developer's responsibility.

### 1.1 Entrypoint Input Delivery

**Property name:** Raw account slice delivery

**What it enforces precisely:** The `entrypoint!` macro expands to a `process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult` signature. The runtime validates that accounts marked as signers have valid transaction signatures before the program is invoked.

**What it does NOT enforce:** Ownership, discriminator, PDA derivation, sysvar addresses, writability assertions, program identity for CPI, or any relationship between accounts.

**Trigger:** Automatic, via `entrypoint!(process_instruction)`.

**Effect of raw usage without additional checks:** All accounts are treated as valid. An attacker who controls all supplied accounts can pass forged data, fake authority accounts, and substitute any account in any position.

---

### 1.2 Runtime Signature Verification

**Property name:** Ed25519 signature enforcement

**What it enforces precisely:** The Solana runtime verifies that every account with `AccountInfo.is_signer == true` in the transaction has a valid Ed25519 signature. This happens before the entrypoint is invoked.

**What it does NOT enforce:** Whether the signing account is the expected authority for the operation. Business-logic authority matching is entirely the developer's responsibility.

**Trigger:** Automatic, runtime-level.

---

### 1.3 Runtime Writability Enforcement

**Property name:** Write-flag enforcement

**What it enforces precisely:** The runtime rejects writes to accounts not marked writable in the transaction. Borrowing mutable data on a non-writable account will fail at the syscall level.

**What it does NOT enforce:** The developer must still verify that writable accounts ARE marked writable before attempting to write, for early validation and clear error messages.

**Trigger:** Automatic, runtime-level.

---

### 1.4 `invoke` / `invoke_signed` Account Ownership Propagation

**Property name:** CPI signer privilege propagation

**What it enforces precisely:** The `solana_program::program::invoke_signed` function allows a program to sign for PDAs by providing seed vectors. The runtime validates that the seeds and caller program ID derive to the claimed signer address. An `invoke_signed` call with invalid seeds will fail.

**What it does NOT enforce:** That the target program is the intended program, that accounts passed to the callee are correctly ordered, or that the callee will not perform unexpected operations with the supplied writable accounts.

**Trigger:** `invoke_signed(&ix, &accounts, &signers)`.

---

## 2. Developer Responsibilities

### 2.1 Account Ownership Verification

**Property name:** Program ownership check

**Why the framework does not handle it:** `AccountInfo` carries no type-level ownership invariant. All accounts in the slice are `AccountInfo` regardless of which program owns them.

**Correct pattern:**
```rust
pub fn process_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vault = next_account_info(accounts_iter)?;
    // Ownership check — must be program-owned
    if vault.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let vault_data = Vault::try_from_slice(&vault.data.borrow())?;
    Ok(())
}
```

**Incorrect pattern developers commonly write:**
```rust
pub fn process_withdraw(accounts: &[AccountInfo]) -> ProgramResult {
    let vault = &accounts[0]; // No ownership check!
    // Attacker supplies a fake account with identical Borsh layout
    let vault_data = Vault::try_from_slice(&vault.data.borrow())?;
    // Program operates on attacker-controlled data
    Ok(())
}
```

---

### 2.2 Signer Verification

**Property name:** Transaction signer check with authority binding

**Why the framework does not handle it:** There is no `Signer<'info>` type. `AccountInfo.is_signer` must be read explicitly.

**Correct pattern:**
```rust
let authority = next_account_info(accounts_iter)?;
// Signer check
if !authority.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
// Authority binding: verify this signer matches the stored authority
let vault_data = Vault::try_from_slice(&vault.data.borrow())?;
if vault_data.authority != *authority.key {
    return Err(ProgramError::InvalidAccountData);
}
```

**Incorrect pattern:**
```rust
// Signer check exists but authority binding missing
let authority = next_account_info(accounts_iter)?;
if !authority.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
// Missing: does this signer match vault.authority?
// Any valid signer can perform this privileged operation
```

---

### 2.3 Discriminator / Type Tagging

**Property name:** Account type discrimination

**Why the framework does not handle it:** Native Rust programs have no automatic discriminator. Borsh deserialization succeeds for any byte sequence that matches the struct layout, regardless of the account type.

**Correct pattern (Borsh enum variant for discriminator):**
```rust
#[derive(BorshSerialize, BorshDeserialize)]
pub enum AccountType {
    Vault,
    Config,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Vault {
    pub account_type: AccountType,
    pub authority: Pubkey,
    pub balance: u64,
}

// In handler:
let vault_data = Vault::try_from_slice(&vault.data.borrow())?;
if !matches!(vault_data.account_type, AccountType::Vault) {
    return Err(ProgramError::InvalidAccountData);
}
```

**Incorrect pattern:**
```rust
// No discriminator — a Config account with the same fields as a Vault passes
let vault_data = Vault::try_from_slice(&vault.data.borrow())?;
// If Config has authority: Pubkey, value: u64 — identical layout — type confusion possible
```

---

### 2.4 PDA Derivation Verification

**Property name:** PDA address authenticity

**Why the framework does not handle it:** There is no `seeds`/`bump` constraint. PDA validation must use `Pubkey::find_program_address` or `Pubkey::create_program_address` manually.

**Correct pattern:**
```rust
let (expected_vault, _bump) = Pubkey::find_program_address(
    &[b"vault", authority.key.as_ref()],
    program_id,
);
if vault.key != &expected_vault {
    return Err(ProgramError::InvalidSeeds);
}
```

**Incorrect pattern:**
```rust
// PDA assumed without derivation check
fn process(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let vault = &accounts[0]; // Assumed to be the correct PDA
    // No find_program_address verification
    // Attacker supplies a different account they control
    Ok(())
}
```

---

### 2.5 Sysvar Validation

**Property name:** Sysvar authenticity

**Why the framework does not handle it:** `solana_program` provides `Clock::from_account_info`, `Rent::from_account_info`, etc., which do validate the account key internally against the canonical sysvar address. However, the simpler `Sysvar::get()` pattern requires no account argument and is immune to substitution attacks.

**Correct pattern:**
```rust
use solana_program::sysvar::{clock::Clock, rent::Rent, Sysvar};
let clock = Clock::get()?;  // Runtime syscall — no account needed
let rent = Rent::get()?;    // No spoofing possible
```

**Also acceptable (with key verification inside `from_account_info`):**
```rust
let clock_account = next_account_info(accounts_iter)?;
let clock = Clock::from_account_info(clock_account)?; // validates key internally
```

**Incorrect pattern:**
```rust
// Manual deserialization of sysvar from AccountInfo without key check
let clock_data = &clock_account.data.borrow();
let timestamp = i64::from_le_bytes(clock_data[32..40].try_into().unwrap());
// No address check — attacker supplies a fake Clock account
```

---

### 2.6 Program Identity Check for CPI

**Property name:** CPI target verification

**Why the framework does not handle it:** `invoke` and `invoke_signed` accept raw `Instruction` structs with a `program_id: Pubkey` field. If this `program_id` comes from an `AccountInfo.key` that is not validated, the attacker controls the CPI target.

**Correct pattern:**
```rust
let token_program = next_account_info(accounts_iter)?;
if token_program.key != &spl_token::ID {
    return Err(ProgramError::IncorrectProgramId);
}
invoke(
    &spl_token::instruction::transfer(
        token_program.key, source.key, destination.key, authority.key, &[], amount
    )?,
    &[source.clone(), destination.clone(), authority.clone()],
)?;
```

**Incorrect pattern:**
```rust
let token_program = next_account_info(accounts_iter)?;
// No key check — attacker substitutes malicious program
invoke(
    &spl_token::instruction::transfer(
        token_program.key, // attacker-controlled!
        source.key, destination.key, authority.key, &[], amount
    )?,
    &[source.clone(), destination.clone(), authority.clone()],
)?;
```

---

### 2.7 Instruction Data Discrimination

**Property name:** Instruction type safety

**Why the framework does not handle it:** `instruction_data` is a raw byte slice. Any dispatch logic relying on Borsh `try_from_slice` for the instruction enum must handle decoding errors, length errors, and variant confusion.

**Correct pattern:**
```rust
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instructions {
    Initialize { data: u64 },
    Withdraw { amount: u64 },
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = Instructions::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    match instruction {
        Instructions::Initialize { data } => process_initialize(program_id, accounts, data),
        Instructions::Withdraw { amount } => process_withdraw(program_id, accounts, amount),
    }
}
```

**Incorrect pattern:**
```rust
// Panic-prone: try_from_slice can panic if data is malformed
let instruction = Instructions::try_from_slice(instruction_data).unwrap();
// An attacker who sends malformed instruction data causes the program to panic
```

---

### 2.8 Reinitialization Prevention

**Property name:** Single-use initialization guard

**Why the framework does not handle it:** Native Rust has no `init` constraint. The `create_account` CPI through the System Program will fail if the account already has non-zero lamports, providing partial protection. An explicit initialized-flag check is required for defense-in-depth.

**Correct pattern:**
```rust
pub fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: u64,
) -> ProgramResult {
    let new_account = next_account_info(accounts_iter)?;
    // Check: reject if already initialized
    if !new_account.data.borrow().iter().all(|&b| b == 0) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    // Proceed with create_account CPI + serialize
    let account_data = NewAccount { data };
    let size = account_data.try_to_vec()?.len();
    let lamports = Rent::get()?.minimum_balance(size);
    invoke(
        &system_instruction::create_account(signer.key, new_account.key, lamports, size as u64, program_id),
        &[signer.clone(), new_account.clone(), system_program.clone()],
    )?;
    account_data.serialize(&mut *new_account.data.borrow_mut())?;
    Ok(())
}
```

**Incorrect pattern:**
```rust
// No initialization guard — attacker reinitializes existing account
pub fn process_initialize(accounts: &[AccountInfo], data: u64) -> ProgramResult {
    let account = &accounts[0];
    let account_data = NewAccount { data };
    account_data.serialize(&mut *account.data.borrow_mut())?; // overwrites existing!
    Ok(())
}
```

---

### 2.9 Account Closure

**Property name:** Safe account closure

**Why the framework does not handle it:** Native Rust has no `close` constraint. Account closure must be implemented manually.

**Correct pattern:**
```rust
pub fn process_close(accounts: &[AccountInfo]) -> ProgramResult {
    let account = &accounts[0];
    let destination = &accounts[1];

    // 1. Transfer lamports
    **destination.try_borrow_mut_lamports()? += account.lamports();
    **account.try_borrow_mut_lamports()? = 0;

    // 2. Zero data
    let mut data = account.data.borrow_mut();
    for byte in data.iter_mut() {
        *byte = 0;
    }

    // 3. Reassign to System Program
    account.assign(&system_program::ID);

    Ok(())
}
```

**Incorrect pattern (revival attack):**
```rust
// Only drains lamports — data and account type intact, revivable
pub fn process_close(accounts: &[AccountInfo]) -> ProgramResult {
    let account = &accounts[0];
    let destination = &accounts[1];
    **destination.try_borrow_mut_lamports()? += account.lamports();
    **account.try_borrow_mut_lamports()? = 0;
    // Data not zeroed — account can be "reopened" in same transaction
    Ok(())
}
```

---

### 2.10 Duplicate Mutable Account Detection

**Property name:** Distinct account identity for mutable pairs

**Why the framework does not handle it:** The runtime does not check for duplicate accounts in the instruction. Passing the same account twice in mutable positions causes undefined arithmetic behavior.

**Correct pattern:**
```rust
let from = next_account_info(accounts_iter)?;
let to = next_account_info(accounts_iter)?;
if from.key == to.key {
    return Err(ProgramError::InvalidArgument);
}
```

**Incorrect pattern:**
```rust
// No identity check — from and to can be the same account
**from.try_borrow_mut_lamports()? -= amount;
**to.try_borrow_mut_lamports()? += amount;
// If from == to, second write overwrites first — balance appears correct but incorrect
```

---

### 2.11 Integer Overflow Protection

**Property name:** Arithmetic overflow safety

**Why the framework does not handle it:** `solana_program` does not require `overflow-checks = true` in `Cargo.toml`. The developer must explicitly add `[profile.release] overflow-checks = true` or use checked arithmetic.

**Correct pattern:**
```rust
vault_data.balance = vault_data.balance
    .checked_add(amount)
    .ok_or(ProgramError::ArithmeticOverflow)?;
```

**Incorrect pattern:**
```rust
vault_data.balance += amount; // Silent wraparound in release if overflow-checks = false
```

---

## 3. Framework-Specific Vulnerability Patterns

### 3.1 Missing Ownership Check with Borsh Deserialization

**Pattern name:** Type confusion via raw Borsh deserialization (`missing_ownership_check`)

**What the developer writes:** `AccountInfo.data.borrow()` followed by `try_from_slice` without checking `account.owner`.

**Why this framework makes it more likely:** Borsh's `try_from_slice` succeeds for any byte sequence that matches the struct layout. Two structs with the same fields (e.g., `Vault { authority: Pubkey, balance: u64 }` and `Config { authority: Pubkey, value: u64 }`) are byte-for-byte interchangeable. Without an ownership check AND a discriminator, type confusion is guaranteed to succeed.

**Formal property that should hold but does not:**
`guard: account.owner == program_id AND account.data[0] == VAULT_DISCRIMINATOR`

**Vulnerable code:**
```rust
use borsh::BorshDeserialize;
use solana_program::{account_info::AccountInfo, program_error::ProgramError, ProgramResult};

pub fn process_update(accounts: &[AccountInfo]) -> ProgramResult {
    let vault_account = &accounts[0];
    // No ownership check, no discriminator check
    let vault = Vault::try_from_slice(&vault_account.data.borrow())?;
    // Attacker passes a Config account with same layout — passes deserialization
    if vault.authority != *accounts[1].key {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}
```

**Correct code:**
```rust
pub fn process_update(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let vault_account = &accounts[0];
    // Ownership check first
    if vault_account.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let vault = Vault::try_from_slice(&vault_account.data.borrow())?;
    // Discriminator check
    if !matches!(vault.account_type, AccountType::Vault) {
        return Err(ProgramError::InvalidAccountData);
    }
    if vault.authority != *accounts[1].key {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}
```

**kani::assert! expression:**
```rust
kani::assert!(vault_account.owner == program_id, "vault must be owned by program");
kani::assert!(
    matches!(vault_data.account_type, AccountType::Vault),
    "account discriminator must be Vault"
);
```

**QEDSpec clause:**
```
guard: vault_account.owner == program_id
guard: vault_data.account_type == AccountType::Vault
```

---

### 3.2 Missing Signer Check on Authority-Gated Instructions

**Pattern name:** Unsigned authority bypass (`missing_signer_check`)

**What the developer writes:** An instruction that checks the authority field for equality but does not verify `is_signer` on the authority account.

**Why this framework makes it more likely:** Native Rust's account parsing uses `next_account_info` which returns an `AccountInfo` with no type-level signer enforcement. Developers performing authority binding via field equality may forget that the presence of the correct `Pubkey` in the `authority` field does not imply the transaction carries a signature from that key.

**Formal property that should hold but does not:**
`guard: authority.is_signer == true AND vault.authority == authority.key`

**Vulnerable code:**
```rust
pub fn process_withdraw(accounts: &[AccountInfo]) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    let vault_data = Vault::try_from_slice(&vault.data.borrow())?;
    // Authority field check exists — but signer check is missing!
    if vault_data.authority != *authority.key {
        return Err(ProgramError::InvalidAccountData);
    }
    // Attacker includes the real owner's pubkey without their signature
    // The transaction is signed only by the attacker
    Ok(())
}
```

**Correct code:**
```rust
pub fn process_withdraw(accounts: &[AccountInfo]) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let vault_data = Vault::try_from_slice(&vault.data.borrow())?;
    if vault_data.authority != *authority.key {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}
```

**kani::assert! expression:**
```rust
kani::assert!(authority.is_signer, "authority must be a transaction signer");
kani::assert!(vault_data.authority == *authority.key, "authority must match stored field");
```

**QEDSpec clause:**
```
guard: authority.is_signer == true
guard: vault.authority == authority.key
```

---

### 3.3 Bump Seed Canonicalization

**Pattern name:** Non-canonical PDA bump acceptance (`init_without_pda`)

**What the developer writes:** Accepting a `bump: u8` from instruction data and using `create_program_address` with it directly rather than calling `find_program_address` to verify the canonical bump.

**Why this framework makes it more likely:** Native Rust programs commonly pass bump seeds as instruction parameters for compute efficiency. The pattern of comparing a user-supplied bump to the canonical bump is less common when `find_program_address` is perceived as expensive.

**Formal property that should hold but does not:**
`guard: bump == find_program_address(seeds, program_id).1`

**Vulnerable code:**
```rust
pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], bump: u8) -> ProgramResult {
    let vault = &accounts[0];
    let owner = &accounts[1];
    // Accepts any valid bump — not just canonical
    let address = Pubkey::create_program_address(
        &[b"vault", owner.key.as_ref(), &[bump]], program_id
    )?;
    if vault.key != &address {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}
```

**Correct code:**
```rust
// During init: use find_program_address and store canonical bump
let (expected, canonical_bump) = Pubkey::find_program_address(
    &[b"vault", signer.key.as_ref()], program_id
);
if new_account.key != &expected {
    return Err(ProgramError::InvalidSeeds);
}
vault_data.bump = canonical_bump; // store
vault_data.serialize(&mut *new_account.data.borrow_mut())?;

// During use: validate with stored canonical bump
let vault_data = Vault::try_from_slice(&vault.data.borrow())?;
let expected = Pubkey::create_program_address(
    &[b"vault", authority.key.as_ref(), &[vault_data.bump]], program_id
)?;
if vault.key != &expected {
    return Err(ProgramError::InvalidSeeds);
}
```

**kani::assert! expression:**
```rust
let (canonical_addr, canonical_bump) =
    Pubkey::find_program_address(&[b"vault", owner.key.as_ref()], program_id);
kani::assert!(vault.key == &canonical_addr, "vault must match canonical PDA");
kani::assert!(stored_bump == canonical_bump, "stored bump must be canonical");
```

**QEDSpec clause:**
```
guard: vault.key == find_program_address([b"vault", owner.key], program_id).address
```

---

### 3.4 Insecure Account Closure — Revival Attack

**Pattern name:** Lamport-only close without data zeroing (`lifecycle_violation`)

**What the developer writes:** Setting lamports to zero without zeroing account data and reassigning to System Program.

**Why this framework makes it more likely:** Native Rust's lamport manipulation is visible and explicit (`**account.try_borrow_mut_lamports()? = 0`). Developers who implement this step correctly may not realize the account data remains intact and the discriminator is still valid, making the account revivable.

**Formal property that should hold but does not:**
`ensures: account.lamports == 0 AND account.data is zeroed AND account.owner == System Program`

**Vulnerable code (insecure level 1 — lamport drain only):**
```rust
pub fn process_close(accounts: &[AccountInfo]) -> ProgramResult {
    let account = &accounts[0];
    let destination = &accounts[1];
    **destination.try_borrow_mut_lamports()? += account.lamports();
    **account.try_borrow_mut_lamports()? = 0;
    // Data intact — discriminator valid — revivable by refunding lamports
    Ok(())
}
```

**Correct code:**
```rust
pub fn process_close(accounts: &[AccountInfo]) -> ProgramResult {
    let account = &accounts[0];
    let destination = &accounts[1];
    // 1. Transfer lamports
    **destination.try_borrow_mut_lamports()? = destination.lamports()
        .checked_add(account.lamports()).ok_or(ProgramError::ArithmeticOverflow)?;
    **account.try_borrow_mut_lamports()? = 0;
    // 2. Zero all data
    let mut data = account.data.borrow_mut();
    for byte in data.iter_mut() { *byte = 0; }
    // 3. Reassign to System Program
    drop(data);
    account.assign(&solana_program::system_program::ID);
    Ok(())
}
```

**kani::assert! expression:**
```rust
kani::assert!(account.lamports() == 0, "lamports must be zero after close");
kani::assert!(account.data.borrow().iter().all(|&b| b == 0), "data must be zeroed");
kani::assert!(account.owner == &solana_program::system_program::ID, "owner must be System Program");
```

**QEDSpec clause:**
```
ensures: account.lamports == 0
ensures: forall i: account.data[i] == 0
ensures: account.owner == system_program::ID
```

---

### 3.5 Arbitrary CPI — Unvalidated Program Target

**Pattern name:** Arbitrary CPI via unchecked program key (`arbitrary_cpi`)

**What the developer writes:** Constructing an `Instruction` with a `program_id` derived from an `AccountInfo.key` that has not been validated against the expected program address.

**Why this framework makes it more likely:** `solana_program::program::invoke` takes a raw `Instruction` struct. The developer builds this struct manually and must supply the `program_id` field. If this field comes from an unvalidated `AccountInfo`, the attacker controls the CPI target entirely.

**Formal property that should hold but does not:**
`guard: token_program.key == &spl_token::ID`

**Vulnerable code:**
```rust
use solana_program::program::invoke;

pub fn process_transfer(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let token_program = &accounts[3]; // Not validated!
    invoke(
        &spl_token::instruction::transfer(
            token_program.key, // attacker-controlled
            accounts[0].key, accounts[1].key, accounts[2].key, &[], amount,
        )?,
        &accounts[..4],
    )
}
```

**Correct code:**
```rust
pub fn process_transfer(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let token_program = &accounts[3];
    if token_program.key != &spl_token::ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    invoke(
        &spl_token::instruction::transfer(
            token_program.key, accounts[0].key, accounts[1].key, accounts[2].key, &[], amount,
        )?,
        &accounts[..4],
    )
}
```

**kani::assert! expression:**
```rust
kani::assert!(token_program.key == &spl_token::ID, "token_program must be SPL Token");
```

**QEDSpec clause:**
```
guard: token_program.key == spl_token::ID
```

---

### 3.6 PDA Sharing via Non-Unique Seeds

**Pattern name:** Over-broad PDA seeds creating shared authority (`permissionless_state_write`)

**What the developer writes:** A PDA derived from global-only seeds (e.g., token mint alone) that creates one shared PDA as the authority for all users.

**Why this framework makes it more likely:** Native Rust programs commonly document PDA seeds in comments but have no constraint system to enforce uniqueness. Developers optimizing for gas may use minimal seeds without recognizing the shared-authority implication.

**Formal property that should hold but does not:**
`guard: pool.withdraw_destination == destination.key AND pool.owner == authority.key`

**Vulnerable code:**
```rust
// Seeds only include mint — shared authority for all users
let (pool_pda, _) = Pubkey::find_program_address(
    &[b"pool", mint.key.as_ref()], program_id
);
// Any user of this mint can authorize withdrawals from any other user's sub-vault
```

**Correct code:**
```rust
// Include owner in seeds — per-user PDAs
let (pool_pda, canonical_bump) = Pubkey::find_program_address(
    &[b"pool", mint.key.as_ref(), authority.key.as_ref()], program_id
);
// AND verify stored destination
let pool_data = PoolState::try_from_slice(&pool.data.borrow())?;
if pool_data.withdraw_destination != *destination.key {
    return Err(ProgramError::InvalidAccountData);
}
if pool_data.authority != *authority.key {
    return Err(ProgramError::InvalidAccountData);
}
```

**kani::assert! expression:**
```rust
kani::assert!(
    pool_data.withdraw_destination == *destination.key,
    "destination must match stored field"
);
kani::assert!(
    pool_data.authority == *authority.key,
    "authority must match stored field"
);
```

**QEDSpec clause:**
```
guard: pool.withdraw_destination == destination.key
guard: pool.authority == authority.key
```

---

### 3.7 Panic via Unwrap on Instruction Data

**Pattern name:** DoS via malformed instruction data (`arithmetic_error`)

**What the developer writes:** Using `.unwrap()` on Borsh deserialization or slice operations on instruction data, causing a panic when an attacker sends malformed data.

**Why this framework makes it more likely:** Native Rust has no IDL-based schema validation. Borsh's `try_from_slice` returns a `Result`, but developers may use `.unwrap()` for brevity, turning any malformed instruction into a program panic that produces a confusing error.

**Formal property that should hold but does not:**
`requires: instruction_data.len() >= expected_size`

**Vulnerable code:**
```rust
pub fn process_instruction(
    _program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]
) -> ProgramResult {
    let instruction = Instructions::try_from_slice(instruction_data).unwrap(); // panic!
    // Attacker sends malformed data — program panics with unhelpful message
    Ok(())
}
```

**Correct code:**
```rust
pub fn process_instruction(
    _program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]
) -> ProgramResult {
    let instruction = Instructions::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    match instruction { /* ... */ }
    Ok(())
}
```

**kani::assert! expression:**
```rust
kani::assert!(
    instruction_data.len() >= core::mem::size_of::<Instructions>(),
    "instruction data must be at least the minimum expected size"
);
```

**QEDSpec clause:**
```
requires: instruction_data.len() >= minimum_instruction_size
```

---

## 4. Trust Boundaries

### Attacker-Controlled Inputs

Every account in the `accounts: &[AccountInfo]` slice is attacker-controlled in a Native Rust program. The attacker controls account positions, account keys, account ownership fields, account data bytes, signer flags (within the signed transaction), and writability flags (within the transaction). All of these must be validated explicitly.

Additionally, `instruction_data: &[u8]` is entirely attacker-controlled. Any slice indexing, length assumptions, or Borsh deserialization must handle adversarial input — including empty slices, overlong slices, and byte sequences that parse to unexpected enum variants.

### Framework Assumptions That the Developer Must Verify

`solana_program` makes the following assumptions that the developer must verify explicitly:
- All accounts in the slice are unchecked — ownership, discriminator, signer, writability, PDA derivation, and address must all be verified by the developer.
- The order of accounts in the slice is determined by the client — there is no schema enforcement.
- `next_account_info` returns accounts in order; if the client sends accounts in the wrong order, the program will operate on the wrong accounts unless each account is positionally validated.

### CPI Trust Boundaries

**What `invoke` / `invoke_signed` verifies:** The runtime validates that `invoke_signed` seed vectors correctly derive the claimed PDA signers. Invalid seeds cause the CPI to fail. The runtime also enforces that writable accounts passed to the callee are marked writable and that signer accounts are correctly signed.

**What the developer must verify:**
- The target program key is the expected program (e.g., `spl_token::ID` for SPL Token).
- Accounts passed to the callee are in the correct order for the callee's instruction interface.
- After a CPI that modifies accounts, re-read account data before using it (do not cache borrows across CPIs).
- Do not pass additional signer privileges (via `invoke_signed` seeds) that are not strictly required for the specific operation.

### What Passing an Account Without Any Checks Leaves Unprotected

Using an account from `next_account_info` without any checks leaves the following completely unprotected: owner (which program created/controls this account), discriminator (what type of data this account holds), signer status (whether a valid signature authorizes this account's participation), PDA derivation (whether this is the correct PDA for the given seeds), and data integrity (whether the data hasn't been tampered with by a malicious program that previously owned this account).

---

## 5. Discriminator and Type Safety

### How Account Types Are Distinguished

Native Rust programs have no automatic discriminator. Common approaches:
1. **Borsh enum wrapper:** Include an `account_type: AccountType` enum field as the first field in every account struct. The `AccountType` enum serializes as a 1-byte or 4-byte integer prefix.
2. **Manual byte tag:** Reserve the first byte of every account as a type tag constant, checked manually before deserialization.
3. **Account size as implicit discriminator:** Relying on `data.len() == STRUCT_SIZE` as a type indicator — insecure if two types share the same size.

### What Prevents Type Confusion Attacks

Only explicit discriminator checks by the developer. `Borsh::try_from_slice` will succeed for any byte sequence matching the field layout. Two structs with identical field types are completely interchangeable at the byte level. The discriminator check must verify that the byte value matches the expected type before accepting the deserialized struct.

### Where the Discriminator Check Happens

The discriminator check must be written by the developer, immediately after ownership verification and before any business logic. It can be bypassed by: using `try_from_slice` without a discriminator check, using raw slice indexing to read fields without deserializing, or relying on account size as a type indicator.

### Developer Responsibility

The developer must define discriminator constants, include the discriminator as a field in every account struct, verify the discriminator after ownership and before data use, and ensure no two account types share the same discriminator value within the same program.

---

## 6. Initialization and Lifecycle

### How Native Rust Prevents Reinitialization Attacks

The System Program's `create_account` instruction fails if the target account already has non-zero lamports. This provides partial protection: if an existing account is rent-exempt, the `create_account` CPI will fail. However, this does not protect against re-initialization of accounts that have been zeroed but not closed, or accounts initialized via data serialization without a `create_account` CPI.

The complete protection requires an explicit check: `if !account.data.borrow().iter().all(|&b| b == 0)` before initializing, or checking the discriminator byte.

### What the Developer Must Do During Initialization

- Verify the account is uninitialized (data zeroed or discriminator byte not set).
- Verify the payer is a signer and is writable.
- Calculate and verify the correct rent-exempt lamport amount.
- Invoke `create_account` via the System Program before writing any data.
- Serialize the struct including the discriminator into the account data.
- Store the canonical bump from `find_program_address` if the account is a PDA.

### How Native Rust Handles Account Closure

There is no automatic closure mechanism. The developer must: transfer all lamports to the destination, zero all data bytes, and reassign ownership to the System Program via `account.assign(&system_program::ID)`. All three steps are required. Omitting the data zeroing or the owner reassignment leaves the account in an inconsistent state vulnerable to exploitation.

### Lifecycle Transitions

Native Rust tracks no lifecycle. All state machine transitions (created, active, settled, closed) must be represented as fields in the account data and checked at the start of each instruction handler.

---

## 7. Arithmetic Safety

### Default Behavior

`solana_program` does not set or require `overflow-checks = true`. Programs initialized without `anchor init` or a custom template may not have this setting. Integer overflow in release builds is **silent wraparound by default** unless `overflow-checks = true` is set.

### How to Enable Overflow Checks

Add to workspace `Cargo.toml`:
```toml
[profile.release]
overflow-checks = true
```

This causes all primitive integer arithmetic to panic on overflow in release builds, matching debug behavior.

### What Requires Explicit Checked Variants

Even with `overflow-checks = true`:
- **`as` casts** (e.g., `value as u64`) silently truncate — use `u64::try_from(value)?`.
- **Wrapping arithmetic** (`wrapping_add`, etc.) bypasses the flag intentionally.
- **Division by zero** panics regardless — use `checked_div` when the divisor may be zero.
- **Direct lamport arithmetic** (`**account.try_borrow_mut_lamports()? += amount`) should use `.checked_add`.

### Framework-Specific Arithmetic Utilities

`solana_program` provides no arithmetic helpers. Use Rust standard: `.checked_add()`, `.checked_sub()`, `.checked_mul()`, `.checked_div()`, `.saturating_add()`, `.saturating_sub()`.

---

## 8. QEDSpec Clause Mapping

| Property | Section | QEDSpec Clause Type | Rationale |
|---|---|---|---|
| Account ownership (`account.owner == program_id`) | 2.1 | `guard` | Pre-execution, account property |
| Signer check (`account.is_signer`) | 2.2 | `guard` | Pre-execution, account property |
| Authority binding (stored field == signer key) | 2.2 | `guard` | Pre-execution, field equality |
| Discriminator / type tag | 2.3 | `guard` | Pre-execution, account data property |
| PDA derivation | 2.4 | `guard` | Pre-execution, account key |
| Sysvar authenticity (`Sysvar::get()`) | 2.5 | `guard` | Pre-execution, canonical read |
| CPI program identity | 2.6 | `guard` | Pre-execution, account key |
| Instruction data validity | 2.7 | `requires` | Pre-execution value: data.len >= min_size |
| Not already initialized | 2.8 | `requires` | Pre-execution value: data is zeroed |
| Canonical bump stored on init | 2.8 | `establishes` | First creation: account.bump == canonical |
| Closure: lamports zero | 2.9 | `ensures` | Post-execution: account.lamports == 0 |
| Closure: data zeroed | 2.9 | `ensures` | Post-execution: all data bytes == 0 |
| Closure: owner reassigned | 2.9 | `ensures` | Post-execution: account.owner == System Program |
| Distinct mutable accounts | 2.10 | `requires` | Pre-execution: from.key != to.key |
| Overflow-free arithmetic | 2.11 | `invariant` | Throughout: arithmetic within type bounds |
| Balance invariant | 2.11 | `ensures` | Post: new_balance == old_balance ± amount |
| PDA sharing prevention | 3.6 | `guard` | Pre-execution: pool.authority == user.key |

---

## 9. Common Audit Findings in This Framework

### 9.1 `missing_ownership_check`

**Why common in Native Rust:** There is no typed account system. `AccountInfo` is untyped. `Borsh::try_from_slice` succeeds regardless of which program owns the account. Developers who write instruction handlers without ownership checks allow attackers to supply foreign accounts with identical data layouts. This is the highest-frequency finding in Native Rust programs, present in essentially all programs that skip the ownership check on any account.

**Framework feature contributing:** No Account<T> wrapper. `next_account_info` returns unvalidated `AccountInfo`.

**Gap analysis detection:** For every `Borsh::try_from_slice` or manual field read, check whether `account.owner == program_id` (or the appropriate foreign program ID) is verified before the deserialization call. Flag any deserialization without this check.

---

### 9.2 `missing_signer_check`

**Why common in Native Rust:** The `.is_signer` field on `AccountInfo` must be read and checked explicitly. Developers who implement authority binding (comparing `account.authority == *signer.key`) may forget that field equality alone does not prove the signer actually signed the transaction. The missing `is_signer` check allows an attacker to include the real authority's pubkey in the instruction without their signature.

**Framework feature contributing:** No Signer<'info> type. `AccountInfo.is_signer` is a plain `bool` field — easy to miss.

**Gap analysis detection:** For every instruction that reads an authority from account data and compares it to another account's key, verify that the other account's `is_signer` is also checked. Flag any authority comparison not accompanied by `is_signer`.

---

### 9.3 `arithmetic_error`

**Why common in Native Rust:** `overflow-checks = true` is NOT the default for `solana_program` projects. Programs not using the Anchor scaffold may silently overflow balances. Additionally, `as` casts (e.g., `amount as u64` from `u128`) silently truncate regardless of the overflow flag. `.unwrap()` on Borsh deserialization panics on malformed instruction data, producing DoS via crafted inputs.

**Framework feature contributing:** No required `Cargo.toml` template. The developer must explicitly add `overflow-checks = true`. No schema validation on instruction data.

**Gap analysis detection:** (1) Check for `overflow-checks = true` in `Cargo.toml`; (2) search for `as` casts on numeric values (flag u128→u64, usize→u32); (3) search for `.unwrap()` on `try_from_slice` or any slice indexing in instruction handlers.

---

### 9.4 `lifecycle_violation` (Account Revival / Zombie Accounts)

**Why common in Native Rust:** Developers implement closure by draining lamports (the visible step) but do not zero account data or reassign ownership. The account appears closed (zero lamports) but its discriminator is valid, its data is intact, and it can be re-funded within the same transaction to become usable again. There is no framework primitive that enforces the three-step closure.

**Framework feature contributing:** No close constraint or equivalent. The correct sequence (drain + zero + assign) must be implemented from scratch.

**Gap analysis detection:** Any instruction named `close`, `withdraw_and_close`, or `settle` that does not contain: (1) zeroing of data bytes; (2) `account.assign(&system_program::ID)`. Flag as lifecycle_violation if either is absent.

---

### 9.5 `insecure_initialisation`

**Why common in Native Rust:** The `create_account` System Program CPI provides partial reinitialization protection (fails if account has lamports), but developers sometimes initialize by writing data directly to an existing account without a `create_account` CPI. In these cases, no reinitialization protection exists. Additionally, programs that use `init_if_needed` logic (checking lamports to decide whether to initialize) can be tricked by an attacker who pre-funds the account.

**Framework feature contributing:** No init constraint. The System Program CPI is the only protection, and it is partial. The developer must add an explicit check for the initialized discriminator.

**Gap analysis detection:** Any initialization handler that writes an account type discriminator (data[0] = TYPE_TAG or Borsh serialization of a struct with an account_type field) without first checking that the existing discriminator is zero or empty is a candidate for `insecure_initialisation`.

---

---

# EMBEDDING-OPTIMIZED VERSION

*Each chunk is independently understandable and begins with framework, topic, and applies-to fields for semantic retrieval.*

---

```
Framework: Native Rust (solana_program)
Topic: Zero Automatic Security Enforcement — Everything Is Manual
Applies to: All instructions in every native solana_program program

Native Rust programs using solana_program provide zero automatic security enforcement. The entrypoint! macro delivers raw &[AccountInfo] and &[u8] slices. There are no typed account wrappers, no constraint attributes, no discriminator systems, no PDA validation, and no sysvar address verification. Every security property must be written as explicit code: account.owner == program_id (ownership), account.is_signer (signer), account.data discriminator byte (type safety), find_program_address derivation (PDA), and token_program.key == &spl_token::ID (CPI target). The entire account slice is attacker-controlled until the developer's checks reject it.
```

---

```
Framework: Native Rust (solana_program)
Topic: Account Ownership Verification — Manual owner Check
Applies to: All instructions accessing program-owned accounts

There is no Account<T> type. Ownership must be checked: if account.owner != program_id { return Err(ProgramError::IllegalOwner); }. This must appear before any Borsh deserialization or data access. Borsh's try_from_slice succeeds for any byte sequence matching the struct layout, so two structs with identical field types are interchangeable at the byte level. Without ownership check + discriminator, type confusion is guaranteed to succeed. QEDSpec: guard: account.owner == program_id.
```

---

```
Framework: Native Rust (solana_program)
Topic: Signer Check — Manual is_signer Verification With Authority Binding
Applies to: All authority-gated and privileged instructions

There is no Signer<'info> type. Signer status: if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }. This is necessary but not sufficient. The authority's key must also be compared to the stored authority field in the account being protected: if vault_data.authority != *authority.key { return Err(ProgramError::InvalidAccountData); }. Field equality without signer check = attacker includes real authority pubkey without their signature. Signer check without field binding = any signer can operate. Both checks are required. QEDSpec: guard: authority.is_signer == true AND vault.authority == authority.key.
```

---

```
Framework: Native Rust (solana_program)
Topic: Account Discriminator — Developer-Defined Type Tagging via Borsh or Manual Byte
Applies to: All instructions deserializing program-owned accounts

No automatic discriminator. Common patterns: (1) AccountType enum as first field in every struct — serializes as 1–4 byte prefix, verified after deserialization; (2) manual first-byte tag, checked before try_from_slice. The discriminator check must appear after ownership and before business logic. Without it: two accounts with identical Borsh-serializable field types (Vault { authority: Pubkey, balance: u64 } and Config { authority: Pubkey, value: u64 }) are indistinguishable — type confusion attack succeeds. Relying only on account size as type indicator is insecure if two types share the same byte size. QEDSpec: guard: vault_data.account_type == AccountType::Vault.
```

---

```
Framework: Native Rust (solana_program)
Topic: PDA Derivation Verification — Manual find_program_address
Applies to: All instructions using Program Derived Addresses

No seeds/bump constraint. During init: let (expected, canonical_bump) = Pubkey::find_program_address(&[b"vault", authority.key.as_ref()], program_id); verify new_account.key == &expected; store vault_data.bump = canonical_bump. During use: validate with create_program_address using the stored bump — not a user-supplied bump from instruction data. Accepting a user-supplied bump and using create_program_address without comparing to find_program_address result is a canonicalization attack — the attacker supplies a valid non-canonical bump. QEDSpec: guard: vault.key == find_program_address(seeds, program_id).address.
```

---

```
Framework: Native Rust (solana_program)
Topic: Arithmetic Safety — overflow-checks Not Set by Default
Applies to: All arithmetic operations in instruction handlers

solana_program does not require or set overflow-checks = true in Cargo.toml. Integer overflow in release builds is silent wraparound by default. To enable: add [profile.release] overflow-checks = true to workspace Cargo.toml. Even with this flag: as casts (e.g., amount as u64 from u128) silently truncate — use u64::try_from(value)?. Wrapping arithmetic (wrapping_add etc.) bypasses the flag. Division by zero panics regardless — use checked_div. Always use .checked_add() / .checked_sub() for lamport arithmetic. Panics from .unwrap() on try_from_slice on malformed instruction data are a DoS vector — use .map_err(|_| ProgramError::InvalidInstructionData)? instead. QEDSpec: invariant: all arithmetic within type bounds.
```

---

```
Framework: Native Rust (solana_program)
Topic: Account Closure — Three-Step Manual Pattern Required
Applies to: All instructions closing accounts

No close constraint. Correct closure: (1) transfer all lamports to destination; (2) zero all data bytes (for byte in data.iter_mut() { *byte = 0; }); (3) reassign owner to System Program (account.assign(&system_program::ID)). All three steps are required. Draining lamports alone (without zeroing data) leaves a revivable account — the discriminator is valid, data intact, re-fundable in same transaction. Not reassigning to System Program leaves a zero-lamport account still owned by the program, creating a zombie state. QEDSpec: ensures: account.lamports == 0; ensures: all data bytes == 0; ensures: account.owner == system_program::ID.
```

---

```
Framework: Native Rust (solana_program)
Topic: Reinitialization Prevention — Explicit Initialized Check Required
Applies to: All initialization instructions

No init constraint. The create_account System Program CPI fails if the account has non-zero lamports (partial protection). Explicit check required: if !account.data.borrow().iter().all(|&b| b == 0) { return Err(ProgramError::AccountAlreadyInitialized); } OR check the discriminator: if data[0] == TYPE_DISCRIMINATOR { return Err(...); }. Omitting this check allows attackers to call initialize() on existing accounts, overwriting authority fields and taking over state. QEDSpec: requires: account.data is zeroed or discriminator byte not set.
```

---

```
Framework: Native Rust (solana_program)
Topic: CPI Program Identity — Manual Key Verification Before invoke()
Applies to: All instructions performing cross-program invocations

No Program<'info, T> type. Before any invoke() call: if token_program.key != &spl_token::ID { return Err(ProgramError::IncorrectProgramId); }. An unvalidated program AccountInfo in CPI position is an arbitrary_cpi vulnerability — the attacker substitutes a malicious program at a different address that implements the same instruction interface but performs harmful operations. The system-program and token-program identities are the most common targets. After CPI, re-borrow account data before using it — CPI may have modified state. QEDSpec: guard: token_program.key == spl_token::ID.
```

---

```
Framework: Native Rust (solana_program)
Topic: Sysvar Authenticity — Use Sysvar::get() Not AccountInfo
Applies to: All instructions reading Clock, Rent, or other sysvars

Passing sysvar AccountInfo without address verification allows sysvar spoofing. Safe pattern: use Clock::get()? and Rent::get()? (runtime syscalls, no account parameter, cannot be spoofed). If an AccountInfo is accepted for a sysvar, verify the address: if clock_account.key != &solana_program::sysvar::clock::id() { return Err(...); }. solana_program's Clock::from_account_info validates the key internally and is also acceptable. Never deserialize sysvar data from an unvalidated AccountInfo. QEDSpec: guard: clock_account.key == Clock::id() (or use Clock::get() with no account).
```

---

```
Framework: Native Rust (solana_program)
Topic: Common Audit Finding — missing_ownership_check
Applies to: All instructions, all account types

Root cause: No Account<T> type. try_from_slice succeeds regardless of account ownership. Detection: for every Borsh try_from_slice call or manual slice access on account data, verify account.owner == program_id is checked before it. Flag any instruction where data is read from an AccountInfo that lacks a preceding ownership check. Highest-frequency finding in native Rust audits. Special case: accounts from the remaining portion of the accounts array after positional destructuring often skip the ownership check.
```

---

```
Framework: Native Rust (solana_program)
Topic: Common Audit Finding — arithmetic_error
Applies to: All instructions performing arithmetic on balances or amounts

Root cause: overflow-checks = true is NOT the default. Programs without this setting silently wrap on overflow. Detection: (1) check Cargo.toml for overflow-checks = true in [profile.release]; (2) search for as casts on numeric values between different widths (u128 as u64, usize as u32); (3) search for .unwrap() on try_from_slice or any fallible operation on instruction_data — panic on malformed input is a DoS vector; (4) check all balance arithmetic for .checked_add() / .checked_sub() usage.
```

---

```
Framework: Native Rust (solana_program)
Topic: Common Audit Finding — lifecycle_violation (Account Revival)
Applies to: All close and settlement instructions

Root cause: No close constraint. Developers implement the visible step (lamport drain) but omit data zeroing and owner reassignment. Detection: any instruction draining lamports to zero without also zeroing all data bytes and calling account.assign(&system_program::ID). Three-step check: (1) lamports set to zero? (2) all data bytes zeroed? (3) owner reassigned to System Program? If any step is missing, flag as lifecycle_violation. Lamport-only closure leaves account revivable within same transaction.
```

---

```
Framework: Native Rust (solana_program)
Topic: Common Audit Finding — missing_signer_check
Applies to: All privileged and authority-gated instructions

Root cause: No Signer<'info> type. is_signer must be checked explicitly. Detection: for every instruction that reads an authority pubkey from account data and compares it to another account's key, verify that the other account's is_signer == true is also checked. An authority field equality check without is_signer allows an attacker to include the real authority's pubkey in the instruction without their signature. Both checks are always required for authority-gated operations.
```

---

```
Framework: Native Rust (solana_program)
Topic: Common Audit Finding — insecure_initialisation
Applies to: All initialization instructions

Root cause: No init constraint. System Program create_account CPI provides partial protection (fails on non-zero lamports) but developers sometimes initialize by direct data serialization without a create_account CPI, bypassing this protection entirely. Detection: any handler that serializes account data (account_data.serialize(&mut *account.data.borrow_mut())?) without first verifying the account is uninitialized (all bytes zero or discriminator not set). Flag any case where data is written without a preceding empty-check. Also flag instruction handlers that initialize by writing to existing accounts if the re-initialization guard is absent.
```