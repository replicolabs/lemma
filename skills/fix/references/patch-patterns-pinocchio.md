# Pinocchio Security Fix Patterns

Precise code patterns for fixing each vulnerability class in Pinocchio
programs. Pinocchio has no framework safety net — all validation is manual.

---

## DC-001 / DC-002: Missing Owner or Signer Check

```rust
// BEFORE — no validation
let authority = accounts[0];

// AFTER — signer check
let authority = accounts[0];
if !authority.is_signer() {
    return Err(ProgramError::MissingRequiredSignature);
}

// AFTER — owner check
if !vault.is_owned_by(&crate::ID) {
    return Err(ProgramError::InvalidAccountOwner);
}
```

In `TryFrom` implementations:

```rust
impl<'a> TryFrom<&'a [AccountInfo<'a>]> for Withdraw<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountInfo<'a>]) -> Result<Self, Self::Error> {
        let [depositor, vault, destination, ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // AFTER — add these checks
        if !depositor.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if !vault.is_owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }

        Ok(Self { depositor, vault, destination })
    }
}
```

---

## DC-008 / DC-018: Arbitrary CPI

```rust
// BEFORE — unvalidated program
let token_program = accounts[3];
Transfer { from, to, authority, amount }.invoke()?;

// AFTER
let token_program = accounts[3];
if token_program.key() != &pinocchio_token::ID {
    return Err(ProgramError::IncorrectProgramId);
}
Transfer { from, to, authority, amount }.invoke()?;
```

---

## DC-011: Sysvar Spoofing

```rust
// BEFORE — unsafe: accepts fake sysvar as account parameter
let clock_account = accounts[4];
let clock_data = clock_account.try_borrow_data()?;
let clock: Clock = bincode::deserialize(&clock_data)?;

// AFTER — safe: use the validated accessor
use pinocchio::sysvars::{clock::Clock, Sysvar};
let clock = Clock::get()?;
let current_time = clock.unix_timestamp;
```

---

## DC-009: Non-Canonical Bump

```rust
// BEFORE — user-supplied bump
let bump = instruction_data[0]; // attacker-controlled
let pda = create_program_address(&[b"vault", &[bump]], &crate::ID)?;

// AFTER — canonical bump stored and reused
// During init:
let (pda, canonical_bump) = find_program_address(&[b"vault"], &crate::ID);
state.bump = canonical_bump;

// During validation in subsequent handlers:
let expected = create_program_address(
    &[b"vault", &[state.bump]],
    &crate::ID,
).map_err(|_| ProgramError::InvalidSeeds)?;
if vault.key() != &expected {
    return Err(ProgramError::InvalidSeeds);
}
```

---

## DC-014: Lamport Griefing

```rust
// BEFORE — transfers exact rent minimum without checking existing lamports
let required = Rent::get()?.minimum_balance(space);
Transfer {
    from: payer,
    to: account,
    lamports: required,
}.invoke()?;

// AFTER — transfer only the deficit
let required = Rent::get()?.minimum_balance(space);
let existing = account.lamports();
if existing < required {
    Transfer {
        from: payer,
        to: account,
        lamports: required - existing,
    }.invoke()?;
}
Allocate { account, space: space as u64 }.invoke_signed(signers)?;
Assign { account, owner: &crate::ID }.invoke_signed(signers)?;
```

---

## Arithmetic Fixes

```rust
// BEFORE
let amount_out = amount_in * reserve_out / (reserve_in + amount_in);

// AFTER — checked with u128 intermediate
let amount_out = (amount_in as u128)
    .checked_mul(reserve_out as u128)
    .and_then(|n| {
        (reserve_in as u128)
            .checked_add(amount_in as u128)
            .map(|d| n / d)
    })
    .ok_or(ProgramError::ArithmeticOverflow)? as u64;
```