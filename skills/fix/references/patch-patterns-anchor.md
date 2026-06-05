# Anchor Security Fix Patterns

Precise code patterns for fixing each vulnerability class in Anchor programs.
Use the exact pattern for the specific gap being fixed.

---

## DC-001 / DC-002: Missing Signer or Owner Check

### Fix: Use typed Signer account

```rust
// BEFORE
pub authority: AccountInfo<'info>,

// AFTER
pub authority: Signer<'info>,
```

### Fix: Add explicit signer constraint

```rust
// BEFORE
pub authority: UncheckedAccount<'info>,

// AFTER
#[account(signer)]
pub authority: UncheckedAccount<'info>,
```

### Fix: Typed Account<T> for ownership

```rust
// BEFORE
#[account(mut)]
pub pool: AccountInfo<'info>,

// AFTER
#[account(mut)]
pub pool: Account<'info, Pool>,
```

---

## DC-003: init_if_needed

```rust
// BEFORE
#[account(init_if_needed, payer = payer, space = 8 + Pool::LEN)]
pub pool: Account<'info, Pool>,

// AFTER
#[account(init, payer = payer, space = 8 + Pool::LEN)]
pub pool: Account<'info, Pool>,
// Add separate check in handler body if conditional init is needed:
// require!(!pool.is_initialized, ErrorCode::AlreadyInitialized);
```

---

## DC-005: Duplicate Mutable Accounts

```rust
// BEFORE
#[account(mut)]
pub token_account_a: Account<'info, TokenAccount>,
#[account(mut)]
pub token_account_b: Account<'info, TokenAccount>,

// AFTER
#[account(
    mut,
    constraint = token_account_a.key() != token_account_b.key()
        @ ErrorCode::DuplicateAccounts
)]
pub token_account_a: Account<'info, TokenAccount>,
#[account(mut)]
pub token_account_b: Account<'info, TokenAccount>,
```

---

## DC-008 / DC-018: Arbitrary CPI

```rust
// BEFORE
pub token_program: AccountInfo<'info>,

// AFTER — Option 1: Typed Program (preferred, zero CU overhead)
pub token_program: Program<'info, Token>,

// AFTER — Option 2: Explicit key check
#[account(constraint = token_program.key() == spl_token::ID @ ErrorCode::InvalidTokenProgram)]
pub token_program: AccountInfo<'info>,
```

---

## DC-010: Account Close Without Zeroing

```rust
// BEFORE — manual lamport transfer without close constraint
let dest = ctx.accounts.destination.to_account_info();
let src  = ctx.accounts.pool.to_account_info();
**dest.lamports.borrow_mut() += **src.lamports.borrow();
**src.lamports.borrow_mut() = 0;

// AFTER — use Anchor close constraint
#[account(mut, close = destination)]
pub pool: Account<'info, Pool>,
pub destination: SystemAccount<'info>,
```

---

## DC-013: Missing has_one

```rust
// BEFORE
#[account(mut)]
pub pool: Account<'info, Pool>,
pub authority: Signer<'info>,

// AFTER
#[account(mut, has_one = authority @ ErrorCode::Unauthorized)]
pub pool: Account<'info, Pool>,
pub authority: Signer<'info>,
```

---

## DC-016: One-Shot Without Init Protection

```rust
// BEFORE — manual init without protection
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    ctx.accounts.pool.authority = ctx.accounts.authority.key();
    Ok(())
}

// AFTER — use Anchor init constraint
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Pool::LEN,
    )]
    pub pool: Account<'info, Pool>,
    // ...
}
```

---

## DC-021: Paired Validator Mismatch

```rust
// BEFORE
#[account(mut)]
pub token_account: Account<'info, TokenAccount>,
pub mint: Account<'info, Mint>,

// AFTER
#[account(
    mut,
    has_one = mint @ ErrorCode::InvalidMint,
)]
pub token_account: Account<'info, TokenAccount>,
pub mint: Account<'info, Mint>,
```

---

## Arithmetic Fixes (DC-006 / DC-007)

```rust
// BEFORE — unchecked arithmetic
let amount_out = amount_in * reserve_out / (reserve_in + amount_in);

// AFTER — Option 1: checked arithmetic (recommended)
let amount_out = (amount_in as u128)
    .checked_mul(reserve_out as u128)
    .ok_or(ErrorCode::ArithmeticOverflow)?
    .checked_div(
        (reserve_in as u128)
            .checked_add(amount_in as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?
    )
    .ok_or(ErrorCode::ArithmeticOverflow)? as u64;

// AFTER — Option 2: enable overflow checks in Cargo.toml
// [profile.release]
// overflow-checks = true
// Then use saturating arithmetic where semantically appropriate:
let amount_out = amount_in
    .saturating_mul(reserve_out)
    .saturating_div(reserve_in.saturating_add(amount_in));
```