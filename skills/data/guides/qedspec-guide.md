# QEDSpec Language Reference Guide
## For the Lemma Security Analysis Tool (qedgen)

---

## 1. The Five Clause Types

Every clause in a `.qedspec` handler block is one of five kinds. Each kind has a precise semantic role in the instruction lifecycle. Getting the kind wrong is the most common cause of `qedgen check` failures.

---

### 1.1 `guard`

**Exact definition.** A `guard` is a bare Boolean constraint placed at the sBPF pragma level — it appears inside a `pragma sbpf { … }` block as a `guard` item, not inside a handler body. In Rust/Anchor handler bodies, the functional equivalent role is played by `requires`. At the handler level the keyword `guard` is not a valid handler clause; attempts to use it inside a handler body are parse errors.

**When to use it.** Use `guard` only inside `pragma sbpf { … }` blocks to annotate assembly-level checks. For every Anchor/Rust instruction constraint, use `requires` instead (see §1.2). Do not confuse the sBPF pragma item `guard` with the concept of "a guard condition" — in documentation the word "guard" is used loosely, but the keyword `guard` is sBPF-only.

**Semantic timing.** At the sBPF level, `guard` items are the annotation of checks that fire before the instruction body begins executing. They are pre-conditions on the raw account buffer layout, not on decoded state.

**Correct examples.**

```fsharp
// Example 1: sBPF instruction with a guard annotation
pragma sbpf {
  instruction counter_increment
  guard "r2 == 1"       // exactly one account in the buffer
  fuel 1000
}
```

```fsharp
// Example 2: Multiple guards on an sBPF handler
pragma sbpf {
  instruction transfer_tokens
  guard "r2 == 3"
  guard "r3 != 0"
}
```

```fsharp
// Example 3: Guard on assembly entry that checks discriminant
pragma sbpf {
  instruction vault_withdraw
  guard "*(u8*)(r1 + 0) == 2"
  scope withdraw_scope
}
```

**Common mistakes.**

1. *Using `guard` as a handler clause in Anchor specs.* `guard` is not in the set of valid handler clauses (`HandlerClause` variants) for Rust/Anchor specs. Writing `guard state.paused == 0` inside a handler body produces a parse error. Use `requires state.paused == 0 else ErrName` instead.

2. *Omitting the `pragma sbpf { }` wrapper.* `guard` items are pragma items. Writing `guard "condition"` at the top level outside a pragma block is a syntax error.

3. *Referencing DSL state fields inside a guard string.* The `guard` string is a raw sBPF register/memory expression, not a DSL expression over `state`. Writing `guard "state.amount > 0"` is semantically wrong; guard strings reference registers (`r1`, `r2`) and raw memory offsets.

---

### 1.2 `requires`

**Exact definition.** `requires <expr> else <ErrorVariant>` is a pre-condition clause on an instruction handler. It asserts that `<expr>` must hold over the pre-state and the instruction parameters before any state transition occurs. If `<expr>` is false, the instruction aborts with `<ErrorVariant>`. The `else <ErrorVariant>` suffix is mandatory; omitting it is a parse error. Multiple `requires` clauses in a single handler are AND-ed together — all must hold for the handler to proceed.

**When to use it.** Use `requires` for any caller-side obligation: input validation (amount > 0), lifecycle pre-conditions (state is Active), signer-index bounds, member-index bounds, or any guard that, if violated, should abort the instruction with a specific program error. Do not use `requires` to express post-conditions or invariant preservation — use `ensures` and `invariant` for those.

**Semantic timing.** `requires` fires before the effect block executes. The codegen emits `requires` as runtime guard checks in the generated `guards/<handler>.rs` file, which is called from the instruction entrypoint before any business logic runs. In Lean proofs, `requires` clauses become the precondition hypotheses of the handler's transition theorem.

**Correct examples.**

```fsharp
// Example 1: Simple amount bound
handler deposit (amount : U64) : State.Active -> State.Active {
  permissionless
  requires amount > 0 else InvalidAmount
  effect { total_deposits += amount }
}
```

```fsharp
// Example 2: Compound precondition (AND)
handler borrow (amount : U64) (collateral : U64) : Loan.Empty -> Loan.Active {
  auth borrower
  requires amount > 0 /\ collateral > 0 else InvalidAmount
  requires state.total_deposits >= amount else InsufficientLiquidity
  effect { amount := amount }
}
```

```fsharp
// Example 3: Lifecycle pre-condition + member index guard
handler approve (member_index : U8) : State.HasProposal -> State.HasProposal {
  auth approver
  requires member_index < state.member_count else NotAMember
  requires state.members[member_index] == approver else NotAMember
  requires state.voted[member_index] == 0 else AlreadyVoted
  effect { approval_count += 1 }
}
```

**Common mistakes.**

1. *Omitting the `else ErrorVariant` clause.* `requires amount > 0` without `else InvalidAmount` is a parse error. Every `requires` must name the error variant to emit on failure.

2. *Using an error variant that is not declared in `type Error`.* If `requires amount > 0 else Foo` appears but `Foo` is not listed under `type Error | ...`, `qedgen check` fails with: `error: unknown error variant 'Foo'`. Declare all error variants in the `type Error` block before referencing them.

3. *Referencing a parameter name that is not in the handler's parameter list or state fields.* `requires delta > 0` where the parameter is named `amount` produces: `error: 'delta' not found in handler parameters or state fields`. Parameter names in `requires` expressions must match the handler's declared `takes` parameters or `state.<field>` paths exactly.

---

### 1.3 `ensures`

**Exact definition.** `ensures <expr>` is a post-condition clause asserting that `<expr>` holds over the post-state after the handler's effect block has been applied. Unlike `requires`, `ensures` has no `else` clause — it is a logical obligation, not a runtime abort condition. The expression may reference `old(state.<field>)` to access the pre-state value of a field for comparison with the post-state value. Multiple `ensures` clauses in a handler are all required to hold simultaneously.

**When to use it.** Use `ensures` to state what the handler guarantees to its callers — a frame condition ("only `total` changed"), a monotonicity claim ("the output is at least the input"), or a structural relationship between pre- and post-state. `ensures` clauses become Lean theorem hypotheses that proof obligations must discharge and, when the interface declares them, become `kani::assume` facts in callee-contract propagation.

**Semantic timing.** `ensures` is checked over the post-state — after the effect block has run and the state transition has been committed. In Lean codegen, `ensures` lowers to the consequent of the handler's transition theorem. In Kani harnesses, `ensures` lowers to `assert!` statements after the handler call. For interface handlers, callee `ensures` clauses propagate into caller proofs as assumed facts.

**Correct examples.**

```fsharp
// Example 1: Frame condition — only one field changed
handler submit_schedule (amount : U64) : State.Active -> State.Active {
  permissionless
  requires amount > 0 else InvalidAmount
  effect { sp_next_free_slot += 1 }
  ensures state.sp_next_free_slot == old(state.sp_next_free_slot) + 1
}
```

```fsharp
// Example 2: Post-condition in an interface handler declaration
interface Token {
  program_id "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
  handler transfer (amount : U64) {
    discriminant "0x03"
    accounts {
      from      : writable
      to        : writable
      authority : signer
    }
    requires amount > 0
    ensures  amount > 0
  }
}
```

```fsharp
// Example 3: Result binder in an interface handler (v2.26+)
interface Oracle {
  program_id "..."
  handler get_price (mint : Pubkey) -> result : U64 {
    discriminant "0x01"
    accounts { feed : readonly }
    ensures result > 0
  }
}
```

**Common mistakes.**

1. *Adding `else ErrorVariant` to an `ensures` clause.* `ensures state.total > 0 else InvariantViolated` is a parse error. `ensures` has no `else` branch — it is a proof obligation, not a runtime check. Runtime aborts go in `requires`.

2. *Referencing `old(...)` without the `state.` prefix.* `ensures total == old(total) + amount` is wrong; the correct form is `ensures state.total == old(state.total) + amount`. The `old()` builtin wraps a full state-field path, not a bare name.

3. *Writing `ensures` on a handler that has no `effect` block.* An `ensures` clause on a no-op handler (no `effect`) that references post-state fields will produce a vacuous or tautological lowering. The `vacuous_property_lowering` lint will surface this as a warning. If the handler does not change state, the `ensures` cannot be meaningful — either add an effect or remove the clause.

---

### 1.4 `invariant` (handler-side clause)

**Exact definition.** Inside a handler body, `invariant Name` links the handler to a top-level named invariant and declares that this handler **preserves** the invariant — i.e., if `Name` holds in the pre-state, it must hold in the post-state. This is the "assume pre, assert post" form. The top-level invariant must already be declared as `invariant Name : <expr>` at the spec level before any handler can reference it. The handler-side `invariant` clause is distinct from `establishes` (see §1.5).

**When to use it.** Use `invariant Name` in handlers that maintain but do not initiate an invariant — any handler that mutates state fields covered by the named predicate and must preserve the predicate. Use `establishes` for the handler that first makes the invariant true (typically the init handler).

**Semantic timing.** Codegen generates a preservation harness: in Kani, `kani::assume(Name(&s))` is inserted before the handler call and `assert!(Name(&s_post))` after. In proptest, the same shape applies. In Lean, the preservation theorem has `h : Name s` as a hypothesis and `Name s'` as the goal.

**Correct examples.**

```fsharp
// Example 1: Top-level declaration + handler-side preservation
invariant root_set :
  state.root != ZERO_ROOT

handler update : State.Active -> State.Active {
  permissionless
  invariant root_set
  requires state.root != ZERO_ROOT
  effect { root := state.root }
}
```

```fsharp
// Example 2: Multiple handlers preserving the same invariant
invariant fee_valid :
  state.fee_bps <= 10000

handler update_fee (new_fee : U64) : State.Active -> State.Active {
  auth admin
  invariant fee_valid
  requires new_fee <= 10000 else FeeTooHigh
  effect { fee_bps := new_fee }
}

handler withdraw (amount : U64) : State.Active -> State.Active {
  auth admin
  invariant fee_valid
  requires amount > 0 else InvalidAmount
  effect { total -= amount }
}
```

```fsharp
// Example 3: Invariant on a count-bounded handler
invariant count_bounded :
  state.count <= MAX_COUNT

handler increment : State.Active -> State.Active {
  permissionless
  invariant count_bounded
  requires state.count < MAX_COUNT else LimitReached
  effect { count += 1 }
}
```

**Common mistakes.**

1. *Using `invariant Name` without a matching top-level `invariant Name :` declaration.* `qedgen check` fails with: `error: handler-side invariant 'Name' references an undeclared invariant`. The top-level declaration must appear before or after the handler in the file (order in the file does not matter, but the name must exist).

2. *Confusing `invariant Name` with `establishes Name`.* Writing `invariant Name` on an init handler that transitions from an uninitialized state where the invariant does not yet hold will cause the Kani harness to inject `kani::assume(Name(&s))` before the call. Since the invariant cannot hold in `Uninitialized` state, the harness becomes vacuously passing. Use `establishes` on init handlers.

3. *Supplying only a description string without a predicate body.* `invariant root_set "root is always non-zero"` (description-only form) generates no harness — no proptest, no Kani, no Lean obligation. Handler-side `invariant root_set` against this documentation-only declaration will silently produce no proof obligation. If verification is needed, the top-level invariant must carry a `rust_expr` or a DSL predicate body.

---

### 1.5 `establishes`

**Exact definition.** `establishes Name` inside a handler body asserts that this handler guarantees the named invariant holds in the post-state, WITHOUT assuming it holds in the pre-state. This is the "no pre-assume, assert post" form — the complement of the handler-side `invariant` clause. The top-level invariant `Name` must be declared at spec level.

**When to use it.** Use `establishes` for handlers that bring the system from an uninitialized or uninvariant state into one where the named invariant first becomes true. Typically used on init or one-shot activation handlers. Precisely: `establishes` is for any handler whose pre-state cannot guarantee the invariant (e.g., `Uninitialized`) but whose post-state must satisfy it.

**Semantic timing.** Codegen generates an establishment harness: in Kani, there is NO `kani::assume(Name(&s))` before the call, but `assert!(Name(&s_post))` appears after. In proptest, the same shape. In Lean, the theorem has no `h : Name s` hypothesis but does have `Name s'` as the goal. This is the critical difference from the handler-side `invariant` clause.

**Correct examples.**

```fsharp
// Example 1: Init handler establishes a named invariant
invariant root_set :
  state.root != ZERO_ROOT

handler init : State.Active -> State.Active {
  permissionless
  establishes root_set
  effect { root := 42 }
}
```

```fsharp
// Example 2: Lifecycle init establishes a balance invariant
invariant vault_initialized :
  state.total_deposits == 0

handler initialize_pool (rate : U64) : Pool.Uninitialized -> Pool.Active {
  auth authority
  establishes vault_initialized
  effect {
    interest_rate  := rate
    total_deposits := 0
    total_borrows  := 0
  }
}
```

```fsharp
// Example 3: One-shot activation establishes a monotonic predicate
invariant status_active :
  state.status == 1

handler activate : State.Pending -> State.Active {
  auth admin
  establishes status_active
  effect { status := 1 }
}
```

**Common mistakes.**

1. *Using `establishes` on a handler that already has `invariant` for the same name.* A handler cannot both `establishes Foo` and `invariant Foo` — these are mutually exclusive semantics. `qedgen check` will reject the duplicate with an error.

2. *Using `establishes` when the pre-state can already satisfy the invariant.* If the handler's pre-state is `State.Active` and `root_set` could already hold, you want `invariant root_set` (preserve), not `establishes root_set`. Using `establishes` here generates a harness with no pre-assume, which is weaker than necessary and may hide preservation bugs.

3. *Forgetting the top-level invariant declaration.* Same as with `invariant Name`: if `invariant root_set :` is not declared at spec level, `establishes root_set` fails with: `error: handler-side establishes 'root_set' references an undeclared invariant`.

---

## 2. State Machine Syntax

### 2.1 Declaring Typed Variants

State types are algebraic data types declared at the top level of a `.qedspec` file using the `type` keyword. Each variant is introduced with a `|` separator. Variants may be:

- **Unit variants** (no fields): `| Uninitialized`
- **Record variants** (with named fields): `| Active of { field_name : FieldType, ... }`

```fsharp
type PoolState
  | Uninitialized
  | Active of {
      authority      : Pubkey,
      total_deposits : U64,
      total_borrows  : U64,
      interest_rate  : U64,
    }
  | Paused

type LoanState
  | Empty
  | Active of {
      borrower   : Pubkey,
      pool       : Pubkey,
      amount     : U64,
      collateral : U64,
    }
  | Liquidated
```

**Supported field types:** `U8`, `U64`, `U128`, `I128`, `Pubkey`, `Bool`. Fields of type `U64`, `U128`, and `U8` map to `Nat` in Lean (for omega arithmetic). `I128` maps to `Int`. `Pubkey` is an opaque 32-byte type. `Bool` maps to `Bool`.

**The `type Error` block** must be declared separately and lists all error variants the program can return:

```fsharp
type Error
  | InsufficientLiquidity
  | Unauthorized
  | InvalidAmount
  | MathOverflow
```

Every error name used in `requires ... else <Name>` must appear in the `type Error` block.

### 2.2 Lifecycle Transitions

A handler's pre-state and post-state are written in the handler signature using the `Type.Variant -> Type.Variant` syntax:

```fsharp
handler handler_name (param : Type) : TypeName.PreVariant -> TypeName.PostVariant {
  ...
}
```

- The type name and variant name are separated by a dot: `Pool.Uninitialized`, `Loan.Active`, `State.HasProposal`.
- If the handler does not change state variant (it operates within the same variant), both sides are identical: `State.Active -> State.Active`.
- If a handler's pre-state and post-state differ, the codegen emits lifecycle enforcement: at runtime, the instruction aborts with `LifecycleViolation` if the account's discriminator does not match the expected pre-variant.

**Handlers without lifecycle transitions** (no state machine) omit the signature entirely:

```fsharp
handler stateless_handler (amount : U64) {
  permissionless
  ...
}
```

**Valid transition patterns:**

```fsharp
// One-shot init (Uninitialized → Active)
handler create_vault : State.Uninitialized -> State.Active { ... }

// Active self-transition (mutation within Active)
handler deposit (amount : U64) : State.Active -> State.Active { ... }

// Terminal transition (Active → Closed)
handler close_vault : State.Active -> State.Closed { ... }

// Multi-state machine with separate type names
handler borrow (amount : U64) : Loan.Empty -> Loan.Active { ... }
handler repay : Loan.Active -> Loan.Empty { ... }
handler liquidate : Loan.Active -> Loan.Liquidated { ... }
```

### 2.3 Which Clause Types Apply to State Machines

| Clause | Applies to state machine handlers? | Notes |
|---|---|---|
| `requires` | Yes | Guards on pre-state fields and params |
| `ensures` | Yes | Post-state field guarantees |
| `invariant Name` | Yes, for non-init handlers | Preserves; pre-assumes the invariant |
| `establishes Name` | Yes, for init/activation handlers | Does not pre-assume; asserts post |
| `guard` | No (sBPF only) | Not a valid handler clause |
| `auth` | Yes | Signer constraint |
| `permissionless` | Yes | Explicit opt-out of signer check |
| `effect` | Yes | Required to change state fields |
| `transfers` | Yes | SPL token CPI |
| `emits` | Yes | Event emission |
| `call` | Yes | Typed CPI |

---

## 3. Effect Declarations

The `effect { }` block specifies how handler execution mutates the state fields of the account. All mutations happen atomically — the effect block is applied as a unit after all `requires` guards pass.

### 3.1 `transfers`

**Purpose.** Declares an SPL token transfer CPI from one token account to another, with an explicit authority.

**Exact syntax:**

```fsharp
transfers {
  from <source_account> to <destination_account> amount <amount_expr> authority <authority_account>
}
```

All four fields (`from`, `to`, `amount`, `authority`) are required. Multiple transfers can appear in a single block, one per line.

**What it generates.** The codegen emits a `spl_token::instruction::transfer` CPI (or equivalent for the target framework). The `CpiProgramPin` cluster kind fires if `transfers` is absent from a handler that calls SPL token operations in the source code, locking in explicit direction.

**Examples:**

```fsharp
// Single transfer: user deposits into pool vault
transfers {
  from depositor_ta to pool_vault amount amount authority depositor
}

// Single transfer: pool lends to borrower
transfers {
  from pool_vault to borrower_ta amount amount authority pool
}

// Two transfers in one handler (e.g., an AMM swap)
transfers {
  from user_token_a_account to vault_a amount amount_in  authority user
  from vault_b to user_token_b_account amount amount_out authority pool
}
```

**Relationship to `effect`.** `transfers` and `effect` are independent clauses and can coexist. `effect` mutates the spec-level state struct; `transfers` fires a CPI. An AMM swap will typically have both: `effect` to update reserve balances, `transfers` to move tokens.

### 3.2 `emits`

**Purpose.** Declares that the handler emits a named event after successful execution.

**Exact syntax:**

```fsharp
emits EventName
```

The event name must be declared at the top level with an `event` block:

```fsharp
event Deposited { depositor : Pubkey, amount : U64 }
```

**What it generates.** In Anchor codegen, `emits EventName` lowers to an `emit!(EventName { ... })` call in the generated scaffold. The agent fills the field values. In Lean and Kani, `emits` is treated as auxiliary metadata — no proof obligation is generated for events alone.

**Examples:**

```fsharp
event SwapExecuted { user : Pubkey, amount_in : U64, amount_out : U64 }

handler swap (amount_in : U64) : State.Active -> State.Active {
  permissionless
  requires amount_in > 0 else InvalidAmount
  effect { reserve_a += amount_in }
  transfers { from user_ta_a to vault_a amount amount_in authority user }
  emits SwapExecuted
}
```

**Note.** `emits` is ignored by the Lean elaborator and Kani/proptest harness generators. It is Quasar/Anchor codegen metadata only. A handler may emit multiple events by writing multiple `emits` clauses.

### 3.3 `call`

**Purpose.** Declares a typed CPI invocation against an `interface` block declared in the spec. Unlike `transfers` (which is hardcoded to SPL token), `call` works with any interface whose shape is declared in the spec.

**Exact syntax:**

```fsharp
call Interface.handler_name(
  param_name = value_expr,
  param_name = value_expr,
  ...
)
```

Arguments must be keyword arguments (`name = value`). Positional arguments are not allowed. The `Interface.handler_name` must resolve against a top-level `interface` block. An optional result binder is written as:

```fsharp
let result_name = call Interface.handler_name(...)
```

**What it generates.** In Anchor/Rust codegen, `call` lowers to the appropriate CPI envelope. In Lean, `call` generates CPI correctness theorems. Interface handlers that declare `ensures` propagate those ensures into the caller's proof obligations as assumed facts.

**Examples:**

```fsharp
// Example 1: SPL token transfer via the bundled Token interface
interface Token {
  program_id "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
  handler transfer (amount : U64) {
    discriminant "0x03"
    accounts {
      from      : writable
      to        : writable
      authority : signer
    }
    requires amount > 0
    ensures  amount > 0
  }
}

handler withdraw (amount : U64) : State.Active -> State.Active {
  permissionless
  requires amount > 0 else InvalidAmount
  effect { total -= amount }
  call Token.transfer(
    from      = vault_ta,
    to        = owner_ta,
    amount    = amount,
    authority = auth,
  )
}
```

```fsharp
// Example 2: Reading a return value from a CPI call
handler price_and_swap (amount_in : U64) : State.Active -> State.Active {
  permissionless
  let price = call Oracle.get_price(mint = mint_a)
  requires price > 0 else BadPrice
  effect { reserve_a += amount_in }
}
```

```fsharp
// Example 3: Two sequential CPIs in one handler
handler deposit_and_stake (amount : U64) : State.Active -> State.Active {
  auth depositor
  requires amount > 0 else InvalidAmount
  effect { total_deposits += amount }
  call Token.transfer(from = user_ta, to = vault_ta, amount = amount, authority = depositor)
  call Staking.stake(amount = amount, owner = depositor)
}
```

**Note on `transfers` vs `call Token.transfer`.** Both model SPL token transfers and generate equivalent CPI code. `transfers { from A to B amount X authority Z }` is the shorthand; `call Token.transfer(from = A, to = B, amount = X, authority = Z)` is the typed form that also propagates interface `ensures` into proofs. Prefer `call` when working with the bundled SPL Token interface to gain the proof-propagation benefit; prefer `transfers` for brevity when proof propagation is not needed.

---

## 4. Authority Binding: The `auth` Keyword

### 4.1 Definition

`auth <account_name>` is a handler-level clause that asserts the instruction requires a specific named account to be a transaction signer. It is the primary mechanism for access control in `.qedspec` files.

**Exact syntax:**

```fsharp
handler handler_name : State.Pre -> State.Post {
  auth account_name
  ...
}
```

A dotted form `auth account.field` is also accepted (v2.29.1+), which desugars to `requires account.field == signer_account.pubkey else Unauthorized`.

### 4.2 How `auth` Lowers to `has_one`

When `auth X` is written on a handler, the codegen:

1. Emits a `has_one = X` constraint in the Anchor account context (`#[account(has_one = X)]`), binding the state account's stored authority pubkey to the signer.
2. Emits a signer check in the generated guards file: `Stmt::SignerCheck { account: X }`.
3. Suppresses the `no_access_control` P1 lint for that handler (the lint fires when a handler mutates state with no signer check at all).

In the account context's `accounts { }` block, the account named by `auth` must appear with the `signer` attribute. If `auth authority` is written but `authority : signer` is absent from the `accounts { }` block, `qedgen check` may emit a warning or the codegen will produce an invalid scaffold.

### 4.3 `auth` vs `permissionless`

These two clauses are mutually exclusive. A handler must have exactly one of:

- `auth <account>` — authenticated; the named account must sign.
- `permissionless` — explicitly unauthenticated; the `no_access_control` P1 lint is suppressed by intent.

Neither implies both. Writing both `auth X` and `permissionless` in the same handler is a `qedgen check` error.

### 4.4 When to Use `auth`

Use `auth` for any handler that must restrict execution to a specific role:

- Admin-only parameter updates: `auth admin`
- Owner-only withdrawals: `auth owner`
- Member-gated voting: `auth approver`
- Borrower-only repayment: `auth borrower`

Use `permissionless` for handlers where the authorization is implicit in the economic constraint (e.g., a liquidation that fires only when a health check fails), or for init handlers where no authority yet exists.

**Examples:**

```fsharp
// Admin-gated fee update
handler update_fee (new_fee : U64) : State.Active -> State.Active {
  auth admin
  accounts {
    admin : signer
    pool  : writable, pda ["pool", admin]
  }
  requires new_fee <= 10000 else FeeTooHigh
  effect { fee_bps := new_fee }
}

// Permissionless: auth comes from the health check, not the caller identity
handler liquidate : Loan.Active -> Loan.Liquidated {
  permissionless
  accounts {
    liquidator    : signer, writable
    loan          : writable, pda ["loan", pool, borrower]
    pool_vault    : writable, token, authority pool
    liquidator_ta : writable, token
    token_program : program
  }
  requires state.amount > state.collateral else AccountHealthy
  transfers {
    from pool_vault to liquidator_ta amount state.amount authority pool
  }
}
```

---

## 5. Common Mistakes That Cause `qedgen check` to Fail

### Mistake 1: Unknown error variant in `requires`

**What causes it.** Writing `requires amount > 0 else FooError` when `FooError` is not listed in the `type Error` block.

**Exact error message:**
```
error: unknown error variant 'FooError' referenced in handler 'deposit'
  hint: declare it in `type Error | ... | FooError | ...`
```

**Correction.** Add the variant to the `type Error` block:
```fsharp
type Error
  | InvalidAmount
  | FooError    // add this
```

---

### Mistake 2: Missing theorem in `Proofs.lean` (`qedgen check` orphan/missing report)

**What causes it.** A `property foo preserved_by [handler_a]` is declared in the spec but `Proofs.lean` has no theorem named `foo_preserved_by_handler_a`.

**Exact error message:**
```
Lean missing theorems (1):
  theorem `foo_preserved_by_handler_a`  MISSING
    Fix: add to Proofs.lean:
      theorem foo_preserved_by_handler_a ... := by sorry
```

**Correction.** Add the stub theorem to `Proofs.lean`:
```lean
theorem foo_preserved_by_handler_a : ... := by sorry
```
Then run `lake build` and `qedgen check` again.

---

### Mistake 3: Spec-hash drift in a Rust handler

**What causes it.** A Rust handler file carries `#[qed(verified, spec = "...", handler = "...", spec_hash = "old-hash")]` but the spec fragment has changed since the hash was recorded.

**Exact error message:**
```
Rust handlers (1):
  src/instructions/deposit.rs:12  handler `deposit`  SPEC HASH DRIFT
    Expected: abc123
    Actual:   def456
    Fix: update the handler body to match the spec, or update
         `spec_hash = "def456"` if the spec change is intentional.
```

**Correction.** Either update the handler implementation to match the new spec, or update the `spec_hash` attribute to the new hash value shown in the `Actual` line.

---

### Mistake 4: Effect field not found in state

**What causes it.** An `effect { }` block references a field name that is not declared in the state type.

**Exact error message:**
```
qedspec: effect field 'balanc' not found in state. Available fields: ["balance", "total"]
```

**Correction.** Fix the typo or use the correct field name as declared in the `type State | Active of { ... }` block. Field names are validated at elaboration time — typos fail fast.

---

### Mistake 5: `auth` and `permissionless` declared together

**What causes it.** A handler body contains both `auth admin` and `permissionless`.

**Exact error message:**
```
error: handler 'update_fee' declares both `auth` and `permissionless`; these are mutually exclusive
```

**Correction.** Remove one. Use `auth admin` for an access-controlled handler; use `permissionless` only if any caller should be allowed to invoke the instruction.

---

### Mistake 6: Orphan theorem in `Proofs.lean`

**What causes it.** `Proofs.lean` contains `theorem foo_preserved_by_old_handler` but `old_handler` has been removed from the spec.

**Exact error message:**
```
Lean orphan theorems (1):
  theorem `foo_preserved_by_old_handler`  ORPHAN
    Reason: Handler `old_handler` no longer declared in spec
    Fix: delete `foo_preserved_by_old_handler` from Proofs.lean,
         or restore the spec declaration.
```

**Correction.** Delete the stale theorem from `Proofs.lean`, or restore the handler in the spec if the removal was unintentional.

---

### Mistake 7: `invariant Name` on a handler that cannot pre-assume the invariant

**What causes it.** Using the handler-side `invariant Name` clause on an init handler whose pre-state is `Uninitialized`, where the invariant cannot possibly hold (e.g., `invariant root_set : state.root != 0` but in `Uninitialized` state `root` has no value).

**What happens.** The Kani harness injects `kani::assume(root_set(&s))` before the call. Since no `Uninitialized`-state satisfies `root != 0`, all harness paths are vacuously pruned — the proof passes trivially and no bug is caught.

**Correction.** Replace `invariant root_set` with `establishes root_set` on the init handler. Use `invariant` only on handlers operating in the variant where the invariant is already expected to hold.

---

### Mistake 8: Description-only invariant generates no harness

**What causes it.** Writing `invariant root_set "root is always nonzero"` (string literal, no predicate) and then expecting `qedgen check` to produce proof obligations.

**What happens.** No harness is generated. Handler-side `invariant root_set` against a description-only declaration emits a documentation note, not a proof obligation. `qedgen check` does not flag this as an error but the invariant is never verified.

**Correction.** Supply a predicate body:
```fsharp
invariant root_set :
  state.root != ZERO_ROOT
```

---

### Mistake 9: Using `sub` effect without a `requires` underflow guard on Nat-typed fields

**What causes it.** Writing `effect { total -= amount }` on a `U64` field without a `requires amount <= state.total` guard.

**What happens.** The codegen auto-generates an underflow guard (`param ≤ s.field`) for `Nat`-typed fields (U64, U128, U8) on `sub` effects. However, the auto-guard uses the spec's checked-underflow error (`MathUnderflow` by default). If the spec intends a different error, the auto-guard may produce the wrong error variant. Additionally, if the spec omits the `requires` guard entirely and relies on the auto-guard, the logical precondition is not visible to Lean proof search.

**Correction.** Add an explicit `requires amount <= state.total else InsufficientFunds` before any `sub` effect to make the underflow guard explicit, visible to proofs, and using the intended error variant.

---

## 6. Complete Annotated Example: AMM Swap Instruction

The following is a complete, valid `.qedspec` file for a simple constant-product AMM with an initialize and a swap instruction. It demonstrates all five clause types, state machine syntax, effect declarations, authority binding, and property/invariant patterns.

```fsharp
// ============================================================================
// amm_swap.qedspec — Simple constant-product AMM
// Demonstrates: all five clause types, state machine transitions,
// transfers, call, emits, auth, permissionless, invariant, establishes,
// ensures, requires, property.
// ============================================================================

spec AmmSwap

program_id "AmMsWaPXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

// ────────────────────────────────────────────────────────────────────────────
// State
// Algebraic data type with two lifecycle variants.
// Pool starts Uninitialized; after init it is Active.
// Paused is an admin-reversible halt.
// ────────────────────────────────────────────────────────────────────────────
type State
  | Uninitialized
  | Active of {
      admin      : Pubkey,
      reserve_a  : U64,     // token A reserve in vault
      reserve_b  : U64,     // token B reserve in vault
      lp_supply  : U64,     // outstanding LP tokens (not verified in this example)
      fee_bps    : U64,     // fee in basis points (0–10000)
      paused     : U64,     // 0 = running, 1 = paused
    }
  | Paused

// ────────────────────────────────────────────────────────────────────────────
// Errors
// Every error variant used in `requires ... else` must appear here.
// ────────────────────────────────────────────────────────────────────────────
type Error
  | AlreadyInitialized
  | PoolPaused
  | InvalidAmount
  | SlippageExceeded
  | ZeroReserve
  | FeeTooHigh
  | Unauthorized
  | MathOverflow
  | MathUnderflow

// ────────────────────────────────────────────────────────────────────────────
// PDAs
// Declare canonical derivation seeds for each PDA account.
// ────────────────────────────────────────────────────────────────────────────
pda pool   ["amm", admin]
pda vault_a ["vault_a", pool]
pda vault_b ["vault_b", pool]

// ────────────────────────────────────────────────────────────────────────────
// Events
// Named event types emitted by handlers. Fields are documentation.
// ────────────────────────────────────────────────────────────────────────────
event PoolInitialized { admin : Pubkey, fee_bps : U64 }
event SwapExecuted    { user : Pubkey, amount_in : U64, amount_out : U64 }
event PoolPaused      { admin : Pubkey }
event PoolResumed     { admin : Pubkey }

// ────────────────────────────────────────────────────────────────────────────
// Bundled SPL Token interface
// Typed CPI target. program_id pins the on-chain program.
// The ensures clause propagates into caller proofs.
// ────────────────────────────────────────────────────────────────────────────
interface Token {
  program_id "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
  handler transfer (amount : U64) {
    discriminant "0x03"
    accounts {
      from      : writable
      to        : writable
      authority : signer
    }
    requires amount > 0
    ensures  amount > 0
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Named invariants (top-level declarations)
//
// These are referenced from handler bodies via `invariant` (preserve) and
// `establishes` (first guarantee). Both forms generate Kani + proptest
// harnesses and Lean obligations.
// ────────────────────────────────────────────────────────────────────────────

// reserves_nonzero: both reserves must be positive when the pool is Active.
// This is the CP invariant prerequisite — a zero reserve makes price
// calculation undefined.
invariant reserves_nonzero :
  state.reserve_a > 0 /\ state.reserve_b > 0

// fee_valid: fee must stay within [0, 10000] basis points (0–100%).
invariant fee_valid :
  state.fee_bps <= 10000

// ────────────────────────────────────────────────────────────────────────────
// Properties (program-wide preservation claims)
//
// `property` generates per-handler proptest/Kani harnesses and Lean
// preservation theorems. Use `preserved_by all` to cover every handler.
// Use `preserved_by [h1, h2]` to scope to specific handlers.
// ────────────────────────────────────────────────────────────────────────────
property reserves_bounded :
  state.reserve_a <= 18446744073709551615 /\ state.reserve_b <= 18446744073709551615
  preserved_by all

// ────────────────────────────────────────────────────────────────────────────
// Handler: initialize_pool
//
// Lifecycle: Uninitialized → Active (one-shot init)
// Auth: permissionless — no pre-existing authority; first caller becomes admin.
//        admin identity is recorded in state via effect.
//
// Clause types demonstrated:
//   - State machine transition (Uninitialized → Active)
//   - `requires` (precondition: fee within range)
//   - `effect` (initial field assignment, := form)
//   - `establishes` (post-state satisfies reserves_nonzero and fee_valid)
//   - `emits` (event emission)
// ────────────────────────────────────────────────────────────────────────────
handler initialize_pool
    (initial_a : U64)
    (initial_b : U64)
    (fee : U64)
    : State.Uninitialized -> State.Active {

  // permissionless: no pre-existing admin to check.
  // The deployer's identity is captured via the `admin` signer account.
  permissionless

  accounts {
    admin          : signer, writable
    pool           : writable, pda ["amm", admin]
    vault_a        : writable, pda ["vault_a", pool]
    vault_b        : writable, pda ["vault_b", pool]
    token_program  : program
    system_program : program
  }

  // requires (precondition, checked before any state mutation):
  // Initial reserves must be positive so the CP invariant is satisfied
  // immediately after initialization.
  requires initial_a > 0 else ZeroReserve
  requires initial_b > 0 else ZeroReserve
  // Fee must be a valid basis-point value (0–100%).
  requires fee <= 10000 else FeeTooHigh

  // effect (state mutation using := for initial assignment):
  // All fields of the Active variant are set here.
  effect {
    reserve_a := initial_a
    reserve_b := initial_b
    fee_bps   := fee
    paused    := 0
    lp_supply := 0
    // admin is set via signer inference: the `admin` account that signed
    // this transaction becomes the stored admin pubkey.
    admin     := admin
  }

  // establishes (no pre-assume; assert post-state satisfies the invariant):
  // init brings the pool from an un-invariant Uninitialized state into one
  // where both named invariants hold. Use `establishes` not `invariant`
  // because the pre-state is Uninitialized and cannot pre-satisfy these.
  establishes reserves_nonzero
  establishes fee_valid

  // emits: log the initialization event.
  emits PoolInitialized
}

// ────────────────────────────────────────────────────────────────────────────
// Handler: swap
//
// Lifecycle: Active → Active (state-preserving mutation)
// Auth: permissionless — anyone holding token A may swap.
//
// Clause types demonstrated:
//   - State machine transition (Active → Active)
//   - `requires` (multiple preconditions)
//   - `effect` (field mutations using +=/−= checked forms)
//   - `invariant` (preserve reserves_nonzero and fee_valid across the swap)
//   - `ensures` (post-state frame condition)
//   - `transfers` (two SPL token transfers: user sends A, receives B)
//   - `emits`
// ────────────────────────────────────────────────────────────────────────────
handler swap
    (amount_in   : U64)     // amount of token A the user is selling
    (min_out     : U64)     // minimum token B the user will accept (slippage)
    (amount_out  : U64)     // actual token B to be sent (computed off-chain, verified by guard)
    : State.Active -> State.Active {

  permissionless

  accounts {
    user           : signer, writable
    pool           : writable, pda ["amm", admin]
    vault_a        : writable, token, authority pool
    vault_b        : writable, token, authority pool
    user_ta_a      : writable, token
    user_ta_b      : writable, token
    token_program  : program
  }

  // requires: all preconditions fire before the effect block.
  // Pool must not be paused.
  requires state.paused == 0 else PoolPaused
  // Input amount must be positive.
  requires amount_in > 0 else InvalidAmount
  // amount_out must be positive (a valid swap cannot yield zero tokens).
  requires amount_out > 0 else InvalidAmount
  // Slippage guard: the caller specified a minimum; the off-chain-computed
  // amount_out must satisfy it.
  requires amount_out >= min_out else SlippageExceeded
  // CP invariant check: (reserve_a + amount_in) * (reserve_b - amount_out)
  // must be >= reserve_a * reserve_b. This is approximated here as a pair
  // of reserve-nonzero checks; a real spec would use mul_div_floor.
  requires state.reserve_a > 0 else ZeroReserve
  requires state.reserve_b >= amount_out else InsufficientLiquidity

  // invariant (preserve, not establish):
  // The swap runs inside the Active variant; both invariants must hold
  // pre-swap (assumed by the harness) and must still hold post-swap
  // (asserted by the harness). `invariant` is correct here, not `establishes`.
  invariant reserves_nonzero
  invariant fee_valid

  // effect: update the reserve accounting.
  // += uses checked addition (overflows → MathOverflow).
  // -= uses checked subtraction (underflows → MathUnderflow).
  effect {
    reserve_a += amount_in
    reserve_b -= amount_out
  }

  // ensures (post-state guarantee, no `else` clause):
  // Frame condition: reserve_a increased by exactly amount_in.
  // reserve_b decreased by exactly amount_out.
  // fee_bps and paused are unchanged.
  ensures state.reserve_a == old(state.reserve_a) + amount_in
  ensures state.reserve_b == old(state.reserve_b) - amount_out
  ensures state.fee_bps   == old(state.fee_bps)
  ensures state.paused    == old(state.paused)

  // transfers: two SPL token CPIs.
  // 1. User sends amount_in of token A into vault_a.
  // 2. Pool sends amount_out of token B from vault_b to user.
  // Authority on pool-side transfers is the pool PDA (a program-derived signer).
  transfers {
    from user_ta_a to vault_a amount amount_in  authority user
    from vault_b   to user_ta_b amount amount_out authority pool
  }

  // emits: log the swap event.
  emits SwapExecuted
}

// ────────────────────────────────────────────────────────────────────────────
// Handler: pause_pool
//
// Lifecycle: Active → Active (sets paused flag; variant unchanged)
// Auth: admin only.
//
// Demonstrates:
//   - `auth` binding (lowers to has_one = admin signer check)
//   - `invariant` fee_valid preservation (fee unchanged by pause)
//   - `ensures` for paused flag frame condition
// ────────────────────────────────────────────────────────────────────────────
handler pause_pool : State.Active -> State.Active {
  // auth: only the stored admin pubkey may pause the pool.
  // Lowers to has_one constraint + signer check in generated code.
  auth admin

  accounts {
    admin : signer
    pool  : writable, pda ["amm", admin]
  }

  // The pool must not already be paused (idempotent pause is not allowed;
  // double-pause would hide a re-entrancy or logic error).
  requires state.paused == 0 else PoolPaused

  // fee_valid is preserved (pausing does not change fee_bps).
  invariant fee_valid

  effect {
    paused := 1
  }

  ensures state.paused   == 1
  ensures state.fee_bps  == old(state.fee_bps)
  ensures state.reserve_a == old(state.reserve_a)
  ensures state.reserve_b == old(state.reserve_b)

  emits PoolPaused
}

// ────────────────────────────────────────────────────────────────────────────
// Handler: resume_pool
//
// Lifecycle: Active → Active (clears paused flag)
// Auth: admin only.
//
// Demonstrates:
//   - `establishes reserves_nonzero` NOT used here — because the pool was
//     Active before the pause, reserves_nonzero was already true at pause
//     time and is preserved across the pause/resume pair. Use `invariant`,
//     not `establishes`, because the pre-state (Active, paused=1) can still
//     satisfy reserves_nonzero.
// ────────────────────────────────────────────────────────────────────────────
handler resume_pool : State.Active -> State.Active {
  auth admin

  accounts {
    admin : signer
    pool  : writable, pda ["amm", admin]
  }

  requires state.paused == 1 else InvalidAmount  // must be paused to resume

  // Preserves both invariants (reserves unchanged, fee unchanged).
  invariant reserves_nonzero
  invariant fee_valid

  effect {
    paused := 0
  }

  ensures state.paused    == 0
  ensures state.reserve_a == old(state.reserve_a)
  ensures state.reserve_b == old(state.reserve_b)

  emits PoolResumed
}

// ────────────────────────────────────────────────────────────────────────────
// Handler: update_fee
//
// Lifecycle: Active → Active
// Auth: admin only.
//
// Demonstrates:
//   - `auth` for access control
//   - `requires` + `invariant fee_valid` working together
//   - `ensures` frame condition on reserves
// ────────────────────────────────────────────────────────────────────────────
handler update_fee (new_fee : U64) : State.Active -> State.Active {
  auth admin

  accounts {
    admin : signer
    pool  : writable, pda ["amm", admin]
  }

  // `requires` enforces the constraint at runtime with a specific error.
  // `invariant fee_valid` generates a harness that assumes the old fee was
  // valid and asserts the new fee is valid after the effect.
  requires new_fee <= 10000 else FeeTooHigh

  // invariant (preserve): fee_bps was valid pre-call; must be valid post-call.
  invariant fee_valid

  effect {
    fee_bps := new_fee
  }

  // ensures: fee_bps updated to new_fee; reserves untouched.
  ensures state.fee_bps   == new_fee
  ensures state.reserve_a == old(state.reserve_a)
  ensures state.reserve_b == old(state.reserve_b)
}
```

---

### Key design decisions in this example

**Why `establishes` on `initialize_pool` but `invariant` on all other handlers.** The pool starts `Uninitialized`; neither `reserves_nonzero` nor `fee_valid` can hold before initialization. `establishes` generates harnesses with no pre-assume — the harness asserts that the invariant is true *after* the init call, verifying that init actually establishes it. All subsequent handlers operate in the `Active` variant where both invariants are known to hold from the prior init; they use `invariant` (assume pre, assert post).

**Why `ensures` accompanies `invariant`.** `invariant` generates a harness that checks the named predicate. `ensures` generates explicit field-level frame conditions. Both are needed: the invariant proves the aggregate predicate; the `ensures` clauses prove that unrelated fields are not silently clobbered. Together they give the harness full coverage of what the handler is and is not allowed to change.

**Why `transfers` is used instead of `call Token.transfer`.** Both are valid. This example uses `transfers` for brevity. In a production spec where you want the SPL Token `ensures` (amount invariant) to propagate as an assumed fact into Lean proofs, replace the two `transfers` entries with two `call Token.transfer(...)` invocations referencing the declared `interface Token` block.

**Why `permissionless` on `swap`.** The AMM is open — any holder of token A may swap. Authorization is enforced economically (slippage guard, reserve checks) rather than by identity. Writing `permissionless` explicitly suppresses the `no_access_control` P1 lint, signalling to the security tool that the absence of `auth` is intentional.