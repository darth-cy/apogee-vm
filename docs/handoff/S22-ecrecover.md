# S22 — secp256k1 ecrecover delegation family

Branch `s22-ecrecover`. **Status: Session A's deliverables are in and green, Session A's
acceptance is not complete, and Session B has not started.** The stage prompt runs S22 as
two ordered build sessions and begins Session B only after Session A's acceptance
sub-list passes. Delivered and green: the design authority, the ABI, the semantics, the
executor, the shim with both of its paths, the corpus and the fixtures; the **non-native
gadget library**, exhaustive at reduced width; and the **step program**, interpreted over
`program::secp256k1` and held to the committed corpus. **Outstanding on Session A:
acceptance 2** — three in-circuit point-arithmetic cases, an accumulator step with
`P == Q`, an identity intermediate and an equal-x-different-y add, one of them carrying a
tamper twin — which has no test anywhere in the tree, because the sub-circuit it would
run on does not exist. Also not delivered: the circuit family, its fill, the request-side
tag column, the tamper twins and the end-to-end proof. §7 is the acceptance list item by
item, §8 is Session A and what it measured, and §8.4 is Session B in order.

Four design questions went to the repository owner before any code and were answered.
Each answer and what follows from it is in §1; two of them contradict frozen text in
`docs/spec/delegation.md`, and §6 of `docs/spec/ecrecover.md` records the amendments with
their price.

Normative documents written or amended this stage:

- **`docs/spec/ecrecover.md`** (new): the EVM semantics, the frame, the row block, the
  scratch bus, the non-native gadget, the recovery composition, the scalar multiplication,
  the row budget, and what it amends in `delegation.md`. **This is the design authority
  the circuit implements**, and it is written to be implemented from rather than
  re-derived.
- **`docs/spec/ecall-abi.md`**: the `0x0502` row.
- **`docs/guest-program-manual.md`**: the two new guests.
- Also updated: the root `CLAUDE.md`, and the `CLAUDE.md` of `constants`, `program`,
  `trace`, `emulator` and `guest-sdk`.

`prompts/S22-ecrecover.md` is committed unchanged.

---

## 1. Read these first — the four answers

### 1.1 An invocation is a block of rows, not a row

`docs/spec/delegation.md` §1 says "one row is one call". A recovery is **259 point
doublings and 133 point additions**, about **1,180 non-native congruences**, and no row
holds it. Two independent derivations put a one-row-per-invocation circuit at:

| | one row per invocation, at `2^8` |
| --- | --- |
| committed columns | ~2,000,000 |
| `CircuitArtifact` bytes | ~300 MB, inside every `VerifyingKey` |
| shard proof | ~200 MB |
| `lookup::check_discharge`, which runs inside `VerifyingKey::check` | ~1.3 × 10¹¹ normalizations **on bytes a verifier was handed** |

against `KECCAK_F`'s 3,764 columns, 100 MB and 11.9 MB. The owner's answer: **many rows
an invocation**, aligned. The number is `ROWS_PER_INVOCATION = 4096`, which at `2^20` is
256 recoveries a shard; it was pinned at 2,048 from an estimate of the congruence count,
and the step program corrected it (§8.3).

### 1.2 The cross-row carry rides the global memory multiset

This engine has no cross-row wiring — a gate list is row-wise or halving. The options put
to the owner were the global multiset in a scratch address space, a new LogUp channel used
as a permutation bus, and a new pair of product-tree roots the verifier compares. The
owner chose the **global multiset**, `DELEGATION_ECRECOVER_SCRATCH = 6`.

It is the option that adds no new argument at all, and two of its consequences are
constraints rather than conventions (`ecrecover.md` §2.3): the carried values must be `M`
columns, because `check_memory` refuses a leaf cone that reads `W`; and the invocation
index must be **bit-bounded on every row**, not only on the rows carrying a frame query,
or two `(invocation, value id)` pairs collide and the chain forks.

It also cannot be RAM, and the reason is worth keeping: every row of an invocation writes
at `4·cycle + FRAME_DELTA`, so a RAM scratch word written and read inside one invocation
would need a gap of −1.

### 1.3 `2^20`

The prompt's pin, and the owner's answer. It is what makes `RANGE16` (16 ≤ 20) and
`TIMESTAMP` (19 ≤ 20) both fit, so the frame's gap checks are S14's 19+19 gadget rather
than keccak's 38 booleans — the one thing this family has that `KECCAK_F` does not.

It is also what forces **one congruence a row** rather than one point operation: a
channel's fraction tree costs `4F − 2` inner columns with `F = next_pow2(L + 1)`, so `L`
is a cliff at 128, and a whole point operation is about 290 obligations
(`ecrecover.md` §6.1).

### 1.4 The second delegation type's anchor: a tag column

`delegation.md` §10 says a second type makes the mirror leaf's `AS` term "a sum over types
of `(tag_t, m_t)`". **That cannot be built as written**, and the reason is not obvious:
`constraints::memory`'s `FRAME_SPACE[DELEG]` is a *literal* per query slot, and
`check_memory` refuses any leaf cone that reads a `W` column — so `is_<t>`, a witness
column, can never reach it.

Three ways out were put to the owner: a tenth frame query (which breaks the eight-role
ceiling — `trace::Row::present` is a `u8` and `Role::Delegate` took the last bit — and
widens add/sub's frame from 8 queries to 9); one shared delegation space with the type in
the anchor address; and **one extra `M` column carrying the tag**, which the owner chose.
`deleg_space_rule` is an *enforcing* gate, which may read `W`, and the leaf's `AS` part
becomes the product `(1, deleg_space, m_deleg)`. Not yet built: §8.

---

## 2. What is delivered, and green

### 2.1 `constants`

```rust
family::ECRECOVER: FamilyId = 10;  family::COUNT = 11;
family::CYCLE_OWNING[ECRECOVER] = false;  family::DEFAULT_HEIGHTS[ECRECOVER] = 1 << 20;
ecall::PRECOMPILE_ECRECOVER: u32 = 0x0502;
address_space::{DELEGATION_ECRECOVER = 5, DELEGATION_ECRECOVER_SCRATCH = 6};
mod secp256k1 { LIMBS = 4, LIMB_BITS = 64, CHUNKS_PER_LIMB = 4, WINDOW_BITS = 4,
                WINDOWS = 64, WINDOW_ENTRIES = 15,
                P, N, P_PLUS_1_OVER_4, G_X, G_Y, G_MULTIPLES }
mod ecrecover { VALUE_WORDS = 8, OFF_HASH/V/R/S/PUBKEY_X/PUBKEY_Y/SUCCESS,
                FRAME_WORDS = 42, V_MIN = 27, V_MAX = 28,
                ROWS_PER_INVOCATION = 4096 }
```

Every limb table was **computed, not transcribed**, and
`crates/program/tests/secp256k1.rs` re-derives each: `p` from `2^256 − 2^32 − 977`, `G`
from the curve equation, `n` from `n·G = ∞` through the joint ladder, `(p+1)/4` from `p`,
and all fifteen `G_MULTIPLES` from the group law. That last one matters more than the
others: the circuit spends them as **gate literals** (§3), so a wrong digit there is a
wrong circuit rather than a wrong test.

### 2.2 `program::secp256k1` — the native reference

Four 64-bit limbs, least significant first, and **the modulus is a parameter rather than a
type**: secp256k1 needs arithmetic mod `p` and mod `n`, the two differ in nothing else, and
a second copy would be a second copy of every bug. That is not master rule 1's
trait-generic field — there is no trait and no generic — and it is what the circuit does
too, a congruence carrying its modulus as gate literals.

```rust
pub type U256 = [u64; 4];   pub const ZERO: U256;  pub const ONE: U256;
pub fn add/sub/less/is_zero/mul_wide/div_rem_wide/rem(..);
pub fn addmod/submod/mulmod/mul_quotient_rem/invmod/powmod(..);
pub struct Point { pub infinity: bool, pub x: U256, pub y: U256 }
pub const INFINITY: Point;  pub fn generator/on_curve/negate/point_add/point_double(..);
pub fn window_table/window_digits/joint_mul(..);
pub enum RecoverFailure { BadRecoveryId, ROutOfRange, SOutOfRange, NotOnCurve, Infinity }
pub fn recover(hash, v, r, s) -> Result<Point, RecoverFailure>;
pub fn curve_y(x, parity) -> Option<U256>;
pub fn from_be_bytes/to_be_bytes/to_frame_words/from_frame_words(..);
pub fn apply_frame(words: &mut [u32]);   pub fn frame_of(hash, v, r, s) -> [u32; 42];
```

`mul_quotient_rem` is the **witness pair a congruence row commits**, `a·b = q·m + r` over
the integers, and is the one function the circuit's fill will call per row.

`invmod` is the binary extended Euclidean algorithm and not Fermat, deliberately: the
witness builder takes one inverse per point operation, 392 an invocation, and 380 modular
multiplications apiece is not affordable.

### 2.3 The corpus

`crates/program/tests/vectors/ecrecover.txt`, written by
`cargo run -p kat-gen -- ecrecover` from **`libsecp256k1`** (the recovery) and
**`tiny-keccak`** (the address). 27 data lines of 9 fields each, under six comment lines.
The signatures are built locally and the oracle answers the *recovery*, which is the
thing under test; the cross-check is as strong either way, because the recovered key is
compared with the oracle's own `PublicKey::from_secret_key`, so a wrong scalar
multiplication makes a signature that recovers to the wrong key.

`libsecp256k1` is taken with `default-features = false, features = ["static-context"]`,
which keeps `std`, `hmac` and `sha2` out of the graph. **Checked for the
feature-unification hazard `tools/transcript-ref` exists to avoid**: `cargo tree -p field`
is unchanged and the `riscv32imac` build of `field` and `constants` is still green.

### 2.4 The guest SDK — the frozen entry point

```rust
pub fn ecrecover(msg_hash: &[u8; 32], v: u8, r: &[u8; 32], s: &[u8; 32]) -> Option<[u8; 20]>;
```

**Frozen.** S24's revm precompile hook routes through it. Behind it the delegated path and
the software fallback are bit-identical **by construction**, not by comparison: both fill
the *same 42-word frame*, and the address is derived from the frame afterwards, once,
through S21's `guest_sdk::keccak256`. The circuit proves the public key and never hashes.

The software recovery is a deliberate duplicate of `program::secp256k1` — `keccak_f`'s
reason: this crate is not a workspace member, links only `constants`, and compiles for one
target.

### 2.5 The emulator

`delegation_frame` takes the width from `program::delegation_frame_words` and the
transform from one `delegated` match, which is now **the only per-family line in the
request path**. `crates/emulator/src/lib.rs`'s `keccak_frame` is gone.

`trace::Role::space` became `space(delegation: Option<FamilyId>)`, because a `Delegate`
query lands in the anchor space of the family the row requested and that is no longer a
constant. Its two call sites — the emulator's recorder and the archive's replay — pass the
family. The archive's replay **refuses** a row claiming a delegation request with no
invocation on its cycle; a panic would have been easy and wrong, because `check_parts`
validates bytes a caller handed in.

---

## 3. Two findings worth reading before the next session

### 3.1 A 256-bit value recomposed to one `Fr` is 6-to-1

`⌊p / |Fr|⌋ = ⌊n / |Fr|⌋ = 5`, verified numerically, so
`0, |Fr|, 2|Fr|, …, 5|Fr|` are all below `p`, all have limbs below `2^64`, and all
recompose to **zero** in `Fr`. One of them is
`30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`.

**Every equality and every zero test in this family must therefore be on two 128-bit
halves.** A single-`Fr` `is_zero` written the obvious way makes the equal-x branch of the
addition gadget selectable at will, and a selectable degenerate branch frees `λ` — which
recovers an arbitrary public key from an honest signature. `ecrecover.md` §3.4 and §5.3.
This is the one finding that would most plausibly have shipped.

### 3.2 `G`'s multiples are gate literals, not setup columns

The prompt says "G's multiples are constant, so they ship as committed setup columns". A
**joint ladder with shared doublings** makes a per-window comb for `G` worthless: separate
ladders cost 259 doublings and 133 additions, and the joint ladder costs the same, because
`R`'s ladder needs the doublings either way. So `G` needs only the single 15-entry table,
which is the same on every row and is therefore one `Linear` gate over literals — where a
setup column constant on every row is the same number with 120 more commitments and an
identity binding, for no gain.

A delegation family cannot carry setup columns today in any case:
`program::setup_commitments` returns an empty list for one and `VerifyingKey::check`
enforces the count. The **step schedule** will need that to change (§8).

---

## 4. The declaration-record leak, and what it cost

Both records started in one `.rodata.apogee.delegations`. `--gc-sections` collects at
**section** granularity, so `guests/keccak-test` declared `ECRECOVER` as well — a guest
whose `VmConfig` would carry a family it cannot call. This is `#[used]`'s failure from the
other direction, and `crates/program/tests/delegation.rs`'
`every_guest_declares_exactly_what_it_links` is the test that exists for it and is what
caught it. Each record now has a section of its own; `link.ld`'s `*(.rodata*)` absorbs the
suffixed names and the scan reads bytes, never section names.

**Both S22 guests declare both families**, and that is detachment working rather than
leaking: `guest_sdk::ecrecover` derives its address through `guest_sdk::keccak256`, so
linking the one shim makes the other genuinely reachable.

**Program identity moved for every guest, and S22 is the first stage where it did.** S21's
deviation 6 recorded that its SDK edit left every loaded `ProgramImage` byte-identical;
this one does not. `fib` grew eight bytes and carries no secp256k1 code — the shim is
dropped — but with `codegen-units = 1` the SDK is one object file, so adding functions to
it moves the ones the linker keeps. `crates/program/tests/vectors/identity.txt` is
re-pinned over the ceremony. Nothing is published and `PROTOCOL_VERSION` is still 0, so
the price is this paragraph.

---

## 5. Artifacts

| Path | What |
| --- | --- |
| `docs/spec/ecrecover.md` | the design authority, eight sections |
| `crates/program/src/secp256k1.rs` | the native reference, ~600 lines |
| `crates/program/tests/secp256k1.rs` | 11 tests: the oracle differential, the exhaustive division, the corpus |
| `crates/program/tests/vectors/ecrecover.txt` | the 27-line corpus, from two outside oracles |
| `tools/kat-gen/src/ecrecover.rs` | the `ecrecover` group |
| `crates/guest-sdk/src/lib.rs` | the shim, the fallback, the record |
| `crates/emulator/tests/ecrecover.rs` | 5 tests: the frame transform, the guests' vectors, both guests run |
| `guests/ecrecover-test`, `guests/ecrecover-fail` | the fixtures, exit 4 and 5 |
| `crates/loader/tests/qemu.rs` | the fallback half, `#[ignore]`d |

---

## 6. Verification performed

On macOS (18 cores), every gate the root `CLAUDE.md` lists above the line:

| gate | result |
| --- | --- |
| `cargo fmt --all -- --check`, all four workspaces | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo clippy` for `transcript-ref`, `guest-sdk` (riscv32imac), `guests`, `prover --features metrics` | clean |
| `cargo test --workspace` | **1,032 passed, 0 failed, 71 ignored** (1,001 / 70 at S21) |
| `cargo test -p prover --features metrics --test metrics` | 10 passed, 2 ignored |
| the `riscv32imac` build of the eight `no_std` crates | green |
| `cargo run -p kat-gen`, then the fixture diff | **clean** |
| `cargo run -p kat-gen -- guests` | all 19 guests reproducible, twice each |
| `cargo test -p program --test delegation -- --ignored` | 1 passed (detachment at both profiles) |

**Not run**, and owed: the QEMU suites (this is a macOS host; the fallback half of
acceptance 3 is `#[ignore]`d and needs the Linux container of
`docs/guest-program-manual.md` §7), and every `# DEFERRED` suite — none of them touches
anything this stage changed except through the guest ELFs and `identity.txt`, but that is
an argument and not a run.

---

## 7. Acceptance, item by item

**Session A**

| # | item | status |
| --- | --- | --- |
| 1 | gadget differential, and exhaustive at reduced limb width | **partial**. The *native* layer is differenced against `num-bigint` on randomized vectors and its 512-by-256 division is checked **exhaustively at reduced width** — 128 normalized divisors × 65,536 dividends, every branch of Knuth's estimate. The *circuit* gadget is built — `constraints::nonnative`, width-parameterized, exhausted at four limbs of one bit over every input, quotient and result (§8.1) — but the family circuit that consumes it is not, so it has no committed vectors to be differenced on. |
| 2 | point-arithmetic edge cases in-circuit, with a tamper twin | **not done** — needs the circuit. The five cases and their exact selectors are specified in `ecrecover.md` §5.3, and the native `point_add` carries the same five. |

**Session B**

| # | item | status |
| --- | --- | --- |
| 3 | ecrecover differential on a committed corpus, fallback bit-identical under QEMU | **partial**. The corpus exists and holds everything the item names — five signatures, both `v`, five accepted `s > n/2`, `r` and `s` at 1, a hash above `n`, and the three failing inputs. The **shim** and the **delegated path** are differenced against it and green. The **circuit** is not built. The QEMU half is written and `#[ignore]`d, not run. |
| 4 | end-to-end `BlockProof` with ≥ 1 ecrecover shard | **not done** |
| 5 | failure-path proof | **partial**: `guests/ecrecover-fail` exists, runs on the emulator and exits 5; it is not proven. |
| 6–8 | the three tamper twins | **not done** |
| 9 | checker validators, artifact regenerate-and-diff, degree-2, padding | **not done** — no artifact yet. The regenerate-and-diff gate is green for everything that does exist. |
| 10 | measured rows per invocation and wall-clock | **partial**. Rows per invocation is **measured**: `constraints::ecrecover::schedule` is 3,779 steps, which pins `ROWS_PER_INVOCATION` at 4,096, and `crates/constraints/tests/schedule.rs` holds that count and the three shapes it beat (§8.3). Wall-clock is not — nothing has been proved — and the ~28 GB a shard in `ecrecover.md` §6.1 is still the tree cost model rather than a run. |

**Must-be-exact**

| # | item | status |
| --- | --- | --- |
| 1 | frame table and ecall number appended; shim, emulator and artifact assert-match | **partial**: the frame table is `ecrecover.md` §2.1, the number is `0x0502`, and `crates/constants/tests/ecall_abi.rs` holds the document, the constants, the shim and the emulator to each other in both directions. The artifact's half is owed. |
| 2 | the EVM validation set; failure provable with zeroed outputs | **done** in the native path, the shim and the emulator, and asserted over the whole corpus. The circuit's half is owed. `ecrecover.md` §1.3 states the *both directions* requirement the prompt's wording leaves implicit. |
| 3 | every limb, carry, quotient and remainder range-checked; no `assume_*` | specified (§3, §6.3); not built |
| 4 | the circuit proves the pubkey only; the shim composes keccak | **done** |
| 5 | anchor obligations per `delegation.md` | not built |
| 6 | four 64-bit limbs, four 16-bit chunks, canonical remainders | pinned in `constants` and honoured by the native layer; the circuit's half is owed. `ecrecover.md` §3.3 records *why* canonicality is load-bearing rather than belt-and-braces: without it the honest quotient needs a fifth limb. |
| 7 | window width 4; one-hot selectors summing to one | specified, with the digit-to-scalar tie the item omits (§5.2); not built |
| 8 | one invocation, one signature, fixed frame, no batching | **done** |

### 7.1 One correction to acceptance 3

**`r = n − 1` cannot be an accepted vector.** Acceptance 3 lists "r and s at 1 and n−1"
among the *passing* inputs. `(n−1)³ + 7` is a quadratic non-residue mod `p` — verified,
and `libsecp256k1` agrees — so no curve point has that `x` and the precompile returns
empty. It is in the corpus's **failing** set, beside `r = 5`. `r = 1` does have a point
(`8` is a residue), and `s = 1` and `s = n − 1` are both accepted; all three are in the
corpus.

---

## 8. Session A, and what it measured

The stage prompt orders Session A before Session B, and Session A is delivered.

### 8.1 `constraints::nonnative`

`docs/spec/ecrecover.md` §3 as data: the congruence over ℤ with its carry chain, the
canonicality complement, the chunk-and-bit bound, and the 128-bit-half equality. **The
width is a parameter**, which is what lets `crates/constraints/tests/nonnative.rs`
instantiate four limbs of one bit and exhaust every input, every quotient and every
result — the statement the 256-bit instance rests on and cannot make.

Three things those tests settled:

- **A congruence proves congruence and nothing more.** At `P = 13` in a four-bit span
  both `d` and `d + 13` satisfy the same gates, so a prover picks which representative to
  bus onward. Canonicality is what makes a result a result, on **every** value a row
  writes and not only where the EVM semantics bound it. §3.3 gains that as its first
  reason.
- **The seventh carry is demonstrated, not asserted.** The test builds the gadget wrong
  on purpose and shows that a carry out of the last position puts results in the wrong
  residue class within reach.
- **The magnitude argument is in exact integers.** A position sits just under `2^131` and
  its carry just under `2^67` — inside the range check's 68 bits by the sign bit alone. A
  third product a position overflows it, and the test asserts that too.

### 8.2 `constraints::ecrecover::schedule`

The step program one invocation runs, a row a step: one congruence shape, four value
slots and a table, with the operands and the coefficients coming from the schedule.
`crates/program/tests/ecrecover_schedule.rs` **interprets** it over
`program::secp256k1` and holds its answer to `apply_frame`'s over the whole committed
corpus, both outcomes. That is the check that says the program is the right program, and
it is worth having before a gate exists: a gate list built from a wrong program is a
correct circuit for the wrong function, and every later test would agree with it.

`APOGEE_TRACE_SCHEDULE=1` on that test prints every value the program computes. The
witness builder has to reproduce exactly that list, and a diff against it is how a
disagreement gets found.

### 8.3 What the measurement moved

| | was | is | why |
| --- | --- | --- | --- |
| `ROWS_PER_INVOCATION` | 2,048 | **4,096** | the program is 3,779 steps; 2,048 came from an estimate of the congruence count |
| recoveries a `2^20` shard | 512 | **256** | the above |
| the window | 4 bits, 15 entries | **3 bits, 4 odd multiples, 8 signed selectors** | cheapest per recovery of the four shapes measured (§2.2) |
| `G`'s multiples | setup columns (prompt) | gate literals | unchanged from §5.1, and now also true of the negated half |
| the complete addition | five cases | signed-odd digits and two invertibility assertions | §5.3, recorded as a deviation |
| the failure substitute | — | `constants::secp256k1::H` | §4.4; `G` makes the ladder degenerate and a **failure** unprovable |

### 8.4 What Session B does, in order

1. **`crates/constraints/src/ecrecover.rs`** — the circuit, from the schedule and from
   `ecrecover.md`. Its own `Assembly`, as `keccak.rs` has, for the same reason:
   `build::assemble` builds trees and its `push_list` is quadratic in the circuit's width.
   The row's gate set is now known exactly: the congruence over five value slots and
   eight table slots, the bound and canonicality of the written value, the is-zero pair
   on 128-bit halves, the one-hot selectors with their digit tie, and the frame window.
2. **The schedule's virtual columns.** `VirtualKind` gains this family's step-periodic
   tables, whose extension is a sum over one period of `eq` against a constant vector
   (§6.2, the owner's decision). `docs/spec/gkr.md` §2's virtual-table set is amended.
   No key's bytes, identity or SRS digest move.
3. **`add_sub`'s tag column** (§1.4). Append it rather than inserting: the artifact moves
   either way, but no existing `M` index needs to.
4. **`trace`'s witness builder** and **`prover::family_fill`**, including `plan_shards`
   dividing by `height / ROWS_PER_INVOCATION`. The builder's values are the interpreter's.
5. **`constraint-manifest.md` §13**, the family's column-by-column account.
6. **The twins**, noting that a **bus** defect surfaces at block level as
   `MemoryArgument`, not at shard level as `Constraint`.
7. **`kat-gen -- ecrecover`** gains the artifact's digest.
8. **The deferred suites**, once, on the measurement host.

The single biggest remaining risk is unchanged in kind and smaller in size: every
equality and zero test must be on **two 128-bit halves** (§3.4), and the one-hot
selectors must be held one-hot as well as boolean — booleanity permits the empty set, and
an all-zero selector row selects the point at infinity by another name.
