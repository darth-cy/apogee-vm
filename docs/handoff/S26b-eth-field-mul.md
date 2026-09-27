# S26b — `MOD_MUL` specialized: four fixed Ethereum moduli

Branch `s26b-eth-field-mul`. One change, stated in one sentence:

> The `MOD_MUL` delegation took an **arbitrary 256-bit modulus** as a runtime
> operand in eight frame words. It takes a **one-word selector** now, naming
> one of four fixed Ethereum fields, and the circuit supplies the modulus as
> literals.

Everything else in this note follows from that, and the three consequences
worth reading first are:

1. **`a < m` and `b < m` are gates.** S26 could not state them — with `m` an
   operand there was nothing to compare against — so the quotient's fit was the
   honest prover's business. Now `q = (a·b − out)/m < m ≤ 2^256` always, and
   every frame the circuit accepts is one a prover can fill.
2. **The frame is 25 words, not 32.** An invocation makes 26 RAM accesses where
   it made 33, and the circuit is 10 committed columns and one row-wise gate
   list smaller.
3. **Ecall `0x0503` is retired and burned, and the call took `0x0504`.**

**And the price, up front, because it is real.** Enforcing the operand bound
means `guests/vendor/k256` must reduce a field element below `p` and not merely
below `2^256`. On the pinned mini-block that costs **1,299,403 guest cycles**,
so the delegation's net saving falls from S26's **−24.2%** to **−18.7%** against
the pre-delegation baseline. §6 is the measurement and §6.1 is why it is not a
mistake.

There is no stage prompt in `prompts/`: the owner's instruction is the stage,
and §1 quotes it.

Documents amended this stage:

- **`docs/spec/delegation.md`**: §3's registry row and the reason the number
  moved; **§10.2 (new)**, the record of an amendment, §10 having had no clause
  for a family that *changes* rather than appends; §9.2's shape numbers; and
  **§14 rewritten**.
- **`docs/spec/constraint-manifest.md`**: **§18 rewritten**, and §3's add/sub
  account, whose `deleg_15_number` literal is the ecall number.
- **`docs/spec/ecall-abi.md`**: §3's row and §4's retired table, which now has
  three entries.
- **`guests/vendor/README.md`**: the `ark-ff` section, and the k256 section's
  operand rule, which S26 wrote as the opposite of what is now true.

---

## 1. The instruction, and the four decisions taken before any code

The owner's instruction, in full:

> Refactor `MOD_MUL` from a generic arbitrary-256-bit-runtime-modulus
> delegation into an Ethereum-specialized field multiplication delegation.
> Scope it only to the fixed moduli that are actually useful for Ethereum block
> execution and crypto-heavy guest code. At minimum support: secp256k1 base
> field modulus `p`, secp256k1 scalar field modulus `n`, BN254 base field
> modulus `p`, BN254 scalar field modulus `r`.
> The modulus must no longer be supplied as an arbitrary 256-bit runtime
> operand. Instead, encode a small modulus selector / operation kind in the
> delegation frame and derive the actual modulus from that selector inside the
> constraint system.
> Assume operands are canonical field elements for the selected modulus and
> enforce `a < m` and `b < m` in-circuit. Keep `out = a * b mod m` and enforce
> `out < m`.
> Because `a,b < m`, the quotient satisfies `q < m`, so the existing 256-bit
> quotient representation is sufficient. Remove any implication that this
> delegation implements general EVM `MULMOD` semantics.
> Do NOT route the EVM `MULMOD` opcode through this delegation. Arbitrary EVM
> `MULMOD` must continue to execute through the normal RV32/software path
> unless a separate accelerator is added later.
> Update the guest-side shims so only Ethereum-relevant crypto libraries use
> this delegation. Keep software fallback where appropriate. The circuit should
> remain statically detachable when none of these operations are present.
> Prefer the smallest selector and constraint surface possible; do not add
> generic bigint functionality or arbitrary modulus support.

Four things it left open, put to the owner before anything was written:

| # | Question | Decision |
| --- | --- | --- |
| 1 | The frame's meaning changes incompatibly. Append-only says redefining a number "does not fail loudly — it quietly makes an old program compute something else", and S-NATIVE-IO's precedent was to *retire and burn* 63/64. Keep `0x0503` or burn it? | **Burn `0x0503`, take `0x0504`.** `constants::ecall::RETIRED_MOD_MUL_WITNESSED_MODULUS` keeps the number so a test can hold it to being unanswered |
| 2 | Only `k256`'s base field is wired today. Without more, the other three selectors have no library caller — wire k256's scalar? arkworks' BN254? both? | **Wire all four.** §4 is what that cost |
| 3 | "Do this as stage 26b" — write `prompts/S26b-*.md`? | **Don't touch `prompts/`.** The instruction is quoted here instead |
| 4 | Rename the family to something that cannot be read as `MULMOD`? | **Keep `MOD_MUL`.** The name says modular multiplication, which is what it does; `MULMOD` is a different word, and the claims to delete were all prose |

---

## 2. The circuit

`crates/constraints/src/mod_mul.rs`. `docs/spec/delegation.md` §14 is
normative and `docs/spec/constraint-manifest.md` §18 is the column-by-column
account; this is the shape of the change.

**The frame**, 25 words where S26 had 32:

| words | what |
| --- | --- |
| `0` | the modulus selector, one of `constants::mod_mul::CODES` |
| `1..9`, `9..17` | `a` and `b`, each below the selected modulus |
| `17..25` | the result |

**The selector**, four codes starting at **1** for `fr_arith::OPS`' reason — a
live row whose selector word is 0, a caller that forgot the modulus, then
satisfies no selector and is unprovable, where a 0-based code would silently
have meant secp256k1's `p`:

| code | field | bits |
| --- | --- | --- |
| 1 `SECP256K1_P` | secp256k1 base, `2^256 − 2^32 − 977` | 256 |
| 2 `SECP256K1_N` | secp256k1 scalar, the group order | 256 |
| 3 `BN254_P` | BN254 base `q` | 254 |
| 4 `BN254_R` | BN254 scalar `r` | 254 |

**Four gates carry the selector**, and `m` gets eight witness columns rather
than being inlined:

```text
selector{c}_boolean       s_i² = s_i                      ×4
selector_rule             word 0 = Σ code_i·s_i
one_modulus_a_live_row    Σ s_i = live
m_limb{k}_rule            m_k = Σ MODULI[i][k]·s_i         ×8
```

Two design notes on that, both recorded in §14.2 and §18.4:

- **`one_modulus_a_live_row` is load-bearing twice.** The first is `fr_arith`'s
  documented lesson: the codes are 1, 2, 3, 4, so `1 + 3 = 4` and a row claiming
  secp256k1's `p` *and* BN254's `q` spells the word of a row claiming BN254's
  `r`; `selector_rule` cannot see it. The second was nearly missed and is the
  more important one: **`m` has no bit decomposition**, its limbs being bounded
  only by each being one entry of a table of literals, and two selectors at once
  would put `m_0` above `2^32`, `S_k = Σ q_i·m_j` above `2^68`, and the limb
  identity's "every term is far below `p`, so the `Fr` equation is the ℤ
  equation" out of reach. So the gate is not redundant at *any* code spacing.
- **Eight columns for `m`, not four products a limb.** Substituting
  `Σ MODULI[i][k]·s_i` wherever `m_k` appears is free in the chains and takes
  `limb{k}`'s 64 `q_i·m_j` products to 256 — gate list 0 from 128 products to
  320. Eight columns and eight degree-1 gates is cheaper, and it also makes "the
  modulus is not the selected literal" a cell a twin can corrupt.

**Three `< m` chains** where S26 had one, one per frame value, each the
`fr_arith` canonicity shape against `m_limb` instead of `p`'s literals. They
are **ungated**, which the fixed modulus is what buys: `m_limb{k}_rule` forces
every modulus limb to 0 on a padding row, so the gate holds there with no `live`
factor.

**Everything else is S26's**: the fifteen limb equations, the fourteen signed
37-bit carries with their `2^36` offset, the quotient's limbs and bits, the
frame gates and the anchor. `CARRY_BITS` and `CARRY_OFFSET` did not move and
should not — the recurrence reads only the limbs' `2^32` bounds, which the
selector does not change.

### 2.1 The shape, measured

| | S26 | S26b |
| --- | --- | --- |
| `M` / `W` / committed | 132 / 3,346 / 3,478 | 104 / 3,364 / **3,468** |
| gate lists at `n = 16` | 23 (7 row-wise + 16) | 22 (**6** row-wise + 16) |
| inner columns | 286 | 158 |
| enforcing (d1/d2) | 3,493 (73/3,420) | 3,502 (86/3,416) |
| relations | 3,779 | 3,660 |
| wire bytes | 1,421,100 | 1,404,716 |
| leaves a side | 33, padded to 64 | 26, padded to **32** |

The row-wise list count fell because the leaf count did: 26 leaves pad to 32
where 33 padded to 64, which is one product-tree level.

`W` went **up** by 18 despite `m`'s 256 bits going away, because two more
264-column chains arrived and the frame's gap bits fell by 266. Net committed:
**−10 columns**, and −7 RAM accesses per invocation.

---

## 3. What the operand bounds buy, and what they are not

They are **not soundness**. S26 was sound without them: an unreduced operand
made the honest quotient overflow eight limbs, the prover's own fill panicked,
and no false statement reached a verifier. `out < m` was and remains the
reduction, and the `(q − 1, r + m)` twin is still what shows it.

They are **totality**. Before, there were frames the circuit would accept that
no prover could fill, and whether a given call was one depended on a caller's
reduction discipline. Now every frame the circuit accepts has a witness and
every witness it has is accepted, and the frame's meaning is exactly "two
canonical elements of the selected field".

**Three refusals by name** came with them, in `emulator::mod_mul_frame`: an
unknown selector, `a ≥ m`, `b ≥ m`. That is not tidiness. Long division answers
correctly for any operands below `2^256`, so an executor that accepted them
would run a guest clean, pass every trace-level test, and leave the failure to a
gate — anonymously, as `LayerInconsistency { layer }`, hours into a deferred
block proof. With the refusals it is a fatal trace-time error that
`kat-gen -- revm` catches on every push. The prover's fill asserts the two
operand bounds too, naming the operand.

S26's zero-modulus refusal is **deleted** with the operand it read, and so is
its test: a four-entry table of primes has no zero in it, and a guard whose
input cannot exist reads as a live check and is not one.

---

## 4. The guest side: all four selectors have a library caller

| selector | what routes | where | cost |
| --- | --- | --- | --- |
| `SECP256K1_P` | `FieldElement10x26::mul`, `::square` | `guests/vendor/k256` (S26, changed) | see §6 |
| `SECP256K1_N` | `Scalar::mul` (and `::square` through it) | `guests/vendor/k256` (new) | free: a `Scalar` is already `< n` and already eight `u32` limbs |
| `BN254_P`, `BN254_R` | `MontBackend::mul_assign`, `::square_in_place` | `guests/vendor/ark-ff` (new vendored crate) | two delegated calls a multiply |

### 4.1 Why `ark-ff` and not `ark-bn254`

`ark-bn254` is fourteen files and would have been the smaller copy. It does not
work: its `#[derive(MontConfig)]` **generates** `mul_assign` and
`square_in_place`, so overriding them there means hand-writing the whole
`MontConfig` impl — fifteen associated constants, three required and the rest
derived, with `GENERATOR` and `TWO_ADIC_ROOT_OF_UNITY` needing a type launder
through `Fp::new_unchecked`. `MontBackend::mul_assign` sits one level below the
derive and forwards to it, so intercepting there is **one function pair in one
file** and covers `Fq2`, `Fq6` and `Fq12` for free, all three being built on
`Fq`'s multiply. `guests/vendor/README.md`'s rule is that the diff a reviewer
reads is the list of changed files, and by that rule the bigger crate is the
smaller review.

The field is chosen by an associated `const` matched on `T::MODULUS`, so it is
decided at compile time per monomorphization and every other arkworks field —
`ark-bls12-381`'s six-limb one, which this workspace also compiles — is
untouched at zero run-time cost.

### 4.2 Two calls, because arkworks is Montgomery and the delegation is not

An `Fp256` holds `x·R` with `R = 2^256 mod p`, and a Montgomery multiply is
`â·b̂·R^-1`. The delegation multiplies plain integers, so the patch issues
`t = â·b̂ mod p` and then `out = t·R^-1 mod p`, with `R^-1` a literal from
`constants::mod_mul::{BN254_P_R_INV, BN254_R_R_INV}`. Both operands of both
calls are below `p` — arkworks keeps every representative reduced and `R^-1` is
a residue — so the operand bound costs this path nothing. `a` is written only
after **both** calls answer.

This is the trade `FR_ARITH` avoided at S23 by carrying the Montgomery
representation in its frame (§13.2), and this family cannot: its four moduli
have four different radices.

### 4.3 The k256 operand rule, which S26 wrote as the opposite

S26's `operand` reduced only until the value fit the frame, and its doc said so:
"an operand at or above `p` is no problem, only one at or above `2^256` is."
That is now false, and the case is **structured, not rare**: `p`'s own raw limb
pattern is upstream's second representation of zero — `normalizes_to_zero`'s
`z1` mask is bit-for-bit `p`'s 26-bit limbs — and the complete projective
formulas produce it whenever a coordinate difference vanishes, which the ladder
does constantly. `packable(p)` is true and `pack(p)` is exactly the `P` constant
S26 passed as the modulus.

`operand` is now `packable(x) && !x.get_overflow()` — upstream's own "is this
magnitude-1 value at or above `p`", ordered after `packable` because that is
where it is meaningful — falling back to a full `normalize`. §6 is what it cost.

---

## 5. Where the four moduli come from, and how they are pinned

`constants::mod_mul::MODULI`, four `[u32; 8]` literals. Four 256-bit numbers
entered `crates/constants` this stage, and that crate's own rule is that a table
copied from a reference is exactly the kind of constant a test must re-derive.
Two readings, each covering a different failure:

- **`cargo run -p kat-gen -- moduli`** writes
  `crates/constants/tests/vectors/moduli.txt` from **`ark-secp256k1`** and
  `ark-bn254`, and CI regenerates-and-diffs it. `ark-secp256k1` is a new
  workspace dependency and exists only for this: secp256k1's `n` has no closed
  form and appears nowhere in `crates/`, so an outside oracle is its only honest
  pin. Master rule 2 names arkworks as exactly that.
- **`crates/constants/tests/moduli.rs`** diffs the constants against that file,
  and separately **re-derives the three that can be re-derived here** — secp's
  `p` as `2^256 − 2^32 − 977`, BN254's two out of `FQ_MODULUS` and
  `FR_MODULUS`. A transcription error fails both; a wrong *oracle* — the
  generator reading another curve's field — fails only the second, which is why
  the second exists.

The same file multiplies `BN254_P_R_INV` and `BN254_R_R_INV` back out against a
doubling chain of its own, so a wrong Montgomery correction is a failed test and
not an arkworks field that computes the wrong answer in a guest and nowhere
else.

`crates/constants/tests/vectors/` is new and is added to CI's
regenerate-and-diff list.

---

## 6. The measurement, and the price

`cargo run --release -p profiler -- block mini-block`, on the pinned mini-block
(block 26,057,509's first two transactions, 392,997 gas):

| | guest cycles | cycles/gas | vs baseline |
| --- | --- | --- | --- |
| before any delegation (S26 §6) | 23,733,540 | 60.4 | — |
| S26, witnessed modulus | 17,986,969 | 45.8 | **−24.2%** |
| **S26b** | **19,286,372** | **49.1** | **−18.7%** |

The journal is the same 90 bytes and the exit status is 0, which is the check
that matters: the whole revm workload computes the same answer through the new
frame, the new operand rule and three patched multiplies.
`cargo run -p kat-gen` regenerated every committed fixture — the revm group
included, which builds and traces the guest — with **no drift at all**.

### 6.1 Where the 1,299,403 cycles went, and why it is the instruction and not a defect

Essentially all of it is one function. `apogee::operand` is **1,464,602 cycles
over 13,410 calls** (109.2 c/call) where S26's fast path was 13, and
`FieldElement10x26::normalize` is 962,136 over 5,796 calls — 43% of operands,
which is exactly the step-2 fraction S26 measured and optimized away. The
`secp256k1` category went 28.11% → 32.63% of the execution and every other
category is where it was.

That is the operand bound, and the operand bound is the instruction. S26
measured this cost and removed it *because nothing then required the operand to
be below `p`*; §3 is what requiring it buys. Two smaller effects push the other
way and do not offset it: the frame is seven words narrower (6,705 calls × ~14
cycles) and the scalar routing added 306 invocations that replace software
multiplies — `MOD_MUL` invocations went 6,705 → 7,011.

**BN254 contributes nothing on this block and was never going to**: the profile
reports `bn254 0.00%`, the mini-block calling no BN254 precompile. S26's own
measurement is why it was wired anyway — block 26,059,800 is 18% BN254 — and
that block is not what is pinned here.

**Proving cost is not guest cycles**, and the two move differently: a `MOD_MUL`
invocation is one row of a `2^16` shard where the software multiply it replaces
is ~1,300 rows spread across execution families. The guest-cycle number is the
proxy this repository measures, and the deferred `prover::revm` suite is what
prices the real thing.

### 6.2 If the price is judged too high

It is one line and one property. Dropping `a < m` and `b < m` restores S26's
`operand` and its −24.2%, at the cost of §3's totality — a frame the circuit
accepts that the prover cannot fill, whenever a caller hands over an unreduced
operand. Nothing else in this stage depends on the bounds, and both twins that
test them (`an_operand_not_below_the_modulus_is_refused`, and the executor's
two refusals) are self-contained. It is the owner's call and not a decision
taken here.

---

## 7. The fixture guest

`guests/mod-mul-ops` is rewritten. It was two halves and is four, and the one
worth reading is the second.

- **The ABI by name**, once per selector, against literal expectations: `7·9 =
  63` below every modulus, `(m−1)² mod m = 1` — the largest operand pair the
  frame admits — and `(m−1)·2 mod m = m−2`. Plus the cross-selector check that
  the same operands under two selectors give two answers.
- **The software path, run rather than reserved.** §2 of the delegation ABI
  requires a caller to have one, and S26 chose `u64` moduli precisely so that
  path could be a single `u128` expression. A fixed-modulus family has no such
  exit — every selectable modulus is 256 bits — so the fallback is a schoolbook
  long division of the guest's own. Rather than leave forty lines nothing ever
  executes, **the guest runs both paths on every by-name call and compares**,
  which turns dead code into a live differential oracle against
  `emulator::mod_mul_frame` and exits 251 on a disagreement.
- **`k256`'s group and scalar arithmetic**, and **`ark-bn254`'s two fields**,
  naming no shim at all.

It exits **28**, one per check passed but the first, and makes **1,567**
`MOD_MUL` invocations where it made 1,227. Its ELF is 446 KB where it was 238,
and its last pc is `0x452c6`, still inside the `2^18` table its fixtures use.

**Nothing inside the guest can see whether a seam is live** — a delegated
multiply and a software one agree on the value, which is the point — so the
thing that tests that a vendored patch still *routes* is the invocation count,
pinned by
`crates/emulator/tests/guests.rs::mod_mul_ops_routes_every_vendored_patch_through_the_ecall`.
Each of the three seams contributes a different number.

---

## 8. What the renumber reached

Burning `0x0503` is not confined to `constants`, and this is the list, because
none of it is obvious:

- **`add_sub.bin` regenerates.** The request-side gate `deleg_15_number` embeds
  the delegation number as a literal (`−1283` becomes `−1284`), and add/sub is
  committed as a full artifact rather than a digest. Its digest is re-pinned in
  `crates/checker/tests/add_sub.rs`, and `constraint-manifest.md` §3's
  relation 102 with it.
- **Every guest declaring `MOD_MUL` has a new image and a new identity**, the
  declaration record being `MARKER_MAGIC ‖ u32 number`.
- **`crates/program/tests/delegation.rs`'s unanswered-number sweep** used
  `PRECOMPILE_FIRST + 4` as its control, which is now answered. It uses the
  retired number and `+ 5`.
- **`crates/constants/tests/ecall_abi.rs`** compares the ABI document and
  `constants::ecall` by name and **by count**, so the retired constant had to
  become a row of §4's table with its identifier in a cell of its own.

---

## 9. Tests

New, and each names the mutation it catches:

| test | what it catches that nothing else does |
| --- | --- |
| `checker::mod_mul::an_operand_not_below_the_modulus_is_refused` | `a = m` with an **honest** witness for it — quotient, result, carries and all three chains — so `a_below_modulus` is the only gate that fails. This is the k256 shape of §4.3, not a hypothetical |
| `checker::mod_mul::two_moduli_at_once_is_refused` | the `1 + 3 = 4` forgery `selector_rule` cannot see, and with it the bound on `m`'s limbs |
| `checker::mod_mul::a_selector_word_that_names_another_field_is_refused` | a row multiplying in a field the guest did not ask for, and a code the table does not hold |
| `checker::mod_mul::a_modulus_limb_that_is_not_the_selected_literal_is_refused` | the selector being decoration |
| `prover::fills::every_mod_mul_shard_the_fill_writes_satisfies_every_gate` | a **permutation** of the fill's columns, which set equality cannot see. The real fill's columns through `gkr::self_check` on all seven shards, padding rows included, in 4.8 s |
| `emulator::mod_mul_refuses_a_frame_no_proof_could_cover` | the three executor refusals, and that `m − 1` on both sides is still admitted |
| `emulator::guests::mod_mul_ops_routes_every_vendored_patch_through_the_ecall` | a vendored patch that stopped routing |
| `constants::moduli` (3 tests) | a mistyped modulus, a wrong oracle, and a wrong Montgomery correction |

Rewritten: `checker::mod_mul` is 15 tests over **six** honest rows — one per
selector plus the `a = 0` and `(m−1)²` corners — where it was 10 over three.
`emulator`'s `u128` oracle now drives the reduction directly (`reduce` was split
out of `mod_mul_frame` for it), because none of the four fixed moduli fits a
`u128` and an oracle written in the same 16-limb arithmetic as the thing it
checks is not an oracle.

Deleted: `emulator::mod_mul_refuses_a_zero_modulus`, whose input cannot exist.

### 9.1 What was run

Green, locally, on this tree:

```
cargo fmt --all -- --check                                    (and the three other manifests)
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p prover --all-targets --features metrics -- -D warnings
cargo clippy --manifest-path tools/transcript-ref/... -- -D warnings
(cd crates/guest-sdk && cargo clippy --target riscv32imac-unknown-none-elf -- -D warnings)
(cd guests && cargo clippy --bins -- -D warnings)
cargo build -p field … -p verifier-core --target riscv32imac-unknown-none-elf
cargo run -p kat-gen                       then git diff --exit-code over every vector dir: clean
cargo run -p kat-gen -- guests             (opt-in, one machine; the ELFs are refreshed)
cargo test -p constants                    7 + 3 + …
cargo test -p program                      14
cargo test -p emulator                     every binary
cargo test -p checker --test mod_mul       15
cargo test -p checker --test add_sub       7
cargo test -p prover  --test fills         5
```

The `# DEFERRED` suites are the batch this stage owes at the end of the
progression; §10 is what each of them is expected to show and what it would
mean if one did not.

---

## 10. What the deferred suites still owe

Nothing in this stage changes a family other than `MOD_MUL` and
`ADD_SUB_LUI_AUIPC`'s one literal, and both are covered at circuit and fill
level in ordinary CI. What only a deferred run can show:

- **`prover::revm`** — the real `2^16` `MOD_MUL` shards, proved and verified,
  now with three patched multiplies feeding them. This is the one that would
  catch an operand the k256 or ark-ff patch failed to reduce, and §4.3 is why it
  is the run to read first.
- **`checker::tamper`** — the anchor twins and the `writes_back_w0` twin over
  the rewritten fixture guest, whose shard count moved with its invocation
  count.
- **`host::prove`** — the mini-block gate, end to end.
- **`prover::metrics`** — unaffected, but it re-measures a statement's peak.

---

## 11. Open items

1. **The `-ENOSYS` fallback is unreachable in this repository and the docs used
   to imply otherwise.** `guests/vendor/README.md` and
   `docs/handoff/S26-cycle.md` §7 pointed at `crates/loader/tests/qemu.rs` as
   the test that ran a binary on an executor with no `MOD_MUL` circuit; S-NATIVE-IO
   deleted that file. This VM answers every delegation, so every shim's `false`
   arm is dead code. The README now says so plainly rather than implying
   coverage. `guests/mod-mul-ops` is the partial answer — it runs its software
   path unconditionally — and the three library patches' fallbacks remain
   unexercised.
2. **`crates/loader/tests/vectors/mod-mul-ops.elf` still has no `PINS` entry**,
   a gap recorded as open twice in `S-NATIVE-IO.md` and not closed here. It
   matters more now: this stage regenerated that ELF on one machine, and nothing
   would have noticed a stale one.
3. **A fifth modulus is a decision, not an append.** The selector codes are
   frozen the moment a verifying key exists over them, by the same append-only
   logic as an ecall number. BLS12-381 — the `0x0a` point-evaluation
   precompile's field — is 381 bits and does not fit this frame at all, so it
   would be a different family.
4. **`docs/handoff/reports/*.json` are frozen machine output and were not
   regenerated.** They are S26's profiler runs, and each carries a
   `frame_words` per candidate — 32 for the `256-bit arithmetic` one, 30 for
   `secp256k1`. Those are the hypothetical frames the *candidate model* uses
   and not `constants::mod_mul::FRAME_WORDS`, so they are still correct as a
   record of what S26 measured; but anyone re-running the profiler and diffing
   will see the tables move, and nothing in the files says they are historical.
   Read them as a handoff note reads: what that stage measured, then.
5. **The `256-bit arithmetic` profiler candidate is still 2.47% of the
   mini-block and still has no accelerator.** It is the EVM's own `MULMOD`,
   `ADDMOD` and friends inlined into 27 opcode handlers, and the instruction is
   explicit that this family is not to serve it. `tools/profiler`'s candidate
   table now says so where it used to imply the opposite.
