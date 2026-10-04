# Recursion

S-RECURSION. This page is the design authority for proving this VM's proofs inside
this VM: the recursion format, the field memory and the coprocessor families that
work on it, the nodes of the aggregation tree, and what leaves the tree. It cites
`docs/spec/delegation.md` (the ecall, the frame, the anchor, detachment),
`docs/spec/memory.md` (the memory argument) and `docs/spec/accumulator.md` (deferred
pairings), and restates none of them.

## 0. The owner's decisions, and why

S-RECURSION first built a leaf as an ordinary guest running `verifier-core` and
measured it on block 257510's proof
(`docs/handoff/reports/S-RECURSION-leaf-257510.json`): 3.02B guest cycles for 207
shards, 15x the block's own. Three quarters of each shard's cycles were the
existing delegations' calling convention, and the wide delegation circuits cost a
parent more to verify than the work they held. A cost model then showed a second
wall. With one commitment per column, every committed column of a node is a point
its parent folds, at about 37 EC additions a point, and a node keeps growing level
after level. So:

| decision | what |
| --- | --- |
| base proving | **frozen**: its per-column format, its keys, its `ADD_SUB` circuit |
| the leaf | an adapter: verifies 32 base shards and folds their per-column commitments, once |
| level 1 up | one homogeneous **recursion format**: stacked commitments (§1.3); every node folds |
| fan-in | 32 base shards a leaf, 2-4 children an internal node; a lone leftover is carried |
| values | a **field memory** of whole `Fr` cells (§2) and coprocessor families on it (§3-§6) |
| the driver | a lean handle-based verifier issuing one coprocessor op a call (§7) |

The projection behind the fan-in, for block 257510, counted in shards:

| leaf fan-in | leaves | shards a leaf | recursion tree | vs. the base proof |
| --- | --- | --- | --- | --- |
| 8 | 26 | ~15 | ~590 | 2.4x |
| 16 | 13 | ~17 | ~300 | 1.3x |
| 32 | 7 | ~19 | ~190 | 0.8x |

Internal nodes settle at 16-20 shards.

---

## 1. Two formats, one code path

### 1.1 The rule

A statement is in the **recursion format** exactly when its `VmConfig` holds
`FIELD_WINDOWS`. That holds exactly when the program declares a field delegation
(§2.2). Every program before this stage declares none, so every base key, statement and
proof keeps its bytes. Nothing is added to a wire form to say which format applies: the
config already says it.

### 1.2 The delegation registry

`constants::delegation::TYPES` stays the one append-only registry, and the recursion
families are appended to it. **`constants::delegation::BASE_TYPES = 6`** is the prefix
the base format's `ADD_SUB` circuit knows: frozen, so the base `ADD_SUB` is byte for
byte S26c's. A recursion-format `ADD_SUB` knows every row. `constraints::family_circuit`
stays the base registry. `constraints::recursion_circuit` is the recursion format's, and
it differs from the base registry in exactly two ways:

- `ADD_SUB` carries every type;
- the families of §2-§6 are present.

The two production callers, the verifying key's load rule and the prover's registration,
pick the registry from the config.

### 1.3 Stacked commitments

A shard commits each of its two phases as **stacks**. The two phases are its `M`
columns, in the global commit phase, and its `W` columns with the multiplicities, in
the shard transcript.

- **Stack width.** At height `2^n`, a stack holds `2^σ` columns with

  ```text
  σ = min(24 − n, the smallest even σ with 2^σ ≥ max(k_M, k_W))
  ```

  `σ` is even because `n` is and Mercury needs `n + σ` even. 24 is the ceremony the
  repository holds (`assets/ptau/ppot_0080_24.ptau`).
- **Layout.** Phase column `i` sits in stack `⌊i / 2^σ⌋` at slot `j = i mod 2^σ`, and
  the stack is the `(n + σ)`-variate multilinear whose evaluations
  `[j·2^n, (j + 1)·2^n)` are that column. The column index is the high variables. Slots
  past the phase's last column are zero.
- **Commitment.** A stack's commitment is its Mercury commitment: one MSM over SRS
  powers `j·2^n …` for each slot, summed. Nothing is materialized.
- **Opening.**
  1. The GKR pass ends with every committed column's value at its point `u`, as today.
  2. `σ` challenges `r` are drawn under `STACK_CHALLENGE`.
  3. Each stack's value is `Σ_j eq(r, j)·v_j`.
  4. A setup column joins as a stack whose only column is itself at slot 0. Its
     commitment is unchanged, because zero padding above a KZG commitment's
     coefficients is free, and its value is `eq(r, 0)·v`.
  5. The shard's one batch opening opens M stacks, then W stacks, then setup columns
     at `u ‖ r`.

`σ = 0` is today's protocol exactly: no challenge is drawn and a stack is a column. The
base format is the recursion format at `σ = 0`, and one code path carries both.

### 1.4 A recursion request leaves `a0` past its frame

A base request writes 0 into `a0` (`docs/spec/delegation.md` §2). A request of a
recursion type — a row of `constants::delegation::TYPES` past `BASE_TYPES` — writes the
frame base it read **advanced past its frame**, `a0 + 4·words`
(`constants::delegation::a0_after`). A tape is a run of consecutive frames, so after
one call `a0` already names the next frame and a replay is back-to-back `ecall`s, one
RISC-V row an op instead of two or three.

- The recursion format's `ADD_SUB` carries `deleg_a0_rule`,
  `Σ_t is_deleg_t·rd_selected − Σ_{t ≥ BASE_TYPES} is_deleg_t·(rs2 + 4·words_t) = 0`,
  in place of the base circuit's `deleg_writes_no_register`. Either way the request
  writes a value it did not choose, which is what the zeroing was for.
- The base circuit keeps its gate and its bytes. The rule is per type, not per format,
  and no base type advances.
- `guest_sdk::recursion`'s field shims hold the answer to `base + bytes` and exit 72 on
  anything else.

---

## 2. The field memory

### 2.1 The space

**`address_space::FIELD = 10`.** A field tuple is `(FIELD, cell, ts, value)`, with
`cell` a `u32` and `value` any `Fr`.

- No instruction reaches it: a load or store names `RAM`. Only §3-§6's rows read and
  write it.
- A field access rides its invocation's requesting cycle `c` at `4·c + Δ`. It carries
  the gap check every read carries: two `RANGE16` chunks, as a frame word's.
- It is not a `MemoryEventLog` event, because a value is not a `u32`.
  `trace::MemoryState` keeps each cell's last `(ts, value)`, and the windows' teardown
  is filled from it.

### 2.2 `FIELD_WINDOWS`

Family 18, height `2^20`. Window `w` is cells `[h·w, h·(w + 1))`, and its rows are
`ZERO_WINDOWS`' circuit with a **stride of one cell a row** instead of four bytes:

- init tuple `(FIELD, cell, 0, 0)`;
- teardown tuple, the cell's last;
- derived slot 5 is `γ_M + FIELD + α_addr·h·w`.

The windows are **consecutive from cell 0**, so the statement carries no window list:
shard `i` is window `i`. A cell outside every window has no init tuple and cannot be
read. The family is in a `VmConfig` exactly when the program declares one of §3-§6's
families, which is the format rule's other half.

---

## 3. `FR_OP` — one field operation a row

Family 19, ecall `0x0509`, anchor space 11, height `2^20`.

**Frame** `[op, d, a, b]`, four words, read and written back unchanged.

| op | name | reads | writes |
| --- | --- | --- | --- |
| 1 | `MUL` | a, b | d ← a·b |
| 2 | `ADD` | a, b | d ← a + b |
| 3 | `SUB` | a, b | d ← a − b |
| 4 | `MAC` | a, b, d | d ← d + a·b |
| 5 | `INV` | a | d ← a⁻¹, and 0 at a = 0 |
| 6 | `EQ` | a, b | nothing: a = b, or there is no witness |
| 7 | `IMM` | — | d ← b, the frame word read as an integer |
| 8 | `SHL` | a | d ← a·2³² + b, the frame word |

**Field queries.**

- `a` is at Δ0, `b` at Δ1 and `d` at Δ2.
- Each is masked by an `M` column (`a_live`, `b_live`, `d_live`) that a degree-1 gate
  ties to the op selectors.
- `a` and `b` are read-only and `d` is read-modify-write.
- The distinct slots make every aliasing legal.

**Gates.**

- The op selectors are boolean, sum to `live` and recompose `w0`.
- One product column `prod = a·x`, where `x` is `b` on `MUL`/`MAC` and `d′` on `INV`.
- Then, each under its selector:

  ```text
  MUL  d′ − prod      ADD  d′ − a − b      SUB  d′ − a + b      MAC  d′ − d − prod
  EQ   a − b          IMM  d′ − w3         SHL  d′ − 2^32·a − w3
  INV  prod − 1 + z,  z·a,  z·d′,  z boolean,  z·(1 − sel_INV)
  ```

---

## 4. `P2_FIELD` — one duplex step a row

Family 20, ecall `0x050A`, anchor space 12, height `2^18`.

**Frame** `[n, s, x, y, d]`, read-only. The row is one step of the transcript's duplex
(`crates/transcript`):

1. It reads the state cells `s, s+1, s+2` at Δ0, `x` at Δ1 when `n ≥ 1`, and `y` at Δ2
   when `n = 2`.
2. It forms the lanes `(n ≥ 1 ? x : s₀, n = 2 ? y : (n = 1 ? 0 : s₁), s₂ + n)`. This is
   the rate overwritten, zero-filled and counted into the capacity.
3. It writes `poseidon2_permute` of them to the triple `d … d+2`, at Δ3.

The state moves to cells its caller chose, so no handle to an old state is ever
overwritten, a challenge is a cell of the new triple, and a transcript's states need no
run of cells to themselves — which a fixed `s + 3` would have forced on every caller.

**Flat, not layered.** Each of the 80 S-boxes commits `u²` and `u⁴`, and each round
but the last commits its three output lanes, the last round's being the next state's
`M` columns: 349 `W` columns, every gate degree 2, each round constant `rc·live` so a
padding row is all zero. S23's `POSEIDON2` is ~200 layers deep, and a parent pays one
sumcheck a layer to verify it, about 3,600 rounds for a `2^18` shard. A flat circuit
is one gate list and about 350 rounds. With stacked commitments the extra columns cost
the parent almost nothing.

---

## 5. `FIELD_IO` — between RAM and the field memory

Family 21, ecall `0x050B`, anchor space 13, height `2^18`.

**Frame** `[op, cell, ptr]`, read-only. Eight RAM data words `ptr + 4k` are at **Δ1**,
which is distinct from the frame's Δ0, so a frame and its data may overlap. The cell is
at Δ0.

| op | name | what |
| --- | --- | --- |
| 1 | `IMPORT` | cell ← `Σ_k w_k·2^{32k}` mod p; the words are read-only |
| 2 | `EXPORT` | `w_k` ← limbs with `Σ_k w_k·2^{32k} ≡ cell`, each `< 2^32` |

- **`IMPORT` reduces.** A non-canonical encoding is harmless: what the verifier
  computes with is the element.
- **`EXPORT` proves congruence and 32-bit limbs, not canonicity.** The guest holds the
  words in RAM and compares them with `p` itself, where that matters. A scalar's
  Pippenger digits need none of it, because `(s + kr)·P = s·P`.
- **Addressability is the multiset's.** An address no window initializes cannot
  balance.

---

## 6. `FQ_OP` — one `Fq` operation a row (outline)

Family 22, ecall `0x050C`, anchor space 14, height `2^20`. An `Fq` element is four
64-bit limbs in four consecutive cells, always canonical. The ops are:

- `MUL`: `c = a·b mod q`, with quotient limbs and signed carries as witnesses;
- `LIN`: `c = s_a·a + s_b·b + s_c·c′ mod q`, for small signed integers;
- `CHECK`: canonicalizes and validates advice.

It is specified in full when built, with the folding of §8.3.

---

## 7. The handle-based verifier: tapes

The guest does not run `verifier-core`: its control flow alone costs about 500k cycles
a shard. A shard's checks have a fixed shape for its family and height, so
`verifier_core::tape` compiles them, on the host, to a **tape**: a straight-line list
of coprocessor calls — `FR_OP`, `P2_FIELD` and `FIELD_IO`'s `IMPORT` — over absolute
cells of the field memory. The guest replays the list, about three RISC-V rows a call,
and nothing in it branches on a value. A tape reads three kinds of cell:

- **constants**, which it makes itself from `IMM`, `SHL` and `SUB`, so they are part of
  the tape and bound with it;
- **slots**, which the caller fills before replaying: the statement's digest and memory
  challenges, the shard's index, window (`verifier_core::shard_window`) and roots, and
  the commitments the statement and the key give it;
- **inputs**, the proof, `IMPORT`ed from a blob laid out in the tape's `Input` order
  (`tape::shard_blob`), which the tape's own checks are what bind.

`tape::shard_tape` is `verify_shard_local`'s steps 7-11 and Mercury's field side, call
for call: the shard transcript over cells (`CellTranscript`, the duplex of §4), the
challenge slots, the GKR backward pass with the gate kernel and the virtual tables, the
channel and root checks, the stack challenges and values, the batch preamble and
`pcs_verify::scalars`. Every check is an assertion — `EQ`, or `x·x⁻¹ = 1` for a
nonzero — and `z`'s resample at zero is an assertion too, a liveness loss at
probability `1/p` and never a soundness one. It leaves the batch weights, the twelve
Mercury scalars, the points they pair with and the claimed `ts_window` to its caller.

What a shard's tape does **not** do, and its caller owes:

- step 4, `ts_window`'s range, and the block's window rule across shards;
- step 10c, which only the two public value shards carry;
- the curve: a point arrives as its four transcript limbs, and the fold validates it
  and holds `cm*`, a hint, to `Σ ρ^i cm_i`.

What a statement chooses the length of — the global phase's absorbs, the
reconciliation product — the guest records at run time through the same `Tape` and
replays at once. `tape::run` is the native reading of a tape over a `Vec<Fr>`, and three
suites hold it to the native verifier: `crates/gkr/tests`' honest proofs and their
forgeries (`tape::gkr_verify` against `gkr::verify`, claim for claim and refusal for
refusal), `crates/pcs-verify/tests/tape.rs` (the preamble and the scalars, to the
sponge state), and the deferred `crates/prover/tests/field_ops.rs`, which replays every
shard of a recursion-format block and holds its outputs to `verify_shard_local` and
`pcs::batch_verify_deferred`.

## 8. Nodes and the tree (outline)

### 8.1 Leaf and internal node

- A **leaf** takes up to 32 base shards of one statement. It replays the base global
  phase, verifies its shards, and folds their per-column deferred checks.
- An **internal node** takes 2-4 recursion proofs of the recursion program and folds
  their accumulators with its own children's deferred checks.
- One binary serves both.

### 8.2 The journal

A node's journal carries:

- the statement digest;
- the shard range it covers;
- the recursion identity it requires of its children;
- its folded accumulator `(A, B)`.

### 8.3 Folding

Every point the node owes, with its scalar times the check's weight from the node's own
transcript, goes through one Pippenger MSM per pairing side on `FQ_OP`. The scalars'
digits come from `FIELD_IO` exports.

### 8.4 The scheduler

The tree's shape is fixed before proving. A node is ready when its children's proofs
exist. The ready queue holds `(node, child proof ids)`, and a worker materializes a
node's advice only when it claims the node. Recursion has its own `max_in_flight`.

## 9. Groth16 and the onchain verifier (outline)

The top node's proof is wrapped in a Groth16 proof whose public inputs carry the folded
accumulator. The onchain verifier checks the Groth16 proof and discharges `(A, B)` with
one pairing equation.
