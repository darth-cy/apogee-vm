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
| 9 | `DIGIT` | a | d ← the low 8 bits of a, b ← (a − d)/2⁸ |

`DIGIT` peels one digit of a scalar for the MSM's buckets (§8.3). A scalar's 32 of them,
with the rest ending at 0, satisfy `s = Σ_k d_k·2^{8k}` **mod p**: a representation of
`s`, not necessarily its canonical one, and exactly what a multiplication of a point of
order `p` needs. The rest goes to `b`, which may be `a` itself, so a chain peels in place.

**Field queries.**

- `a` is at Δ0, `b` at Δ1 and `d` at Δ2.
- Each is masked by an `M` column (`a_live`, `b_live`, `d_live`) that a degree-1 gate
  ties to the op selectors.
- `a` is read-only, `d` is read-modify-write, and `b` is read-modify-write on `DIGIT`
  rows and written back unchanged on every other (`b_kept`).
- The distinct slots make every aliasing legal.

**Gates.**

- The op selectors are boolean, sum to `live` and recompose `w0`.
- One product column `prod = a·x`, where `x` is `b` on `MUL`/`MAC` and `d′` on `INV`.
- Then, each under its selector:

  ```text
  MUL  d′ − prod      ADD  d′ − a − b      SUB  d′ − a + b      MAC  d′ − d − prod
  EQ   a − b          IMM  d′ − w3         SHL  d′ − 2^32·a − w3
  INV  prod − 1 + z,  z·a,  z·d′,  z boolean,  z·(1 − sel_INV)
  DIGIT  a − d′ − 2^8·b′, with d′ and 2^8·d′ in RANGE16
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

## 6. `FQ_OP` — one `Fq` operation a row

Family 22, ecall `0x050C`, anchor space 14, height `2^20`: its `TIMESTAMP` table needs
19 variables, so `2^20` is forced, not chosen. The owner chose this shape over a
guest-built-frame variant and a three-operand one, with the fold's cost counted
including its RISC-V glue (§0, §8.3).

**An element** of BN254's base field is four consecutive cells holding 64-bit limbs,
`v = Σ_i v_i·2^{64i} < 2^256`, congruent to the element mod `q` and **not necessarily
below it**: reduction is lazy, and only this family writes an element, every limb it
writes range-checked. The executor writes the reduced result, the honest
representative.

**Frame** `[op, d, a, b]`, read-only. The op word is the code (bits 0..3), three
indirection flags `ind_d`, `ind_a`, `ind_b` (bits 3, 4, 5) and a **digit cell**
(`word >> 6`). An indirect operand's element is its word plus `8·digit`, the digit being
that cell's value: a word names a window's buckets, eight cells apiece (`x` then `y`),
and the digit picks one. That is what makes the MSM's per-point template a static tape
(§8.3); a direct operand's word is its element.

| op | name | the identity `a·y + z = q·K + d′` | `d′` |
| --- | --- | --- | --- |
| 1 | `MUL` | `y = b`, `z = 0` | written |
| 2 | `ADD` | `y = 1`, `z = b` | written |
| 3 | `SUB` | `y = 1`, `z = 6q − b`, nonnegative for any `b < 2^256` | written |
| 4 | `MULEQ` | `y = b`, `z = 0` | `d`, kept: the row asserts `a·b ≡ d` |
| 5 | `FROM128` | `y = 0`, `z = d′`, so `K = 0`; `d′₀ + 2^64·d′₁ = a₀` and `d′₂ + 2^64·d′₃ = a₁` | written |

`FROM128` turns a point coordinate's two transcript limbs into an element, and its limb
ranges are what bound each limb below `2^128`.

**The identity** holds over the integers. It is checked as four equations over 128-bit
groups of limb positions, `(0,1)`, `(2,3)`, `(4,5)` and `(6)`, with three signed carries
between them. `y` is four committed columns, so `a_i·y_j` is degree 2. `z`'s limbs are
`sel·b_k` and `sel·d′_k` products plus the literal `6q_k` on `SUB`. Every term of a group
equation is below `2^208` for any assignment the ranges admit — `a`, `b`, `d′` below
`2^256`, `K₀..K₂` below `2^64`, `K₃` below `2^76`, the carries below `2^76` — so no
equation wraps mod p, and the four equations together are the integer identity. The
quotient's top limb `K₃` and the carries go through `TIMESTAMP`'s 19-bit chunks, and
`K₀..K₂` and `d′`'s limbs through `RANGE16`. A carry is its chunks less `2^75·live`, so the
all-zero padding row has carry 0.

**Accesses**, each at its own slot so any two operands may name one element: the digit
cell at Δ0, `a` at Δ1, `b` at Δ2 and `d` at Δ3, all on for every live row. `b`'s and
`d`'s four cells **share one read timestamp and one gap**, because only this family
writes an element and it writes all four cells together. `a`'s four cells carry one
each, because `FROM128`'s operand is transcript limbs, imported one at a time. Two rules
follow for a guest, and the honest fill refuses a trace that breaks either:

- every operand names an element, including one the op ignores (`FROM128`'s `b`);
- an element is read whole until it is dead, since exporting its limbs reads them one
  at a time.

**Shape.** 48 `M` and 73 `W` committed columns and 630 inner columns. `TIMESTAMP`
carries 30 obligations, filling 31 of a 32-leaf tree; `RANGE16` carries 50, filling 51 of
64. Two more `TIMESTAMP` obligations double that tree, and `artifact` asserts both counts.
`constraints::fq_op::witness` is the row's arithmetic: `y`, `d′`'s chunks, `K` by exact
2-adic division (`K = (a·y + z − d′)·q⁻¹ mod 2^576`) and the carries over the field.
It asserts `q·K` back.

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

**The guest's form** is `tape::encode`: the imports hoisted, since a tape never reuses a
cell, then runs of one family's frames, each run its ecall number, its count and its
frames back to back. `guest_sdk::recursion::import` fills a tape's inputs from its blob,
and `replay` walks the runs, `a0` advancing past every frame itself (§1.4).

**Measured** on block 257510's first 32 base shards, by a leaf with no fold whose tapes
and slots are advice (`docs/handoff/reports/S-RECURSION-tape-leaf-257510.json`):

- **Coprocessor calls:** 223,599 `FR_OP` calls, 54,615 duplexes and 60,393 imports. That
  is about 7,000, 1,700 and 1,900 a shard, a fifth of one shard of each family for the
  whole slice.
- **RISC-V:** 3.19M cycles. 1.25M of them copy the tapes out of advice, which tapes in an
  image do not. 1.27M replay them, at 4.6 cycles a call, the run switches most of that.
  0.67M import, at 11 a word. `replay` has since run eight calls an iteration, about two
  cycles a call; what is left is per run, and a shard tape's runs are short, a duplex
  every few field operations.

A tape replayed as straight-line `ecall`s from `.text`, its frames in `.rodata`, costs one
cycle a call, and that is the form binding takes (§8).

What a statement chooses the length of — the global phase's absorbs, the
reconciliation product — the guest records at run time through the same `Tape` and
replays at once. `tape::run` is the native reading of a tape over a `tape::Memory`, which
models each access's timestamp as well as each cell's value (§8.3), and three
suites hold it to the native verifier: `crates/gkr/tests`' honest proofs and their
forgeries (`tape::gkr_verify` against `gkr::verify`, claim for claim and refusal for
refusal), `crates/pcs-verify/tests/tape.rs` (the preamble and the scalars, to the
sponge state), and the deferred `crates/prover/tests/field_ops.rs`, which replays every
shard of a recursion-format block and holds its outputs to `verify_shard_local` and
`pcs::batch_verify_deferred`.

## 8. Nodes and the tree

### 8.1 Two programs, one procedure

A **node** verifies statements and folds their deferred checks into one accumulator
(§8.3). There are two node programs, one crate's two binaries (`guests/recursion`), on
the owner's decision:

- **The leaf** verifies a slice of shards, `from..to`, of one statement of the **base
  program**.
- **The internal node** verifies two to four whole statements of the two recursion
  programs, which are its children's proofs. It reads each child's journal out of the
  public window step 10c binds, holds the children to one another, and folds their
  accumulators beside their shards' checks.

Both run `verifier_core::node::node`, one procedure that a host and a guest each run
through a `Driver`. The host runs it natively, answering every request for advice from
the proofs and recording the words the guest will read, every MSM witness among them.
The guest runs it by its coprocessor calls. So a host refuses whatever a guest would, by
name, before any guest runs.

**The image** is everything static, encoded as a guest replays it, so the host replays the
very words the guest does:

- each program's families' shard tapes, pooled so a tape two programs share is held once;
- the prologue that fills a shard's slots from the node's cells, and the fold after it;
- the MSMs' templates;
- step 10b's boundary half;
- the node's constants.

`build.rs` builds both images on the host with `verifier-core` itself, and each binary
holds its own in `.rodata`, so a node's identity binds every tape it replays.

- The leaf's image is built from `base.key`, the base program's key without its circuits
  (`profiler base-key` writes it from a proof archive). It is the base program's tapes,
  5.6 MB, so **the leaf's window families are at `2^22`**.
- The node's image is built from `programs.key`, the two recursion programs' configs as
  their ELFs derive them (`profiler program-keys`). A config depends on code and
  parameters, not on `.rodata`, so a second run agrees. It is 2.8 MB, and the node's
  windows are at `2^20`.

Both programs derive the same sixteen families: six execution families, four field
families, `FIELD_WINDOWS`, the three RAM window families and the two public ones.

**What binds what:**

- A leaf holds the base program's identity as a constant.
- An internal node takes the two recursion programs' identities as claims and journals
  them, so the top checks them once.
- Every program's setup commitments arrive as advice. They are held to its identity by
  recomputing it, and the entry pc with them.
- The SRS digest and the generic table are the ceremony's, constants of every image.
- The procedure's own tapes do no field arithmetic, so no node declares the `FR_ARITH`
  family: a tape's constants are `IMM` and `SHL` from bytes.

**The global transcript is a chain across the tree** (`verifier_core::chain`).

- The node with a statement's first shard runs the prefix, G1–G7.
- Every node absorbs the memory commitments of the shards it verifies, G8. These are the
  same cells it opens against, absorbed from the transcript state the node before it
  left.
- The node with the last shard runs the suffix, G9–G11. That settles the digest and the
  memory challenges every node took as claims, and the boundary's half of step 10b.

A segment's messages are an even number of scalars, so every seam between shards has the
prefix's parity, and a state there is three lanes and at most one pending input. That
input is copied: it is a slot cell the next shard overwrites. The statement's shape (its
counts and windows) is constants of the tapes built from it, and every node journals its
digest, because a node names its shards by the shape and only the prefix absorbs it.

**Across shards**, per statement:

- the roots' products;
- each cycle-owning family's time windows: non-empty, and in order;
- step 10c, where a public shard is, with `io_digest` from the same window words.

Where one node holds a whole statement, as an internal node holds each child's, it also
makes the memory argument, `Π reads · R_b = Π writes · W_b`.

**An internal node over its children:**

- Each child is verified as a statement, and its exit must be 0.
- Its journal is read from its output window's words, a cell a 32-byte word.
- An internal child must require the identities this node requires.
- Neighbours must be of one base statement, with the same shape, digest, challenges,
  `io_digest`, exit status and total. Their shards must be adjacent, their chain states
  must meet, and their time windows must be in order across the seam.
- A child's `(A, B)` is folded under a weight drawn after absorbing its whole journal
  (`FOLD_CHILD`, 45).
- Where the children cover the whole base statement, the node makes the memory argument
  over the products they journal.

### 8.2 The journal

47 cells, one a 32-byte word, as `EXPORT` writes them (`verifier_core::node::journal`):

| cells | what |
| --- | --- |
| 0 | the base statement's shape digest |
| 1–7 | its global digest, four memory challenges, `io_digest`, exit status |
| 8–10 | its shard count, and the shards this node covers, `from..to` |
| 11–18 | the chain's state at `from` and at `to`: three lanes and a pending input each |
| 19–22 | the covered shards' read and write root products; `(W_b, R_b)` where `to` is the count |
| 23–28 | the first and last covered shard's family and time window |
| 29–44 | `A` and `B`, each `x` then `y` in four 64-bit limbs |
| 45–46 | the leaf program's and the node program's identities a node requires; 0 for a leaf |

The root is the node covering `0..count`. Its journal says that the base statement's every
shard was verified, the global transcript run end to end, and the memory argument made.
What remains for the top is the accumulator's one pairing check, and the two identities
held to the published ones.

### 8.3 Folding

A node folds every deferred check it verifies into one accumulator `(A, B)`: `A` the
points that pair with `[1]_2`, `B` those that pair with `[x]_2`
(`docs/spec/accumulator.md` §2), each the sum of its points times their scalars.
`verifier_core::fold` builds it as tapes, in three parts.

**The weights.** After a shard's tape, a transcript of the node's own — a duplex over
cells, carried from shard to shard — absorbs the shard transcript's final state under
`FOLD_STATE` (43) and draws two weights, `w` and `w′`, under `FOLD_WEIGHT` (44). That
state binds every point and scalar of the shard's deferred checks, so a shard's weights
are drawn after everything they weight, and the folded check fails unless every shard's
holds, but with probability about `2/r` a shard.

**The scalars** (`fold::shard_fold`):

- entry `i` of the shard's Mercury check gets `w·e_i`, on the side
  `pcs_verify::ENTRY_POINTS` gives it;
- `cm*` gets `w′` more, and each opened commitment `cm_i` gets `−w′·ρ^i`. That is the batch
  check `cm* = Σ ρ^i·cm_i`, which a shard's tape cannot make because it is curve
  arithmetic, folded beside the Mercury check. So the recursion verifies what the native
  verifier does, the hint `cm*` included;
- `[1]_1` and the setup commitments are **merged**. Every shard of a family owes the same
  points, so a shard's fold adds its share to the point's scalar, and the point enters the
  MSM once, after the node's last shard. On block 257510's first 32 shards that is 9
  points where it was 229.

**The MSMs**, one a side: Pippenger with 8-bit digits, shaped so that nothing a replay does
depends on a value.

- **GLV.** BN254's endomorphism `φ(x, y) = (β·x, y)` is `λ` on G1, so a scalar splits as
  `k ≡ s₁·k₁ + λ·s₂·k₂` with `k₁, k₂ < 2^128`. The split is a host witness (`fold::split`),
  and the template holds it to `k`: each half is below `2^128` by its 16 `DIGIT`s leaving
  nothing over, and each sign is a bit. A point is then two 128-bit scalars over **16
  windows** of 256 buckets, about a 256-bit scalar's work over 32, and the fixed work,
  which is per window, halves.
- **A point is one template.** It holds the point to the curve: `y² = x³ + 3`, and G1's
  cofactor is 1, so on the curve is in the group, where `φ` is `λ`. It holds the split to
  the scalar, forms `s₂φ(P)` and `s₁P`, and makes one affine bucket addition a window for
  each, the bucket indirect through the window's digit cell (§6). A half's 16 additions
  land in 16 windows, so they never collide and share one inversion: a host witness held
  by one `MULEQ`. The template is 396 `FQ_OP` and 47 `FR_OP` calls over ten witness cells.
- **Offset buckets.** Bucket `b` starts at `(b + 1)·R` for a fixed point `R`, so no
  addition meets infinity and no running sum doubles a point. The finish subtracts what
  the offsets add, once.
- **A loop is one template replayed.** The finish is each window's running sums, batched
  across the windows, then Horner by doubling. It and the prelude's offsets and bucket
  setting are loops: one short template each, replayed, its bucket or window indirect
  through a counter cell the template steps itself. A side's fixed work is about 110k
  `FQ_OP` calls, and its templates about two thousand.
- **The point at infinity** adds nothing. Its four limbs are held to the sentinel, and a
  real point's cannot be.

**Cells.** `FQ_OP` reads an element's four cells under one timestamp (§6). So a template's
temporaries are elements on one grid of four from its scratch, where nothing else writes,
and the next step reuses them. `tape::run`'s `Memory` models each access's timestamp and
refuses an element read whole that was not written whole, so a layout that breaks the
rule fails natively and not in a proof.

**Checked natively.** `host::recursion::leaf` and `internal` run a node in the guest's
order — shard tapes, folds, MSMs — over one `Memory`, which is also how they compute
every witness. Each then discharges `(A, B)` with one pairing check. That check holds the
fold itself, every weight, side and merged scalar, to the shards' checks. `crates/host/tests/msm.rs`
holds the MSM to `curve::msm`, `φ` to `λ`, and the offsets' constants to their points.

**Measured** on block 257510's first 32 base shards by the leaf's measurement guest
(`docs/handoff/reports/S-RECURSION-fold-leaf-257510.json`). The slice is 28 add/sub
shards, each of 27 memory, 35 witness and 7 setup commitments, and four window shards.

| family | calls | shards |
| --- | --- | --- |
| `FQ_OP` | 901,276 | one `2^20`, 147k to spare |
| `FR_OP` | 312,984 | one `2^20` |
| `P2_FIELD` | 54,743 | one `2^18` |
| `FIELD_IO` | 81,137 | one `2^18` |

The two MSMs' fixed work is about 220k of the `FQ_OP` calls, and some 1,720 points are
396 each. Before GLV and merging, the same leaf took 1,188,658.

### 8.4 The scheduler

`bench recurse` (`tools/bench/src/recurse.rs`).

**The tree is fixed before anything is proved** (`host::recursion::Tree::plan`).

- **Leaves** are runs of consecutive base shards. A leaf closes before a shard that would
  take it past `--leaf` shards (64), or its folds' estimated `FQ_OP` rows past
  `--budget` (none). A shard alone over the budget is a leaf of its own.
- **Internal nodes** come in levels, each over at most `--fan-in` (4) and at least two
  children. A group of one is carried up a level as it is.
- The plan is written to `<out>/tree.txt` before the first node starts.

A node costs about one shard a family before it does any work, sixteen in all. So a
leaf is cheapest large: another `FQ_OP` shard costs one shard, another node sixteen.

**A node is a process**, `bench recurse-node <out> <id>`:

- It reads the tree, the two recursion programs and its children's proofs from `<out>`.
- It builds its advice only then: the children verified, every tape replayed natively.
- It proves at most `--shards-in-flight` shards at once, verifies the proof, and writes
  `<out>/<id>.block`.

So a node's memory is its own process's, and nothing a node needs is queued. The ready
queue is the tree itself. A node is ready when its children's proofs exist, and the
scheduler starts ready nodes in tree order, at most `--in-flight` at a time. It starts
no thread: it polls its children. A proof already in `<out>` is not proved again, so a
stopped run resumes. A rerun must plan the same tree and build the same programs, or it
is refused: its proofs are found by node id.

**At the root**, the scheduler checks what a verifier of the tree owes beyond the root's
own proof:

- the proof verifies under its program's key;
- the journal covers the base statement's shards, `0..count`;
- its statement cells are the base statement's: the global digest, the four memory
  challenges, `io_digest`, the exit status and the shard count;
- the journal requires the two programs' identities. The scheduler holds them to the
  programs it built; a verifier takes them from a channel the prover does not control;
- the accumulator `(A, B)` discharges with one pairing check (§8.2).

## 9. Groth16 and the onchain verifier (outline)

The top node's proof is wrapped in a Groth16 proof whose public inputs carry the folded
accumulator. The onchain verifier checks the Groth16 proof and discharges `(A, B)` with
one pairing equation.
