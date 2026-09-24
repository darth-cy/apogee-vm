# Delegation: the ABI, the anchor, and the three delegation families

Frozen as of S21 and **appended to at S23**, which added two families under
§10's rule and amended §3 and §5.1 where more than one delegation type made a
literal impossible (§10.1). **This page is the delegation ABI** — every
delegation family obeys it. Changing anything here but by §10's append rule is
a protocol-version change.

S22 was cancelled and never shipped (`prompts/00-master.md`, "Stage register:
cancelled stages"); every sentence that promised it a number, a tag or a frame
table is gone.

It cites `docs/spec/ecall-abi.md` for the calling convention, `docs/spec/memory.md`
for the memory argument, `docs/spec/execution-trace.md` for the clock and the
frame of a cycle, and `docs/spec/block-proof.md` for the block's rules; it
restates none of them.

| crate | what |
| --- | --- |
| `crates/constants` | the ecall number, the address-space tag, the slot, the marker, and keccak's two tables |
| `crates/guest-sdk` | the shim, the software fallback, and the declaration record |
| `crates/emulator` | the ecall, the frame's execution, and the invocation record |
| `crates/trace` | the delegation address space, the `Delegate` role, and `DelegationTrace` |
| `crates/program` | the declared set, and the family's place in a `VmConfig` |
| `crates/constraints` | `delegation`, the shared frame; `keccak`, `poseidon2` and `fr_arith`, the circuits; `add_sub`, the request-side gates |
| `crates/prover` | the fill and the shard's ts window |
| `crates/checker` | the anchor-tamper helper and the block-level hook |

---

## 1. What a delegation family is

A **delegation family** proves a function of guest memory that would cost too
many cycles to run as instructions. It differs from an execution family in
exactly four ways, and in no others:

- It is **invoked, never decoded.** No instruction word names it, it claims no
  pc, it sets no `family_extra_mask` bit, and it has no decoded table. A
  requesting cycle hands it a pointer, and it dereferences that pointer at fixed
  offsets — the *indirect-access* pattern. Prior art carries the invocation over
  a CSR write, with the CSR number doubling as the delegation type; this VM
  carries it over an ecall, whose number is the type.
- Its **rows are invocations**, not cycles. One row is one call. It runs its own
  trace beside the CPU families, and its shards are planned from its invocation
  count like any other family's rows.
- Its accesses **ride the one global memory multiset** (`docs/spec/memory.md`
  §1). There is no second argument, no side channel and no new tuple shape.
- It is in a `VmConfig` exactly when the **linked binary declares it** (§7),
  which is the third and last presence rule `decode_program` has.

Everything else is an ordinary family: one arm in `constraints::family_circuit`,
one fill in `prover::family_fill`, a shard proof of the frozen shape, and
`verify_shard` and `verify_block` unchanged.

---

## 2. The calling convention

A delegation call is an ecall, so `docs/spec/ecall-abi.md` §1 is its convention
unchanged: **`a7` carries the number, `a0` the first argument, and the call
preserves every register but `a0`.**

| register | role |
| --- | --- |
| `a7` | the delegation ecall number |
| `a0` | in: the **frame base pointer**; out: 0 on success |

A delegation number is in the **precompile** range `0x0500..=0x05FF`
(`constants::ecall::PRECOMPILE_FIRST`..`PRECOMPILE_LAST`), because a delegation
is a deterministic function of guest memory and never prover advice. Numbers are
**append-only, forever**, for the reason every ecall number is: redefining one
does not fail loudly, it quietly makes an old program compute something else.

An executor without the circuit answers `-ENOSYS` and the caller runs its
software path — `docs/spec/ecall-abi.md` §5's convention, which is what lets one
guest binary run under `qemu-riscv32` and under this VM. An executor **with** the
circuit answers 0. A shim treats exactly `-ENOSYS` as "run the software path" and
every other nonzero as a hard `exit(72)`.

The two executors therefore run **different instructions** from the first
delegation on, by construction and not by disagreement, while computing the
same value. That is why nothing compares their instruction streams: the
comparison is the guest's *answer* — its exit status and its fd 1 — in
`crates/emulator/tests/qemu_outputs.rs` and, against expected bytes, in
`crates/loader/tests/qemu.rs` at both optimisation levels. In-guest,
`guests/keccak-test` and `guests/recursion-ops` check the delegated result
against the software one directly and exit the same status under either
executor, which is what holds the two paths to one another. A per-instruction
comparison with QEMU was S12's acceptance and is **withdrawn** (owner's
decision, S25); `crates/emulator/CLAUDE.md` records why.

An executor that has the circuit but whose `VmConfig` lacks the family answers
neither: it is `EmuError::DelegationFamilyAbsent`, a fatal trace-time failure
(§7). A program that calls a delegation it did not declare is one no trace
describes and no proof covers, and that is a different failure from a VM that
lacks the circuit.

---

## 3. The registry

One table ties a family, its number and its frame width together:
`program::DELEGATIONS`. Append-only, ascending by family id.

| family | id | ecall | frame words | address space |
| --- | --- | --- | --- | --- |
| `KECCAK_F` | 9 | `PRECOMPILE_KECCAK_F` = `0x0501` | 50 | `DELEGATION_KECCAK_F` = 4 |
| `POSEIDON2` | 10 | `PRECOMPILE_POSEIDON2` = `0x0500` | 24 | `DELEGATION_POSEIDON2` = 5 |
| `FR_ARITH` | 11 | `PRECOMPILE_FR_ARITH` = `0x0502` | 25 | `DELEGATION_FR_ARITH` = 6 |

`0x0500` was assigned at S10 with a calling convention and no circuit; S23 gave
it one. The numbers are not in family-id order and need not be: a family id
orders the statement, an ecall number names the call, and this table is what
ties them together.

The table itself is `constants::delegation::TYPES`, which `program::DELEGATIONS`
*is* — one array, read by the emulator's dispatch, by the request-side gates and
by this page's tests.

**Each delegation family has an address-space tag of its own**
(`constants::address_space`), append-only beside `REG = 1`, `RAM = 2` and
`PC = 3`. The tag *is* the delegation type, which is why a keccak request cannot
be answered by another type's invocation at the same frame base, and why the
anchor's address needs to carry nothing but the pointer. Tags stay nonzero, so
no real tuple is all zeros.

`crates/constants/tests/ecall_abi.rs` holds the number in this table, the number
in `constants::ecall`, the number the shim calls and the number the emulator
dispatches on to `docs/spec/ecall-abi.md` §3's row, in both directions and by
count — S10's single-source pattern, extended.

---

## 4. The frame

The **frame** is the contiguous block of guest memory the base pointer names.
It is read and written **in place**, and its contents are the delegated
function's input and output.

- The frame base is the value of `a0` on the requesting cycle.
- The frame is `4 · <frame words>` bytes; §3's registry is the width per
  family, and §6, §12.1 and §13.1 are the three frame tables.
- **Frame word `j` is at byte offset `4j`.** Word indices are the frame's whole
  addressing: there are no sub-word accesses and no offsets of any other kind.
- `KECCAK_F`'s bytes are in **SHA-3 byte order**: lane `A[x][y]` takes index
  `i = 5y + x` and occupies words `2i` and `2i + 1`, **low half first**, so the
  frame read as bytes is the state read as bytes.

**Two frame rules, and the circuit carries both:**

1. **Alignment.** The base is word-aligned. In the circuit that is not a
   statement over `Fr` — 4 is a unit there — but a decomposition: `base` is
   `RAM_ORIGIN + 4·q` with `q` a sum of 29 committed booleans, so a base that is
   not word-aligned has no witness at all (`keccak.rs`'s `base_aligned`).
2. **Bounds.** The whole frame lies inside the RAM window: `RAM_ORIGIN ≤ base`
   and `base + <frame bytes> ≤ 2^31`. The upper half is its own decomposition,
   `2^31 − <frame bytes> − base` as a sum of 31 booleans (`base_in_window`). The
   emulator computes the same bound in `u64`, because `base + <frame bytes>`
   wraps a `u32` at the top of the window and a wrapped comparison passes a
   check it should fail.

Both are fatal guest errors in the emulator — `Misaligned` and `OutOfBounds`,
the same two a misaligned load raises — so an execution the emulator refuses is
one no proof could have covered.

### 4.1 The frame in the trace

Every frame word is an ordinary RAM query (`docs/spec/execution-trace.md` §3):
a read of what was there, a write of what the function computed. So:

- **The invocation rides the requesting cycle.** It is not a cycle of its own:
  its writes are at `4 · cycle + Δ` with
  `Δ = constants::delegation::FRAME_DELTA = 0`, the requesting cycle's first
  slot, and its reads carry their own read timestamps with a gap check apiece
  (§6.2). Cycle numbering, the shard plan and the clock are unchanged — an
  invocation adds no cycle.
- **The slot is 0, and it has to be.** `(RAM, 0)` is a pair no query of
  `constraints::memory`'s table holds, which is what lets `trace`'s frame
  builder recognise an invocation's events as *not this row's* and pass over
  them. A family that stamped its frame writes at Δ = 3 would land on the
  requesting family's own `ram` query, which is `(RAM, 3)`: the first frame
  event would be filed into the requesting row and the second would reach that
  builder's "no free frame query takes" panic. The **anchor** is the slot-3
  side of the ABI and is a different constant, `ANCHOR_DELTA` (§5.1).
- **All frame words share one slot.** They are distinct addresses, and
  `docs/spec/execution-trace.md` §3 already provides that distinct addresses may
  share a slot; two queries at one address never do.
- **The log order is frozen, and it is timestamp order**: the request row's pc
  query, then the invocation's frame words **in frame order**, ascending by
  word index, then the request row's roles in `ROLES` order. The frame words
  sit *between* the pc query and the roles because they ride Δ = 0 while the
  roles ride Δ = 1, 2 and 3. Nothing else reconstructs that order, so the
  emulator emits it and `TraceArchive`'s `check_parts` replays it
  (`crates/trace/src/archive.rs`).

---

## 5. The anchor

A request and an invocation must pair **one to one**. Without that the
delegation side is free: N requests could close against one real invocation and
N−1 executions would be elided, or an invocation with no request could permute a
block of guest memory the program never asked about.

The pairing rides the one global memory multiset, in the delegation family's own
address space.

### 5.1 The two sides

**The requesting row** is an ordinary ecall row of the family that owns ecall
cycles — `ADD_SUB_LUI_AUIPC`, by `program::row_kind`. It carries one extra
query, the **mirror**, at `constraints::memory::DELEG` (query id 8, the eighth
role, `Δ = 3`), whose mask is `m_deleg = m_pc · Σ_t is_deleg_t` over the type
selectors and whose address is the frame base the row read from `a0`.

**One `deleg` query serves every delegation type, and the type rides a memory
column.** The mirror's leaf must name the requested type — its `AS` term is that
type's tag — and a leaf may read no `W` column, because `W` is committed after
the memory challenges (`docs/spec/memory.md` §8, `check_memory`'s provenance
rule). The type selectors a family commits *are* witness columns, so the tag
crosses into the leaf through one more `M` column of the frame, `deleg_space` at
`M[1 + 5w]`, which the family pins with a degree-1 enforcing gate:

```text
deleg_space − Σ_t tag_t · is_deleg_t = 0        add_sub's `deleg_space_rule`
```

It is 0 on every row that requests nothing, because each `is_deleg_t` is 0
unless the row is an ecall and `is_ecall` is 0 on a padding row. A frame without
the `deleg` query does not carry the column at all, and `trace`'s frame builder
writes it from the mirror event's own address space.

Why not one query per type: a second mirror query would need a ninth
`trace::Role`, and `trace::Row::present` is a full `u8`
(`docs/spec/execution-trace.md` §7). Why not a literal: with one delegation
family the tag *was* a literal on the mask, and with three it cannot be.

**The invocation row** carries two anchor leaves beside its frame words:

```text
write (the answer)    live · T(AS_f, base, 0,           0)             + 1 − live
read  (the teardown)  live · T(AS_f, base, 4·cycle + 3, anchor_value)  + 1 − live
```

The answer is **stamped 0** — the timestamp no ordinary cycle can produce, a
cycle being numbered from 1 — and its value is the literal 0. The teardown
consumes what the request wrote back.

### 5.2 The three request-side zeroings

Gated on the mirror query's own mask, the requesting row's circuit forces
**three** things, and not two:

| # | gate | what it forces |
| --- | --- | --- |
| 1 | `deleg_writes_no_register` | `rd`'s written value is 0: a delegation request writes no register |
| 2 | `deleg_read_ts_zero` | the mirror read's **timestamp** is 0 |
| 3 | `deleg_read_value_zero` | the mirror read's **value** is 0 |

and one more that is addressing rather than a zeroing:

| | `deleg_addr_rule` | the mirror's address is `a0`'s read value, the frame base |

**Why each.** Without (1) the request writes `a0` with whatever it likes, and
the ABI's "returns 0" binds nothing. (2) is the anchor proper: lose it and the
requests **chain** — row `k`'s mirror read consumes the tuple row `k−1` wrote
back — so N requests close the permutation against one real invocation and N−1
executions are elided while the proof still verifies. (3) is the one an earlier
rebuild dropped while restoring the other two, because the headline defect named
only the timestamp: the request's read tuple must mirror the invocation's write
**on address, timestamp and value**, or the two are different tuples and never
cancel.

The mirror's *written* value is free. It is the value the invocation's teardown
consumes, and both sides are the prover's; an honest fill writes 0 on both.

**What the twins found, and what (2) therefore buys.** In *this* family the
chain above is not mountable by editing cells at all, and the reason is worth
recording for every later family. Switching an invocation off drops its **50 RAM frame
accesses** with it, so the word at `base + 4j` loses a write that the next
invocation's `read_ts` still names; repairing the anchor side does not repair
that, and repairing that means re-pointing the next invocation's 50 reads,
re-deriving its 1,600 state bits and re-running the permutation — which is
proving the execution rather than eliding it. So what refuses a dropped
invocation here is the **global multiset**, not gate (2), and
`crates/checker/tests/tamper.rs` asserts `MemoryArgument` for both of those
twins.

What (2) buys is that the pairing is **local**: a request whose mirror read is
stamped is refused by a gate on its own shard, with no appeal to the frame's
chains at all. A delegation family with a smaller frame — or one whose rows read
nothing that chains — would have nothing else to rely on, and the gate is what
makes the ABI's guarantee independent of the family. The three zeroings are
therefore asserted at **shard** level, where `Constraint` precedes
`MemoryArgument` and the gate is the answer; at block level
`verify_global_memory` runs first (`docs/spec/block-proof.md` §3) and every one
of these reads `MemoryArgument`.

### 5.3 Why the pairing is 1:1

In the delegation family's address space the only tuples are the mirrors' and
the anchors'. Split them by timestamp.

A **live** row's `4·cycle + 3` is never 0. On the request side `m_deleg = 1`
forces `m_pc = 1`, so the row's pc write is on the pc chain, which ends at the
boundary's `t_pc < 2^38` — so `4·cycle` is a small canonical integer. On the
invocation side `live = 1` puts the row's 50 frame writes on RAM chains, which
start at an init tuple at timestamp 0 and grow by `1 + gap` with each gap below
`2^38` over fewer than `2^70` steps (`docs/spec/memory.md` §4.2) — so `4·cycle`
is a small canonical integer there too.

So the reads at timestamp 0 are exactly the requests' and the writes at
timestamp 0 exactly the invocations', and the balance gives

- `#requests = #invocations`, with the two multisets of **frame bases** equal;
- and, over the nonzero-timestamp half, each invocation's
  `(base, 4·cycle + 3, anchor_value)` equal to some request's — so **every
  invocation sits at a request's base and at that request's cycle**.

That is what the frame's own chains then need. The invocation's reads consume
the last writes before `4·cycle` at each frame address and its writes are
consumed by the next reads there, so the permutation lands at the right place in
each word's history — and a base the request did not name would put it somewhere
else entirely.

Two further facts close the argument:

- **An invocation cannot self-cancel.** Its frame read at word `j` would have to
  equal its own write there, but the gap gate makes the read timestamp strictly
  below `4·cycle`. So every frame query joins a real chain.
- **A frame outside the windows cannot balance.** §4's bounds put every frame
  address in `[RAM_ORIGIN, 2^31)`, where a RAM window's rows are; an address
  below `RAM_ORIGIN` is masked out of window 0 by `V[ram_live]` and has no init
  tuple at all (`docs/spec/memory.md` §3.3).

### 5.4 What the trace level does not see

An invocation is **not a log event**. Its frame accesses are, but its two anchor
tuples are the delegation circuit's leaves, so `MemoryEventLog::self_check`
credits each request's pair and every delegation-space query balances by itself.
The trace-level check is therefore vacuous on that space **by construction**, and
says so. The 1:1 pairing is the circuit's statement and the global multiset's,
never the trace's.

For the same reason a delegation space does **not chain**: every query there
reads the answer tuple stamped 0 whatever came before, which is exactly what the
three zeroings enforce, and `AddressSpace::chains()` is where the log says so.

---

## 6. The keccak-f circuit

`constants::family::KECCAK_F`, one keccak-f[1600] permutation a row.
`constraints::keccak` is the circuit; `docs/spec/constraint-manifest.md` §12 is
its column-by-column account.

### 6.1 The columns

| subtree | columns |
| --- | --- |
| `M[0..4]` | `cycle`, `live`, `base`, `anchor_value` |
| `M[4 + 4j ..]` | frame word `j`: `addr`, `read_ts`, `read_value`, `write_value` |
| `W[0..1600]` | the input state's bits: bit `z` of lane `i` at `64i + z` |
| `W[1600..3500]` | 38 gap bits a frame read, in frame order |
| `W[3500..3529]` | `(base − RAM_ORIGIN) / 4`, 29 bits |
| `W[3529..3560]` | `2^31 − 200 − base`, 31 bits |

**One mask for the whole row.** The 50 frame words and the anchor are one
invocation: live together or not at all. `live` is the mask every leaf carries,
and the only one `check_memory` has to hold to booleanity.

There is **no setup column, no virtual table and no lookup channel** (§9).

### 6.2 The bounds

Every bound is a bit decomposition with a booleanity gate, and each is counted
on the emitted artifact rather than on the vector handed in.

| what | how |
| --- | --- |
| a frame word's value `< 2^32` | `input_w{j}` recomposes it from its own 32 input bits, so the bound and the read are one gate |
| a written word | `output_w{j}`, gated on `live`, recomposes it from the permutation's output bits |
| a read's timestamp gap `∈ [0, 2^38)` | `gap_w{j}`: `4·cycle − read_ts − 1` is a sum of 38 booleans — `FRAME_DELTA` is 0, so the constant is `−live` |
| the frame base's alignment and floor | `base_aligned` |
| the frame's ceiling | `base_in_window` |
| word `j`'s address | `addr_w{j}`: `live·(addr_j − base − 4j) = 0` |

`output_w{j}` is gated on `live` and must be: a padding row's committed cells
are zero, the circuit computes keccak-f of the zero state there, and an ungated
gate would ask the written word to be it. `live` is therefore carried to the top
beside the 50 written words — 51 columns through 168 layers, which is what a
layered circuit pays to let its last gate read a committed column.

### 6.3 The round block

Twenty-four identical blocks of seven sub-layers. Every gate is degree ≤ 2 in
the layer below; the ceiling is not negotiable and nothing here moves it.

| sub-layer | writes | gate |
| --- | --- | --- |
| 1 | `p0`, `p1` (320 each), `A` | `A[x][0] ⊕ A[x][1]`, `A[x][2] ⊕ A[x][3]` |
| 2 | `q` (320), `A` | `p0 ⊕ p1` |
| 3 | `c` (320), `A` | `q ⊕ A[x][4]` — the column parity `C[x]` |
| 4 | `u` (1600), `c` | `A[x][y] ⊕ C[x−1]` |
| 5 | `b` (1600) | `u ⊕ rot(C[x+1], 1)` — the state after theta |
| 6 | `v` (1600), `B'` (1600) | `B'[x+1][y] · B'[x+2][y]`, and `B'` itself |
| 7 | the round's output (1600) | `B' ⊕ (B'[x+2][y] − v)`, with iota folded |

- **XOR is `x + y − 2xy`**, pairwise, which is why a five-way parity takes three
  levels and why the state passes through them.
- **rho and pi are pure rewiring.** They are applied in sub-layer 6's addressing
  and cost nothing: `B'[X][Y][Z]` reads the bit at `x = 3Y + X mod 5`, `y = X`,
  `z = Z − r[x][y]`, the inverse of `B[y][2x + 3y] = rot(A[x][y], r[x][y])`.
- **chi is split in two**, which is the only way `a ⊕ (¬b & c)` fits degree 2:
  `v = b·c` at one layer, then `a + c − v − 2ac + 2av` at the next.
- **iota folds into sub-layer 7's gate.** An XOR with a constant bit is affine —
  `g ⊕ 1 = 1 − g` — so a round constant's set bits negate that lane's gate and
  give it the constant 1. No layer, no column, no gate of its own.

The permutation's two tables are `constants::keccak::{ROTATIONS,
ROUND_CONSTANTS}`, re-derived from the Keccak reference's generators by
`crates/constants/tests/keccak.rs` rather than copied.

### 6.4 The memory subtree

The frame's 50 words and the anchor give 51 leaves a side, padded to 64 with
leaves that are literally 1 — 128 columns at layer 1, reduced pairwise over six
row-wise lists to the two roots, then carried to the halving phase. The output
map is `[read_root, write_root]` and nothing else, `constants::memory::READ_ROOT`
and `WRITE_ROOT` (`docs/spec/memory.md` §1).

---

## 7. Static detachment

**A delegation family is in a `VmConfig` exactly when the linked binary declares
it.** Not a build flag, not a caller's argument, not a heuristic over the
instruction stream — that stream cannot say: the ecall number is a run-time `a7`
value and no instruction word carries it.

The declaration is a **record the shim itself emits**:

```text
MARKER_MAGIC (8 bytes, "APOGDEL1")  ‖  the declared ecall number (u32, little-endian)
```

`constants::delegation::{MARKER_MAGIC, MARKER_BYTES}`. The guest SDK places one
per delegation shim in an **allocated** `.rodata` section, so:

- it is kept exactly when the shim is reachable, and dropped when it is not —
  which is **reachability**, not `#[used]`: the guests pin `codegen-units = 1`,
  so the SDK is one object file, and a `#[used]` record would be in every guest
  that links the SDK at all;
- `crates/loader` carries it into the image as an ordinary file-backed byte,
  with no loader change and no widening of `ProgramImage`'s S10-frozen shape;
- program identity already binds it, through the image column
  (`docs/spec/memory.md` §6.2), so a declaration cannot be altered without
  moving identity.

The shim reads its own ecall number **out of the record**, through
`core::hint::black_box`, and that is what makes the record load-bearing rather
than decorative: a shim that exists has a record, the number it calls is the
number the record declares, and at `opt-level = 3` the optimiser cannot fold
the read into an immediate and leave the record unreferenced.

Both halves are tested in `crates/program/tests/delegation.rs`, by two tests of
different reach: `every_guest_declares_exactly_what_it_links` covers **every**
committed guest at the committed profile, and
`reachability_survives_the_optimiser` covers `keccak-test` and `fib` at **both**
optimisation levels, which is the half `#[used]` would break. What decides it is
**reachability, not execution**: `guests/keccak-unused` never runs its call and
declares `KECCAK_F` all the same, because the linker can see the call and cannot
know the branch is dead. A guest that never names `keccak256` declares
nothing.

`program::declared_delegations(image)` is the scan — over the image's
file-backed bytes, **at every byte offset**, in address order. Byte-wise and not
word-wise because a `static`'s address is the linker's: a record that happened
to land off a word boundary would be a declaration silently lost, and a build
that proves nothing is worse than one that fails. A record naming a number no
delegation family answers is `ProgramError::UnknownDelegation`, loud, because it
means the guest and the preprocessor disagree about the ABI. A number declared
twice is one declaration.

A guest that *deliberately* embedded the magic would declare a family it does not
use, which costs it a family in its own `VmConfig` and its own identity and
nothing else. The failure that matters is the other one — calling a delegation
without declaring it — and that is the fatal `DelegationFamilyAbsent`.

**A guest that links a shim but never calls it** declares the family, derives a
`VmConfig` holding it, and proves **zero** shards of it: `plan_shards`' `ceil(0 /
height)` is 0 with no code anywhere. A guest that links no shim derives a family
set without it, and identity, the statement descriptor and the shard list are as
if the family did not exist.

**An executed delegation ecall whose family the `VmConfig` lacks** is the fatal
`EmuError::DelegationFamilyAbsent`, raised by `trace_run` — the only path that
has a `VmConfig` — before any trace is returned.

---

## 8. Shards, the ts window, and the block

A delegation family appends to `constants::family::CYCLE_OWNING` as **`false`**.
That one constant is the whole of its treatment in a block:

- `verifier_core::check_ts_windows` skips every family whose flag is false
  (`docs/spec/block-proof.md` §4), so a delegation family's shard windows are
  asked for **no emptiness and no disjointness**. They could not be given one:
  cycle numbers are global, invocations interleave with the cycles that request
  them, and two delegation shards of one execution are consecutive *invocations*,
  not consecutive *times*.
- The window a delegation shard claims is read off its own `M[0]`:
  `[4·cycle(row 0), 4·max cycle + 4)` — the same expression `prover::ts_window`
  uses for a cycle-owning family, over the same column, and it spans the
  requesting cycles of the invocations the shard holds. **Row 0 and the
  maximum, not the first and last rows**: a delegation shard is `2^8` rows and
  holds only as many invocations as the execution made, so its tail is padding
  and padding carries cycle 0. Reading the last row would put the end below the
  start, which step 4 of `verify_shard` refuses. It is
  three-way since S21: trivial for a RAM window family, and this for the other
  two kinds. The window is a claim about *when the requests were*, since an
  invocation carries its requesting cycle and nothing of its own.
- Step 4 of `verify_shard` still holds `start ≤ end ≤ 2^38`, as it does for every
  shard.

**No gate ties a claimed window to the rows committed under it**, here or
anywhere: S20 removed that obligation deliberately (`docs/spec/block-proof.md`
§4.1), because the global memory multiset already forces every live row onto one
consistent history. A delegation shard is no different — what places an
invocation in time is its frame words' chains and its anchor, not its window.

Statement order is unchanged: `statement_shards` lists `INIT_TEARDOWN`, then
`ZERO_WINDOWS`, then every other family ascending, so a delegation family's
shards sort last. `verify_block` needs no edit at all.

---

## 9. The height, and why there is no lookup channel

`KECCAK_F` takes **`2^8`**, added to `constants::family::HEIGHT_MENU` at S21.
One row is a whole permutation, and a whole permutation is **354,762 inner
columns** over 177 layers (`docs/spec/constraint-manifest.md` §12.7);
`gkr::forward` materializes every layer at the full height, so a shard's forward
pass is that count times its height times 32 bytes:

| height | forward pass | permutations a shard |
| --- | --- | --- |
| `2^8` | 2.9 GB | 256 |
| `2^10` | 11.6 GB | 1,024 |
| `2^12` | 46.5 GB | 4,096 |
| `2^16` | 744 GB | 65,536 |

`2^8` is also **even**, which Mercury needs for `b = sqrt(2^n)` to exist, so the
menu below `2^16` had `2^8`, `2^10`, `2^12` and `2^14` to choose from.

At `2^8` **no range channel's table fits**: `V[range16]` over 8 variables holds
`[0, 2^8)`, not `[0, 2^16)`, and `lookup::channel_trees` refuses a channel whose
bound exceeds the circuit's variables (`docs/spec/lookup.md` §3). So the family
carries **no channel at all**, and every bound of §6.2 is a bit decomposition
with a booleanity gate.

That is a deviation from `docs/spec/memory.md` §7's 19+19 timestamp-gap gadget,
and it is deliberate: the gadget's statement is `gap ∈ [0, 2^38)`, and 38
booleans say the same thing without a table. It costs 1,900 committed columns —
bits, in a circuit that is already 1,600 bits wide — and it removes the failure
`constants::family::DEFAULT_HEIGHTS` warns about, a family reaching a channel
assertion inside `VerifyingKey::check` on bytes a verifier was handed.

**A delegation family must therefore be absent from `family_circuit`'s
minimum-height arm, and must carry no lookup channel.** The two go together: a
family with a channel needs that channel's height, and at that height its
permutation does not fit.

---

## 10. What a later delegation family may append

Everything above is frozen. A later delegation family appends, and appends only:

1. a row to §3's registry — its family id, its ecall number, its frame width and
   its address-space tag, each taking the next value;
2. a **frame table** of its own, in the shape of §4: the word count, what word
   `j` holds, and the byte order. §4's two frame rules and §4.1's trace rules
   are not its to restate or change;
3. its circuit, its fill, its shim and its declaration record.

The **anchor is not appendable**: §5's two leaves, three zeroings and addressing
rule are the same for every delegation family, and a family that wrote its own
would be a family whose pairing nobody had argued. What varies with the type is
the address-space tag, and nothing else.

The request-side gates are `ADD_SUB_LUI_AUIPC`'s and grow by one selector and
three gates per delegation type — `is_deleg_t`'s booleanity, the gate making it
an ecall's, and the gate pinning `a7` to that type's number — while
`deleg_mask_rule`, `deleg_space_rule`, `ecall_is_exit`, `exit_status` and
`next_pc_rule` each gain one term per type on an existing product's *other*
factor. Every one of them stays degree 2. That is the one place a new delegation
type touches an existing family's circuit.

### 10.1 What S23 amended, and why

S21 wrote this rule as "its leaf's `AS` term is the sum over types of
`(tag_t, m_t)`". **That is not implementable**: a leaf carries `γ_M` and the
three `α`s, so `check_memory`'s provenance rule refuses it the moment it reads a
`W` column, and a type selector is one. The repair is §5.1's `deleg_space`
column — a memory column the family pins to its witness selectors — and it costs
one `M` column on the one frame that holds the `deleg` query. Nothing else in §5
moved: the two leaves, the three zeroings, the addressing rule and §5.3's
argument are S21's unchanged, and the keccak circuit's bytes did not move at
all.

---

## 11. What this does not do

- **It does not bind a delegation's result to anything but memory.** The circuit
  proves the frame after equals the function of the frame before; that the guest
  then reads the frame is the guest's business, and the RAM chain's.
- **It does not give the trace level a pairing check.** §5.4.
- **It does not make a delegation shard's window mean anything.** §8.
- **It does not delegate the sponge.** `guest_sdk::keccak256` runs its padding
  and its rate absorption in guest code and delegates one ecall per keccak-f
  block. The delegated path and the software fallback are bit-identical, which
  `crates/emulator/tests/guests.rs` and `crates/loader/tests/qemu.rs` hold over
  `guests/keccak-test`'s six digests — themselves re-derived from `tiny-keccak`
  rather than restated — and the fallback is what runs under `qemu-riscv32`.
- **It does not change the proof's shape.** A delegation `ShardProof` is a
  `ShardProof`, and `verify_shard`, `verify_block`, `PublicInputs` and
  `VerifyingKey` are S16's and S20's unchanged.

---

## 12. The Poseidon2 circuit

`constants::family::POSEIDON2`, one width-3 Poseidon2 permutation a row.
`constraints::poseidon2` is the circuit; `docs/spec/constraint-manifest.md` §13
is its column-by-column account.

The function is `transcript::poseidon2_permute` — the same 4 + 56 + 4 rounds,
the same `x^5` S-box, the same external and internal matrices and the *same*
round constants, read from `constants::POSEIDON2_RC3_*` with no second copy.
`docs/spec/transcript.md` is that function's page, and this one restates none
of it.

### 12.1 The frame

24 words: three lanes of eight, read and written in place.

| words | what |
| --- | --- |
| `0..8` | lane 0, canonical little-endian `Fr` |
| `8..16` | lane 1 |
| `16..24` | lane 2 |

**Canonical, in the mathematical sense**: the 32 bytes of lane `i` are
`Fr::to_bytes` of its value, and the circuit's canonicity gates (§13.3's pattern)
refuse any encoding at or above the modulus. That is the opposite of the
Fr-arithmetic frame's choice (§13.2) and deliberately so: here the conversion
costs six Montgomery operations against 240 the delegation removes, and it buys
a circuit that is `poseidon2_permute` itself rather than `poseidon2_permute`
conjugated by a scaling.

### 12.2 The columns

| subtree | columns |
| --- | --- |
| `M[0..4]` | `cycle`, `live`, `base`, `anchor_value` |
| `M[4 + 4j ..]` | frame word `j`: `addr`, `read_ts`, `read_value`, `write_value` |
| `W[0..912]` | 38 gap bits a frame read, in frame order |
| `W[912..941]` | `(base − RAM_ORIGIN) / 4`, 29 bits |
| `W[941..972]` | `2^31 − 96 − base`, 31 bits |
| `W[972..4092]` | six values' bits: the three lanes in, then the three out, each 256 word bits then 264 canonicity bits |

No setup column, no virtual table and no lookup channel (§9).

### 12.3 The round block

Sixty-four identical blocks of **three** sub-layers, the same three whether the
round is full or partial:

| sub-layer | writes | gate |
| --- | --- | --- |
| 1 | `q_i = (state_i + c_i)^2`, and `t_i = state_i + c_i` | the round constant folds into both |
| 2 | `q2_i = q_i · q_i`, `t_i` carried | |
| 3 | the linear layer over `v_i = q2_i · t_i` | the matrix folds into the products' coefficients |

`x^5 = x^4 · x` needs `x^4`, and `x^4 = (x^2)^2` needs `x^2`: two
multiplication layers per S-box, which is the degree ceiling's price and not a
choice. The constant add and both matrices are degree 1 and fold into a
neighbour, so a round costs three gate lists and no more. A partial round
S-boxes lane 0 alone and carries lanes 1 and 2 through the first two
sub-layers.

The initial `external_matrix` — the one before round 1 — folds into round 0's
first square, so it costs no layer of its own.

**`x^2` is computed, not committed.** A committed helper is readable by gate
list 0 alone (`docs/spec/gkr.md` §2), so the 80 of them would have to be
carried up through every layer that had not consumed them yet: 5,040
pass-through columns against 736 of actual work. Computing it costs one more
gate list a round and nothing else, and it is *stronger* — a layer value is
forced by its gate, where a committed one would need an enforcing gate to be
forced at all.

### 12.4 The output

The permutation's three final lanes are compared with the three the invocation
*wrote*, at the last gate list, gated on `live`:

```text
live · (final_j − Σ_k 2^{32k}·write_value(8j + k)) = 0        `out_lane{j}`
```

Gated, and it must be: a padding row's committed cells are zero, the circuit
still computes the permutation of the zero state there, and an ungated gate
would demand the written lane equal it. `live` and the three recomposed written
lanes are therefore carried to the top — four columns through 192 layers, which
is what a layered circuit pays to let its last gate read a committed column.

---

## 13. The Fr-arithmetic circuit

`constants::family::FR_ARITH`, **one `Fr` operation a row**.
`constraints::fr_arith` is the circuit; `docs/spec/constraint-manifest.md` §14
is its column-by-column account.

### 13.1 The frame, and one operation an invocation

25 words.

| words | what |
| --- | --- |
| `0` | the operation code: 1 add, 2 multiply, 3 inverse |
| `1..9` | operand `a` |
| `9..17` | operand `b` |
| `17..25` | the result, the only words the invocation computes |

**One invocation is one operation and one row.** `ops/row = 1` is the cost model
the recursion guest's contraction is sized against, and it is also what the
anchor forces: §5's two leaves are the *row's*, so an invocation spanning
several rows would write several answer tuples against one mirror read and the
honest prover would be refused. A batch would have to be several operations in
one row, and it would buy nothing — the circuit's cost is per operation either
way, and the guest's marshalling, which dominates, does not amortize. The
delegated backend of §13.4 makes one-operation calls in any case: `Mul` has one
multiplication in it.

The words the invocation does not compute are written back unchanged, so the
guest's operands survive the call.

### 13.2 The encoding, and why it is not the mathematical value

The three values cross the frame in **`field::Fr`'s in-memory representation** —
the four Montgomery limbs written little-endian, which `Fr::to_memory_bytes`
writes. Each 32-byte group is still a canonical little-endian encoding of a
field element, and §13.3's gates refuse one at or above the modulus; it is just
that the element it encodes is `x·R` rather than `x`, where `R = 2^256 mod p`.

That is the whole reason the delegation is worth making. A mathematically
canonical frame would cost a Montgomery conversion per operand — `to_bytes` is
a Montgomery reduction and `from_bytes` a Montgomery multiply — which is about
twice the software multiply the delegation replaces, so a delegated multiply
would be *slower* than not delegating at all.

The three operations are therefore exactly what `Fr`'s own `Add`, `Mul` and
`inverse` compute on those representatives:

```text
add   out = a + b
mul   out = a·b·R^-1          which is what one Montgomery multiply is
inv   out = R^2·a^-1, and 0 at a = 0
```

`R^-1` and `R^2` are literals the circuit derives from `constants::FR_R` rather
than restating. `inverse(0) = 0` is this delegation's convention where `Fr`'s is
`None`; the two are reconciled in the backend, which answers `None` itself and
never makes the call.

### 13.3 The gates

Over the three values `a`, `b`, `out` recomposed from their frame words:

| gate | what |
| --- | --- |
| `<v>_word{k}` | word `k` is `Σ 2^t·bit`, which is its 32-bit bound and its decode at once |
| `<v>_canonical{i}` | `w_i − p_i − b_{i−1} + 2^32·b_i = d_i`, the borrow chain of `X − p` over eight 32-bit limbs |
| `<v>_below_modulus` | `b_7 = live`: the subtraction borrowed out, so `X < p` |
| `opcode_rule` | the opcode word is `1·f_add + 2·f_mul + 3·f_inv` |
| `one_op_a_live_row` | `f_add + f_mul + f_inv = live` |
| `prod_rule` | `prod = a·b`, ungated |
| `inv_is_an_inverse` | `a·inv + z − f_inv = 0` |
| `is_zero_at_nonzero` | `a·z = 0` |
| `inverse_of_zero_is_zero` | `z·inv = 0` |
| `out_rule` | `out = f_add·(a + b) + R^-1·f_mul·prod + R^2·f_inv·inv` |

Four of those deserve a sentence.

**Canonicity is a borrow chain, not a comparison.** Every term of a limb
equation is a small integer in a range far below `p`, so the `Fr` equation *is*
the integer equation; the eight of them telescope to `X − p + 2^256·b_7 = D`
with `D` below `2^256`, and `b_7 = 1` puts `X` below `p`. Without it a frame
value would have several encodings and the delegated path and the software
fallback would disagree on which.

**`one_op_a_live_row` is load-bearing and the opcode does not replace it.** The
codes are 1, 2 and 3, so `add + mul` spells the same opcode word as `inv`: on
an inverse row a prover may set `f_add` and `f_mul` instead and `opcode_rule`
still holds. Exactly one selector a live row is the only thing that refuses it.

**The product helper is what buys the degree.** `f_mul·a·b` is degree 3, so the
product is pinned by an ungated gate of its own and the selected relation reads
it.

**The inverse needs three gates, not two.** `a·inv + z = f_inv` alone lets a
prover set `z = 1` at `a ≠ 0` and prove `inv(a) = 0`; `a·z = 0` fixes that and
still leaves `inv` free at `a = 0`, so "inverse(0) = 0" would be prose. `z·inv =
0` is the third, and it is what makes the convention a constraint.

### 13.4 The guest-target backend

`field` and `transcript` route their own operations through the two
delegations when compiled for `riscv32`, and fall back to their own software
path on `-ENOSYS`:

| crate | what routes | to |
| --- | --- | --- |
| `field` | `add_limbs`, `mont_mul`, `Fr::inverse` | `guest_sdk::recursion::fr_arith` |
| `transcript` | `poseidon2_permute` | `guest_sdk::recursion::poseidon2` |

Selected by `#[cfg(target_arch = "riscv32")]` and a **target dependency** on
`guest-sdk` — not a cargo feature, which the master's anti-goal 1 bans and
`crates/prover/tests/one_feature.rs` enforces. The direction is forced: cargo
refuses a dependency cycle, so `guest-sdk` may not name `Fr` and its shims take
frames of bytes.

Two consequences worth stating.

- **The fallback is bit-identical by construction.** It is not a second
  implementation held equal by a test; it is the same function, one branch
  below the ecall.
- **A guest that does field arithmetic declares both families**, because the
  shims are reachable from `Fr`'s operators. That is the seam working: a guest
  doing field work is a guest whose proof needs those circuits.
