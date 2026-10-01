# Delegation: the ABI, the anchor, and the six delegation families

Frozen as of S21, **appended to at S23**, which added two families under §10's
rule and amended §3 and §5.1 where more than one delegation type made a literal
impossible (§10.1), and **amended at S26b**, which specialized §14's family to
four fixed moduli and moved its ecall number (§10.2). **This page is the
delegation ABI** — every delegation family obeys it. Changing anything here but
by §10's append rule is a protocol-version change, and §10.1 and §10.2 are the
two that have been made.

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
| `crates/constraints` | `delegation`, the shared frame; `keccak`, `poseidon2`, `fr_arith` and `mod_mul`, the circuits; `add_sub`, the request-side gates |
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
software path — `docs/spec/ecall-abi.md` §5's convention. An executor **with** the
circuit answers 0. A shim treats exactly `-ENOSYS` as "run the software path" and
every other nonzero as a hard `exit(72)`.

**This VM implements all four, so its executor never answers `-ENOSYS` to one**, and
the fallback is a rule of the ABI rather than a path taken here. It is what makes a
delegation *optional*: an executor may register any subset of the families and a guest
compiled against the full set still runs, which is why the number is a delegation and
not a new instruction. The obligation it puts on a caller is real either way — a shim
with no software path behind it turns a missing circuit into a wrong answer instead of
a slower one — and §14.1 is where choosing that path shapes a caller's design.

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
| `KECCAK_F` | 9 | `PRECOMPILE_KECCAK_F` = `0x0507` | 51 | `DELEGATION_KECCAK_F` = 4 |
| `POSEIDON2` | 10 | `PRECOMPILE_POSEIDON2` = `0x0500` | 24 | `DELEGATION_POSEIDON2` = 5 |
| `FR_ARITH` | 11 | `PRECOMPILE_FR_ARITH` = `0x0502` | 25 | `DELEGATION_FR_ARITH` = 6 |
| `MOD_MUL` | 15 | `PRECOMPILE_MOD_MUL` = `0x0504` | 25 | `DELEGATION_MOD_MUL` = 7 |
| `SHA256_COMP` | 16 | `PRECOMPILE_SHA256_COMP` = `0x0505` | 24 | `DELEGATION_SHA256_COMP` = 8 |
| `EC_ADD` | 17 | `PRECOMPILE_EC_ADD` = `0x0506` | 97 | `DELEGATION_EC_ADD` = 9 |

`0x0500` was assigned at S10 with a calling convention and no circuit; S23 gave
it one. The numbers are not in family-id order and need not be: a family id
orders the statement, an ecall number names the call, and this table is what
ties them together. `MOD_MUL`'s id is 15 and not 12 because S-IO took 12, 13 and
14 for its window families in between, which is what append-only means.

`MOD_MUL`'s **number** is `0x0504` and not `0x0503` for the same rule read the
other way. S26 gave it `0x0503` over a 32-word frame carrying a witnessed
modulus; S26b made the frame 25 words with a selector, which is a different
call, so `0x0503` is **retired and burned** — an old binary issuing it would
have its modulus read as a selector and every later word misread, with nothing
failing loudly, which is exactly what append-only exists to prevent.
`constants::ecall::RETIRED_MOD_MUL_WITNESSED_MODULUS` keeps the number so a
test can hold it to being unanswered, and `docs/spec/ecall-abi.md` §4 is the
retired table. **The family id and the address-space tag did not move**: the
family is the same family, refactored.

`KECCAK_F`'s number is `0x0507` and not `0x0501` for the third reading of the
same rule. S21 gave it `0x0501` over a 50-word frame holding the state and
nothing else, and one call performed a **whole permutation**; S26d made one call
one **round**, which is a 51-word frame whose word 0 is the round (§6.1). An old
binary issuing `0x0501` under the new executor would have its first state word
read as a round selector and get one round of a permuted state back, with nothing
failing loudly — so `0x0501` is **retired and burned**,
`constants::ecall::RETIRED_KECCAK_F_WHOLE_PERMUTATION` keeps it, and the
re-shaped call took the next free number. The family id, the address-space tag
and the byte order of the state did not move.

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

`constants::family::KECCAK_F`, **one Keccak round a row**. `constraints::keccak`
is the circuit; `docs/spec/constraint-manifest.md` §12 is its column-by-column
account.

**This section was re-shaped at S26d** and §10.4 records what moved and why. S21
made one row a whole keccak-f[1600] permutation: 1,600 boolean state columns, 24
seven-layer round blocks, 354,762 inner columns over 177 layers. All 24 rounds
and all 1,600 bits coexisted horizontally, which fixed the family at `2^8` — 256
permutations a shard — and made five keccak shards **97% of a measured
mini-block's proof bytes** (§9.1).

One round a row is the other trade, and it is the same one `EC_ADD` makes: a
computation too wide for one row is decomposed into several rows and **RAM is the
glue**. A permutation is 24 consecutive invocations, the frame is ordinary RAM,
and the global memory multiset is what proves round `r`'s written state is round
`r + 1`'s read state (§6.4). There is no second cross-row mechanism.

### 6.0 What one round costs, and what it buys

| | S21, a permutation a row | S26d, a round a row |
| --- | --- | --- |
| height | `2^8` | `2^18` |
| committed columns | 3,764 | 1,764 |
| inner columns | 354,762 | 5,490 |
| layers | 177 | 29 |
| artifact wire bytes | 100,254,040 | 1,900,468 |
| permutations a shard | 256 | 10,922 |
| forward pass a shard | 2.9 GB | ~60 GB |
| **proof bytes a shard** | **11,880,012** | **381,100** |
| **proof bytes a permutation** | **46,406** | **34.9** |

The last row is the point: **1,330 times fewer proof bytes for the same work**,
from 31.2× the shard and 42.7× the permutations in it.

The right column is `2^18`, one menu entry above the floor this family's two
channels imply and not the `2^16` the re-shape first made reachable, and §9.2 is
why: a shard's proof is a function of its circuit's width and depth and barely of
its rows — 381,100 bytes against 373,276 at `2^16` — so the fatter shard is the
cheaper proof. That column's two proof-byte rows are **derived**, not measured:
`crates/prover/tests/keccak.rs`' `proof_bytes` is a closed form over the artifact
and it reproduces the measured 373,276 at `2^16` exactly, which is what licenses
reading it forward.

**What the guest pays, measured.** 24 ecalls and 24 stores of the round word a
permutation instead of one ecall. At `--release`, `guest_sdk::keccak256` over
`guests/keccak-test`'s corpus is **1,681.5 cycles a call** — six calls, ten
permutations, so about 1,009 cycles a permutation for the whole sponge — and the
loop's own share of that is roughly 145 cycles more than S21's single call. At
`opt-level = 0` it is four times worse: the committed debug ELF is **193,156
cycles against S21's 154,708** for the same program, so +38,448 for ten
permutations, because the shim is a real call with a stack frame per round rather
than five inlined instructions. The workload that matters — `guests/revm-block` —
is proven at `--release` for the reason `docs/spec/revm-block.md` gives, and there
the trade is ~145 cycles against thousands of proof bytes a permutation.

**There is no bit anywhere in this circuit** but the structural selectors. The
committed unit is a **byte**, and every Boolean operation of the round is one
obligation on the `XOR8` channel — a virtual table of the 65,536 triples
`(a, b, a ^ b)` (`docs/spec/lookup.md` §14). Everything else follows from the two
identities

```text
a & b   = (a + b − (a ^ b)) / 2          (¬a) & b = (b − a + (a ^ b)) / 2
```

which are *linear forms* over the obligation's result, so `AND` and `ANDN` cost
no obligation of their own; and from the observation that masking a byte's top
`s` bits is one XOR against a **literal**, which makes a rotation a
literal-weighted combination of a byte and its masked copy (§6.3).

So the circuit is **flat**, like `MOD_MUL`'s and `EC_ADD`'s: every relation is an
obligation or a degree-≤2 enforcing gate over base columns, no relation produces
an inner column, and the only inner columns in the artifact are the two memory
product trees, the two channels' fraction trees and the halving phase.

### 6.1 The frame and the columns

The frame is **51 words, 204 bytes**. Word 0 is the round; the state follows in
SHA-3 byte order, lane `A[x][y]` at `i = 5y + x` occupying state words `2i` and
`2i + 1`, low half first.

| word | holds | read | written |
| --- | --- | --- | --- |
| 0 | the round, in `0..24` | yes | unchanged |
| `1 + 2i` | lane `i`'s low half | yes | the round's output |
| `1 + 2i + 1` | lane `i`'s high half | yes | the round's output |

The round word is written back **unchanged**, and the guest's own proven loop is
what advances it. The alternative — the circuit writing `round + 1` — would save
the guest one store a round and would have it write 24, a value no round claims,
into a frame the next permutation must reset anyway.

| subtree | columns |
| --- | --- |
| `M[0..4]` | `cycle`, `live`, `base`, `anchor_value` |
| `M[4 + 4j ..]` | frame word `j`: `addr`, `read_ts`, `read_value`, `write_value` |
| `W[0..102]` | two `RANGE16` gap chunks a frame read, in frame order |
| `W[102..106]` | `base_low`, `base_low_hi`, `base_room`, `base_room_hi` |
| `W[106..130]` | `round_sel`, 24 one-hot round selectors |
| `W[130..134]` | `rc`, the round constant's four nonzero bytes |
| `W[134..334]` | `state_in`, the input state: 25 lanes of 8 bytes |
| `W[334..494]` | `parity`, theta's five-fold XOR, four steps a byte |
| `W[494..534]` | `c_mask`, `C ^ 0x80` |
| `W[534..574]` | `theta_d`, `D[x]` |
| `W[574..774]` | `theta_a`, `A' = A ^ D` |
| `W[774..950]` | `rho_mask`, `A' ^ mask(s)` for the 22 lanes rho splits |
| `W[950..1150]` | `rho_out`, `B`, the state after rho and pi |
| `W[1150..1350]` | `chi_and`, `B1 ^ B2` |
| `W[1350..1550]` | `chi_out`, chi's output |
| `W[1550..1554]` | `iota_out`, lane `(0,0)`'s four bytes after iota |
| `W[1554..1556]` | the `RANGE16` and `XOR8` multiplicity columns |

**One mask for the whole row.** The 51 frame words and the anchor are one
invocation: live together or not at all. `live` is the mask every leaf carries,
and the only one `check_memory` has to hold to booleanity.

There is **no setup column**, so nothing here needs binding: both channels' tables
are closed forms of the row index and cost no commitment and no movement of the
SRS digest.

### 6.2 The gates

Three hundred and eighty-five enforcing gates, all on gate list 0, all degree ≤ 2.

| what | how |
| --- | --- |
| a state word's value `< 2^32`, and its bytes | `input_w{j}`: `read_value = Σ 2^{8m}·byte`, one gate a word. **Ungated and degree 1** — both sides are 0 on the all-zero padding row — and it is the word's decode *and* its 32-bit bound at once, the bytes being bounded by the obligations that read them. No frame word of this family carries a `bound32` pair, where every one of `EC_ADD`'s does |
| a written state word | `output_w{j}`: the same, over the round's output bytes. Ungated for the same reason, which S21's could not be: there the output was computed through 168 layers from committed bits, so a padding row's gate would have asked the written word to be keccak-f of the zero state |
| the round word surviving the call | `writes_back_w0` |
| the round | `round_rule`: `read_value(0) = Σ r·round_sel[r]` |
| one round a live row | `one_round_a_live_row`: `Σ round_sel[r] = live`, plus a booleanity gate each |
| the round constant | `rc{t}_rule`: `rc[t] = Σ ROUND_CONSTANTS[r]'s byte · round_sel[r]` |
| rho and pi | `rho_pi_l{i}_b{j}`, one gate a byte: `B = 2^{s−1}·(A' + m) + 2^{s−9}·(A' − m)` over the two bytes the rotation reads, with the constant riding `live` |
| a read's timestamp gap `∈ [0, 2^38)` | four `RANGE16` obligations, §10.3's shape. **There is no `gap_w{j}` gate** |
| the frame base's alignment and floor | `base_aligned` |
| the frame's ceiling | `base_in_window` |
| word `j`'s address | `addr_w{j}`: `live·(addr_j − base − 4j) = 0` |

**`one_round_a_live_row` is load-bearing and not decorative**, for
`mod_mul::one_modulus_a_live_row`'s reason at its sharpest: the codes here are
`0..24`, so **every** pair sums to another round's word — `1 + 2 = 3` — and
without it a row could claim two rounds, satisfy `round_rule`, and XOR two round
constants into lane `(0,0)`.

Every value in the round is therefore bounded, and the argument is one sentence:
**membership of a three-wide `XOR8` tuple bounds each of its three positions to
`[0, 256)` individually**. Input bytes are bounded because the `theta_a`
obligation reads each at position 1; every stage's output because the obligation
that writes it reads it at position 2; and the derived forms — `rotC`, `B`,
`ANDN` — because they are integer combinations of bounded values whose maximum is
255. A packed key `a + 256·b` would be one column cheaper a lookup and would
bound neither operand on its own.

### 6.3 The round, as obligations

`θ → ρ → π → χ → ι` directly, 1,020 obligations, not one of them a bit.

| step | obligations | shape |
| --- | --- | --- |
| θ, `C[x]` | 160 | four XORs a byte fold five lanes: `parity[x][b][s]` |
| θ, `C ^ 0x80` | 40 | one XOR against the literal `0x80`, which gives `C & 0x80` and so `ROTL(C, 1)` |
| θ, `D[x]` | 40 | `C[x−1] ^ ROTL(C[x+1], 1)`, the rotation a linear form at position 0 |
| θ, `A'` | 200 | `A[i] ^ D[i mod 5]` |
| ρ | 176 | one XOR against the literal `mask(s)` per byte of each of the 22 lanes whose rotation is not a whole number of bytes |
| χ, `B1 ^ B2` | 200 | the helper from which `(¬B1) & B2` is linear |
| χ, the output | 200 | `B0 ^ ((¬B1) & B2)`, the `ANDN` a linear form at position 0 |
| ι | 4 | `chi_out[0] ^ rc`, on the four byte positions a round constant can reach |

**The rotation, written out.** For `r = 8q + s` with `0 < s < 8`, byte `j` of
`ROTL64(v, r)` is `2^s·lo(v[u]) + hi(v[w])` with `u = (j − q) mod 8`,
`w = (j − q − 1) mod 8`, `hi(x) = x >> (8 − s)` and `lo(x) = x − 2^{8−s}·hi(x)`.
With `m = v ^ mask(s)` the obligation pins, `v & mask(s) = (v + mask − m)/2`, so

```text
hi(v) = (v + mask − m) / 2^{9−s}        lo(v) = (v − mask + m) / 2
byte  = 2^{s−1}·(v[u] + m[u]) + 2^{s−9}·(v[w] − m[w]) + mask·(2^{s−9} − 2^{s−1})
```

Every weight is a literal `Fr`; `2^{s−9}` is the inverse of `2^{9−s}`, and it is
**exact** rather than an approximation because `m` is the true XOR, so
`v & mask(s)` is a genuine multiple of `2^{8−s}`. At `s = 0` the rotation is a
byte permutation and `m` is never read — which is why 3 of the 25 lanes need no
mask columns and the `rho_mask` block is 22 lanes wide, the one place this
circuit's blocks are not 25.

**`ι` touches four byte positions and no more.** Keccak's round constants set
only the bits `2^j − 1` for `j` in `0..7` — bits 0, 1, 3, 7, 15, 31 and 63 — so a
constant's little-endian bytes are zero everywhere but at positions 0, 1, 3 and 7.
`constants::keccak::IOTA_BYTES` is that list and
`IOTA_BYTES_ARE_THE_ONLY_ONES` asserts it at compile time.

### 6.4 The cross-row glue

**The frame is ordinary RAM, and that is the whole mechanism.** Round `r` writes
the 50 state words at `4·cycle_r + FRAME_DELTA`; round `r + 1` reads them at the
same 50 addresses and its `read_ts` names that write. Both tuples are in the one
global multiset, so they cancel only if the values agree — which is the same
argument `EC_ADD`'s group 0 and group 2 rely on for the six words they pass
(§16.2), and it needs no column, no tag and no bus.

What makes 24 such rows a keccak-f rather than 24 unrelated rounds is the
**guest's own proven code**: `guest_sdk::keccak256` runs `for round in 0..24 {
frame.round = round; ecall }`, and every instruction of that loop is proven by
the execution families like any other guest computation. The delegation's job is
one round; the loop's job is that there are 24 of them with the right indices,
and `round_rule` is what ties each row's arithmetic to the number the loop
stored.

A **send/receive bus** keyed by `(invocation, round)` would be unsound here for
§16.2's reason: the multiset has no way to say two tuples belong to one
invocation without a column the anchor's provenance rules refuse.

### 6.5 The memory subtree, and the number to watch

The frame's 51 words and the anchor give 52 leaves a side, padded to 64 with
leaves that are literally 1 — 128 columns at layer 1, reduced pairwise over six
row-wise lists to the two roots. The output map is
`[read_root, write_root, range16_num, range16_den, xor8_num, xor8_den]`: the two
memory roots, then a `(num, den)` pair per channel in `channels()` order, which
is ascending by channel id — so `RANGE16` (1) before `XOR8` (4).

**1,020 is three short of a cliff, and it is the number to watch.** A LogUp
fraction tree has `(lookups + 1).next_power_of_two()` leaves, so 1,020
obligations give 1,024 and 1,024 would give 2,048 — 4,096 more inner columns and
another **34.4 GB** a shard at `2^18` — more than half again on the family that
already sets a block's peak, 59.6 GB to 93.9 (§9.2). That is why `ι` is four obligations and not
eight, and it is recorded here because a later change that adds four obligations
to this circuit doubles its tree. `constraints::keccak::check_shape` asserts both
the count and the cliff.

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

## 9. The height, and the one lookup channel a delegation family may carry

**Each delegation family takes its own height, and the six do not share one.**
`POSEIDON2`, `FR_ARITH` and `SHA256_COMP` take `2^8`; `MOD_MUL` and `EC_ADD` take
`2^16`; `KECCAK_F` takes `2^18` (§9.1, §9.2). A height is a *ceiling* derived from
one family's width and a *floor* derived from its channels, never a rule about
delegation — and, since S26d, it may also be a deliberate step *above* that floor,
four times the rows for a quarter the proof bytes a permutation (§9.2).

**This section said "and why there is no lookup channel" until S26c, and §10.3 is
the amendment.** A family at `2^16` **or above** may carry `RANGE16`, and since
S26d one also carries `XOR8`. What did not change is the reason the original rule
existed: a family at `2^8` can carry no channel at all, and no family at any
height the menu offers below `2^20` can carry `TIMESTAMP`.

What follows is `KECCAK_F`'s original argument, which is what put `2^8` on the
menu. **It no longer applies to that family and is kept because it is the
clearest statement of what a delegation height is a ceiling on.** At S21 one
keccak row was a whole permutation, and a whole permutation was **354,762 inner
columns** over 177 layers; `gkr::forward` materializes every layer at the full
height, so a shard's forward pass is that count times its height times 32 bytes:

| height | forward pass, S21's shape | permutations a shard |
| --- | --- | --- |
| `2^8` | 2.9 GB | 256 |
| `2^10` | 11.6 GB | 1,024 |
| `2^12` | 46.5 GB | 4,096 |
| `2^16` | 744 GB | 65,536 |

`2^8` is also **even**, which Mercury needs for `b = sqrt(2^n)` to exist, so the
even powers below `2^16` that S21 could have taken were `2^8`, `2^10`, `2^12`
and `2^14`. S26d re-shaped the row first — 5,478 inner columns, so `2^16`, the
floor its two
channels imply, is about 15 GB and 2,730 permutations a shard — and then, the row
being narrow, took the height one entry past that floor as well: **5,490** inner
columns at `2^18`, about **60 GB** and **10,922** permutations a shard (§6.0).
The 60 GB is `EC_ADD`'s three terms (§16.4) at this width — 46.05 GB of inner
layers, 2.23 GB of committed base and 11.27 GB of transition 0's half-height `Fr`
bind. What keeps `2^8` on the menu is the three families still at it. The menu
has a second sub-`2^16` entry since S-STREAM, `2^12`, and it is **not** a
delegation height: it is the pinned height of the two public-value families,
which is what places their windows (`docs/spec/public-values.md` §2). A
channel-free delegation family may be declared at it — `POSEIDON2`, `FR_ARITH`
and `SHA256_COMP` reach no table that would refuse it — and none is.

At `2^8` **no range channel's table fits**: `V[range16]` over 8 variables holds
`[0, 2^8)`, not `[0, 2^16)`, and `lookup::channel_trees` refuses a channel whose
bound exceeds the circuit's variables (`docs/spec/lookup.md` §3). So a family
there carries **no channel at all**, and every bound of such a family is a bit
decomposition with a booleanity gate.

That is a deviation from `docs/spec/memory.md` §7's 19+19 timestamp-gap gadget,
and it is deliberate: the gadget's statement is `gap ∈ [0, 2^38)`, and 38
booleans say the same thing without a table. It costs 38 committed columns a
frame word, and it removes the failure
`constants::family::DEFAULT_HEIGHTS` warns about, a family reaching a channel
assertion inside `VerifyingKey::check` on bytes a verifier was handed.

**A delegation family at `2^8` must therefore carry no lookup channel**, and
**no delegation family may carry `TIMESTAMP` at any height this menu offers**:
that channel's `BITS` is 19, so its table needs `2^20` rows, which is an
execution family's floor and not a delegation family's. A frame's timestamp gap
is consequently never a `TIMESTAMP` obligation — it is a bit decomposition at
`2^8` and, since S26c, four `RANGE16` obligations at `2^16` or above (§10.3).

**`family_circuit`'s minimum-height guard is derived, not a list.** Until S26c it
named the seven execution families explicitly and a delegation family's arm sat
below it, because a family with no channel reaches no `BITS ≤ trace_vars`
assertion and naming it in the guard would have refused the heights these
families actually take. Since S26c the guard reads each family's **own**
`channels()` and takes the widest range channel's `BITS`, so a family is held to
exactly the floor its channels imply and no table of families has to be kept in
step: `SHA256_COMP` with no channel has a floor of 0, `KECCAK_F`, `EC_ADD` and
`MOD_MUL` a floor of 16, and the seven execution families 19 as before. **Since
S26d the per-channel number is `lookup::table_vars` and not `BITS` with a range
filter**: `XOR8`'s table is 65,536 rows without being a range channel at all, so
a filter on `IS_RANGE` would have given a family carrying it alone a floor of 0
and an incomplete table at every height below `2^16` — true of `KECCAK_F` only by
the accident of its also carrying `RANGE16`. The floor is tested
before the artifact is built, so a family below it returns `None` for a clean
`Err` rather than panicking inside `VerifyingKey::check` on bytes a verifier was
handed.

### 9.1 `2^8` is not free, and S26 is where it shows

The argument above is about the **forward pass**, and at S21 it was `KECCAK_F`'s:
354,762 inner columns at `2^16` is 744 GB, so the height had to come down. S26's
`MOD_MUL` is two orders of magnitude smaller — **270** inner columns at the time —
and for that family `2^8` is a different trade, which the stage measured rather
than assumed:

| | at `2^8` | at `2^16` |
| --- | --- | --- |
| `MOD_MUL` forward pass a shard | 2.2 MB | 566 MB |
| invocations a shard | 256 | 65,536 |
| S26's pinned mini-block (6,705 invocations) | **27 shards** | 1 shard |
| block 26,059,700, measured (268,200) | **1,048 shards** | 5 shards |
| block 26,059,900, from its call counts (603,450) | **2,358 shards** | 10 shards |

**A `2^8` shard's *proof* does not shrink with its height.** It is dominated by
per-layer sumcheck messages and base claims, which are a function of the circuit's
width and depth and not of the row count: `KECCAK_F`'s was a measured 11,880,012
bytes for 256 invocations, and `MOD_MUL`'s committed width was 92% of that. So
`2^8` costs about 11 MB of proof per 256 invocations — ~290 MB for S26's pinned
mini-block, ~11 GB for a measured whole block and ~25 GB for the busiest of the
four S26 profiled — where the `2^20` execution shards the delegation *removes*
were about 60 KB each. Prover work and
peak memory move the other way by a wide margin; it is only the artefact that
grows.

**The same cost was already in the repository and predated `MOD_MUL`.** S25's
bench report on that mini-block is 37 shards and 61,323,886 proof bytes, of which
the five `2^8` `KECCAK_F` shards were 59.4 MB — **97% of the proof**, against 3%
for the thirty-two execution and window shards. A delegation family's height has
been the dominant term in proof size since S21.

**S26d is that finding acted on, and it is the reason the section reads in the
past tense.** Raising `KECCAK_F`'s height could not come first — at 354,762 inner
columns a row the forward pass forbade it — so the row was re-shaped (§6.0). The
same 1,080 permutations that were five `2^8` shards and 59.4 MB are now **one
`2^18` shard and 0.38 MB**, a tenth of it occupied — 353 proof bytes a permutation
on this workload, and **34.9** at full occupancy (§6.0), against 46,406. On
that mini-block the whole proof falls from 61.3 MB to about 2.3 MB, and keccak
stops being the dominant term in it. The width the
family could not afford at `2^16` is what one round a row removed, and the height
then followed it — one entry past the floor, to `2^18`, because a shard's proof
barely grows with its rows (§9.2).

### 9.2 `DEFAULT_HEIGHTS` is per family, and the six differ by three orders of magnitude

S26 first left it at `2^8` "consistent with the three families before it", and
that reason was wrong: **consistency between delegation families has no
technical content.** A family's ceiling is the width of one row's circuit, and
those widths differ by three orders of magnitude — 354,762 inner columns for
S21's `KECCAK_F` against 270 for S26's `MOD_MUL`. Holding the second down to the
first's height bought nothing and cost the table above.

So the heights are per family, which is what `DEFAULT_HEIGHTS` was always able
to express:

| family | inner | committed | height | why that one |
| --- | --- | --- | --- | --- |
| `KECCAK_F` | 5,490 at `2^18` | 1,764 | **`2^18`** | re-shaped at S26d and then raised past its floor; 16 is the floor `RANGE16`'s table and `XOR8`'s each imply, 18 is the choice above it, and the paragraph below is why. It was 354,762 and 3,764 at `2^8` |
| `POSEIDON2` | 2,020 | 4,192 | `2^8` | `2^16` is 13.0 GB, and the guests that reach it invoke it in the hundreds |
| `FR_ARITH` | 142 | 2,680 | `2^8` | ditto, 5.9 GB |
| `MOD_MUL` | 2,244 at `2^16` | 325 | **`2^16`** | re-shaped at S26c; §10.3 |
| `SHA256_COMP` | 16,688 | 8,216 | `2^8` | `2^16` is 35 GB of forward pass a shard, and no guest here invokes it often enough to buy the rows back — contrast `KECCAK_F` below |
| `EC_ADD` | 8,772 at `2^16` | 1,420 | **`2^16`** | forced: `RANGE16` needs 16 variables and `2^18` is 4x worse |

**`KECCAK_F`'s `2^18` is the first height here that is a choice above a floor
rather than the floor itself.** Its two channels' tables put the floor at 16
(§9's derived guard) and `family_circuit` accepts `16 ≤ n ≤ 30` for it, `2^16`
included. What buys the extra entry is that **a delegation shard costs its height
and not its occupancy, while its proof costs neither**: a proof is a function of
the circuit's width and depth, and the sumcheck rounds grow as `11n + n(n+1)/2` —
369 at `2^18` against 312 — while the rows grow fourfold. So a shard's proof goes
from 373,276 bytes to 381,100 while the permutations in it go from 2,730 to
10,922: a quarter the proof bytes a permutation, for four times the shard,
~60 GB against ~15. **At ~60 GB it is now the peak-setting family of a block**,
ahead of `EC_ADD`'s 20.5 GB (§16.4). It buys the pinned mini-block nothing, whose
permutations fit one shard at either height and occupy a tenth of this one; it is
aimed at the **stateless full block**, where the 45,000–103,000 permutations
`docs/handoff/S-BATCH-miniblock-gate.md` §11.2's node count implies are **5 to
10** shards and 1.9–3.8 MB of keccak proof, against 17 to 38 shards and
6.3–14.2 MB at `2^16`.

Two properties made the raise cheap **at S26b**, and S26c changed the second of
them. **A height changes no gate**: it adds one halving list per variable, each
carrying one node per output, so at that stage `MOD_MUL` at `2^16` was 22 lists,
158 inner columns and 3,660 relations against `2^8`'s 14, 142 and 3,644, with the
committed width, the gate split and the zero lookups identical. The property
itself still holds and
`crates/checker/tests/mod_mul.rs::a_height_moves_only_the_halving_layers` is what
says so — it compares `2^16` against `2^18` now, `2^8` no longer being a height
this family has, and it compares **enforcing** gates rather than every relation,
because a halving list produces one node per output and the total therefore grows
with the height by exactly `outputs × Δn`.

The second property was **"a delegation family carries no channel"**, and §10.3
withdrew it: `MOD_MUL` carries `RANGE16` since S26c, so `family_circuit` accepts
`16 ≤ n ≤ 30` for it and not `0 ≤ n ≤ 30`. The current shape is 26 lists, 325
committed columns, 2,244 inner and 2,369 relations with 274 obligations and four
outputs — the two memory roots and the channel's fraction pair
(`docs/spec/constraint-manifest.md` §18.1). **The height was already `2^16`
before the channel needed it**, for the reason this section gives, so the
channel's floor cost this family nothing and the two constraints coincide.

What the raise is *not* free of: the height is in `VM_CONFIG`, which program
identity absorbs, so **every guest declaring `MOD_MUL` has a new identity** and
every verifying key over one has new bytes. The same is true of `KECCAK_F` at
S26d, and there the ecall number moved too, so **every guest that hashes has a
new identity**. That also means the height is a
property of the **program**, not of the execution — it cannot be chosen per
block, and `2^16` is the choice for the busiest block `guests/revm-block` is
meant to prove. At 268,200 invocations that block is 5 shards with 18% padding;
the same height costs S26's pinned mini-block one shard at 90% padding, and a
`2^8` shard's proof being ~11 MB whatever its occupancy, that trade is the right
way round.

The one number still missing is a `2^16` `MOD_MUL` shard's **measured** peak and
proof size, which only a run of the deferred `prover::revm` and `host::prove`
suites produces; the figures above are computed from the widths in
`docs/spec/constraint-manifest.md` §1.2.

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

### 10.2 What S26b amended, and why

§10 says a later family **appends, and appends only**, and has no clause for a
family that *changes*. S26b is one: it narrowed `MOD_MUL`'s frame from 32 words
to 25 and replaced its witnessed modulus with a four-way selector. That is a
protocol-version change and it is recorded here, in the rule it amends, as
§10.1 is.

What changed is confined to the three things §10 lets a family own — its row in
§3, its frame table in §14.1, and its circuit, fill, shim and declaration
record — plus the ecall number, which moved for the append-only reason §3 now
states. **Nothing else in this page moved**: the calling convention, the frame
rules, the anchor's two leaves and three zeroings, the ts-window convention and
the no-channel rule are all untouched, and the other three families' bytes did
not change. The one gate outside the family that moved is
`ADD_SUB_LUI_AUIPC`'s `deleg_15_number`, whose literal is the ecall number, so
`add_sub.bin` regenerated.

**Why the generality went.** §14.1 argued for the witnessed modulus on the
ground that "one family serves every 256-bit modulus", against two
constant-modulus families costing two ids, two ecalls, two circuits and two
request selectors. That argument was sound and its premise was wrong: the
alternative was never *two* families, it was **one** family with a selector,
which costs one frame word and four boolean columns. And the witnessed modulus
had a price the argument did not count — with `m` an operand the circuit cannot
state `a < m`, so the quotient's fit was the honest prover's business and not
the statement's. §14.3 is what that cost, and §14.2 is what removing it bought.

### 10.3 What S26c amended: a delegation family may carry `RANGE16` at `2^16` or above

§9 read "and why there is no lookup channel" and stated the rule twice, as a
property of `2^8` and as a rule about delegation families generally. The first
half stands; **the second is withdrawn**, and `EC_ADD` and `MOD_MUL` carry
`RANGE16` at `2^16`.

**What the channel is worth.** A 32-bit bound is one committed column and two
obligations where a bit decomposition is 32 columns with 32 booleanity gates, and
a frame's 38-bit timestamp gap is two columns where it is 38. `EC_ADD`'s frame is
97 words, so the gap alone is 3,746 bit columns against 194 chunk columns — and
the family has 24 more 32-bit values to bound besides. Re-shaping `MOD_MUL` the
same way at the same time took its committed width from **3,468 to 325**, a
factor of 10.7, and its proof from 360,948 bytes a shard to 135,220.

**What the amendment does not touch.** A family at `2^8` still carries no
channel, because no table fits there — `SHA256_COMP` is the worked example, and
its row is 20,000 inner columns, so `2^16` is not open to it. And **no**
delegation family may carry `TIMESTAMP` at any height on this menu: `BITS = 19`
needs `2^20`, which is an execution family's floor. So a frame's timestamp gap is
never that channel's obligation — it is a bit decomposition at `2^8` and three
`RANGE16` chunks at `2^16`, the third carrying a scaled obligation that is exact
at `2^38`.

**What it costs.** Three things, each of which S26c paid.

- **The minimum-height guard stops being a list.** It named the seven execution
  families and a delegation family's arm sat below it; a family with a channel
  now has a floor, so the guard reads each family's own `channels()` and derives
  the floor from the widest range channel's `BITS`. A list would have had to be
  kept in step with two families whose heights differ from every other's.
- **A channel-carrying family has a floor, and its circuit does not exist below
  it.** It is `2^16` for both of these, so a suite cannot build either at four
  rows for a whole-shard forward pass. `crates/checker/tests/{mod_mul,ec_add}.rs`
  evaluate one row of the real `2^16` circuit instead, which is both cheaper and
  a stronger statement. A family may sit *above* its floor — `KECCAK_F` does
  since S26d (§9.2) — but never below it.
- **One multiplicity column per channel per circuit**, last in the witness
  subtree, filled by `crates/trace` and read by no gate. It has to exist because
  `a.committed()` names it.

### 10.4 What S26d amended: one keccak round a row, and a fifth channel

§10 has no clause for a family that *changes*; S26b was the first and this is the
second. `KECCAK_F`'s row went from **a whole keccak-f[1600] permutation to one
round**, its frame from 50 words to 51, its height from `2^8` to `2^18` and its
ecall number from `0x0501` to `0x0507`. Everything is confined to the three things
§10 lets a family own — its registry row, its frame table and its circuit, fill,
shim and declaration record — plus the ecall number, and plus one thing §10 did
not anticipate at all (below). The one gate outside the family that moved is
`ADD_SUB_LUI_AUIPC`'s `deleg_9_number`, whose literal *is* the ecall number, so
`add_sub.bin` regenerated exactly as it did at S26b.

**Why the row was re-shaped before the height.** §9.1 measured the cost of `2^8`
and could not act on it for this family: at 354,762 inner columns a row, `2^16` is
744 GB of forward pass. The width was the problem, and all of it came from one
decision — representing the state as 1,600 booleans, which makes every XOR a
degree-2 gate and forces all 24 rounds to coexist horizontally. A byte-oriented
state with a byte XOR table is 5,478 inner columns at `2^16`, which fits there at
about 15 GB — and `2^18`, the height this stage went on to take, at about 60 GB —
and 24 rows a permutation is then **half** the column-rows one row used to be
(§6.0). The proof shrinks 1,330× a permutation. The guest pays ~150 cycles a
permutation against ~4, which on any real workload is worth about a tenth of one
execution shard against gigabytes of proof.

**The thing §10 did not anticipate: a fifth LogUp channel.** `XOR8`
(`docs/spec/lookup.md` §14) is a **table** channel whose table is a *closed form*
— the first of either kind. That is a change to `docs/spec/lookup.md`'s frozen
channel list and to `prompts/00-master.md`'s Lookups invariant, authorized by the
owner and recorded in both. It costs no commitment, no setup column and no
movement of the SRS digest, which is why it is cheaper than folding a byte table
into the `GENERIC` channel would have been — three setup columns to commit and
open against, and every verifying key's SRS digest and bytes moved again with
them. **The height half of that argument is void**: the `GENERIC` table does not
exist below `2^18`, which is the height this family now takes anyway, so what
`XOR8` still buys over it is the binding and not the rows.

**What did not change.** The anchor, its two leaves, the three request-side
zeroings and the addressing rule (§5); the frame's two rules and its trace rules
(§4, §4.1); static detachment (§7); the ts-window convention (§8); the state's
SHA-3 byte order; the family id; the address-space tag; `guest_sdk::keccak256`'s
signature and the sponge and padding behind it; and the proof's shape.

**One number a later change has to respect**, and it is in §6.5: the `XOR8`
channel carries 1,020 obligations against a 1,024-leaf fraction tree, so four more
double the tree.

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
  `crates/emulator/tests/guests.rs` holds over `guests/keccak-test`'s six digests —
  themselves re-derived from `tiny-keccak` rather than restated. The guest never
  chooses the path and cannot tell which ran.
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

---

## 14. The Ethereum field-multiplication circuit

`constants::family::MOD_MUL`, **one multiplication a row**, new at S26 and
specialized at S26b under §10.2. `constraints::mod_mul` is the circuit;
`docs/spec/constraint-manifest.md` §18 is its column-by-column account.

### 14.0 Why it exists

`tools/profiler` measured a whole mainnet block and **56.66% of its guest cycles
were secp256k1**, of which **44.4% of the block** was 256-bit modular multiply
and square inside `k256` — 60,345 calls at about 1,300 cycles each
(`docs/handoff/S26-cycle.md`). Nothing else on the list was within a factor of
three. The guest does not verify transaction signatures — the witness carries the
recovered sender (§1.2 of `docs/spec/revm-block.md`) — so all of it is the `0x01`
precompile called by contracts.

**This is not an `ecrecover` delegation.** `prompts/00-master.md`'s stage register
cancelled that and the cancellation stands: there is no ecrecover family, no
signature in any frame, no curve anywhere in this circuit, and no recovery. What
this family proves is one modular multiplication of two 256-bit integers in one
of four fixed fields.

**And it is not `MULMOD`.** The EVM's opcode takes an arbitrary modulus, which
this frame has no representation for; nothing routes the opcode here, and an
accelerator for it would be a different family with a different frame.

### 14.1 The frame, and one multiplication an invocation

25 words.

| words | what |
| --- | --- |
| `0` | the modulus **selector**, one of `constants::mod_mul::CODES` |
| `1..9` | operand `a`, **below the selected modulus** |
| `9..17` | operand `b`, below it too |
| `17..25` | the result, the only words the invocation computes |

The selector's four codes, and the fields they name:

| code | constant | modulus |
| --- | --- | --- |
| 1 | `SECP256K1_P` | secp256k1's base field, `2^256 − 2^32 − 977` |
| 2 | `SECP256K1_N` | secp256k1's scalar field, the group order |
| 3 | `BN254_P` | BN254's base field `q` — the `0x06`/`0x07`/`0x08` precompiles' coordinate field |
| 4 | `BN254_R` | BN254's scalar field `r`, which is also this VM's own `Fr` |

**Codes start at 1**, as `fr_arith::OPS` does and for the same reason: a live
row whose selector word is 0 — a caller that built a frame and forgot the
modulus — then satisfies no selector and is unprovable, where a 0-based code
would have silently meant secp256k1's `p`.

**Those four and no others**, and the set is what makes the family Ethereum's
rather than general. Between them they are every 256-bit field block execution
multiplies in: `ecrecover`'s curve and its scalars, and the BN254 precompiles'
tower. A fifth is a frame append under §10, not something this family reserves
room for.

**The modulus is not an operand, and that is the S26b change.** S26 carried it
in eight frame words. The argument was that one family then served every
256-bit modulus, against two constant-modulus families costing two ids, two
ecalls and two circuits — and the argument missed that the alternative was one
family with a selector. What the selector costs is one frame word and four
boolean columns. What it buys is in §14.2 and §14.3, and §10.2 is the record of
the change.

**One operation, and there is no opcode word.** The family multiplies and does
nothing else, because that is what the measurement asked for: every other
operation `k256` performs on a field element — add, negate, the modulus
correction — costs under 100 cycles natively, so delegating one would be *slower*
than not. A second operation is a later family or a frame append under §10, not a
field this one reserves.

### 14.2 The gates

Over the three frame values `a`, `b`, `out`, the selector, the modulus `m` it
names, and the quotient `q`:

| gate | what |
| --- | --- |
| `writes_back_w{j}` | words 0 to 16 are written back unchanged, so the caller's selector and operands survive |
| `selector{c}_boolean` | each of the four selectors is a bit |
| `selector_rule` | `word 0 = Σ code_i·s_i`: the field the circuit reduces in is the one the guest asked for |
| `one_modulus_a_live_row` | `Σ s_i = live`: exactly one field a live row |
| `m_limb{k}_rule` | `m_k = Σ MODULI[i][k]·s_i`: the modulus is the selector's literal, which is also its `2^32` bound |
| — | **Since S26c every one of these bounds is a `RANGE16` obligation and not a gate.** Each of `a`, `b` and `out`'s eight limbs carries a committed high halfword and a 16+16 pair; the quotient's eight the same; each of the fourteen carries a value and two chunks; and the frame's 25 timestamp gaps two chunks apiece with a scaled obligation on the top one. 274 obligations replace 3,320 booleanity gates and the 32 decodes that read them, which is what took the family from 3,468 committed columns to 325 (`docs/spec/constraint-manifest.md` §18.4, §18.5, and §10.3 for the amendment that allowed it) |
| `limb{k}` | `P_k − S_k − out_k + c_{k−1} − 2^32·c_k = 0`, where `P_k = Σ_{i+j=k} a_i·b_j` and `S_k = Σ_{i+j=k} q_i·m_j` |
| `<v>_diff{i}_{t}_boolean`, `<v>_borrow{i}_boolean` | the three `< m` chains' bits |
| `<v>_canonical{i}` | `v_i − m_i − b_{i−1} + 2^32·b_i = d_i` |
| `<v>_below_modulus` | `b_7 = live`: the subtraction borrowed out, so `v < m` |

Six of those deserve a sentence.

**The limb identity is an integer identity, and the 32-bit bounds are what make
it one.** Every term of `limb{k}` is a small integer: `P_k` and `S_k` are each at
most eight products of values below `2^32`, so under `8·2^64 = 2^67`, and the
largest coefficient in the gate is `2^32` times a carry's offset, `2^68`. All of
it is far below `p`, so the `Fr` equation *is* the ℤ equation — the same argument
§13.3's borrow chain rests on. Drop any word's decomposition and the gate becomes
a statement modulo `p` instead, which is no statement about `a·b` at all.

**`one_modulus_a_live_row` is load-bearing twice, and the second time is not
about the selector.** The first is §13.3's lesson from `fr_arith`'s three
opcodes: the codes are 1, 2, 3, 4, so `1 + 3 = 4` and a row claiming
secp256k1's `p` *and* BN254's `q` spells the word of a row claiming BN254's
`r`; `selector_rule` cannot see it and the sum gate is what refuses it. The
second is the paragraph above: `m` has **no bit decomposition** — its limbs are
bounded only by being one table entry each — and two selectors at once would
put `m_0` above `2^32`, `S_k` above `2^68`, and the "far below `p`" argument
out of reach. So the gate is not redundant at any code spacing, and a later
table separated to 1, 2, 4, 8 would still need it.

**`m` costs eight witness columns rather than four products a limb.** The
alternative was inlining `Σ MODULI[i][k]·s_i` wherever `m_k` appears; the chains
would read four terms instead of one, which is free, but every `q_i·m_j` in
`limb{k}` would become four products, taking gate list 0 from 128 products to
320. Eight committed columns and eight degree-1 gates is the cheaper half, and
it is also what makes "the modulus is not the selected literal" a cell a tamper
twin can corrupt.

**The carries are signed, with an offset, and the offset is derived.** A carry is
written `Σ 2^t·bit − 2^36·live`, so a padding row's carry is 0 and a live row's
spans `[−2^36, 2^36)`. The bound it must cover is the fixed point of
`C = (2^67 + 2^32 + C)/2^32`, just above `2^35` — a full factor of two of room,
and `crates/constraints/src/mod_mul.rs`' `the_carry_offset_covers_the_bound`
computes it rather than trusting the arithmetic in this paragraph. **The
selector does not tighten it**: the bound reads only the limbs' `2^32` bounds.

**The identity closes because the last position has no outgoing carry.** Summing
the fifteen equations weighted by `2^{32k}` gives `a·b − q·m − out = c_14·2^{480}`,
so the fifteenth equation, which has no `c_14` term, *is* the identity. Fourteen
carries, fifteen positions.

**Three chains, and they are not three of the same thing.** `out < m` is the
reduction and nothing else supplies it: without it a prover answers `r + m` with
the quotient one lower, the identity holds over the integers just as well, every
limb is still bounded and every carry still divides.
`crates/checker/tests/mod_mul.rs`' `a_result_not_below_the_modulus_is_refused`
builds exactly that twin — result, quotient, bits, carries and chain all
recomputed, as an honest prover of that claim would — and requires
`out_below_modulus` to be the one relation that catches it. `a < m` and `b < m`
are **not** soundness; they are §14.3.

Unlike §13.3's canonicity chain, these three are **ungated**: that one subtracts
`p`, a literal, which has to be multiplied by `live` to vanish on a padding row,
and here `m_i` is a column that `m_limb{k}_rule` already forces to zero there.
The whole padding row is zeros and every gate above holds on it.

**`m > 0` needs no gate.** Every entry of the table is a 256-bit odd prime, and
`crates/constraints/src/mod_mul.rs`' `every_modulus_is_a_256_bit_odd_value` is
what says a fifth entry would have to be too.

### 14.3 The operand bounds, and what they make true

`q`'s bits bound it to `2^256`. With `a < m` and `b < m` enforced,
`q = (a·b − out)/m ≤ (m−1)²/m < m ≤ 2^256`, so the honest quotient **always**
fits its eight limbs.

That is the whole point of the operand bounds, and it is a completeness property
rather than a soundness one. S26 had soundness without them: an unreduced operand
made the quotient overflow eight limbs, the prover's own fill panicked, and the
verifier was never at risk — "a cost to the prover and never a hole for the
verifier", which was true. What it was not was *total*: there were frames the
circuit would have accepted that no prover could fill, and whether a call was one
depended on a caller's reduction discipline. Since S26b **every frame the circuit
accepts has a witness and every witness it has is accepted**, and the frame's
meaning is exactly "two canonical elements of the selected field".

The price is paid by the caller, and it is real. `guests/vendor/k256` now
reduces an operand below `p` where it used to reduce only below `2^256`
(§14.4), which is the `normalize` S26 measured at 0.6 million guest cycles on
the pinned mini-block and deliberately removed. Enforcing the bound put it
back.

`crates/emulator`'s executor refuses all three bad frames **by name** — a
selector no code names, `a` at or above the modulus, `b` at or above it. That
is not tidiness: long division answers correctly for any operands below
`2^256`, so without the refusals a guest with an unreduced operand runs clean,
every trace-level test passes, and the only thing that fails is a gate —
anonymously, as `LayerInconsistency { layer }`, hours into a block proof. With
them it is a fatal trace-time error that `kat-gen -- revm` catches on every
push. The prover's fill asserts the same two operand bounds, naming the
operand, for the same reason.

### 14.4 The guest-target backend

`guest_sdk::recursion::mod_mul` is the shim and `ModMulFrame` its frame — limbs
rather than bytes, because every caller already holds 32-bit limbs and a byte
frame would cost a pack and an unpack per call, a fifth of what the delegation
saves. `false` on exactly `-ENOSYS`, as every shim answers. The four codes are
re-exported from `guest_sdk::recursion` beside it, so a caller names the field
rather than spelling a number twice.

**All four selectors have a library caller**, each through a **vendored** copy
under `guests/vendor/` and a `[patch.crates-io]` entry
(`guests/vendor/README.md`):

| selector | what routes | where |
| --- | --- | --- |
| `SECP256K1_P` | `FieldElement10x26::mul` and `::square` | `guests/vendor/k256`, `src/arithmetic/field/field_10x26.rs` |
| `SECP256K1_N` | `Scalar::mul` (and `::square` through it) | `guests/vendor/k256`, `src/arithmetic/scalar.rs` |
| `BN254_P`, `BN254_R` | `MontBackend::mul_assign` and `::square_in_place` | `guests/vendor/ark-ff`, `src/fields/models/fp/montgomery_backend.rs` |

Neither crate offers a hook — no `extern`, no feature, nothing to override — and
the alternative was writing signature recovery and a pairing ourselves; the owner
chose the patch, which keeps the audited code. `crates/prover/tests/one_feature.rs`
skips `guests/vendor/**`, because master anti-goal 1's hazard — a configuration
nobody builds — is about *this* repository's crates and not about a third party's
feature table that a `[patch]` carries in unchanged.

**Three caller-side rules, and the vendored patches are the worked examples.**

*An operand must be below the selected modulus, not merely below `2^256`.* This
is §14.3's price and it is the rule S26's patch broke by design. `k256` stores a
field element as ten 26-bit limbs with a magnitude up to 8, and the old
`operand` reduced only until the value fit the frame — its doc said "an operand
at or above `p` is no problem", which is now false. Worse, `p`'s own raw limb
pattern is upstream's **second representation of zero** (`normalizes_to_zero`'s
`z1` mask is exactly it), and the complete projective formulas produce it
whenever a coordinate difference vanishes, so `a = p` is a structured case and
not a `2^-224` accident. The patch's test is now `packable(x) &&
!x.get_overflow()` — upstream's own "is this magnitude-1 value at or above `p`",
ordered after `packable` because that is where it is meaningful — falling back
to a full `normalize`. The **scalar** path pays none of this: a `Scalar` is a
`U256` already below `n`, so its operands satisfy the bound by the type's own
invariant.

*A Montgomery caller pays two calls, not one.* The delegation multiplies plain
integers. arkworks' `Fp256` holds `x·R` with `R = 2^256 mod p`, and a Montgomery
multiply is `â·b̂·R^-1`, so `guests/vendor/ark-ff` issues `t = â·b̂ mod p` and
then `out = t·R^-1 mod p`, with `R^-1` a literal from
`constants::mod_mul::{BN254_P_R_INV, BN254_R_R_INV}`. Two delegated calls still
beat one software Montgomery multiply by roughly an order of magnitude, and this
is the trade §13.2 avoided for `FR_ARITH` by carrying the Montgomery
representation in the frame instead — which this family cannot do, its four
moduli having four different radices. The patch sits in `ark-ff` rather than
`ark-bn254` because that crate's `#[derive(MontConfig)]` *generates* its own
`mul_assign`, so the intercept has to be one level below it; the selector is an
associated `const` matched on `T::MODULUS`, so it is decided at compile time and
every other arkworks field — `ark-bls12-381`'s six-limb one included — is
untouched.

*The frame is built once, not zeroed and then filled.* `ModMulFrame::of` writes
the selector, both operands and eight zero result words in one pass. The obvious
`new()`-then-`set()` shape cost a `memset` and three `memcpy`s a call, 1.4 million
cycles on S26's pinned block. §2's shim model charges `4 + 2·frame_words` for a
call; that is the *floor*, and a caller that marshals badly pays several times it.
The 25-word frame charges 54 where the 32-word one charged 68.

**A caller owes a software path, and at 256 bits it is no longer one line.** §2
requires one behind every shim. The three library callers get theirs for free —
upstream's own multiply, one branch below the ecall, which is the shape §13.4
describes and the reason the delegated and software answers cannot disagree by
construction. `guests/mod-mul-ops`, which calls the family by name, cannot: S26
chose `2^32` and `2^61 − 1` as its moduli precisely so its fallback could be one
`u128` expression, and a fixed-modulus family has no such exit. So it carries a
schoolbook 512-bit long division of its own — and **runs it on every call,
comparing**, rather than reserving it for an executor that will never ask. That
turns forty lines of dead code into a differential oracle against
`emulator::mod_mul_frame`, which is the better of the two things to have.

---

## 15. The SHA-256 compression circuit

`constants::family::SHA256_COMP`, **one compression a row**, new at S26c.
`constraints::sha256` is the circuit; `docs/spec/constraint-manifest.md` §19 is
its column-by-column account.

### 15.0 Why it exists

Ethereum's `0x02` precompile, and the cheapest regular circuit surface on the
profiler's list after the two S26b took. SHA-256 is sixty-four rounds of fixed
rotations, XORs and 32-bit additions — no modular reduction, no field, no
table — which is the smallest possible arithmetization per unit of guest work:
every bound is a bit that already exists for the XORs' sake.

**It is the compression function and not the digest**, which is what makes the
routing easy. The padding and the block loop are Merkle–Damgård's and belong to
the caller; `guest_sdk::sha256` is where they live, and one ecall covers one
64-byte block. A digest-shaped frame would have needed a length, a variable
number of blocks and a decision about where padding happens, none of which a
fixed-width frame expresses.

### 15.1 The frame

**24 words, 96 bytes**, word-aligned per §4.

| words | holds | read | written |
| --- | --- | --- | --- |
| 0–7 | the chaining state `H0..H7`, little-endian `u32` each | yes | **yes** |
| 8–23 | the block's sixteen schedule words `W0..W15`, **big-endian decoded** | yes | unchanged |

The forty-eight schedule words `W16..W63` the message schedule derives are the
circuit's own advice and **never cross the frame**: they are a function of the
sixteen, so carrying them would be 192 bytes of frame a guest would have to
compute to hand over.

**The words are `u32`s and the block is big-endian decoded.** SHA-256 is a
big-endian design where keccak is a little-endian one, and the decode has to
happen somewhere; it happens in the caller, because the caller already holds
the bytes and the circuit already holds the value. `constants::sha256`'s
`STATE_WORD`, `BLOCK_WORD` and `FRAME_WORDS` are the layout and
`guest_sdk::recursion::Sha256Frame`'s three `const` assertions pin it, so a
renumbering fails the build rather than transposing the state and the block.

**There is no frame this family can refuse**, and it is the only one of the six
of which that is true: every `u32` is a legal chaining word and a legal schedule
word, so `emulator::sha256_frame` takes no `pc` and has no error path. What a
caller can still get wrong is the *padding*, which is why
`guests/sha256-ops` checks seven message lengths chosen for the boundary the
padding turns on.

### 15.2 The circuit, in one paragraph

Three gate lists. List 0 bit-decomposes every frame word, copies the carried
bits and builds the `x·y` helper of each three-way XOR; list 1 assembles the
carried scalars and the XOR values; list 2 is the sixty-four rounds, the
forty-eight schedule equations and the eight output sums. Every bound is a bit
with a booleanity gate — the family is at `2^8`, where no channel's table fits
(§9) — and the carries are three bits for a round, two for a schedule word and
one for an output sum, each derived rather than observed.

**The recurrence is over two sequences, not eight working words.** `b`, `c` and
`d` are `A_{i−1}`, `A_{i−2}` and `A_{i−3}`; `f`, `g` and `h` are `E_{i−1}`,
`E_{i−2}` and `E_{i−3}`. So the round is
`A_{i+1} = T1 + T2 − 2^32·ca_i` and `E_{i+1} = A_{i−3} + T1 − 2^32·ce_i`, the
eight-variable shuffle costs nothing, and the four non-positive indices of each
sequence *are* the frame's state words — which is the whole of `B`, `C`, `D` and
`H`'s existence in this arithmetization.

**A round's constant `K_i` rides the row's `live` mask and is not a bare
literal.** A padding row is an all-zero row, and `… − K_i = 0` cannot hold on
one; `checker::check_padding` refuses such a circuit, and S26c shipped it that
way until the checker suite ran. The mask is an `M` column that only gate list 0
may read, so it is carried like any other value — one column a layer, which is
what the correct statement costs.

---

## 16. The elliptic-curve addition circuit

`constants::family::EC_ADD`, **one third of one addition a row**, new at S26c.
`constraints::ec_add` is the circuit; `docs/spec/constraint-manifest.md` §20 is
its column-by-column account.

### 16.0 Why it exists, and what it is not

The point operations under Ethereum's `0x06` and `0x07` precompiles, and — far
more valuable — the ones inside `k256`'s `ecrecover`, which S26's profile ranked
first in every workload it measured. After S26b routed that crate's field
multiply through `MOD_MUL`, a projective addition was twelve `MOD_MUL`
invocations; it is now three `EC_ADD` ones.

**It is not a scalar multiplication and not a pairing.** A ladder is the
caller's — `guest_sdk::recursion::ec_add_complete` is one addition — and the
pairing is out of scope by the stage's own terms. **It is not `ecrecover`
either**: `prompts/00-master.md`'s stage register cancelled that family and the
cancellation stands.

### 16.1 The formula, and why it is the caller's

Renes–Costello–Batina 2015 **Algorithm 7** for `a = 0`, in **homogeneous
projective** coordinates — `x = X/Z`, `y = Y/Z`. It is **complete**: `P + P`,
`P + (−P)`, `P + O` and a non-normalized `Z` all come out right, so the guest
branches on nothing, the circuit has no degenerate row, and no inverse witness
exists anywhere in it.

That choice is not the circuit's convenience. `guests/vendor/k256`'s
`ProjectivePoint::add` **is** this algorithm over this representation, so the
delegation is a drop-in for a method whose storage does not move — which is the
owner's rule: a delegation understands the representation its caller already
uses. The two paths therefore agree **limb for limb** and not merely as points.
BN254 arrives affine at revm's `Crypto::bn254_g1_add` boundary and the guest
lifts it with `Z = 1`, which is free; arkworks' own `Projective` is *Jacobian*,
so a caller converting between them does `(X·Z, Y·Z², Z)` one way and
`(X·Z, Y, Z³)` the other.

**Completeness is what makes a ladder five lines**, and it is worth saying why
that matters more than the formula's cost. An incomplete formula needs a case
for the first iteration, a case for a doubling and a case for the identity, and
each is a place to be wrong only on inputs a test does not reach.

### 16.2 Three invocations, and the frame that glues them

Twelve multiplications, in **three groups of three reductions**:

```text
group 0    xx = X1*X2          yy = Y1*Y2          zz = Z1*Z2
group 1    m4 = (X1+Y1)(X2+Y2) m5 = (Y1+Z1)(Y2+Z2) m6 = (X1+Z1)(X2+Z2)
group 2    X3 = xy*ym - byz3*xz
           Y3 = yp*ym + bxx9*xz
           Z3 = yz*yp + xx3*xy
```

with `xy = m4 − xx − yy`, `yz = m5 − yy − zz`, `xz = m6 − xx − zz`,
`bzz3 = b3·zz`, `ym = yy − bzz3`, `yp = yy + bzz3`, `byz3 = b3·yz`,
`xx3 = 3·xx` and `bxx9 = 3·b3·xx`.

**Nine reductions, not twelve**: each of the three outputs is two products under
one quotient, which the limb identity's shape allows for free.

**The three rows are glued by the frame, not by a bus.** Group 0 leaves `xx`,
`yy` and `zz` in words 49..73 and group 2 reads them there, as ordinary RAM words
on an ordinary RAM chain. Nothing new carries them — no new address space beyond
the family's own, no new presence rule — and `checker::memory_columns_from_log`
still covers every column. A send/receive bus keyed by `(invocation, stage, slot)`
was the alternative and it is **unsound** as a cross-row mechanism here: the
multiset that would pair a send with a receive has no way to say that the two
belong to the same invocation without a column the anchor's provenance rules
refuse.

**97 words, 388 bytes**, word-aligned per §4.

| words | holds | read by | written by |
| --- | --- | --- | --- |
| 0 | the selector: a curve **and** a group, one of `constants::ec_add::CODES` | every group | none |
| 1–8 | `X1` | groups 0, 1 | group 2 (`X3`) |
| 9–16 | `Y1` | groups 0, 1 | group 2 (`Y3`) |
| 17–24 | `Z1` | groups 0, 1 | group 2 (`Z3`) |
| 25–48 | `X2`, `Y2`, `Z2` | groups 0, 1 | none |
| 49–72 | `xx`, `yy`, `zz` | group 2 | group 0 |
| 73–96 | `m4`, `m5`, `m6` | group 2 | group 1 |

Group 2 writes its results **over** `X1`, `Y1` and `Z1`, which the first two
groups have by then finished reading. That is what keeps the frame at 97 words
rather than 121.

**The three codes of a curve must be invoked in group order.** Two transposed is
not a refusal anywhere — it is a different point, computed from lanes whose
previous contents were zero — so the order is not left to a caller:
`guest_sdk::recursion::ec_add_complete` walks it, and
`constants::ec_add::{SECP256K1_GROUPS, BN254_GROUPS}` are the two triples, held
to the `CODE_CURVE`/`CODE_GROUP` tables by `const` assertion.

### 16.3 What the circuit has to get right, and what it got wrong first

The six selectors are boolean and sum to `live`, so a live row claims exactly one
(curve, group) pair, and `selector_rule` ties that claim to **frame word 0** —
the selector columns and the word the guest wrote are one claim. `m_limb{k}_rule`
and `b3_rule` fix the curve's modulus limbs and its `b3 = 3b` to that claim's
literals, which is also their `2^32` bound: `m` and `b3` need no range check at
all. Every frame word carries a 32-bit bound as a `RANGE16` obligation on its
high halfword, and the twelve frame values carry a `< m` borrow chain whose
conclusion is gated to the groups that read them.

Each slot's four operands are committed columns pinned by degree-2 gates to
**bounded linear combinations** of those values, so the pin is also the bound and
an operand needs no range check of its own. The identity is then one shape for
all nine slots:

```text
A*B + C*D + 1024*m^2 = q*m + out
```

Three things about it are easy to get wrong, and two of them were.

- **`D` carries the sign, not the identity.** Group 2's slot 0 is
  `xy·ym − byz3·xz`, and a per-group sign on a product's coefficient is not
  expressible — a coefficient is one literal or one challenge — so the minus
  rides `D`, which is `xx + zz − m6` where the other slots' is `m6 − xx − zz`.
- **The offset is 1024 and 256 was wrong.** It exists to keep the quotient
  unsigned, and it must cover the most negative left-hand side any slot can
  reach. The binding slot is group 2's `Y3`, not its `X3`: `yp·ym + bxx9·xz`
  reaches `−(22·22 + 63·3)·m² = −673·m²`. At 256 the honest quotient of such a
  row is negative and the row **unprovable**, and `zz` above about `0.76m` is
  enough on its own — roughly a quarter of random invocations. It is a
  completeness bug and not a soundness one, which is exactly why nothing but an
  honest witness against the gates can find it: the executor computes the right
  answer, the guest agrees with its own software path, and only the prover fails.
- **A gated conclusion is `enable·(1 − b_7) = 0` and never `b_7 = enable`.** The
  second forces the borrow to 0 where `enable` is 0, so a value that *is* below
  the modulus on a row that does not read it becomes unprovable — and every lane
  is such a value, the six intermediates being zeroed by the guest's frame
  constructor and a group-2 row's `X1..Z2` being ordinary coordinates. That
  spelling made **every row of this family unprovable** while every shape test,
  the executor and both fixture guests passed. The chain's sixteen `canonical`
  gates are *ungated* and hold for any value, so a non-reading value still owes a
  real chain.

Both are now derived rather than argued: `the_offset_covers_every_slot` and
`the_carry_offset_covers_every_slot` read one operand-ceiling table, because the
same products bound the carry's width and the offset's floor and only one of the
two arguments had been made.

The sixteen limb equations telescope to the identity exactly when the last carry
is zero, which the last position forces by having no outgoing carry; `out`'s own
chain puts it below `m`. Integer division being unique, `out` is the reduction
and nothing else.

### 16.4 The height, and what it costs

`2^16`, and **forced rather than chosen**: the `RANGE16` channel needs sixteen
variables (§10.3), Mercury needs an even count, and `2^18` is four times worse.

One shard is a computed **20.5 GB** — 18.3 GB of forward pass, 0.7 GB of
committed base, 1.5 GB of the first bind's half-height table — against 5.1 GB for
`MOD_MUL` at the same height and ~11 GB for an execution shard. **So this was the
peak-setting family in a block until S26d**, which put `KECCAK_F` at `2^18` and
~60 GB a shard (§9.2); this one is second. That is a fact about the stage rather
than a problem it solved: the lever that remains is the group count, five groups
of two reductions being about two-thirds the width at two more invocations an
addition. `docs/handoff/S26c-sha256-ec.md` records the measured figure against
this estimate.

The channel is what makes the row narrow enough to be worth it at all. Without
it the 97-word frame's timestamp gaps alone are 3,686 bit columns against 194
chunk columns, and 24 more 32-bit values want bounding besides.
