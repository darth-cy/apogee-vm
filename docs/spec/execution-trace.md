# The execution trace

Frozen at S12. S14 amended §4, §6 and §9 for the halting sentinel and the register and
PC boundary of `docs/spec/memory.md` §4–§5. S21 appended the eighth role, `delegate`, and
a delegation call's row and its invocation's frame (§4, §6, §7;
`docs/spec/delegation.md` §4.1 and §5.1). **S25 deleted the transfer cycle** (§1, §4, §6):
a provable `read` moves one word, on the ecall's own row, and a `write` moves no memory
event at all — so every instruction is one cycle again and every live row advances the pc.
No role was added and none moved.

**This document is the timestamp convention**: what every memory query
of an execution is, when it happens, and in what order the trace records it. S14's
memory-argument fill and S16's ecall-row constraints cite it; they do not restate or
reinvent it. `crates/emulator` produces a trace that follows it, `crates/trace` holds
one, and `crates/emulator/tests/trace.rs` restates the frame table below from this page
rather than from the emulator and checks every row of every traced guest against it.

The numbers live in `constants::memory` and `constants::address_space`.

## 1. The clock

Cycle `c` occupies the four timestamps `4c + Δ`, one per **slot** `Δ ∈ {0, 1, 2, 3}`
(`TS_STEP = 4`). Every family uses the same four-slot stride, whether or not it fills
all four.

- **Cycles are numbered from 1.** Timestamp 0 is the initial write of every address
  (section 2), and a query's read must strictly precede its write, so a cycle-0 pc
  query — which would write at timestamp 0 — could not follow the initial write it
  reads.
- **The clock is 38 bits**: every timestamp is below `2^38` (`TS_BITS = 38`), so the
  last cycle is `2^36 - 1`. An execution that would run past it stops with the named
  fatal error `ClockOverflow`, never a wrap.
- **Every instruction is one cycle.** No exception. Until S25 a `read` or a `write` that
  moved bytes was preceded by one *transfer cycle* per word — a cycle at the same pc with
  `next_pc = pc` — and S14's open question 10 asked how such a cycle's RAM write could be
  confined. The answer this repository took is that it is not: a provable `read` delivers
  exactly one 4-aligned word and carries that word's RAM query on **its own row**, which
  already reads the buffer and the count it must be checked against
  (`docs/spec/ecall-abi.md` §4). A `write` carries no RAM query at all. So the exception
  is gone rather than amended, and with it the machine's only row that did not advance the
  pc.

## 2. Address spaces

| Space | Tag | Address | Initial value, at timestamp 0 |
| --- | --- | --- | --- |
| registers | `REG = 1` | the register index, `0..32` | 0, `x0` included |
| RAM | `RAM = 2` | the byte address of the **4-aligned word**, in `[RAM_ORIGIN, RAM_ORIGIN + RAM_LENGTH)` | the program image's bytes, zero wherever no segment has a file byte |
| program counter | `PC = 3` | 0, the only address | the entry point |

The tags are nonzero so that no real tuple is all zeros: `(REG, x0, ts 0, value 0)` is
the initial write of `x0`, and with `REG = 0` it would be. RAM is word-granular: a byte
or halfword access queries the word it lies in.

## 3. A query

A memory query is one event at one address: a **read** of `read_value`, last written at
`read_ts`, and a **write** of `write_value` at `ts = 4·cycle + Δ`.

- A query that only reads writes back what it read — so a register read and a load's
  data read are each one query, never two.
- `read_ts < ts`, strictly: the gap `ts - read_ts - 1` is non-negative and, by the
  clock, below `2^38`.
- **Queries at distinct addresses may share a slot; two queries at one address never
  do.** An address may be queried at two slots of one cycle — `add a0, a0, a1` reads
  `a0` at slot 1 and writes it at slot 3 — which is why the ordering is by slot and not
  by cycle.

## 4. The frame of each instruction class

Which queries a cycle makes, by slot. Slot 0 is the pc query, every cycle: `pc` read,
`next_pc` written. A register query exists for **every register field the instruction's
form has, whatever register it names** — `x0` included — and for none it lacks.

| Class | Δ = 1 | Δ = 2 | Δ = 3 |
| --- | --- | --- | --- |
| `lui`, `auipc`, `jal` | | | `rd` |
| `jalr`, register-immediate | `rs1` | | `rd` |
| branches | `rs1` | `rs2` | |
| register-register, M | `rs1` | `rs2` | `rd` |
| loads | `rs1` | the word, read | `rd` |
| stores | `rs1` | `rs2` | the word, read and rewritten with the stored bytes merged in |
| `lr.w` | `rs1` | | the word, read and written back; `rd` |
| `sc.w` | `rs1` | `rs2` | the word, rewritten to `rs2`; `rd` ← 0 |
| AMOs | `rs1` | `rs2` | the word, rewritten to `op(old, rs2)`; `rd` ← `old` |
| `fence` | | | |
| an ecall's own row | `a7` | its arguments | `a0` ← the result |
| a **delegation** request's row | `a7` | `a0`, the frame base | `a0` ← 0; and `delegate`, the mirror query |
| a `read`'s row | `a7` | `a0` fd, `a1` buf, `a2` count | `a0` ← the count delivered; and the **word at `a1`** |

`ebreak` has no row: it is a fatal guest error. A `read`'s row and the atomics family
both fill all four slots in one cycle, each with slot 3 shared by the RAM query and the
`rd` write, which sit at distinct addresses. A `write`'s row is an ordinary ecall row:
its bytes leave through no memory event, because the query it used to make bound nothing
(§6).

**`next_pc`** is the sequential fall-through — `pc + 2` for a two-byte instruction,
`pc + 4` otherwise — except where control moves: a jump's target, a taken branch's, and
the exit row's `HALT_PC` (section 6). **Every live row advances the pc**, since S25 left
no row that rewrites it unchanged.

## 5. The x0 rule

`x0` is an ordinary register in the trace and a constant in the machine: it starts at 0
like `x1`–`x31`; a read of `x0` is a REG query at address 0; an instruction whose `rd`
is `x0` logs its slot-3 write-back **with value 0**, whatever it computed. So `x0`'s
queries read and write 0, always, and how the constraints enforce that is S14's choice
over this fixed trace behaviour.

## 6. ecall

An ecall's own row reads `a7` at slot 1, the argument registers its number uses at
slot 2, and writes `a0` at slot 3; its `next_pc` is `pc + 4`, except on an `EXIT` row,
which writes the halting sentinel `constants::memory::HALT_PC = 1` instead
(`docs/spec/memory.md` §5). `HALT_PC` is odd and no instruction's `next_pc` is, so a
pc that ends there ended on an exit row.

| Number | Arguments read | `a0` written |
| --- | --- | --- |
| `READ` 63 | `a0` fd, `a1` buf, `a2` count | bytes delivered, `min(count, left)`; `-EBADF` for a descriptor other than 0 and 3 |
| `WRITE` 64 | `a0` fd, `a1` buf, `a2` count | `count`; `-EBADF` for a descriptor other than 1 and 2 |
| `EXIT` 93 | `a0` status | the status, unchanged; `next_pc` is `HALT_PC`, and execution stops after this row |
| a **delegation** number | `a0`, the frame base | 0, and the row carries its mirror query; `-ENOSYS` on an executor without the circuit |
| anything else | none | `-ENOSYS` |

The three slot-2 reads sit at distinct registers, which is what lets them share the
slot. `docs/spec/ecall-abi.md` is the normative meaning of each call.

**A `read` moves one word, on this row.** A `read` on fd 0 or fd 3 requires
`a2 = constants::ecall::READ_WORD_BYTES = 4` and a 4-aligned `a1` inside the RAM window;
anything else is a **fatal guest error**, not a short answer, because the circuit pins
both (`docs/spec/ecall-abi.md` §4). Its slot-3 RAM query is the word at `a1`, read and
written back with the delivered bytes merged into the low `n` of them, where `n` is what
`a0` gets — `min(4, left)`. **The query is made even at end of stream**, writing the word
back unchanged, which is what lets the circuit key the query's mask on "this row is a
`read`" and have no "did it move anything" selector to constrain. A `read` answering
`-EBADF` moves nothing and makes no query.

**A `write` moves no memory event at all.** It reads its bytes out of RAM and appends
them to its stream, and the query it used to make bound nothing: what ties fd 1 to the
execution is the guest's own `io_digest` over the bytes it assembled with ordinary loads
and stores, which the memory argument does bind (`docs/spec/memory.md` §10). Only the
RAM-window bound survives, because reading outside the window is a fatal guest error
however the bytes are used.

**What a guest pays for this.** One `ecall` per word read, and its own copying:
`guest_sdk::read_input` loops a word at a time through an aligned scratch, about six
cycles a word. On S24's 717-byte witness that is ~1,100 cycles; it grows linearly, and it
is the number to watch if a much larger stream ever arrives on fd 0.

## 7. The order of the log

Events are recorded in cycle order and, inside a cycle, **the pc query first, then one
query per role present, in this frozen order**:

| Role | Slot | Space | What |
| --- | --- | --- | --- |
| `rs1` | 1 | REG | `rs1`; an ecall row's `a7` |
| `rs2` | 2 | REG | `rs2`; an ecall row's `a0` |
| `arg1` | 2 | REG | an ecall row's `a1` |
| `arg2` | 2 | REG | an ecall row's `a2` |
| `load` | 2 | RAM | a load's word |
| `ram` | 3 | RAM | a store's, an atomic's or a `read`'s word |
| `rd` | 3 | REG | `rd`; an ecall row's `a0` result |
| `delegate` | 3 | the delegation family's own | a delegation request's mirror query, at the frame base it handed over |

The rule underneath is **by slot, then by role number**, and every role today is
numbered in slot order, so it is exactly the table's order and the log is ordered by
timestamp. A role appended later — an ecall's `a3`, say — keeps its new number and takes
its place in a cycle by its slot, so appending one renumbers nothing. S21's `delegate` is
the eighth and it took the last bit: **the `present` mask is a full `u8` now**, and a
ninth role widens it, which is a schema change.

A **delegation invocation's** frame accesses are not roles and are not this row's: they
ride the requesting cycle at `constants::delegation::FRAME_DELTA`, which is 0, so they
follow the pc query and precede the roles, and they belong to the delegation family's own
row (`docs/spec/delegation.md` §4.1). `(RAM, 0)` is a pair no role has, which is how
`trace`'s frame builder tells them apart.

The atomics family keeps its RAM query at slot 3 for every instruction it owns, `lr.w`
included, though `lr.w` has no `rs2` and a load puts its word at slot 2: one family, one
frame, as the stage prompt keeps the whole A extension in one circuit.

## 8. Routing

Every cycle goes to exactly one family: the one whose decoded table claims its pc. A pc
no table claims is impossible after S11's partition; the tracer panics on one rather than
skipping it.

## 9. The trace-level memory argument

`MemoryEventLog::self_check` is this section run: the writes — an initial write at
timestamp 0 of every touched address, holding its section 2 value, plus every query's
write — equal, as a multiset of `(space, address, timestamp, value)`, the reads — every
query's read, plus a teardown read of every address's last write. With one write per
address per timestamp and every gap non-negative, that balance pairs each read with
exactly the last write before it, which is sequential consistency. Teardown is taken
from the log itself, so everything after an address's last honest query balances by
construction — its final value changed, a final query moved later or added, whole
trailing cycles removed. The argument is no different for final values: the registers'
final tuples come from boundary scalars and a RAM word's teardown from a window family's
columns (`docs/spec/memory.md` §3–§4), both supplied by the prover and absorbed before
any memory challenge is drawn, so a changed final value or a final query moved later or
added is caught by the row constraints, not by teardown. What the verifier fixes is two
final values: `x0`'s, 0, and the pc's, `HALT_PC`. Only an exit row writes `HALT_PC`, so
a trace whose trailing cycles, exit row included, were removed cannot balance
(`docs/spec/memory.md` §4–§5, which also lists what S16's constraints owe the
sentinel). For a snapshot, `TraceArchive` holds the log to the family rows event for
event, which is where the cycle count lives.
