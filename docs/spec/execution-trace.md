# The execution trace

Frozen at S12. **This document is the timestamp convention**: what every memory query
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
- **Every instruction is one cycle**, except a `read` or `write` ecall that moves bytes,
  which is one cycle per word moved and then its own (section 5). Those extra cycles are
  **transfer cycles**, and they count: an execution's cycle count, its cycle profile and
  its shard plan all include them.

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

- A query that only reads writes back what it read — so a register read, a load's data
  read and a `write` transfer are each one query, never two.
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
| an ecall transfer | | | the word |

`ebreak` has no row: it is a fatal guest error. The atomics family is the one that fills
all four slots in one cycle, and it does so with slot 3 shared by the RAM query and the
`rd` write, which sit at distinct addresses.

**`next_pc`** is the sequential fall-through — `pc + 2` for a two-byte instruction,
`pc + 4` otherwise — except where control moves: a jump's target, a taken branch's, and
an ecall transfer's unchanged `pc`.

## 5. The x0 rule

`x0` is an ordinary register in the trace and a constant in the machine: it starts at 0
like `x1`–`x31`; a read of `x0` is a REG query at address 0; an instruction whose `rd`
is `x0` logs its slot-3 write-back **with value 0**, whatever it computed. So `x0`'s
queries read and write 0, always, and how the constraints enforce that is S14's choice
over this fixed trace behaviour.

## 6. ecall

An ecall's own row reads `a7` at slot 1, the argument registers its number uses at
slot 2, and writes `a0` at slot 3; its `next_pc` is `pc + 4`, always.

| Number | Arguments read | `a0` written |
| --- | --- | --- |
| `READ` 63 | `a0` fd, `a1` buf, `a2` count | bytes delivered, `min(count, left)`; `-EBADF` for a descriptor other than 0 and 3 |
| `WRITE` 64 | `a0` fd, `a1` buf, `a2` count | `count`; `-EBADF` for a descriptor other than 1 and 2 |
| `EXIT` 93 | `a0` status | the status, unchanged; execution stops after this row |
| `PRECOMPILE_POSEIDON2` 0x500 | `a0` state pointer | `-ENOSYS` until its circuit exists; the row already has the frame it will keep |
| anything else | none | `-ENOSYS` |

The three slot-2 reads sit at distinct registers, which is what lets them share the
slot. `docs/spec/ecall-abi.md` is the normative meaning of each call.

**Transfer cycles.** A `read` or `write` that moves `n > 0` bytes to or from
`[buf, buf + n)` is preceded, immediately, by one transfer cycle for each word those
bytes touch, in ascending address order. A transfer cycle's slot 0 re-writes the
unchanged `pc` (`next_pc = pc`), and its slot 3 is the word's RAM query: for a `read`,
the word with the delivered bytes merged in — partial words at either end keep their
other bytes — and for a `write`, the word read and written back. Nothing else. The
ecall's own row then comes last and writes the real `next_pc`, so pc continuity holds
through every transfer, and every ecall row has the same fixed shape whether or not
bytes moved. A call that moves nothing has no transfer cycles. A byte outside the RAM
window is the fatal guest error `OutOfBounds`, never an answer.

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
| `ram` | 3 | RAM | a store's, an atomic's or a transfer's word |
| `rd` | 3 | REG | `rd`; an ecall row's `a0` result |

The rule underneath is **by slot, then by role number**, and every role today is
numbered in slot order, so it is exactly the table's order and the log is ordered by
timestamp. A role appended later — an ecall's `a3`, say — keeps its new number and takes
its place in a cycle by its slot, so appending one renumbers nothing. The `present` mask
is a `u8` with one bit to spare; a ninth role widens it, which is a schema change.

The atomics family keeps its RAM query at slot 3 for every instruction it owns, `lr.w`
included, though `lr.w` has no `rs2` and a load puts its word at slot 2: one family, one
frame, as the stage prompt keeps the whole A extension in one circuit.

## 8. Routing

Every cycle goes to exactly one family: the one whose decoded table claims its pc.
Transfer cycles sit at their ecall's pc, so they belong to the add/sub/lui/auipc family
with it. A pc no table claims is impossible after S11's partition; the tracer panics on
one rather than skipping it.

## 9. The trace-level memory argument

`MemoryEventLog::self_check` is this section run: the writes — an initial write at
timestamp 0 of every touched address, holding its section 2 value, plus every query's
write — equal, as a multiset of `(space, address, timestamp, value)`, the reads — every
query's read, plus a teardown read of every address's last write. With one write per
address per timestamp and every gap non-negative, that balance pairs each read with
exactly the last write before it, which is sequential consistency. Teardown is taken
from the log itself, so everything after an address's last honest query balances by
construction — its final value changed, a final query moved later or added, whole
trailing cycles removed — exactly as in the argument, where teardown's values and the
cycle count are bound by other means. For a snapshot, `TraceArchive` holds the log to
the family rows event for event, which is where the cycle count lives.
