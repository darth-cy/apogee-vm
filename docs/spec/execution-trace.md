# The execution trace

What every memory query of an execution is, when it happens and the order the trace records it in;
the emulator that produces a trace and the containers that hold one. The memory argument
([memory.md](memory.md)) and every family's frame are built on this convention.

## 1. The clock

Cycle `c` occupies the four timestamps `4c + Δ`, one per **slot** `Δ ∈ {0, 1, 2, 3}`
(`constants::memory::TS_STEP`). Every instruction is one cycle and nothing else is: a delegation
invocation rides the cycle that requested it, so the cycle count is the instruction count.

- **Cycles are numbered from 1.** Timestamp 0 is every address's initial write, and a read must
  strictly precede its write, so a cycle-0 pc query could not follow the value it reads.
- **The clock is 38 bits** (`TS_BITS`): every timestamp is below `2^38`, the last cycle is
  `2^36 − 1`, and the cycle that would pass it is the fatal `ClockOverflow`, raised before it is
  recorded.

## 2. Address spaces

| Tag | Space | Address | At timestamp 0 |
| --- | --- | --- | --- |
| 1 | `REG` | a register index, `0..32` | 0, `x0` included |
| 2 | `RAM` | the byte address of a 4-aligned word in RAM, a public window or the advice region | the image's bytes in RAM, 0 past them; the public input's and the advice's layouts; 0 in the journal |
| 3 | `PC` | 0 | the entry point |
| 4–9 | `DELEGATION_KECCAK_F` … `DELEGATION_EC_ADD`, a base-format delegation family's anchor each | a frame base | no initial write |
| 10 | `FIELD` | a cell, any `u32` | 0 |
| 11–14 | `DELEGATION_FR_OP` … `DELEGATION_FQ_OP`, a recursion family's anchor each | a frame base | no initial write |

The tags are nonzero so that no real tuple is all zeros, as `x0`'s initial write would be. A byte or
halfword access queries its word, and `trace::InitialMemory` is what RAM starts from. An anchor
space, in [delegation.md](delegation.md) §3's order, is a delegation family's type, not memory: a
query there reads the tuple stamped 0 with value 0, whatever came before; requests pair with
invocations and nothing chains ([delegation.md](delegation.md) §5). Field cells hold whole `Fr`
elements, reached only by the recursion families ([recursion.md](recursion.md) §2).

## 3. A query

A memory query is one event at one address (`trace::MemoryEvent`): a **read** of `read_value`, last
written at `read_ts`, and a **write** of `write_value` at `ts = 4c + Δ`.

- A query that only reads writes back what it read: a register read or a load is one query.
- `read_ts < ts`, strictly; the gap `ts − read_ts − 1` is below `2^38`.
- Queries at distinct addresses may share a slot; two at one address never do. An address may be
  queried at two slots of a cycle — `add a0, a0, a1` reads `a0` at slot 1 and writes it at slot 3
  — which is why the log is ordered by slot.

## 4. The frame of each instruction class

Slot 0 is the pc query, every cycle: `pc` read, `next_pc` written. A register query exists for
every register field of the decoded instruction, whatever register it names, `x0` included.

| Class | Δ = 1 | Δ = 2 | Δ = 3 |
| --- | --- | --- | --- |
| `lui`, `auipc`, `jal` | | | `rd` |
| `jalr`, register-immediate | `rs1` | | `rd` |
| branches | `rs1` | `rs2` | |
| register-register, M | `rs1` | `rs2` | `rd` |
| loads | `rs1` | the word, read | `rd` |
| stores | `rs1` | `rs2` | the word, the stored bytes merged in |
| `lr.w` | `rs1` | | the word, written back; `rd` ← it |
| `sc.w` | `rs1` | `rs2` | the word ← `rs2`; `rd` ← 0 |
| AMOs | `rs1` | `rs2` | the word ← `op(old, rs2)`; `rd` ← `old` |
| `fence` | | | |
| `ecall` | `a7` | `a0` (§6) | `a0` ← the result; a delegation's mirror query |

`ebreak` has no row (§10). An atomic's row and a delegation request's carry two queries at slot 3,
at distinct addresses. A family's frame is the union of its instructions' queries
([memory.md](memory.md) §2). **`next_pc`** is the fall-through — `pc + 2` after a compressed
instruction, `pc + 4` otherwise — except a `jal`'s or taken branch's `pc + imm`, a `jalr`'s
`(rs1 + imm) & !1`, and the exit row's `HALT_PC` ([memory.md](memory.md) §5).

An invocation's accesses ride its requesting cycle but belong to its own family's row: its frame
words in RAM at slot 0 (`constants::delegation::FRAME_DELTA`), a `FIELD_IO` invocation's eight data
words in RAM at slot 1 (`constants::field_io::DATA_DELTA`), and a recursion family's field cells
at slots of its own ([delegation.md](delegation.md) §4, [recursion.md](recursion.md) §2.1).

## 5. The x0 rule

`x0` is an ordinary register in the trace and a constant in the machine: it starts at 0, a read of
it is a `REG` query at address 0, and an instruction whose `rd` is `x0` logs its slot-3 write with
value 0, whatever it computed. So every query at `x0` reads and writes 0, which the x0 gadget
enforces ([memory.md](memory.md) §2).

## 6. ecall

An ecall's row is one cycle of `ADD_SUB_LUI_AUIPC`. It reads `a7` at slot 1 and writes `a0` at
slot 3; the rest depends on the number ([ecall-abi.md](ecall-abi.md)):

| `a7` | Δ = 2 | `a0` written | `next_pc` | Besides |
| --- | --- | --- | --- | --- |
| `EXIT` | `a0`, the status | the status | `HALT_PC` | the execution stops |
| a delegation number | `a0`, the frame base | 0, or for a recursion type the base past the frame ([recursion.md](recursion.md) §1.4) | fall-through | the mirror query at the frame base (§7); the invocation (§4) |
| any other | none | `-ENOSYS` | fall-through | no proof admits the row ([ecall-abi.md](ecall-abi.md) §3) |

## 7. The order of the log

Events are recorded in cycle order and, within a cycle, by slot and then by role: the pc query;
then an invocation riding the cycle, its frame words in frame order and a `FIELD_IO` invocation's
data words after them; then one query per role the row has, in `trace::ROLES` order:

| Role | Slot | Space | What |
| --- | --- | --- | --- |
| `rs1` | 1 | `REG` | `rs1`; an ecall's `a7` |
| `rs2` | 2 | `REG` | `rs2`; an ecall's argument `a0` |
| `load` | 2 | `RAM` | a load's word |
| `ram` | 3 | `RAM` | a store's or an atomic's word |
| `rd` | 3 | `REG` | `rd`; an ecall's result `a0` |
| `delegate` | 3 | the requested family's anchor space | a delegation request's mirror query |

`ROLES` is in slot order, so the log is in timestamp order, which `MemoryState::record` asserts;
`trace::Row::present` holds one bit per role in a `u8`, and no two roles share a `(space, slot)`
pair. The atomics family keeps its word at slot 3 for every instruction, `lr.w` included, so one
frame serves the whole A extension.

## 8. Routing

Every cycle goes to the one family whose decoded table claims its pc ([program.md](program.md) §4);
a pc no table claims, or one claimed by a family not its instruction's, panics the tracer. An
invocation goes by its type to its family's buffer.

## 9. The trace-level memory check

`MemoryEventLog::self_check(&InitialMemory)` runs the memory argument natively over a whole log.
First the timestamp rules: every address one its space has, every timestamp on the clock and in
order, every read before its write, one query per address and timestamp. Then the balance: as
multisets of `(space, address, timestamp, value)`, an initial write at timestamp 0 of every touched
address plus every query's write equals every query's read plus a teardown read of every address's
last write. With one write per address and timestamp and no negative gap, this pairs each read
with the last write before it: sequential consistency. What it cannot see:

- Teardown is each address's last write, taken from the log, so everything after an address's last
  honest query balances by construction: a final value changed, a final query moved later or
  added, trailing cycles removed. In a proof the final values are the boundary scalars and the
  window families' teardown columns, fixed before any memory challenge, and the verifier fixes
  `x0`'s and the pc's ([memory.md](memory.md) §4, §5).
- An anchor-space query is credited with its invocation's two tuples and balances alone; that
  requests and invocations pair 1:1 is the circuits' ([delegation.md](delegation.md) §5).
- Field-cell accesses are not events ([recursion.md](recursion.md) §2.1).

## 10. The emulator

`crates/emulator` runs RV32IMAC on one hart over a `ProgramImage`, with no interrupts and no
privilege levels; `aq`/`rl` and `fence` order nothing. `emulator::run` returns an `Execution`: the
registers, the exit status, the cycle count and the public values. `emulator::trace_run` returns
the family buffers, the `MemoryEventLog` and the `CycleProfile` too, and `emulator::StreamingRun`,
the prover's pull-based tracer, hands over a family's buffer as a `ShardChunk` the moment it reaches
its height ([streaming.md](streaming.md) §2). The three differ only in what records a cycle, and a
run is a pure function of `(image, io)`, with no clock, randomness or threads, so two runs cut the
same shards. A nonzero exit status is an execution, not an error.

Three points differ from a hosted RV32IMAC. `sc.w` always succeeds, storing and writing 0, as the
circuits do ([memory-ops.md](memory-ops.md) §6). A misaligned halfword or word access is fatal,
never split. The instruction stream is the image decoded at load, so a store into `.text` changes
RAM and not what executes.

Every other stop is a fatal `EmuError`, and `run` and `trace_run` return no trace beside one:
`NotAnInstruction` (the all-zero halfword included), `IllegalInstruction`, `Ebreak`, `Misaligned`
(a frame base too), `OutOfBounds` (an access outside [ecall-abi.md](ecall-abi.md) §6's regions, an
advice word past what the host supplied, or a frame not wholly in RAM), `ClockOverflow`,
`PublicInputTooLong` and `JournalTooLong` (the input, or the journal's length word at exit, above a
window's payload), `DelegationFamilyAbsent` (on the tracing paths, a delegation number the image did
not declare) and `DelegationFrame` (a frame its family has no witness for,
[delegation.md](delegation.md) §6). An unassigned ecall number is not an error but `-ENOSYS`
(§6).

There is no second executor: `crates/emulator/tests/trace.rs` restates §4's table and checks every
traced row against it, and §9's check and the checker's multiset, memory and family-row suites hold
the rest.

## 11. Trace containers

`crates/trace` holds what an execution leaves; the emulator is its only producer.

- **Family buffers.** `trace::FamilyTraces` holds one buffer per family of the `VmConfig`. A
  `FamilyTrace`, empty for a window family, is raw live rows, column-major, in small integer types:
  `cycle`, `pc`, `next_pc`, `present`, and per role `addr`, `read_ts`, `read_value`,
  `write_value`; no padding, no polynomial. A row stores everything its queries carry but a write
  timestamp, `4c + Δ`, and the pc query's read timestamp, `4(c − 1)`. A delegation family's
  `DelegationTrace` has a row per invocation: the requesting cycle, the frame base, the frame
  words, and a recursion family's cell and data-word accesses.
- **`RowSlice`, `FrameSlice`.** One shard's rows, `[i·h, min((i + 1)·h, len))`, borrowed: what the
  memory column builders read, never the log ([memory.md](memory.md) §2). `Row::delegation_space`
  recovers a mirror query's space from the `a7` the row read.
- **`MemoryState`**, the last-access tables: each register's, the pc's, each RAM word's and each
  field cell's last `(ts, value)`. `O(touched addresses)`, and all the register and pc boundary,
  the RAM window list (`trace::init_windows`) and the window families' teardown need.
- **`MemoryEventLog`**, the events and a `MemoryState`: `O(cycles)`, kept only by `trace_run`, read
  by §9's check, the `TraceArchive` and `checker::memory_columns_from_log`, the independent reading
  the column builders are held to.
- **`TraceArchive`**, the post-execution snapshot: buffers, log, profile, public values and advice.
  Its file is two `postcard` values, five phase sections and then their timings, so the
  deterministic payload is a byte prefix of it, and only a canonical encoding of self-consistent
  parts is read back. No proving path reads one; `checker::TamperHarness` and the retained archived
  path do ([streaming.md](streaming.md) §6).
- **`CycleProfile`, `ShardPlan`.** The profile counts rows per family, cycles for a cycle-owning
  family (summing to the cycle count) and invocations for a delegation family.
  `trace::plan_shards` is `⌈count / height⌉` per family; a window family plans 0 there, its count
  being the prover's ([streaming.md](streaming.md) §4).
