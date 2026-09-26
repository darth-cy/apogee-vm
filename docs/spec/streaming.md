# The streaming prover: two passes, one partial shard per family

New at S26. It adds **no protocol**: no transcript message, no challenge, no
wire form, no circuit, no constant. It changes exactly one thing — *when* a
column exists — and the acceptance is that the block comes out byte for byte the
same (§7).

It cites `docs/spec/block-proof.md` for the block and the shard cut,
`docs/spec/shard-proof.md` §2 for the global commit phase, `docs/spec/memory.md`
for the memory argument and the windows, and `docs/spec/public-values.md` for the
three regions; it restates none of them.

| crate | what |
| --- | --- |
| `crates/trace` | `MemoryState`, the last-access tables apart from the log; `RowSlice` and `FrameSlice`, a shard's rows; the row-reading column builders |
| `crates/emulator` | `StreamingRun`, the pull-based tracer, and `ShardChunk` |
| `crates/prover` | `prove_block_streaming`, the two passes and the backpressure |
| `crates/checker` | `memory_columns_from_log`, the log reading the row reading is held to |

---

## 1. What it is for, in numbers

Before S26 a block's prover was `O(total shards)` in memory during its commit
phase and `O(cycles)` before that, and both are measurements rather than
estimates:

| what | per unit | S25's mini-block (24.2M cycles, 37 shards) | the pinned full block (~1.72e9 cycles, ~1,900 shards) |
| --- | --- | --- | --- |
| `prover::statement_inputs`' memory columns, all live at once | ~300 MB a shard | 11 GiB | **500–600 GB** |
| `emulator::trace_run`'s family buffers | 177 B a cycle | 4.3 GB | ~305 GB |
| its memory event log | ~128 B a cycle | 3.1 GB | ~220 GB |

The first line is `docs/handoff/S25-block.md` §7, measured. The second and third
are the struct definitions — `trace::FamilyTrace` is 4 + 32 columns of small
integers a row, `trace::MemoryEvent` is 32 bytes and a cycle has four or five —
and together they are why streaming the commit phase alone would not have been
enough: an `r8i.8xlarge` has 256 GB and the *trace* of that block is 520 GB.

**What the streaming prover holds instead**, and nothing else:

- one **partial** buffer per family, at most `height − 1` rows (§3.1);
- the **last-access tables**, `O(touched addresses)` (§3.2);
- at most `max_in_flight` **filled** shards, each being proved (§5);
- the statement's commitment metadata: `64 · columns` bytes a shard, and the
  `ShardProof`s, which are the output.

Nothing accumulates between the executor and the proving workers. A shard that
has been proved is gone.

---

## 2. The two passes

```text
PASS 1 — EXECUTE + PRECOMMIT                PASS 2 — REEXECUTE + PROVE
  execute the guest                           execute the same guest again
  a shard fills → build its M columns         a shard fills → queue it
  commit M, keep the 64-byte points           the queue reaches N → prove them
  drop the columns and the shard              write the proofs, drop the shards
  at exit: the window families' shards        at exit: the window families'
  the statement, then G1–G11                  assemble the BlockProof
```

**Pass 1 must produce the exact ordered set of per-shard memory commitments that
`statement_inputs` and `global_commit_phase` would have produced**, and it does
so by construction rather than by comparison:

- a commitment is `[f(τ)]_1` of one column, an MSM that reads no transcript, so
  *when* it is computed cannot affect it;
- what the global transcript absorbs is the list in **statement order** —
  `INIT_TEARDOWN`, `ZERO_WINDOWS`, then every other family ascending
  (`verifier_core::statement_shards`) — and pass 1 collects its commitments
  against their `(family, index)` and places them into that order before
  absorbing anything. Shards fill in *execution* order, which is a different
  order, and the two init families' shards do not exist until the execution is
  over.

**Pass 2 must regenerate the same shard boundaries**, and it does because the
emulator is a pure function of `(image, io)`: no clock, no randomness, no
threads, and its one hash map is accessed by key. Two runs give identical cycle
numbering, identical rows, and therefore identical cuts. `prove_block_streaming`
asserts pass 2's cycle profile and `Execution` equal pass 1's, which is what
turns that reasoning into a check.

**The `M` columns are not recommitted in pass 2, and that is stronger than
recommitting them.** A shard's opening builds `cm*` from the *statement's*
memory commitments — pass 1's — while its polynomial side is pass 2's columns.
A pass that built different columns therefore produces an opening that **fails
verification**. The prompt's "optional but valuable" recommit-and-assert would
cost a second full commit phase (15% of the mini-block's wall clock) to catch,
as a prover-side panic, exactly what the verifier already catches.

---

## 3. What survives an execution, and what does not

### 3.1 The rows

A shard's rows are `[index·h, min((index+1)·h, len))` of its family's buffer —
`docs/spec/block-proof.md` §5.1, unchanged. The streaming executor produces that
cut directly: it appends rows to one partial buffer per family and, **the moment
a buffer reaches that family's height**, hands the buffer over as a
`ShardChunk` and starts a fresh one. So a partial buffer never holds more than
`height − 1` rows at a record boundary and a chunk never has to be split, which
matters because one instruction can commit many cycles — a `read` or `write`
ecall commits one *transfer cycle* per word it moves
(`docs/spec/execution-trace.md` §6).

The tail is the partial buffers at exit, each the family's last short shard.

A fill therefore reads its shard through `trace::RowSlice` (a cycle-owning
family) or `trace::FrameSlice` (a delegation family), which are borrowed windows
into a buffer. The archived path makes one by slicing the archive; the streaming
path makes one over the chunk it has just been handed. **That is the whole of
what the two paths do differently**: one `prover::ShardSource`, one fill, one
`prove_shard_columns`.

### 3.2 The memory

`trace::MemoryState` is the **last-access tables** — per register, per RAM word
and the pc, the `(timestamp, value)` of the last write — and it is what
`MemoryEventLog::record` was already maintaining in order to fill each new
query's read side. It is `O(touched addresses)`, not `O(cycles)`.

Everything a statement needs beyond a shard's own rows is a function of exactly
that state:

| what | where |
| --- | --- |
| the register and pc boundary, 64 scalars | `trace::build_boundary_finals` |
| the `ZERO_WINDOWS` shard list | `trace::init_windows` |
| every RAM window's teardown columns | `trace::build_init_teardown_columns` |
| a value window's teardown columns | `trace::build_value_window_columns` |

So a streaming run keeps the tables and **never collects an event at all**.
`emulator::trace_run` still keeps the whole log, because a `TraceArchive` is
every event (`docs/spec/shard-proof.md` §10) and the archived path is what
resume, the tamper harness and every committed fixture use.

Two consequences worth stating rather than discovering:

- **A window family's shard is not a fact until the execution is over.** Its
  teardown column is every address's *last* write. `prover::ShardRows::Window`
  is the arm that carries the state, and it exists so that no cycle-owning fill
  can reach a state that is not yet final.
- **The window builders probe per row rather than filtering the whole final
  state.** A window is `height` addresses and an execution touches far more, so
  the old scan was `O(windows × touched words)` where probing is
  `O(windows × height)`.

### 3.3 The one thing a row does not store

A buffer does not store the pc query's read timestamp, because it is always
`4·(cycle − 1)`: the pc's last write before cycle `c` is cycle `c − 1`'s pc
query, whatever family owned that cycle. Everything else a cycle's events carry
is in the row.

The exception that needed care is the **delegation mirror query's address
space**. `trace::Role::Delegate`'s space is the row's and not the role's — the
space *is* the delegation type (`docs/spec/delegation.md` §5.1) — and the
whole-log builder read it off the event. A row recovers it from its own `a7`,
which a delegation row reads at slot 1 (`docs/spec/execution-trace.md` §6):
`trace::Row::delegation_space`. That is the one derivation the row reading has to
make that the log reading did not, and it is the reason §7's comparison runs over
guests that make delegation calls.

---

## 4. The statement is pass 1's

Pass 2 does not re-derive the statement. The window list, the shard counts, the
boundary and the public values are absorbed and challenged at the end of pass 1,
and pass 2 proves shards *against* them. What pass 2 asserts is that its own
execution agrees — the cycle profile and the `Execution`, which are small — and
what a divergence in the columns costs is a proof that does not verify (§2).

The shard counts are pass 1's other closing act, and the cut the executor made
is checked against `trace::plan_shards` family by family. The two cannot differ
— both are `ceil(rows / height)` over the same rows — and the assertion is what
says so out loud.

---

## 5. Backpressure

`prove_block_streaming(setup, io, max_in_flight)`. `max_in_flight` is the number
of **filled** shards that may be held between the executor and the proving
workers, and therefore what bounds the peak: a batch of that many is proved with
one `rayon` parallel iterator, each task building its shard's columns, its base
layer, its GKR proof and its opening and then dropping all of it.

It is an argument and not a constant because the caller is the only one that
knows the machine — a shard's base layer plus its forward pass is about 1.5 GB at
`2^20` — and it is the knob `RAYON_NUM_THREADS` used to be. It must be at least
1.

**The block does not depend on it.** Shards are placed by their statement
position, and each proof is a function of the global state and its own columns
alone, so the schedule cannot reach a challenge — the same argument
`docs/spec/block-proof.md` §5.2 makes about the thread count.
`crates/prover/tests/streaming.rs`' `a4` proves the bytes equal at 1 and at 8.

**There are no threads and no channels.** Master anti-goal 7 bans both, and the
batch-then-prove shape needs neither: the executor runs until the queue is full,
the queue is proved, the executor resumes. Execution is under 1% of a block's
wall clock (S25 measured 4.3 s of 850 s), so the overlap a producer/consumer
queue would buy is not worth a thread.

---

## 6. What the streaming path does not have

**No phase snapshots and no resume.** The archive's five sections are built on a
post-execution section holding the whole trace (`docs/spec/shard-proof.md` §10),
which is the thing this path exists not to have. `prove_block` and
`TraceArchive` are unchanged and keep resume, `checker::TamperHarness` and every
committed fixture; `prove_block_streaming` is what a block too large to archive
uses. A streaming run that is killed re-executes, and execution is cheap.

**No `TraceArchive` at all**, so no `tools/bench` phase timings from one. The
streaming path returns a `StreamingReport` instead: the cycle count, the shard
count, the peak in flight, and the two passes' execute and prove clocks. It is a
measurement and never an input — the block is byte-identical whatever it says.

---

## 7. The acceptance

| # | claim | where | runs in |
| --- | --- | --- | --- |
| 1 | the two column readings — a shard's rows, and the whole event log — agree column for column and row for row, over eight guests including three that make delegation calls | `crates/checker/tests/memory.rs::the_row_reading_and_the_log_reading_of_a_frame_agree` | CI |
| 2 | the `deleg_space` column is the requested family's tag on every live mirror query and zero elsewhere, over the delegation fixtures — three guests, because no single one requests all four families | `…::the_delegation_space_column_is_the_requested_family` | CI |
| 3 | the streaming executor's chunks are the planned shards, row for row, and no chunk exceeds its height | `crates/emulator/tests/streaming.rs::the_chunks_are_the_planned_shards_row_for_row` | CI |
| 4 | its final state is the log's, and so are the window list and the boundary read off it | `…::the_streamed_state_is_the_logs` | CI |
| 5 | **the streamed block is the archived block, byte for byte**, over S16's statement, a delegation statement and S-IO's | `crates/prover/tests/streaming.rs::a1`, `a2`, `a3` | deferred |
| 6 | it does not depend on `max_in_flight` | `…::a4` | deferred |

Claims 1 to 4 are what hold the design in ordinary CI, and they are deliberately
where the risk is: everything the streaming path does differently is a column
built from rows instead of from events, and a shard cut by a flush instead of by
arithmetic. Claim 5 is the one that needs real proofs, and it is the one that
cannot be fast — the cheapest real statement is a `2^20` shard.

---

## 8. Maintenance

A later stage that adds a family adds nothing here: a cycle-owning family's rows
flush like any other's, a delegation family's invocations flush like any other's,
and a window family's shard is built from the state at the end. What *would*
touch this page:

- a new **role** on a cycle's row, which §3.3's event derivation has to carry;
- a new **address space** whose last write something reads, which `MemoryState`
  has to keep;
- anything that makes a shard's columns depend on rows outside that shard, which
  would break §3.1 and is what the frame's design deliberately avoids.
