# The proving path: two passes, one partial shard per family

Built at S26 as a second path beside the archived one. **Made the only one at S-STREAM**
(owner's decision): `prover::prove_block_streaming` proves every block and every statement
in this repository, and nothing proves through `prover::prove_block` any more (§1.2, §6).
**Pipelined at S-PIPELINE** (owner's decision): both passes run `max_in_flight` workers that
pull shards from the executor on demand, with no batch and so no barrier (§5) — master
anti-goal 7's one exception.

It adds **no protocol**: no transcript message, no challenge, no wire form, no circuit, no
constant. It changes exactly one thing — *when* a column exists.

It cites `docs/spec/block-proof.md` for the block and the shard cut,
`docs/spec/shard-proof.md` §2 for the global commit phase, `docs/spec/memory.md`
for the memory argument and the windows, and `docs/spec/public-values.md` for the
three regions; it restates none of them.

| crate | what |
| --- | --- |
| `crates/trace` | `MemoryState`, the last-access tables apart from the log; `RowSlice` and `FrameSlice`, a shard's rows; the row-reading column builders |
| `crates/emulator` | `StreamingRun`, the pull-based tracer, and `ShardChunk` |
| `crates/prover` | `prove_block_streaming`, the two passes and the pipeline that runs both |
| `crates/verifier` | `proof_archive`, the four files a proved block leaves on disk (§6.4) |
| `crates/checker` | `memory_columns_from_log`, the log reading the row reading is held to |

---

## 1. Why this is the only path

### 1.1 The numbers

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

**The archived path's last measurement is the argument's other half.** S-BATCH's
mini-block gate ran `host::prove` down `prove_block` and recorded **136.28 GiB** at
`RAYON_NUM_THREADS=12` over 31 shards — 3.9× what `docs/handoff/S25-block.md` records
for the same gate, because `MOD_MUL` and `EC_ADD` joined the statement after that note
was written. That note's own reading of the archived path is 60–180 GB resident for a
typical block and 660–819 GB for a heavy one, and its conclusion is the sentence this
section exists to carry: **streaming is mandatory, not preferred**
(`docs/handoff/S-BATCH-miniblock-gate.md` §3 and §11.3). **No pre-S26c memory figure in
this repository is usable for sizing**, including the ones above.

**What the streaming prover holds instead**, and nothing else:

- one **partial** buffer per family, at most `height − 1` rows (§3.1) — and at exit
  these become the execution's last shards, the same memory under a new owner;
- the **last-access tables**, `O(touched addresses)` (§3.2);
- at most `max_in_flight` **claimed** shards, one per worker: each its rows and whatever
  columns, commitments, forward pass and proof it has grown into so far (§5);
- shards the executor has filled and no worker has claimed yet: **rows only, at most one
  per family** — a buffer that reached its height and has not been taken, where a
  partial buffer stood a step before (§5.1);
- the statement's commitment metadata: `64 · columns` bytes a shard, and the
  `ShardProof`s, which are the output.

Nothing accumulates between the executor and the proving workers. A shard that
has been proved is gone.

### 1.2 The rule

**Streaming is the only proving path.** Every block and every statement in this
repository — every deferred suite, `host::prove`, `tools/bench`'s `prove` verb — goes
through `prover::prove_block_streaming`.

`prover::prove_block`, `advance`, `finish`, the phase snapshots and their section
codecs still compile and were **deliberately retained**, because
`checker::TamperHarness` is built on the `TraceArchive` they read and the root
`CLAUDE.md` says the harness is not optional. What they are not is a path anything
runs. §6 is what was kept, what is forbidden, what enforces it, and what the decision
cost.

---

## 2. The two passes

```text
PASS 1 — EXECUTE + PRECOMMIT                PASS 2 — REEXECUTE + PROVE
  max_in_flight workers, one executor         the same, over the same execution
  a worker with no shard claims the next:     a worker with no shard claims the next:
    it steps the guest until a buffer fills     it steps the guest until a buffer fills
    builds that shard's M columns               fills every column of that shard
    commits them, keeps the 64-byte points      proves it, keeps the proof
    drops the columns and the shard             drops the columns and the shard
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
verification**. The recommit-and-assert S26's stage prompt called "optional but
valuable" would cost a second full commit phase (15% of the mini-block's wall clock)
to catch, as a prover-side panic, exactly what the verifier already catches.

**The price of the second execution is the clock, not the peak.** Execution is under
1% of a block's wall clock — S25 measured 4.3 s of 850 s — so running the guest twice
buys the whole of §1.1 for about 0.5% more time.

---

## 3. What survives an execution, and what does not

### 3.1 The rows

A shard's rows are `[index·h, min((index+1)·h, len))` of its family's buffer —
`docs/spec/block-proof.md` §5.1, unchanged. The streaming executor produces that
cut directly: it appends rows to one partial buffer per family and, **the moment
a buffer reaches that family's height**, hands the buffer over as a
`ShardChunk` and starts a fresh one. So a partial buffer never holds more than
`height − 1` rows at a record boundary and a chunk never has to be split. Every
record appends at most one row to any one family's buffer — a cycle to the family
whose table claims its pc, and a delegation request one more to the family it
invokes — so a buffer can reach its height but never overshoot it
(`docs/spec/execution-trace.md` §8).

The tail is the partial buffers at exit, each the family's last short shard.

A fill therefore reads its shard through `trace::RowSlice` (a cycle-owning
family) or `trace::FrameSlice` (a delegation family), which are borrowed windows
into a buffer. `ShardSource::archived` makes one by slicing a `TraceArchive`; the
streaming path makes one over the chunk it has just been handed. **That is the whole
of what the two constructions do differently**: one `prover::ShardSource`, one fill,
one `prove_shard_columns`. It is also why `shard_columns` is path-neutral and why the
tamper harness, which uses it, needed nothing from this stage (§6.1).

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
every event (`docs/spec/shard-proof.md` §10) and the archive is what
`crates/checker`'s column-fill suites, `checker::TamperHarness` and every committed
fixture read. Holding an execution is not proving from one (§6.2).

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

A nonzero exit status gets a line of its own at `phase`, because there is no
statement phase left to carry one: a guest that panicked exits 101 having published
whatever it had committed, which is a journal that decodes and a proof that verifies
and an answer to a different question (`docs/spec/debug-info.md` §3).

---

## 5. The pipeline: pulled, bounded, and with no barrier

`prove_block_streaming(setup, io, max_in_flight)`. Both passes run one **pipeline**
(`crates/prover/src/streaming.rs`'s `pipeline`): `max_in_flight` workers over one
executor, each worker claiming the next shard the moment its own is finished. Pass 1's
work on a shard is building and committing its `M` columns; pass 2's is filling every
column and proving it. The window families' shards are not the pipeline's — they are not
a fact until the execution is over (§3.2) — and follow it in batches under the same
bound.

### 5.1 What is held, and what bounds it

**A worker claims a shard before anything heavier than its rows exists.** A worker with
nothing takes the pipeline's one lock and claims the next shard: one the executor has
already filled, if one is waiting, and otherwise it **steps the executor itself**, under
the lock, until some family's buffer fills. Everything the shard grows into — its
columns, its multiplicities, its commitments, its base layer and forward pass, its
opening — is built by that worker after the claim, and dropped before its next one.

So two quantities, each bounded by the structure and not by a schedule:

| what | bound | what holds it there |
| --- | --- | --- |
| shards claimed: rows, and anything built from them | `max_in_flight` | one shard a worker and `max_in_flight` workers; every claim asserts it |
| shards filled and not yet claimed | rows only, **at most one per family** | the executor steps only for a claim with nothing waiting, one step fills at most two buffers and the exit at most one per family; `Source::admit` asserts it |

The second row is the executor's own state under a new owner: a buffer that reached its
height and has not been taken, where §1.1 already counts one partial buffer per family.
**The executor never runs ahead of demand.** There is no producer and no queue for one to
fill: a run whose workers are all busy is a run whose executor is stopped. A delegating
ecall that fills two buffers in one step leaves one of them waiting for the next worker
to finish, and the exit's tail — one shard per family, the buffers the executor already
held — is claimed one shard at a time like any other.

**Workers and not a pool size, because the pool size never bounded anything.** On the
archived path the parallel step was one `par_iter` over the whole shard list, and rayon
steals into a new shard task while a thread is parked in a nested `par_iter` — S-BATCH
walked the log and found **17 shards simultaneously live at 12 threads, and 10 at 6**
(`docs/handoff/S-BATCH-miniblock-gate.md` §3). The workers here are **not** rayon
threads. Each shard's work runs on rayon's **global** pool, so `RAYON_NUM_THREADS` is the
cores the shards share, and a worker blocked on that work cannot steal a second shard: the
bound is the worker count, and nothing a scheduler decides can move it. Two consequences
follow from the same fact. A `ThreadPool::install` around `prove_block_streaming` bounds
only the window families' batches, not the shards — which is why
`crates/prover/tests/block.rs` asserts thread-count independence shard by shard on a
one-thread pool rather than around the whole call. And a worker runs its shard's fill on
its own thread, outside the pool, so a pass can have up to `RAYON_NUM_THREADS +
max_in_flight` threads runnable; a fill is one thread, and the operating system shares
the cores.

### 5.2 What the barrier cost, and what replaced it

Until S-PIPELINE the bound was a **batch**: `max_in_flight` filled shards proved with one
`par_iter`, and the executor stopped until the whole batch was done. With the number of
live shards held below the core count, fork-join has no other shape. The first
full-block proof — devnet block 257,510 through `revm-block-stateless`, 349M cycles, 382
shards, 32 cores, `max_in_flight` 12, before S26e — measured what it cost:

| step | seconds | share | cores busy |
| --- | --- | --- | --- |
| pass 1: execute | 55 | 1% | 1 |
| pass 1: commit 382 shards, one at a time | 2,232 | 34% | ~3.5 of 32 |
| pass 2: re-execute, and fill each batch | 650 | 10% | 1, no overlap with proving |
| pass 2: prove 31 batches of 12 | 3,641 | 55% | 70–100% |

About **23% of the proving slots sat idle**, each batch waiting for its slowest shard —
the 154 s `KECCAK_F` shard, and the slower shift and memory shards — beside 77–107 s for
the rest. And pass 1 used three or four cores of 32, because a shard's fill is one thread
and only its MSMs are parallel, and it committed one shard at a time.

The pipeline answers each line:

- **pass 1 commits `max_in_flight` shards at a time**, so one shard's single-threaded
  fill overlaps the other workers' MSMs;
- **a shard's fill overlaps the other workers' proving**, and the executor steps while
  they prove — it is a worker's own claim that runs it;
- **there is no batch**: a worker that finishes claims the next shard, so a slow shard
  holds one worker and nothing else. What is left is the end of each pass, where the
  last shards finish with fewer than `max_in_flight` beside them.

**Measured on the same block** at S-PIPELINE, with S26e's fewer cycles in the tree too
(`docs/handoff/S-PIPELINE.md` §1.1):

- **Pass 1 took 191 s for 207 shards**, 6.5× faster per shard, with 25.7 of 32 cores busy.
- **Pass 2 held 11.95 of 12 shards and 30.4 of 32 cores until the guest exited**, and
  gained ~10%. The gain is small because an idle slot in a batch had never idled its
  cores: rayon gave them to the shards still running.
- **What is left is the exit's tail**, 460 s of 2,290. Its longest stretches are the two
  `2^18` `KECCAK_F` shards' one-thread fills, 200 s and 279 s.

**What this section said before, and why it was wrong.** S26 wrote that the
batch-then-prove shape needed no threads and no channels, and that "execution is under 1%
of a block's wall clock, so the overlap a producer/consumer queue would buy is not worth
a thread". It was right about the executor and wrong about the shape: the cost was never
the executor's. It was the barrier's, and the serial fills'.

### 5.3 Why threads, and why exactly these

The pipeline is **master anti-goal 7's one exception** (owner's decision, S-PIPELINE):
`max_in_flight` workers under `std::thread::scope`, sharing one `std::sync::Mutex`
around the executor and the shards it has filled. Everything inside a shard is still
rayon over data.

*Start the next shard when any one finishes* is decided at run time by whichever worker
finishes, so it needs one point where the workers coordinate, and fork-join cannot say it
with a bound below the core count. Three alternatives were weighed and refused:

- **rayon only, overlapped batches** — `rayon::join` of the executor and the next
  batch's fills against the current batch's proofs. It needs no exception and it
  overlaps the fills and the execution, but the barrier stays.
- **`par_bridge` in a pool of `max_in_flight` threads, each shard installed into a second
  pool** — the same schedule, on rayon's internal mutex. Its bound would rest on
  `par_bridge`'s per-thread re-entry guard, an implementation detail of rayon, and on a
  pool size, which is the reasoning S-BATCH found failing.
- **a producer thread and a channel** — a queue is somewhere for the executor to run
  ahead into, and production must follow demand (§5.1).

The shape is one scope and one lock, and `crates/prover/tests/one_pipeline.rs` holds it
there: it fails on a thread, lock, channel, atomic, `OnceLock` or `async fn` anywhere
else in the proving stack's sources, and on `streaming.rs` growing a second scope or a
second lock.

### 5.4 Why it is correct

- **The block does not depend on it.** Shards are placed by their statement position,
  and each proof is a function of the global state and its own columns alone, so the
  schedule cannot reach a challenge — the same argument `docs/spec/block-proof.md` §5.2
  makes about the thread count. `crates/prover/tests/streaming.rs` proves the bytes
  equal at 1 and at 8 over two statements, and `crates/prover/tests/block.rs`'
  `the_block_does_not_depend_on_the_thread_count` is the other half.
- **It cannot deadlock.** There is one lock. It is never held while a shard is worked,
  never taken twice by one worker, and nothing blocks while holding it but the
  executor's own step.
- **The failure returned is the earliest in fill order, at any worker count.** Shards
  are claimed in fill order, so every shard before the first failure recorded has been
  claimed, and a claimed shard is always worked to its end: if one of them fails too, it
  is recorded, and it is earlier. A failure stops every claim after it. An executor
  failure ranks after every shard it filled — which have all been claimed, the executor
  stepping only when none is waiting.
- **A panic stops the rest, and is raised as itself.** A drop guard sets the stop flag
  as a worker unwinds; a panic inside the executor poisons the lock, which every worker
  reads as stop. The shards in flight finish, and the first panic is re-raised once
  every worker has stopped.

### 5.5 The knob

It is an argument and not a constant because the caller is the only one that knows the
machine — a shard's base layer plus its forward pass is about 1.5 GB at `2^20` and rather
more for a delegation family. It must be at least 1.

**It is the one knob there is, and what it buys is a bracket rather than a formula.**
On a 51-shard mini-block on a 247 GiB box, under the batch shape, four in flight peaked
at 77.10 GiB and eight at 83.91, and the extra four were worth 14% of the wall clock —
6.8 GiB for 214 s, which is why `tools/bench/src/block.rs`' `DEFAULT_IN_FLIGHT` is 8. The
deferred suites take 4 (`crates/prover/tests/common/mod.rs`' `IN_FLIGHT`): a suite is run
for its verdict and not for its wall clock. `StreamingReport::peak_in_flight` is the most
shards held at once in either pass, the window families' batches included; it does not
count the filled and unclaimed rows of §5.1.

**A batch's shards peaked together, and a pipeline's do not.** Every shard in a batch
started at once, so their forward passes coincided; workers desynchronize within a few
shards, so `max_in_flight` concurrent shards are rarely at their peaks together. The
bound is the same `max_in_flight` shards either way, and the figures above are the batch
shape's. The pipeline's one measurement so far is §5.2's block at 12 in flight:
**173.92 GiB**, against the batch shape's 192.97. The two `2^18` `KECCAK_F` shards set
that peak, held together in the exit's tail with nothing else: two shards, not twelve.
There, the delegation shards set the peak and the bound did not.

---

## 6. The archived path: retained, forbidden, and what it cost

S26 left two proving paths standing. S-STREAM closed that on the owner's decision,
and the shape of the close is unusual enough to be worth stating in full: the code
stayed and the *use* of it went.

### 6.1 What was retained, and why

`prover::prove_block`, `advance`, `finish` and the codecs for
`docs/spec/shard-proof.md` §10's four later sections — the fifth, post-execution, is
`crates/trace`'s own — are all still in `crates/prover/src/phases.rs`, with the §10
schemas still exercised by that file's own unit tests, and `trace::TraceArchive` is
untouched. They were kept for one reason: **`checker::TamperHarness` writes a cell into
a shard's columns and re-proves that one shard, and there is no streaming seam for it to
do that through.**
Pass 1 commits the memory columns and pass 2 re-executes, so a tamper applied in one
pass contradicts the other; the harness needs an execution it can hold still and read
twice, which is what an archive is. The root `CLAUDE.md` records that the harness is
not optional — `crates/host/tests/prove.rs`' advice twin is built on it.

Two more things read a `TraceArchive` and are not proving from one:
`crates/checker`'s column-fill suites, which compare the row reading against the log
reading (§7, claim 1), and `crates/emulator/tests/archive.rs`, which round-trips the
container.

The per-shard component is **path-neutral and not forbidden**: `statement_inputs`,
`global_commit_phase`, `shard_columns`, `prove_shard` and `prove_shard_columns` take a
`ShardSource` (§3.1) and do not care which construction made it. That is what the
tamper harness, `crates/prover/tests/block.rs` and `crates/checker/tests/tamper.rs`
use, and it is the same code the streaming path runs.

### 6.2 What is forbidden, and what enforces it

Forbidden outside `crates/prover/src`: calling `prove_block`, and naming `advance`,
`finish` or `prove_block` in a `use prover::…` list.

`crates/prover/tests/one_proving_path.rs` is what says so. It reads every `.rs` file
in the repository — skipping `target`, `.git`, `assets`, `guests/vendor` and `docs` —
ignores comment-only lines, and fails naming every offending file and line. Its second
test reads `crates/prover/src/phases.rs` and fails if `prove_block` has been *deleted*,
which is the other half of the decision: a stage that removes the archived path must
remove that test and say what became of the tamper harness.

**The rule is a grep because the alternative is deletion**, and deletion would take the
harness with it. It is the same instrument `crates/prover/tests/one_feature.rs` uses
for master anti-goal 1, for the same reason: the property is about the whole repository,
so the test has to read the whole repository.

### 6.3 What was lost, and it was not nothing

**Resume is gone as a capability anything uses.** `prompts/00-master.md` rule 9,
*Archivable stages*, is **withdrawn** (owner's decision, S-STREAM, recorded inline in
the rule itself). Snapshot-and-resume rested on a post-execution section holding the
whole trace and a commit phase holding every shard's columns at once — §1.1's two
`O()`s, and the thing this path exists not to do. The two tests that proved it are
deleted: `crates/prover/tests/block.rs`' `a10_a_resumed_block_is_byte_identical` and
`crates/prover/tests/acceptance.rs`' `a9_a_resumed_statement_is_byte_identical`. A
killed run re-executes, and execution is under 1% of the clock.

**The streamed-equals-archived oracle is gone and nothing replaces it.** Until
S-STREAM, `crates/prover/tests/streaming.rs` held the streamed block equal to
`prove_block`'s byte for byte over the three arms of `prover::ShardRows`. A test may
not run the archived path now, so that comparison went. What is genuinely lost is
**"two independent constructions agree"**: a change that moved the prover and the
verifier together would now pass. The owner took the decision with the loss stated.

What survives it, and it is not weak:

- `verify_block` on every statement every proving suite proves, which is a
  self-consistency check over the whole of `docs/spec/shard-proof.md`;
- `crates/emulator/tests/streaming.rs`, the executor's chunks against `trace_run`'s
  buffers row for row and its final state against the log's (§7, claims 3 and 4);
- `crates/checker/tests/memory.rs`'
  `the_row_reading_and_the_log_reading_of_a_frame_agree`, the two column readings
  compared over eight guests (§7, claim 1);
- `crates/prover/tests/block.rs`' `a7`, which rebuilds the global commit phase from a
  `TraceArchive` through `statement_inputs` and `global_commit_phase` and asserts its
  digest is the **streamed** block's first shard's `global_digest`. That is the one
  surviving place where an archived construction and a streamed one are held to the
  same bytes, and it costs no extra proof.

**The `prover/metrics` cargo feature is retired** and `docs/spec/metrics.md` is
deleted. It instrumented the archived path — five of its seven metered entry points
took a `&TraceArchive` — so it measured a path nothing runs, which is master
anti-goal 1's stated hazard rather than an exception to it. The workspace has exactly
one feature now, `prover/debug-info` (`docs/spec/debug-info.md` §0). What survives it
is `tools/bench`'s `prove` verb, which needs no feature, and
`tools/bench/src/report.rs`'s `peak_rss`, which is where the RSS ground-truth rule
now lives.

### 6.4 The one thing a proving run archives: the proof

There is no `TraceArchive` on this path and so no phase sections to time. What a run
still has to leave behind is the **proof**, because recursion development reads one
back: a recursion guest's input is a base proof, and producing one is a quarter of an
hour nobody should pay twice.

`verifier::proof_archive` — re-exported as `host::proof_archive`, and reached from
`bench prove --out <dir>` — writes four files under one directory, each the bare
`to_bytes()` payload with no header and no framing of its own:

```text
  <stem>.vk         VerifyingKey::to_bytes
  <stem>.identity   the identity this run claims, 64 lowercase hex digits + newline
  <stem>.public     PublicInputs::to_bytes
  <stem>.block      BlockProof::to_bytes
```

```rust
pub fn write_proof(dir: &Path, stem: &str, vk: &VerifyingKey, block: &BlockProof)
    -> Result<ProofPaths, String>;
pub fn read_proof(dir: &Path, stem: &str)
    -> Result<(VerifyingKey, [u8; 32], PublicInputs, BlockProof), String>;
```

**Three of the four are the CLI's files, and the fourth is deliberately not its
argument.** `verifier block <vk> <identity-hex> <public> <block>` reads `<stem>.vk`,
`<stem>.public` and `<stem>.block` as they are. Its identity is the 64 hex digits
themselves, from a channel the prover does not control, and never `<stem>.identity`:

```text
  verifier block <stem>.vk <identity from your own channel> <stem>.public <stem>.block
```

`"$(cat <stem>.identity)"` in that slot checks the proof against its prover's own
claim: fine for re-reading a proof you produced, and evidence of nothing to anyone
else. It lives in `crates/verifier` rather than in the host SDK because the *reader* is
there, and `crates/verifier/tests/cli.rs` writes its files through this module rather
than through a local closure, which is what keeps the two from drifting.

Four things about it that are decisions and not accidents:

- **`<stem>.public` is redundant and is written anyway.** `BlockProof::to_bytes`
  already carries the statement, so `read_proof` could reconstruct it — but the CLI
  takes it as a file of its own, and a reader should not have to write a script to
  produce one. `write_proof` writes
  `block.statement()` and never a second copy a caller supplies, so the two cannot
  disagree.
- **The `.vk` is the large file**, and it is written unconditionally. It carries every
  registered family's `CircuitArtifact`, and the delegation artifacts are megabytes —
  which is why `tools/kat-gen` pins them by digest. A key cache nobody validates is
  worse than tens of MB, and a proof whose key is missing is not a proof anyone can
  check.
- **`<stem>.identity` is a record, not an input.**
  A key recomputes its own identity when it loads, so the key is not its own authority
  for it: what makes a proof a proof *of a particular program* is a comparison against
  a value from a channel the prover does not control. Writing it beside the proof
  records what the run claimed; `read_proof` hands the bytes back without comparing
  them to anything.
- **`read_proof` goes through `load_verifying_key`**, the loader with the load rules —
  it recomputes the SRS digest from the key's own points and revalidates every circuit
  against the registry (`docs/spec/shard-proof.md` §7) — and not through
  `VerifyingKey::from_bytes`, which checks encoding only.

`tools/bench`'s verb writes the bundle only **after** the block verifies: a proof that
does not verify is not worth a reader's disk. A bundle that does not write fails the
run, once the report is printed (`tools/bench/CLAUDE.md`).

---

## 7. The acceptance

| # | claim | where | runs in |
| --- | --- | --- | --- |
| 1 | the two column readings — a shard's rows, and the whole event log — agree column for column and row for row, over eight guests including three that make delegation calls, and over every shard a family's rows are cut into | `crates/checker/tests/memory.rs::the_row_reading_and_the_log_reading_of_a_frame_agree` | CI |
| 2 | the `deleg_space` column is the requested family's tag on every live mirror query and zero elsewhere, over three guests, which between them request five of the six delegation spaces | `…::the_delegation_space_column_is_the_requested_family` | CI |
| 3 | the streaming executor's chunks are the planned shards, row for row, and no chunk exceeds its height, over thirteen guests | `crates/emulator/tests/streaming.rs::the_chunks_are_the_planned_shards_row_for_row` | CI |
| 4 | its final state is the log's, and so are the window list and the boundary read off it | `…::the_streamed_state_is_the_logs` | CI |
| 5 | the block does not depend on `max_in_flight`, over S16's statement (the `Rows` arm) and a delegation statement (the `Invocations` arm), and each is a block `verify_block` accepts | `crates/prover/tests/streaming.rs::a1`, `a2` | deferred |
| 6 | nothing in the repository proves through the archived path, and the archived path is still there | `crates/prover/tests/one_proving_path.rs` | CI |
| 7 | the pipeline works every shard the execution fills exactly once, at 1, 3 and 8 workers, and never more than the worker count at once — read off its own count and off the intervals the work recorded | `crates/prover/src/streaming.rs::tests::every_filled_shard_is_worked_once_and_never_more_than_workers_at_once` | CI |
| 8 | the executor steps only for a claim with nothing waiting, and shards are claimed in fill order | `…::the_guest_is_stepped_only_for_a_claim_with_nothing_waiting` | CI |
| 9 | the failure returned is the earliest in fill order at any worker count, and a panic reaches the caller as itself | `…::the_earliest_failure_in_fill_order_is_the_one_returned`, `…::a_panic_in_one_shard_reaches_the_caller_as_itself` | CI |
| 10 | no thread, lock, channel or atomic outside the pipeline, and the pipeline is one scope and one lock | `crates/prover/tests/one_pipeline.rs` | CI |

Claims 1 to 4 and 6 to 10 are what hold the design in ordinary CI, and they are
deliberately where the risk is: everything this path does differently is a column built
from rows instead of from events, a shard cut by a flush instead of by arithmetic, and a
shard claimed by a worker instead of drained from a batch. Claims 7 to 9 drive the real
executor over `guests/shards` — seventeen add/sub shards filled in mid-run, every other
family's at exit — and put a stand-in where the work goes, because what a shard's work
is does not reach the pipeline.

**Claim 5 is two statements and not three, and that is the shape of the loss in §6.3.**
It was eight real blocks — three statements proved twice each against an archived
reference, plus S16's twice more at two bounds — and it is four, two statements at two
bounds each, held against each other. The `Window` arm needs no run of its own: a window
family's shard is built after the pipeline, over the final state, at any bound. The
delegation statement earns its place because pass 2's workers finish shards in whatever
order the schedule picks while the statement is in ascending-`FamilyId` order, so a block
whose two orders disagree is the case a worker count could plausibly reach. The
three arms are each still proved and verified by the suites that are about them:
`tests/block.rs` and `tests/acceptance.rs` the `Rows` arm, `tests/keccak.rs` the
`Invocations` arm, `tests/public_io.rs` the `Window` arm.

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
  would break §3.1 and is what the frame's design deliberately avoids;
- a change to the pipeline's shape — a second lock, a producer, a queue the executor
  could run ahead into, or a thread anywhere else — which is master anti-goal 7's
  exception and therefore the owner's decision; `crates/prover/tests/one_pipeline.rs`
  is where it fails;
- a second proving path of any kind, which is §6.2's rule and therefore the owner's
  decision and nobody else's — `crates/prover/tests/one_proving_path.rs` is where the
  argument would have to be made, not routed around;
- **deleting** `prove_block`, which takes `checker::TamperHarness` with it (§6.1) and
  fails `the_archived_path_is_retained` until the note says what replaced the harness.
