# The streaming prover

How one execution becomes a `BlockProof`: the guest runs twice, and a fixed number of workers
prove its shards as the executor fills them. The block is [proof.md](proof.md)'s, and its bytes do
not depend on the schedule; this page fixes when each column exists, and so what a proof costs.

> **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** Pass 1 commits nothing and pass 2
> opens nothing, so a streamed block is **UNSOUND** ([proof.md](proof.md) §3).

## 1. The prover, and what it costs

`prover::prove_block_streaming(setup, io, max_in_flight)` proves every block: `host::prove` wraps
it over the `ProverSetup` that `host::setup` builds from an ELF. Beside the block it returns a
`StreamingReport`: each pass's wall clock and the executor's time inside it, the cycle and shard
counts, and the most shards held at once.

Its memory follows the shards in flight, not the shard or cycle count: a partial buffer per
family (§4), the last-access tables (§3), at most `max_in_flight` shards being worked and one
filled shard's rows per family waiting (§5), and the output, the `ShardProof`s. The executor's
whole output, `emulator::trace_run`'s buffers and event log at about 300 bytes a cycle, never
exists; executing twice (§2) costs time instead.

A shard costs its height times its circuit's width ([circuits.md](circuits.md) §1), however few
of its rows are live. `gkr::forward` holds every inner layer as field elements,
`32·Σ_{k≥1} w_k·2^{n_k}` bytes over layer `k`'s width and variable count (8.4 GiB for a `2^20`
`SHIFT_BITWISE` shard), and `gkr::prove` adds a copy of the layer it reduces and an `eq` table.

## 2. The two passes

```text
pass 1                                       pass 2
  execute; for each shard as it fills:         execute again; for each shard as it fills:
    drop it unbuilt (UNFINISHED: commit          fill every column, prove the shard,
    its M columns, below)                        keep the proof, drop the rest
  at exit: the statement, then G1–G9           at exit: the window families' shards
                                               the statement's roots, the BlockProof
```

Each pass drives a fresh `emulator::StreamingRun`, which hands over a family's buffer as a
`ShardChunk` the moment it reaches the family's height (§4); the workers of §5 take the chunks.

**Pass 1** runs the execution to its end. At exit it derives the window list, shard counts and
boundary from the final state (§3), asserts the cut equals `trace::plan_shards`, and runs G1–G9
([proof.md](proof.md) §2).

**ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** Pass 1 is meant to commit each
shard's `M` columns as the shard fills — its family's fill with them moved out and no
multiplicities — and the window families' shards at exit, and to put the commitments in statement
order for the global transcript to absorb. A commitment reads no transcript, so only its place in
the absorbed order would matter, not when it was computed. Nothing is committed: each filled shard
is dropped unbuilt.

**Pass 2** re-executes. The emulator is a pure function of `(image, io)`, with no clock,
randomness or threads, so it cuts the same shards; pass 2 asserts that its `CycleProfile`,
`Execution`, window list and boundary are pass 1's. Each shard gets every column, multiplicities
included, and `prover::prove_shard_columns`: the shard transcript and the GKR proof
([proof.md](proof.md) §4). Proofs go to their statement positions, and `prover::public_inputs`
copies each shard's two memory roots into the statement.

**Nothing holds pass 2's columns to pass 1's.** A shard's opening is meant to take its `M`
commitments from the statement, pass 1's, and its polynomials from pass 2's columns, so columns
that differed would give an opening the verifier refuses. There is no opening
([proof.md](proof.md) §5), so pass 2's columns are bound to nothing.

## 3. What survives an execution

A streaming run records no memory event. At exit `StreamingRun::finish` hands over each non-empty
partial buffer as its family's last shard, and a `StreamedExecution`: the last-access tables
(`trace::MemoryState`), the `CycleProfile` and the `Execution`
([execution-trace.md](execution-trace.md) §11). Beyond the shards' rows, the guest's inputs and
its journal, everything the statement needs is a function of that final state: the boundary
(`trace::build_boundary_finals`), `ZERO_WINDOWS`' list (`trace::init_windows`) and the window
families' teardowns ([memory.md](memory.md) §3). So a window family's shard exists only once the
execution is over (§5).

A fill reads one shard through `prover::ShardSource`, its `ShardRows` a `trace::RowSlice` (a
cycle-owning family) or, for a window family alone, the final `MemoryState`. The streaming path
builds it over a fresh chunk, `ShardSource::archived` over a slice of a `TraceArchive` (§6);
nothing else differs. Memory columns come from a shard's rows alone
([execution-trace.md](execution-trace.md) §11), and `checker::memory_columns_from_log` rebuilds
them from the event log, independently ([circuits.md](circuits.md) §3).

## 4. The shard plan

A family's rows, in the order they are appended, are cut into shards of its `VmConfig` height
`h`: shard `i` is rows `[i·h, min((i + 1)·h, len))`, the last padded to `h` with zero rows
([memory.md](memory.md) §2). `trace::plan_shards` is `⌈rows/h⌉` per family over the
`CycleProfile`, a cycle-owning family's rows being its cycles, so a family the execution never
reached has no shard. A window family plans 0; its shards are windows ([memory.md](memory.md) §3),
counted by `shard_counts` in `crates/prover/src/lib.rs`: one `INIT_TEARDOWN` shard and one of each
public window whatever the execution did, a `ZERO_WINDOWS` shard per entry of `init_windows`, and
one per advice window supplied (`trace::advice_window_count`). The counts are the statement's
`shard_counts` ([proof.md](proof.md) §1).

**The flush.** `StreamingRun` makes the cut as it runs. After a cycle is recorded, a buffer that
has reached `h` rows is handed over as `ShardChunk { family, index, rows }`, `index = rows/h − 1`,
and replaced by an empty one. A cycle appends one row, to its owning family's buffer, so a buffer
reaches `h` without passing it, a step fills at most one, and no chunk is split. At exit `finish`
hands over the partial buffers. Chunks arrive in fill order, not statement order, and pass 1
asserts that each family's count is the plan's.

## 5. The pipeline

`pipeline` (`crates/prover/src/streaming.rs`) runs both passes: `max_in_flight` workers under
`std::thread::scope` and one `std::sync::Mutex` around a `Source`, which holds the executor, the
filled shards no worker has claimed, and the counts. Under the lock a worker gives back its shard
and claims the next: a waiting one, or else it steps the executor itself until a buffer fills
(`Source::claim`, the only place the guest runs). Outside the lock it builds the shard's columns,
works it and drops it. These are the prover's only threads and only lock; within a shard,
parallelism is rayon over data.

| held | bound | by |
| --- | --- | --- |
| claimed shards, and all built from them | `max_in_flight` | one a worker; asserted in `Source::claim` |
| filled, unclaimed shards | rows only, one per family | the executor steps only for a claim with nothing waiting, a step fills at most one buffer and the exit one per family; asserted in `Source::admit` |

The executor never runs ahead of demand, and there is no batch: a slow shard holds one worker.
The workers are not rayon threads. A shard's forward pass and sumchecks run on rayon's global
pool, so `RAYON_NUM_THREADS` sets the cores the shards share, and a worker blocked in that work
cannot take a second shard as a rayon thread waiting in a nested join would. Fills run on the
workers' own threads, one each, so up to `RAYON_NUM_THREADS + max_in_flight` threads are runnable.
Fork-join cannot express this: below one shard per core, a batch waits for its slowest shard.

- **The block is independent of the schedule.** A shard's proof is a function of the global state
  and its own columns, its transcript a fresh sponge seeded with the digest ([proof.md](proof.md)
  §4); no proof depends on the thread count ([gkr.md](gkr.md) §5); proofs are placed by statement
  position. `crates/prover/tests/streaming.rs` compares the bytes at 1 and 8 in flight.
- **The failure returned is the earliest in fill order**, at any worker count: claims follow fill
  order, a claimed shard is worked to its end, a failure stops later claims (`Source::fail`), and
  an executor failure ranks after every shard it filled.
- **No deadlock**: the lock is never held while a shard is worked or taken twice by one worker,
  and nothing waits under it but the executor's step.
- **A panic** stops the claims, through a drop guard (`StopOnPanic`) or, inside the executor, the
  poisoned lock; the shards in flight finish, and the panic is re-raised as itself.

The window families' shards follow the pipeline, built from the final state in rayon batches of
at most `max_in_flight`, which are all that a `ThreadPool::install` around the call bounds.

**The knob.** `max_in_flight`, at least 1, is an argument because only the caller knows the
machine; `host::prove` takes it from its caller. `StreamingReport::peak_in_flight` is the most
shards claimed or batched at once in either pass.

## 6. The retained archived path

`emulator::trace_run` keeps a whole execution, every buffer and the `MemoryEventLog`, and
`trace::TraceArchive::from_execution` holds it ([execution-trace.md](execution-trace.md) §11).
The per-shard component reads one through `ShardSource::archived`, with the same fills and shard
proving: `prover::statement_inputs` (counts, windows, boundary), `global_commit_phase`,
`shard_columns`, `prove_shard`, `prove_shard_columns` and `public_inputs`.
`checker::TamperHarness` is built on it ([circuits.md](circuits.md) §3): it writes changed cells
into shards' columns, re-runs the global commit phase where a tamper moves the boundary, and
re-proves, which needs an execution held still and read twice. Streaming has no such seam: pass 2
rebuilds, by re-executing, the columns pass 1 read, so a cell changed in either pass would
contradict the other. **UNFINISHED** ([proof.md](proof.md) §3): a changed `M` column is meant to
be recommitted in that fresh global phase, which would move every challenge; nothing is committed,
so it moves none.

`prover::prove_block(setup, archive, plan)`, `advance(setup, archive, until)` and
`finish(archive)` prove a block from an archive; nothing outside `crates/prover/src/phases.rs`
calls them. `prove_block` refuses a plan that is not `plan_shards` of the archive's profile.
`advance` fills the archive's four later phase sections in order, timing each, and decodes any it
already holds, so an imported archive resumes; a stopped streaming run starts again. No column is
stored: a phase rebuilds them from the archive. The sections, in [proof.md](proof.md) §9's
encodings, each refusing a byte too many or too few:

| section | content |
| --- | --- |
| `PostCommit` | the statement's `PublicInputs` bytes, without roots; the global transcript after G9 as its 226-byte `postcard` snapshot ([transcript.md](transcript.md) §3); the four memory challenges; the digest |
| `PostGkr` | per shard, in statement order: family `u32`, index `u32`, `ts_start` and `ts_end` `u64`, the outputs, the GKR proof, the base claims' point, the shard transcript's snapshot after the GKR proof |
| `PostOpening` | each shard's `ShardProof` bytes: the section an opening is meant to fill, and with none (**UNFINISHED**, [proof.md](proof.md) §3) a proof is its GKR pass alone |
| `Final` | the complete `PublicInputs` bytes, then the proofs |
