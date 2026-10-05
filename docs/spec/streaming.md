# The streaming prover

How one execution becomes a `BlockProof`: the guest runs twice, and a fixed number of workers
commit, then prove, its shards as the executor fills them. The block is [proof.md](proof.md)'s,
and its bytes do not depend on the schedule; this page fixes when each column exists, and so what
a proof costs.

## 1. The prover, and what it costs

`prover::prove_block_streaming(setup, io, max_in_flight)` proves every block: `host::prove` wraps
it over the `ProverSetup` that `host::setup` builds from an ELF, `bench prove` drives it
([tools.md](../tools.md) §1), and recursion nodes are proved through it. Beside the block it
returns a `StreamingReport`: each pass's wall clock and the executor's time inside it, the cycle
and shard counts, and the most shards held at once.

Its memory follows the shards in flight, not the shard or cycle count: a partial buffer per
family (§4), the last-access tables (§3), at most `max_in_flight` shards being worked and one
filled shard's rows per family waiting (§5), and the output, 64 bytes a commitment and the
`ShardProof`s. The executor's whole output, `emulator::trace_run`'s buffers and event log at
about 300 bytes a cycle, never exists; executing twice (§2) costs time instead.

A shard costs its height times its circuit's width ([circuits.md](circuits.md) §1), however few
of its rows are live. `gkr::forward` holds every inner layer as field elements,
`32·Σ_{k≥1} w_k·2^{n_k}` bytes over layer `k`'s width and variable count (42 GiB for a `2^18`
`KECCAK_F` shard, 8.4 GiB for a `2^20` `SHIFT_BITWISE` one), and `gkr::prove` adds a copy of the
layer it reduces and an `eq` table. The opening, after the forward pass is dropped, copies every
committed column.

Measured on the base proof of [recursion.md](recursion.md) §10:

| | |
| --- | --- |
| workload | block 257,510 of `glamsterdam-devnet-8`, `revm-block-stateless`: 60 transactions, 101.5 Mgas, 198M cycles, 207 shards |
| machine | 32 vCPUs, 247.7 GiB, `--in-flight 12` |
| pass 1 | 191 s; 25.7 vCPUs busy on average; one-thread fills 81% of its shard-seconds; sampled RSS at most 15.9 GiB |
| pass 2 | 2,290 s; on average 11.95 of 12 shards held and 30.4 vCPUs busy until the guest exits; then the exit's 460 s tail, whose longest stretches are the two `KECCAK_F` shards' one-thread fills, 200 s and 279 s |
| peak RSS | 173.92 GiB: the two `2^18` `KECCAK_F` shards, together in the tail with nothing else in flight |

Twelve shards in flight never reached that peak: a delegation family's height set it, and
`max_in_flight` bounds only how many shards coincide.

## 2. The two passes

```text
pass 1                                       pass 2
  execute; for each shard as it fills:         execute again; for each shard as it fills:
    fill its M columns, commit them,             fill every column, prove the shard,
    keep the points, drop the columns            keep the proof, drop the rest
  at exit: the window families' shards         at exit: the window families' shards
  the statement, then G1–G11                   the statement's roots, the BlockProof
```

Each pass drives a fresh `emulator::StreamingRun`, which hands over a family's buffer as a
`ShardChunk` the moment it reaches the family's height (§4); the workers of §5 take the chunks.

**Pass 1** commits each shard's `M` columns, its family's fill with them moved out and no
multiplicities, one commitment a column (in the recursion format one a stack of `2^σ`,
[recursion.md](recursion.md) §1.3). At exit it derives the window list, shard counts and boundary
from the final state (§3), asserts the cut equals `trace::plan_shards`, commits the window
families' shards, puts the commitments in statement order by `(family, index)`
([proof.md](proof.md) §1) and runs G1–G11 ([proof.md](proof.md) §2). A commitment reads no
transcript, so only its place in the absorbed order matters, not when it was computed.

**Pass 2** re-executes. The emulator is a pure function of `(image, io)`, with no clock,
randomness or threads, so it cuts the same shards; pass 2 asserts that its `CycleProfile`,
`Execution`, window list and boundary are pass 1's. Each shard gets every committed column,
multiplicities included, and `prover::prove_shard_columns`: shard transcript, GKR proof, opening
([proof.md](proof.md) §4, §5). Proofs go to their statement positions, and
`prover::public_inputs` copies each shard's two memory roots into the statement.

**`M` is not recommitted**: a shard's opening takes its `M` commitments from the statement, pass
1's, and its polynomials from pass 2's columns, so columns that differed would give an opening
the verifier refuses.

## 3. What survives an execution

A streaming run records no memory event. At exit `StreamingRun::finish` hands over each non-empty
partial buffer as its family's last shard, and a `StreamedExecution`: the last-access tables
(`trace::MemoryState`), the `CycleProfile` and the `Execution`
([execution-trace.md](execution-trace.md) §11). Beyond the shards' rows, the guest's inputs and
its journal, everything the statement needs is a function of that final state: the boundary
(`trace::build_boundary_finals`), `ZERO_WINDOWS`' list (`trace::init_windows`), the window
families' teardowns ([memory.md](memory.md) §3) and the field-window count. So a window
family's shard exists only once the execution is over (§5).

A fill reads one shard through `prover::ShardSource`, its `ShardRows` a `trace::RowSlice` (a
cycle-owning family), a `trace::FrameSlice` (a delegation family) or, for a window family alone,
the final `MemoryState`. The streaming path builds it over a fresh chunk, `ShardSource::archived`
over a slice of a `TraceArchive` (§6); nothing else differs. Memory columns come from a shard's
rows alone ([execution-trace.md](execution-trace.md) §11), and `checker::memory_columns_from_log`
rebuilds them from the event log, independently ([circuits.md](circuits.md) §3).

## 4. The shard plan

A family's rows, in the order they are appended, are cut into shards of its `VmConfig` height
`h`: shard `i` is rows `[i·h, min((i + 1)·h, len))`, the last padded to `h` with zero rows
([memory.md](memory.md) §2). `trace::plan_shards` is `⌈rows/h⌉` per family over the
`CycleProfile`, cycles for a cycle-owning family and invocations for a delegation family, so a
family the execution never reached has no shard. A window family plans 0; its shards are windows
([memory.md](memory.md) §3), counted by `shard_counts` in `crates/prover/src/lib.rs`: one
`INIT_TEARDOWN` shard and one of each public window whatever the execution did, a `ZERO_WINDOWS`
shard per entry of `init_windows`, one per advice window supplied (`trace::advice_window_count`),
and field windows through the highest cell touched (`MemoryState::field_windows`). The counts
are the statement's `shard_counts` ([proof.md](proof.md) §1).

**The flush.** `StreamingRun` makes the cut as it runs. After a cycle is recorded, a buffer that
has reached `h` rows is handed over as `ShardChunk { family, index, rows }`, `index = rows/h − 1`,
and replaced by an empty one. A cycle appends at most one row to any buffer, the owning family's
and, for a delegation request, one invocation to the delegation family's, so a buffer reaches `h`
without passing it, a step fills at most two, and no chunk is split. At exit `finish` hands over
the partial buffers. Chunks arrive in fill order, not statement order, and pass 1 asserts that
each family's count is the plan's.

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
| filled, unclaimed shards | rows only, one per family | the executor steps only for a claim with nothing waiting, a step fills at most two buffers and the exit one per family; asserted in `Source::admit` |

The executor never runs ahead of demand, and there is no batch: a slow shard holds one worker.
The workers are not rayon threads. A shard's MSMs, forward pass, sumcheck and opening run on
rayon's global pool, so `RAYON_NUM_THREADS` sets the cores the shards share, and a worker blocked
in that work cannot take a second shard as a rayon thread waiting in a nested join would. Fills
run on the workers' own threads, one each, so up to `RAYON_NUM_THREADS + max_in_flight` threads
are runnable. Fork-join cannot express this: below one shard per core, a batch waits for its
slowest shard.

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
machine; `bench prove --in-flight` defaults to 8. `StreamingReport::peak_in_flight` is the most
shards claimed or batched at once in either pass.

## 6. The retained archived path

`emulator::trace_run` keeps a whole execution, every buffer and the `MemoryEventLog`, and
`trace::TraceArchive::from_execution` holds it ([execution-trace.md](execution-trace.md) §11).
The per-shard component reads one through `ShardSource::archived`, with the same fills and shard
proving: `prover::statement_inputs` (counts, windows, boundary, every shard's `M` columns),
`global_commit_phase`, `shard_columns`, `shard_memory_columns`, `prove_shard`,
`prove_shard_columns` and `public_inputs`. `checker::TamperHarness` is built on it
([circuits.md](circuits.md) §3): it writes changed cells into shards' columns, recommits changed
`M` columns in a fresh global commit phase and re-proves, which needs an execution held still and
read twice. Streaming has no such seam: pass 2 rebuilds, by re-executing, the columns pass 1
committed, so a cell changed in either pass would contradict the other.

`prover::prove_block(setup, archive, plan)`, `advance(setup, archive, until)` and
`finish(archive)` prove a block from an archive; nothing outside `crates/prover/src/phases.rs`
calls them. `prove_block` refuses a plan that is not `plan_shards` of the archive's profile.
`advance` fills the archive's four later phase sections in order, timing each, and decodes any it
already holds, so an imported archive resumes; a stopped streaming run starts again. No column is
stored: a phase rebuilds them from the archive. The sections, in [proof.md](proof.md) §9's
encodings, each refusing a byte too many or too few:

| section | content |
| --- | --- |
| `PostCommit` | the statement's `PublicInputs` bytes, without roots; the global transcript after G11 as its 226-byte `postcard` snapshot ([transcript.md](transcript.md) §3); the four memory challenges; the digest |
| `PostGkr` | per shard, in statement order: family `u32`, index `u32`, `ts_start` and `ts_end` `u64`, the witness commitments, the outputs, the GKR proof, the base claims' point, the shard transcript's snapshot after the GKR proof |
| `PostOpening` | each shard's `ShardProof` bytes |
| `Final` | the complete `PublicInputs` bytes, then the proofs |
