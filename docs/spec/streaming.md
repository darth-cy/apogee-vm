# The streaming prover

How one execution becomes a `BlockProof`: the guest runs twice, and a fixed number of workers
prove its shards as the executor fills them. The block is [proof.md](proof.md)'s, and its bytes do
not depend on the schedule; this page fixes when each column exists, and so what a proof costs,
and how the same witness is checked against its circuits without a proof (§7).

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
of its rows are live. `gkr::forward` holds every inner layer as `Fp2` elements,
`16·Σ_{k≥1} w_k·2^{n_k}` bytes over layer `k`'s width and variable count (4.2 GiB for a `2^20`
`MUL_DIV` shard, 16.4 GiB for a `2^22` `MEM_SUBWORD` one), and `gkr::prove` adds a copy of the layer it reduces and an `eq` table.

## 2. The two passes

```text
pass 1                                       pass 2
  execute; for each shard as it fills:         execute again; for each shard as it fills:
    fill it, commit its M columns,               fill every column, commit M and W,
    keep the commitment, drop the rest           prove and open the shard, keep the proof
  at exit: the window shards' M commitments,   at exit: the window families' shards
    the statement, then G1–G9                  the statement's roots, the BlockProof
```

Each pass drives a fresh `emulator::StreamingRun`, which hands over a family's buffer as a
`ShardChunk` the moment it reaches the family's height (§4); the workers of §5 take the chunks.

**Pass 1** runs the execution to its end, the worker that claims a filled shard running its
family's fill and committing the `M` columns among it (`prover::memory_commitment_of`), no
multiplicities built. At exit it refuses an execution whose status is not 0,
`ProverError::NonzeroExit` ([proof.md](proof.md) §6, step 0): the status exists only there, so the
filled shards' commitments are spent and nothing else is, and `host::prove` runs the guest once
untraced first to spend none. Otherwise it derives the window list, shard counts and boundary from
the final state (§3), asserts the cut equals `trace::plan_shards`, commits the window families'
shards over the final state in batches of at most `max_in_flight`, puts every commitment in
statement order and runs G1–G9 ([proof.md](proof.md) §2). A commitment reads no transcript, so
only its place in the absorbed order matters, not when it was computed.

**Pass 2** re-executes. The emulator is a pure function of `(image, io)`, with no clock,
randomness or threads, so it cuts the same shards; pass 2 asserts that its `CycleProfile`,
`Execution`, window list and boundary are pass 1's. Each shard gets every column, multiplicities
included, and `prover::prove_shard_columns`: its `M` and `W` columns committed again, the shard
transcript, the GKR proof and the opening ([proof.md](proof.md) §4, §5). Proofs go to their
statement positions, and `prover::public_inputs` copies each shard's two memory roots into the
statement.

**The opening holds pass 2's columns to pass 1's.** A shard's opening takes its `M` commitment
from the statement, pass 1's, and its polynomials from pass 2's columns, so columns that differed
would give an opening the verifier refuses. Pass 2 recommits the `M` columns rather than keep pass
1's openers, which would grow with the shard count.

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
cycle-owning family), a `trace::FrameSlice` (a delegation family) or, for a window family alone,
the final `MemoryState`. The streaming path
builds it over a fresh chunk, `ShardSource::archived` over a slice of a `TraceArchive` (§6);
nothing else differs. Memory columns come from a shard's rows alone
([execution-trace.md](execution-trace.md) §11), and `checker::memory_columns_from_log` rebuilds
them from the event log, independently ([circuits.md](circuits.md) §3).

## 4. The shard plan

A family's rows, in the order they are appended, are cut into shards of its `VmConfig` height
`h`: shard `i` is rows `[i·h, min((i + 1)·h, len))`, the last padded to `h` with zero rows
([memory.md](memory.md) §2). `trace::plan_shards` is `⌈rows/h⌉` per family over the
`CycleProfile`, a cycle-owning family's rows being its cycles and a delegation family's its entries
times its rows an entry, so a family the execution never reached has no shard. A delegation shard
is whole entries, a call's, a call's arrays, an op's or a hash op's: `h` over the rows an entry of
them, a power of two dividing `h`. A trie program's ops may straddle shards, each op carrying what
its rows start from ([precompiles.md](precompiles.md) §6.7). A window family plans 0; its shards
are windows ([memory.md](memory.md) §3), counted by `shard_counts` in `crates/prover/src/lib.rs`: one
`INIT_TEARDOWN` shard and one of each public window whatever the execution did, a `ZERO_WINDOWS`
shard per entry of `init_windows`, and one per advice window supplied
(`trace::advice_window_count`). The counts are the statement's `shard_counts`
([proof.md](proof.md) §1).

**The flush.** `StreamingRun` makes the cut as it runs. After a cycle is recorded, a buffer that
has reached `h` rows is handed over as `ShardChunk { family, index, rows }`, `index = rows/h − 1`,
and replaced by an empty one; a delegation buffer holding a shard's entries likewise, its chunk
carrying them in `calls`. A cycle appends one row, to its owning family's buffer, and a delegation
call one entry to each of its families, or one per op and per hash op of its program, each pushed
and flushed in turn, so a buffer reaches `h` without passing it and no entry is split. A step fills
at most one buffer a family while a trie call's entries fit one shard of each of its families,
`h` ops of `MPT_NODES` and `h/16` hash ops of `MPT_ROUNDS`, 4,096 at `2^16`, and the SDK's
`Trie::root` keeps every call within one at the default heights ([precompiles.md](precompiles.md)
§6.3). At exit `finish` hands over the partial buffers. Chunks arrive in fill order, not statement
order, and pass 1 asserts that each family's count is the plan's.

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
| filled, unclaimed shards | rows only, one per family | the executor steps only for a claim with nothing waiting, a step fills at most one buffer a family (§4) and the exit one; asserted in `Source::admit` |

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
machine; `host::prove` takes it from its caller. `prover::DEFAULT_MAX_IN_FLIGHT`, 8, is what every
proving path in the repository passes: on an r8i.8xlarge at `2^20` execution shards, 4 → 8 cut
the business guests' prove time by 16–25% for 10–13 GiB more peak, the CPU-seconds unchanged, and
16 added nothing for an 11-shard statement. `StreamingReport::peak_in_flight` is the most
shards claimed or batched at once in either pass.

## 6. The retained archived path

`emulator::trace_run` keeps a whole execution, every buffer and the `MemoryEventLog`, and
`trace::TraceArchive::from_execution` holds it ([execution-trace.md](execution-trace.md) §11).
The per-shard component reads one through `ShardSource::archived`, with the same fills and shard
proving: `prover::statement_inputs` (counts, windows, boundary, every shard's memory commitment), `global_commit_phase`,
`shard_columns`, `prove_shard`, `prove_shard_columns` and `public_inputs`.
`checker::TamperHarness` is built on it ([circuits.md](circuits.md) §3): it writes changed cells
into shards' columns, re-runs the global commit phase where a tamper moves the boundary, and
re-proves, which needs an execution held still and read twice. Streaming has no such seam: pass 2
rebuilds, by re-executing, the columns pass 1 read, so a cell changed in either pass would
contradict the other. A changed `M` column is recommitted in that fresh global phase, which moves
every challenge.

`prover::prove_block(setup, archive, plan)`, `advance(setup, archive, until)` and
`finish(archive)` prove a block from an archive; nothing outside `crates/prover/src/phases.rs`
calls them. `prove_block` refuses a plan that is not `plan_shards` of the archive's profile.
`advance` fills the archive's four later phase sections in order, timing each, and decodes any it
already holds, so an imported archive resumes; a stopped streaming run starts again. No column is
stored: a phase rebuilds them from the archive, and recommits a shard's groups to open them. The
sections, in [proof.md](proof.md) §9's
encodings, each refusing a byte too many or too few:

| section | content |
| --- | --- |
| `PostCommit` | the statement's `PublicInputs` bytes, its memory commitments in and its roots not; the global transcript after G9 as its `postcard` snapshot ([transcript.md](transcript.md) §3); the five memory challenges; the digest |
| `PostGkr` | per shard, in statement order: family `u32`, index `u32`, `ts_start` and `ts_end` `u64`, the witness commitment, the outputs, the GKR proof, the base claims' point, the shard transcript's snapshot after the GKR proof |
| `PostOpening` | each shard's `ShardProof` bytes, its opening in them |
| `Final` | the complete `PublicInputs` bytes, then the proofs |

## 7. The circuit check

`host::check(setup, io, max_in_flight, max_cycles) -> Result<CheckReport, CheckFailure>` holds
the execution a proof would be made of to every circuit the proof would be verified by,
committing and proving nothing. A Prover Host runs it on each candidate batch, so a batch whose
proof would fail is refused before any proving starts: a run the executor accepts and the circuits
reject is a completeness defect of the core.

1. **The untraced run.** `emulator::run_bounded(image, io, max_cycles)` refuses a fatal run, a
   run that passes `max_cycles` cycles (`EmuError::CycleLimit { limit }`,
   [execution-trace.md](execution-trace.md) §10) and a nonzero exit status before any column
   exists, as `host::prove`'s first run does.
2. **The witness pass.** `prover::witness_block_streaming(setup, io, max_in_flight, max_cycles,
   work)` is pass 1's execution (§2) under the same cap, the same pipeline (§5) and the same
   statement record, but where pass 1 commits a shard's `M` columns it fills every column through
   the fill and multiplicities pass 2's proof takes them from (`ShardWitness`) and hands them to
   `work`; window shards come after the exit, in batches of `max_in_flight`. Its memory is §1's
   bound without any forward pass: at most `max_in_flight` shards' committed columns.
3. **Each shard**, as it fills: `checker::evaluate_rows` evaluates every row-local relation of
   the family's flat list on every row through the kernel, padding rows among them, and folds the
   halving lists over the rows into the circuit's outputs ([circuits.md](circuits.md) §3); then
   each channel's root pair must hold, the public windows' value columns must be the statement's
   words, and the time window must be within the clock.
4. **The statement**: `check_memory_windows`, `check_ts_windows` over every shard's record, and
   `verifier_core::verify_global_memory` over every shard's roots: the boundary in range,
   `v_10 = exit_status`, and the multiset reconciling against the register and pc boundary.

The challenges are the check's own: the five memory challenges, then `g` and `β`, squeezed from a
Poseidon2 transcript ([transcript.md](transcript.md)) that absorbs the program identity, the
public input and the advice under `CIRCUIT_CHECK`. The witness is a function of exactly those, so
no input can be chosen against the values it is checked at; each fingerprint wrongly agrees with
probability about its degree over `|Fp2|`.

| a proof's check ([proof.md](proof.md) §6) | the circuit check |
| --- | --- |
| 0, exit status 0 | the untraced run's status, and the record's |
| 2, the window rules and the payload ceiling | `check_memory_windows`; the executor refuses an input or journal past its window |
| 4, the time window | each shard's, and `check_ts_windows` over all (B4) |
| 7–8, the GKR pass | every relation on every row, exactly, rather than at a random point |
| 9, each channel's root pair | the same pairs, folded from the rows |
| 10c, the public windows | every word of the value column, rather than one evaluation |
| 10b, the boundary and the reconciliation | `verify_global_memory` itself, over the folded roots |
| 1, 3, 5, 6, 10a, 11, B1, B3 | not checked: they read commitments, the transcript or a proof's shape, which an honest prover's columns always meet |

A refusal, `CheckFailure`, names what fails: `Execution(EmuError)`, `NonzeroExit { status }`,
`Prover(ProverError)` (a column the fill refuses, such as an unassigned ecall's row),
`Relation { family, shard, row, relation }` (the lowest row, the first relation there in relation
order), `Channel { family, shard, channel, unmatched }` (the first tuple no table row holds, from
`checker::channel_sums`, or `None` where the counts are what is wrong), `PublicValue { family,
shard, row }`, `Statement(_)`, `Memory(_)`, or `Unsupported { family, detail }`, a circuit the
evaluator cannot read, a defect of the core. A shard's failure is the earliest in fill order, as
§5's is.

**What it does not establish.** That the two passes of a proof build the same columns, which the
executor's determinism gives and pass 2 asserts; that the commitments and openings verify, which
they do for an honest prover's columns; and anything [proof.md](proof.md) §1's statement binds
that this execution does not choose: the identity a verifier holds, the key.

**Cost**, measured on 2026-11-24 on an Apple M5 Pro (18 cores, 48 GB), release build, under
`apogee-host`'s `guard.sh 8 900`, on `guests/amazon`'s batch from
`crates/emulator/tests/guests.rs` (77 signed purchases, 3,860,659 cycles) with its execution
families at `2^20`, 22 statement shards:

| | wall | peak RSS |
| --- | --- | --- |
| `emulator::run` | 68 ms | 3.8 MB |
| `host::check`, `max_in_flight` 8 | 4.9 s, the executor 0.8 s of it | 5.3 GB |
| `host::check`, `max_in_flight` 1 | 11.9 s | 2.2 GB |
| `host::setup`, once a program | 2.1 s | 0.34 GB |

The peaks include the setup. A check's time is the prover's fill of every shard and one
evaluation of every row; its memory is the shards' committed columns, where a proof of the same
shards holds their forward passes too (§1).
