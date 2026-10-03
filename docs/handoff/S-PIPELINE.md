# S-PIPELINE — the shard pipeline: pulled, bounded, and with no barrier

One stage, one branch (`s-pipeline`), on the owner's instruction after the first
full-block proof (`../apogee-stateless-runs/2026-10-02`, devnet block 257,510 through
`revm-block-stateless`): commit pass 1's shards in parallel, fill the next shards while
the current ones prove, and replace lock-step batches with a sliding window — and **the
pattern needs to be defensible**. It changes no proof byte, no transcript, no wire form,
no circuit and no constant. It changes how the prover spends a machine.

## 0. The decisions, and who took them

- **The pattern: a scoped worker pool** (owner's choice of three, put to the owner
  before any code). `max_in_flight` workers under `std::thread::scope`, one
  `std::sync::Mutex` around the executor, and everything inside a shard still rayon over
  data. The two refused: **rayon-only overlapped batches** (`rayon::join` of the
  executor and the next batch's fills against the current batch's proofs), which needs
  no rule change but keeps the barrier; and **`par_bridge` in a pool of `max_in_flight`
  threads installing into a second pool**, whose bound would rest on `par_bridge`'s
  per-thread re-entry guard, an implementation detail of rayon 1.12.
- **Master anti-goal 7's one exception**, authorized with that choice (§3).
- **Pull-based, with backpressure** (owner's instruction, mid-stage): demand from an
  available worker is what produces the next shard; the executor does not run ahead
  generating shards; nothing memory-heavy — filled columns, commitments, GKR structures —
  is ever queued; a worker claims a shard *before* its trace and fill data are
  materialized; and `max_in_flight` bounds every memory-heavy shard state, not merely
  the shards currently proving. The design below is exactly that, and two assertions in
  the code hold it there.

## 1. What the run showed

The batch shape, as measured on the first full-block run (349M cycles before S26e, 382
shards, 32 cores, `max_in_flight` 12, 6,635 s proving):

| step | seconds | share | cores busy |
| --- | --- | --- | --- |
| pass 1: execute | 55 | 1% | 1 |
| pass 1: commit 382 shards, one at a time | 2,232 | 34% | ~3.5 of 32 |
| pass 2: re-execute, and fill each batch | 650 | 10% | 1, no overlap with proving |
| pass 2: prove 31 batches of 12 | 3,641 | 55% | 70–100% |

About 23% of the proving slots sat idle, each batch waiting for its slowest shard — the
154 s `KECCAK_F` shard and the slower shift and memory shards, against 77–107 s for the
rest.

Reading the source said why each line was what it was:

- **Pass 1 used three or four cores because nothing in a shard's fill uses rayon.**
  `crates/prover/src/fill.rs`, `crates/trace` and the emulator have no parallel code;
  only the MSMs in `commit_all` are parallel, and `commit_chunks` committed one shard at
  a time on purpose ("holding two shards' columns here would buy nothing but a second
  shard's worth of peak"). The fill dominates a shard's pass-1 time.
- **Pass 2's fills ran before proving and in step.** Every task in a batch filled
  first and proved second, so the batch's fills overlapped one another and nothing else,
  and the executor ran only between batches.
- **The barrier was the batch.** Fork-join is the only shape that bounds live shards
  below the core count without coordination, and its price is that a batch finishes when
  its slowest shard does.

`docs/spec/streaming.md` §5 had said the opposite — that the batch-then-prove shape
needed no threads because "execution is under 1% of a block's wall clock". That was true
of the executor and beside the point: the cost was the barrier's and the serial fills'.
§5 now says so.

### 1.1 The same block, through the pipeline

Measured at `1fcd5b2` on the same box with the same command: `bench prove --stateless`,
`--in-flight 12`, `APOGEE_DEBUG=phase`. Every log line was timestamped and `vmstat`
sampled the CPU every 10 s (`../apogee-stateless-runs/2026-10-03`, which also archives the
proof). The block verified, and its journal is the fixture's 43 bytes.

**S26e is in this tree and not in §1's.** The guest is 198M cycles and 207 shards, and
`SHA256_COMP` is one `2^18` shard where it was 32 at `2^8`. So the totals measure both
stages, and only each pass's rate per shard and its cores busy measure this one:

| | batches (§1) | pipeline |
| --- | --- | --- |
| pass 1 | 2,287 s; 5.99 s a shard; ~3.5 of 32 cores busy | 191 s; 0.92 s a shard; 25.7 of 32 |
| pass 2 | 4,291 s; 7.99 shard-seconds of GKR and opening per second | 2,290 s; 8.89 |
| proving | 6,635 s; 382 shards | 2,481 s; 207 shards |
| peak RSS | 192.97 GiB | 173.92 GiB |

- **Pass 1 is 6.5× faster per shard.**
  - It held all 12 shards for 75% of the pass, 11.34 on average.
  - Its fills now bound it: they are 81% of its shard-seconds, one thread each.
  - Its sampled memory never passed 15.9 GiB.
- **Pass 2 kept the box full until the guest exited**: 11.95 of 12 shards held on
  average and 30.4 of 32 logical CPUs busy for 1,825 s, 80% of the pass.
  - A shard costs what it did: the `2^20` families' GKR times are within ~10% of §1's.
  - The gain is ~10%, not the quarter §1's idle slots suggested. A finished shard's idle
    slot never idled its cores: rayon gave them to the shards still running, which is
    §1's 70–100% busy while proving.
- **What remains is the exit's tail: 460 s holding 5.6 of 12.**
  - Its shards exist only once the guest exits, and the workers claimed all eleven within
    122 s.
  - `KECCAK_F#1` ran 388 s, 200 of them its fill on one thread, and finished 169 s after
    every other shard.
  - `KECCAK_F#0`, claimed 215 s before the exit, ran 563 s, 279 of them its fill.
- **The peak was the two `2^18` `KECCAK_F` shards**, held together in the tail with
  nothing else: two shards, not the twelve the bound allows.

**The pipeline's share is an estimate.** Scaling §1's run to this shard mix (its executor
by cycles, its commits by non-SHA shards, pass 2 by GKR and opening work) puts the batch
shape at ~3,900 s here. That makes the pipeline's share ~36% of the wall clock: 7.0× on
pass 1 and ~10% on pass 2. A run of `main` on the same box would measure it.

## 2. The pipeline

`crates/prover/src/streaming.rs`. Both passes run one function, `pipeline`, over a
`Source` behind the one lock:

```text
worker:  loop {
             lock;  give back the shard I held (and its error, if it failed);
                    claim the next: a waiting shard if there is one,
                                    else step the executor until a buffer fills;
             unlock;
             work it — pass 1: build and commit its M; pass 2: fill and prove it;
         }
```

- **`Source::claim`** is the only place the guest is stepped, for the worker claiming,
  and only when no filled shard is waiting. At exit it calls `finish` and the tail
  becomes ordinary waiting shards.
- **`Source::admit`** asserts that no family ever has two shards waiting. One step fills
  at most two buffers (the requesting family's, and the delegation family's for a
  delegating ecall) and the exit at most one per family, so a second shard of a family
  arriving while the first waits would mean production ran ahead of demand.
- **`claim` asserts** that the shards claimed never exceed the workers.
- **`Source::fail`** keeps the earliest failure in fill order and stops every claim
  after it; `give_back` records a worker's failure there.
- **`StopOnPanic`**, a drop guard, stops the claims when a worker unwinds. A panic inside
  the executor poisons the lock instead, which every worker reads as stop. `pipeline`
  joins every worker and re-raises the first panic as itself.

### 2.1 What is held, and what bounds it

| what | bound | held there by |
| --- | --- | --- |
| shards claimed — rows, and everything built from them | `max_in_flight` | one shard a worker; `claim`'s assertion |
| shards filled and not yet claimed | rows only, at most one per family | stepping only on demand; `admit`'s assertion |

The second row is the executor's own state under a new owner: a buffer that reached its
height and has not been taken, where a partial buffer stood a step before. **There is no
queue of anything heavier than rows**, and a run whose workers are all busy has a stopped
executor. The workers are not rayon threads, so a worker blocked on its shard's rayon
work cannot steal a second shard — the failure S-BATCH documented on the archived path
(17 shards live at 12 threads) cannot happen here, and the bound is the worker count and
nothing a scheduler decides.

### 2.2 Why it is correct

- **The block does not depend on the schedule.** Proofs are placed by statement
  position, and each is a function of the global state and its own columns — the same
  argument as before, unchanged.
- **No deadlock.** One lock; never held while a shard is worked; never taken twice by
  one worker; nothing blocks while holding it but the executor's step.
- **The failure returned is the same at any worker count.** Claims are in fill order,
  so every shard before the first failure recorded has been claimed, and a claimed shard
  is worked to its end; the earliest failure is always among them. An executor failure
  ranks after every shard it filled, which have all been claimed.
- **A panic never hangs the run**: the claims stop, the shards in flight finish, the
  panic is raised as itself.

### 2.3 What stayed a batch

The window families' shards — `INIT_TEARDOWN`, `ZERO_WINDOWS`, the two public windows,
`ADVICE_WINDOWS` — are not the pipeline's. Their teardown columns are every address's
*last* write, so they are not a fact until the execution is over (`docs/spec/streaming.md`
§3.2), and they need the final state the pipeline hands back. They follow it, in both
passes, as `par_iter` batches under the same bound, exactly as pass 2 already proved
them. They are a handful of cheap shards, and keeping them out kept the pipeline about
one thing. Pass 1's window commitments were sequential before and are batched now.

### 2.4 What a worker's thread means for a caller

The workers are plain threads, so their rayon work goes to rayon's **global** pool:
`RAYON_NUM_THREADS` bounds the shards' cores, and a `ThreadPool::install` around
`prove_block_streaming` now bounds only the window batches. Two things followed.

- **`crates/prover/tests/block.rs`' `the_block_does_not_depend_on_the_thread_count`**
  (deferred) proved the whole block inside a one-thread `install`. Under the pipeline that
  would still pass while varying the thread count of almost nothing, so it now asserts
  the claim where it lives: on a one-thread pool, the global commit phase rebuilt from the
  archive (as `a7` rebuilds it) must have the streamed block's digest, and every shard
  proved by `prove_shard` must be the streamed block's byte for byte. It proves the same
  six shards on one thread that it did before. It is also, now, a second place where an
  archived construction is held to the streamed one — every shard's proof, where `a7`
  holds only the digest — so its message names both causes a mismatch could have.
- A worker runs its shard's fill on its own thread, outside the pool, so a pass can have
  up to `RAYON_NUM_THREADS + max_in_flight` threads runnable. A fill is one thread, and the
  operating system shares the cores.

Running each shard's whole work inside a caller's pool instead (`install` from each
worker) would have kept the old meaning of `install` and given back the problem the
pipeline exists to avoid: a pool thread waiting in a nested join takes an injected
whole-shard job and runs it to the end before resuming the shard it was in.

## 3. `prompts/00-master.md` — anti-goal 7, amended (authorized)

Anti-goal 7 ("No async, no threads, no interior mutability. Parallelism is `rayon` over
data, and nothing else") gains **one named exception**, in anti-goal 1's form: the
streaming prover's shard pipeline, `max_in_flight` workers under `std::thread::scope`
sharing one `Mutex` around the executor; why fork-join cannot express it; that it is
pull-based; and **"This is not a precedent."** The owner authorized the edit in choosing
the pattern, whose description named it.

`crates/prover/tests/one_pipeline.rs` is what keeps it one site, the way
`tests/one_feature.rs` keeps anti-goal 1's exception one key:

1. every `.rs` file under `crates/*/src` and `tools/*/src` (134 today) is read, and a
   thread spawn or scope, a lock or condition, a channel, an atomic, `OnceLock` or
   `async fn` anywhere but `crates/prover/src/streaming.rs` fails, naming the file and
   line. Tests and guests are not swept, and the file says why: `tests/common`'s `SEQ`
   is a test's counter, and `guests/atomics`' atomics are the A extension it proves;
2. `streaming.rs` itself is held to **one** `std::thread::scope(` and **one**
   `Mutex::new(`, and nothing else from the list — a second lock or a channel would be a
   different design, not a change to this one;
3. the exception is written down in `prompts/00-master.md`, both `CLAUDE.md`s and
   `docs/spec/streaming.md`.

## 4. What changed outside the pipeline

- **`StreamingReport`** (`crates/prover`). `pass1_commit_ns` and `pass2_prove_ns` are
  gone: the passes overlap execution with work, so a commit or prove "interval" no
  longer exists. In their place, **`pass1_ns` and `pass2_ns`, each pass's wall clock**,
  with `pass1_execute_ns` and `pass2_execute_ns` the executor's time *inside* them.
  `peak_in_flight` is the most shards held at once in either pass, window batches
  included; it does not count waiting rows.
- **`tools/bench`**. `Phases` maps `commit_ms` and `gkr_ms` to the two wall clocks and
  `execution_ms` to the executor's time, and **`Phases::total_ms` leaves `execution_ms`
  out**, which is what keeps `unattributed_ms` the honest remainder rather than negative.
  The table says so in its note. The JSON's shape is unchanged; its meaning is not, and
  a figure here is comparable with neither a pre-S-STREAM report nor a pre-S-PIPELINE
  one.
- **`host`**: doc comments only.
- **The debug log** (`docs/spec/debug-info.md`, "Which pass died"). `pass 2 flushed …
  queue=` is gone with the queue. Every shard of every pass now has a `take` line when a
  worker claims it — its place in fill order, `in_flight=k/N`, `waiting=w` — and a
  `committed` or `proved` line when the worker is done, carrying `fill_ms` (one thread)
  and the total. The two `pass N done` lines carry the pass's wall clock, the executor's
  time and the pass's own peak. A `take` with no `committed`/`proved` names a shard that
  was in flight when a run died; `in_flight` held below the bound in mid-pass is a pass
  whose executor is the bottleneck.

## 5. The frozen API

```rust
// crates/prover — unchanged signature
pub fn prove_block_streaming(setup: &ProverSetup, io: &GuestIo, max_in_flight: usize)
    -> Result<(BlockProof, StreamingReport), ProverError>;
// changed fields
pub struct StreamingReport {
    pub cycles: u64, pub shards: usize, pub peak_in_flight: usize, pub max_in_flight: usize,
    pub pass1_ns: u64, pub pass1_execute_ns: u64,
    pub pass2_ns: u64, pub pass2_execute_ns: u64,
}
// crate-private, two callers (pass 1 and pass 2)
fn pipeline<T: Send>(pass: u8, run: StreamingRun<'_>, workers: usize,
                     work: impl Fn(&ShardChunk) -> Result<T, ProverError> + Sync)
    -> Result<Piped<T>, ProverError>;
```

`max_in_flight` keeps its meaning — the most shards alive at once, and what the peak is a
function of — and gains a second: it is the worker count.

## 6. Tests

Fast, in `cargo test --workspace`:

- `crates/prover/src/streaming.rs`'s four unit tests drive the **real executor** over
  `guests/shards` at `2^16` — seventeen add/sub shards filled in mid-run, every other
  family's at exit — with a stand-in where the work goes, because what the work is does
  not reach the pipeline: every filled shard worked exactly once at 1, 3 and 8 workers
  and never more than the worker count at once, read off the pipeline's own count *and*
  off intervals the work recorded; the executor stepped only for a claim with nothing
  waiting, claims in fill order, two held claims counted as two; the earliest failure in
  fill order returned at 1 and 4 workers; a panic reaching the caller as its own
  payload. 0.7 s. With the feature on, the same run prints the window filling to
  `in_flight=8/8` and staying there, `waiting` never above 1.
- `crates/prover/tests/one_pipeline.rs`'s three (§3).

Deferred: `crates/prover/tests/streaming.rs` is unchanged in code — it still proves the
block equal at `max_in_flight` 1 and 8 over two statements, and its assertions on
`peak_in_flight` still hold by the reasoning in §2.3 (S16's peak is still the
three-shard window batch); its doc comments now speak of workers, not a batch.
`crates/prover/tests/block.rs`' thread-count test is reworked (§2.4).

## 7. What this stage owes

### Green here

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo clippy -p prover --all-targets --features debug-info -- -D warnings`
- `cargo test -p prover --lib`, and with `--features debug-info`: 6 and 23 tests
- `cargo test -p prover --test one_pipeline --test one_proving_path --test one_feature`
- `cargo test -p prover --features debug-info --test debug_info`

No file under `tools/transcript-ref`, `tools/stateless-ref`, `crates/guest-sdk` or
`guests/` changed, so their fmt, clippy and build lines are untouched by this stage.

### CI's

`cargo test --workspace`, on the owner's standing instruction: green at `1fcd5b2`, with
every other step of `ci.yml`.

### On the dev box

The full-block run the stage was built for, and the peak under the pipeline: §1.1.

### Owed

- **The deferred suites**, in one batch at the end of the progression,
  `crates/prover/tests/streaming.rs` first: it is the one that holds this stage's claim
  on real proofs.
