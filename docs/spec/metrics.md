# The proving metrics harness

> `crates/prover/src/metrics`, behind the `metrics` cargo feature. Added at S20 on the
> owner's instruction. This document is the schema and the reading guide; the module docs
> are the implementation's own.

---

## 0. The exception, and its limits

The workspace has **one cargo feature**, `prover/metrics`, and it is the one and only
exception to master **anti-goal 1**:

> **No cargo features. Zero.** One build configuration for the whole workspace.
> `[features]` tables, `#[cfg(feature = "...")]`, `optional = true` dependencies, and
> `--no-default-features` are all banned. A configuration nobody builds is broken and
> undiscovered; a configuration everybody builds should not be conditional. If code is
> optional, delete it.

The owner granted it at S20, for this harness and nothing else, with the rule left
standing for every future progression. Two things hold that:

- **`crates/prover/tests/one_feature.rs`** reads every `Cargo.toml` in the repository —
  the workspace's, and the three manifests deliberately outside it — and fails if any
  `[features]` **table** exists but this crate's, or if this crate's declares any key but
  `metrics`. (A `features = [...]` *key* inside a dependency entry selects an upstream
  crate's features, which the anti-goal permits and the workspace manifest already does
  for `ark-ec` and `ark-ff`. Only a table header declares a feature of ours.)
- **CI builds, clippies and tests the feature-on configuration too.** The anti-goal's
  stated hazard is "a configuration nobody builds is broken and undiscovered"; a
  configuration CI builds is neither.

The feature enables **no dependency**, optional or otherwise, and changes **no proof
byte** — `tests/metrics.rs` proves S16's statement through both entry points and compares
the two blocks on the wire.

### Why a feature and not a runtime switch

Because the harness is deliberately liberal. Sizing a shard's forward pass walks every
layer of every column, which is work proportional to the trace; sizing its base layer
walks every committed column. A runtime switch would leave that code compiled into every
proving run and reachable by a branch. The feature deletes it instead.

---

## 1. The seam

`Stage`, `ByteClass` and `ShardId` are plain data and are compiled in both builds. The
collector is not:

| | feature off (the default, and every proof in this repository) | feature on |
| --- | --- | --- |
| `Recorder` | a zero-sized struct; every method an empty `#[inline(always)]` body | the collector |
| `Span` | zero-sized | `(Stage, Instant)` |
| `Recorder::start` | **does not read the clock** | `Instant::now()` |
| the data model, the reports | do not exist | `metrics::on` |

So the prover's internals take `&mut Recorder` unconditionally. A ZST argument is not
passed and an empty inlined call emits no code, so the default build is the code that was
there before, and **timing needs no `cfg` at a call site**:

```rust
let span = rec.start(Stage::ShardForward);
let values = forward(artifact, base, &challenges);
rec.end(span);
```

What does need gating is a measurement whose **arguments** cost something — every byte
count, every shape note. Those use the `metric!` macro, which expands to nothing at all
with the feature off, so the argument is never evaluated:

```rust
metric!(rec.bytes(ByteClass::ForwardLayers, metrics::layer_values_bytes(&values)));
```

**No shared state.** Master anti-goal 7 bans global mutable state and the workspace has no
interior mutability, so the collector is threaded and not ambient. Each rayon task builds
its own `Recorder::for_shard`, returns it beside its result, and the caller `absorb`s them
in the order the indexed `map` collected — statement order. Two runs' reports therefore
differ only in their timings, never in their ordering.

---

## 2. The stages

Frozen in this order; appending is allowed, renumbering is not
(`tests/metrics.rs::the_stage_table_is_its_own_index`). A parent is **measured in its own
right**, not summed from its children, so the gap between the two is visible — the report
prints it as `(unattributed)` and it is itself a finding.

| root | children | what |
| --- | --- | --- |
| `setup_total` | `setup_register`, `setup_commit`, `setup_key_check` | `ProverSetup::new`: the registry's compilation, the setup MSMs, the key's load rules |
| `statement_columns` | `statement_shard_fill` | `statement_inputs`: every shard's `M` columns built from the archive |
| `global_commit_total` | `global_commit_msm`, `global_transcript` | the memory columns committed, then G1–G11 |
| `shard_columns_total` | `shard_fill`, `shard_multiplicities` | one call of `shard_columns`. **Read its sample count against the shard count** |
| `shard_gkr_task` | — | one rayon task's whole body in the GKR region |
| `shard_opening_task` | — | the same in the opening region |
| `shard_gkr_total` | `shard_base_layer`, `shard_witness_commit`, `shard_seed`, `shard_forward`, `shard_sumcheck`, `shard_replay` | S1–S5 |
| `shard_opening_total` | `shard_opening_columns`, `shard_opening_decode`, `shard_batch_open` | S6 |
| `block_total` | `block_plan_check`, `block_gkr_region`, `block_opening_region`, `block_final_section`, `block_finish`, `block_assemble` | `prove_block` |
| `archive_encode` | — | a phase section written |
| `archive_decode` | — | a phase section a resumed archive already held |

`block_gkr_region` and `block_opening_region` are the **wall** time of a parallel region.
The speedup is that wall against the sum of `shard_gkr_task` — **one task's whole body**,
not `shard_gkr_total`. The region waits for each task to build its shard's columns as well
as to prove it, so measuring only `gkr_part` against the wall understates the figure: on
the S16 statement it read **0.84×**, which is not a speedup at all and is not what the
region did. The report prints:

```
gkr region       6.41x over 18 threads (36% of them)
```

A figure well below the thread count is the region waiting on its slowest shard, and
`ProvingMetrics::slowest` names which.

**`block_total`'s `(unattributed)` remainder is the statement phase.** `statement_columns`
and `global_commit_total` are roots of their own — they are not shard work and do not
belong under a region — but they happen inside `prove_block`, so `block_total` minus its
listed children is very nearly their sum. On the S16 statement: 60.95 ms of remainder
against 31.55 ms + 27.01 ms of statement work. The two adding up is a check on the
accounting, not a finding — and watching that remainder fall from 1.82 s to 61 ms is how
the fix above was confirmed.

### What the stage counts already say

`shard_columns_total` reports **twice** the shard count — 4 for the S16 statement's two
shards — and that is the resume design's price, deliberately paid. `advance` builds every
shard's committed columns in the `PostGkr` phase, drops them, and builds them again in the
`PostOpening` phase, because the archive stores proofs and not columns
(`docs/spec/shard-proof.md` §10): one `2^20` base layer is 388 MiB, and the boundary
between the two phases is a **resume point** — a run killed during the opening region keeps
its GKR work, which is 11.9 s of a 16.1 s block here and most of 779 s on the S20 block
suite. `crates/prover/CLAUDE.md` records what fusing the two regions, or holding the base
layers across the boundary, would each cost.

**It read three before the harness existed, and the third was pure waste.**
`statement_inputs` was calling `shard_columns` — the whole committed set, every channel's
multiplicities counted — to take the `M` half out of it and drop the rest. The statement
commits `M` and nothing else, so it now calls `shard_memory_columns`, which runs the fill
and moves the memory columns out of the result. `build_multiplicities` is about **99%** of
what `shard_columns` costs (880 ms against 16 ms for the fill, on one `2^20` shard), and
that third pass was the **sequential** one, so removing it is pure wall clock:

| | before | after |
| --- | --- | --- |
| `statement_columns` | 1.783 s | **31.55 ms** |
| `shard_columns_total` | 5.360 s over 6 | **3.594 s over 4** |
| `block_total` | 17.723 s | **16.083 s** (−9.3%) |

The block is byte-identical either way (`tests/metrics.rs`), and the modelled peak is
unchanged at 4.95 GiB — this was never resident, only recomputed.

The other stage counts to read this way: `shard_gkr_total` and `shard_gkr_task` are once
per shard, `statement_shard_fill` is once per shard, and `archive_encode` is once per phase
section written.

---

## 3. The byte classes

| class | what |
| --- | --- |
| `memory_columns` | a shard's `M` columns, live for the whole global commit phase |
| `witness_columns` | a shard's `W` columns, multiplicities excluded |
| `multiplicities` | what `build_multiplicities` appends |
| `setup_columns` | the `S` columns a shard reads |
| `base_layer` | the `M ++ W ++ S` columns a shard proves over |
| `forward_layers` | **the forward pass's materialized layers** — the prover's largest structure |
| `opening_columns` | the opening's clone of the committed columns |
| `commitments` | 64 bytes a point |
| `gkr_proof`, `opening`, `statement`, `archive_section` | the wire forms |

A column is sized **as it is stored**: `crates/poly`'s small-type backings are the point of
that crate, and a `u1` column of `2^20` rows is 128 KiB where the `Fr` backing of the same
column would be 32 MiB. Counting the lifted `Fr` value would hide exactly the saving the
backing exists for.

---

## 4. The memory model

### 4.1 What it is, and what it is not

The harness **does not measure resident set size**. Reading peak RSS in-process needs libc
FFI or a `GlobalAlloc` wrapper, both `unsafe` and so banned by master anti-goal 4; the
owner chose allocation accounting over an exception at S20.

What it reports instead is **the bytes the prover asks for**, attributed to a cause. That
is a different and in some ways better quantity — it is deterministic, machine-independent,
reproducible, and it says *which structure* the bytes are — but it is strictly a **lower
bound** on RSS. It does not count:

- allocator slack, fragmentation, and pages freed but not returned to the OS;
- rayon's worker stacks and its own bookkeeping;
- the SRS, the trace archive and the program image, which are live for the whole run;
- any transient a called crate makes and drops inside a stage — `pcs::batch_open`'s
  scratch, the sumcheck's per-round buffers, MSM buckets.

Quote it as a floor and as an attribution. `/usr/bin/time -l` (`-v` on Linux) remains the
ground truth for RSS, as it is in every handoff note.

### 4.2 The peak

A shard is largest inside `gkr_part`, where its **base layer and its forward pass are live
at the same moment**. Those two classes, and only those two, carry
`ByteClass::resident_at_shard_peak` — pinned by a test so the model cannot drift from its
statement — and `shard_peak_bytes` is **the largest sample of each, never their sum**.
That distinction is load-bearing: `advance` builds a shard's base layer twice, once for the
GKR phase and once for the opening phase having dropped it in between, so two samples of one
class are one structure built twice and not two held at once. Summing would report every
real block about a base layer too large.

Shard proving is the block's one parallel step (`docs/spec/block-proof.md` §5), so at the
worst moment `min(rayon threads, shards)` shards each hold one. Summing the largest that
many is `modelled_block_peak`:

```
modelled_block_peak = Σ over the min(threads, shards) largest shard_peak_bytes
```

`modelled_resident_floor` adds the statement's memory columns, which are live across the
region.

**This is the number that explains S20's memory regression.** Proving shards in parallel
took `guests/mem`'s statement from 14.7 GB to 32.3 GB — about 2.2× for about 1.4× the
speed — and the model gives the shape of that before the run is made: one thread holds one
shard's peak, `n` threads hold the `n` largest. A caller that must bound the peak runs
`prove_block` inside its own `rayon::ThreadPoolBuilder` pool, and the model says what each
pool size costs.

### 4.3 Calibration

One measurement so far, S16's statement — two shards, `ADD_SUB_LUI_AUIPC` at `2^20` and
`INIT_TEARDOWN` at `2^16`, 18 rayon threads, **dev profile**, macOS/aarch64:

| | |
| --- | --- |
| modelled shard peak, `(0, 0)` | 4.94 GiB (base layer 776 MiB + forward layers 4.18 GiB) |
| modelled shard peak, `(7, 0)` | 8.5 MiB |
| modelled block peak | 4.95 GiB = **5.31 GB** |
| modelled floor (+ memory columns) | 5.36 GB |
| **measured, `/usr/bin/time -l`** | **8.60 GB** |

The model is **62% of the measured peak**, which is what a floor that excludes allocator
slack, rayon's stacks, the SRS, the archive and every in-stage transient should look like.
Note that only one shard is large here, so the block peak is one shard's peak whatever the
thread count; the thread-count effect the model predicts shows on a statement with several
large shards, and `guests/mem`'s seven-shard statement is the one to measure it on.

**Do not quote the model where the measured figure is what matters** — quote it to
attribute a peak to a structure, to compare two configurations, or to predict the effect of
a thread count.

### 4.4 A caution on `nanos_per_cycle`

It is `block_total / total_cycles`, and it is only meaningful when the trace fills its
shards. `guests/addsub` runs **29 cycles** in a `2^20`-row family, so the harness reports
0.63 seconds a cycle — true, and useless. Read it beside the occupancy table, which says
the same thing directly: 29 cycles in 1,048,576 rows is 0.0% full. A cycle-owning family's
shard cannot be smaller than `2^20` (`docs/spec/lookup.md` §3), so a small guest pays for a
whole one; this is where that shows.

---

## 5. The reports

`impl Display` is the human one: environment, what was proven, the stage tree with sample
counts and the slowest sample, the byte classes, the modelled peak, a per-shard table and a
per-family circuit table. `ProvingMetrics::to_json` is the machine one — one object,
written by hand so the harness needs no serialization dependency the workspace would not
otherwise have.

Both render from an empty recorder, which is what a phase nobody ran leaves.

---

## 6. The API

```rust
// crates/prover, feature = "metrics"
pub fn prove_block_metered(setup: &ProverSetup, archive: &mut TraceArchive, plan: &ShardPlan)
    -> Result<(BlockProof, ProvingMetrics), ProverError>;
pub fn advance_metered(setup: &ProverSetup, archive: &mut TraceArchive, until: Phase)
    -> Result<ProvingMetrics, ProverError>;

// and, for a caller assembling its own run, the same parts with a recorder:
impl ProverSetup { pub fn new_metered(program, srs, rec: &mut Recorder) -> Result<..>; }
pub fn statement_inputs_metered(setup, archive, rec: &mut Recorder) -> Result<..>;
pub fn global_commit_phase_metered(vk, srs, inputs, rec: &mut Recorder) -> GlobalCommitState;
pub fn shard_columns_metered(setup, archive, family, index, windows, rec) -> Result<..>;
pub fn prove_shard_metered(ctx, archive, family, shard_idx, rec) -> ShardProof;
pub fn prove_shard_columns_metered(ctx, family, shard_idx, columns, rec) -> (ShardProof, Vec<_>);
```

**Every frozen signature is unchanged.** `prove_block`, `advance`, `prove_shard`,
`prove_shard_columns`, `global_commit_phase`, `statement_inputs`, `shard_columns` and
`ProverSetup::new` take what they took at S20 and return what they returned; each is now a
one-line call into a private `_rec` implementation with a throwaway recorder, which in the
default build is a zero-sized value and no call at all.

---

## 7. Running it

```
cargo test -p prover --features metrics --test metrics          # the harness's own tests
cargo test -p prover --features metrics --test metrics -- --include-ignored --nocapture
                                                                # DEFERRED; prints the report
cargo clippy -p prover --all-targets --features metrics -- -D warnings
```

The `--include-ignored` line proves S16's statement twice (about 8.6 GB a time) and prints
both reports. It belongs with the other deferred suites: under the owner's standing
instruction those run **once at the end of a progression**, not per commit, and from S22
on they run on the **measurement host** — an EC2 `r8i.8xlarge`, 32 vCPU, 256 GiB — which
is started for a run and stopped after it (root `CLAUDE.md`, "Commands").

That is also why every number this harness reports is quoted with its environment. The
modelled figures are machine-independent by construction (§4.1) and the measured ones are
not: `modelled_block_peak` is a function of the rayon thread count, and the thread count
is a property of the host. **A report pasted into a handoff note without the host it was
taken on is not a measurement** — name the cores, the memory, the profile and the OS, as
§4.3's calibration does.
