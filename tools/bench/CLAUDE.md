# `tools/bench`

## What this crate owns
One routine per thing worth measuring, and **verbs** that run real proving jobs: since S25
`prove`, which proves one block and emits a `BenchReport`, and since S-RECURSION
`recurse`, which proves a base block proof's recursion tree.

```
cargo run --release -p bench                     # every routine, in registry order
cargo run --release -p bench -- zerocheck-verify # just that one
cargo run --release -p bench -- --list           # the registry, and the verbs

cargo run --release -p bench -- prove mini-block --hourly-usd 2.36 --json report.json
cargo run --release -p bench -- prove mini-block --in-flight 4   # the backpressure bound
cargo run --release -p bench -- prove mini-block --out proofs/   # write the proof out
cargo run --release -p bench -- prove --stateless <fixture.json | input.bin> [--case <name>]
```

**`recurse` proves a base block proof's recursion tree** (S-RECURSION,
`src/recurse.rs`, `docs/spec/recursion.md` §8.4):

```
cargo run --release -p bench -- recurse <dir>/<stem> --out <dir> [--leaf 64] [--budget <rows>]
    [--fan-in 4] [--in-flight 1] [--shards-in-flight 1] [--limit <shards>]
cargo run --release -p bench -- recurse-node <out> <id> [--shards-in-flight 1]   # what recurse runs
```

`<dir>/<stem>` is a proof archive `prove --out` wrote. The scheduler first builds the
`leaf` and `node` binaries and holds `guests/recursion/base.key` to the archive's key and
`programs.key` to the two binaries' program keys, refusing with the `profiler` verb that
rewrites a stale one (`tools/profiler/CLAUDE.md`). Then it sets each program up once and
writes `<out>/leaf.elf`, `node.elf`, `leaf.vk` and `node.vk`, printing both identities.

**The tree is planned before anything is proved** (`host::recursion::Tree::plan`, over
`host::recursion::shard_costs`) and written to `<out>/tree.txt`: a `base <dir>/<stem>` line,
then `Tree::to_text`. Leaves are runs of consecutive base shards, at most `--leaf` of them
and, given `--budget`, at most that many estimated `FQ_OP` rows of folds, a shard alone
over it being a leaf of its own; then levels of internal nodes over two to `--fan-in`
children, a group of one carried up a level. `--fan-in` is 2 to 4, the procedure's
limit, and refused outside it. A node costs about a shard a family before it does any work — sixteen — so a leaf
is cheapest large: another `FQ_OP` shard is one shard, another node sixteen. `--limit <n>`
plans over the base statement's first `n` shards only, which proves everything but the
root's claim to the whole statement.

Each node is a **process**, `bench recurse-node <out> <id>`. It reads `tree.txt`, the
archive, its program's `.elf` from `<out>` and, for an internal node, the other's and its
children's `<c>.block` with both `.vk`s; sets its own program up again, a `ProverSetup`
not being saved, only its key; builds its advice only then, through
`host::recursion::leaf` or `internal`, whatever it verifies checked and every tape
replayed natively; proves at most `--shards-in-flight` shards at once, verifies the proof
and holds its journal to the native one; and writes `<out>/<id>.block` through
`<id>.block.partial` and a rename. Its stdout and stderr are `<out>/<id>.log`. So a node's
memory is its own process's, and a node could run on another machine sharing the
directory. The scheduler starts the lowest ready id while fewer than `--in-flight` run —
every leaf before any internal node, the leaves being numbered first — and polls them
every half second. That is how it stays outside master anti-goal 7: it starts no thread,
and `crates/prover/tests/one_pipeline.rs` sweeps this crate too.

**A proof already in `<out>` is not proved again, so a stopped run resumes.** Done means
`<id>.block` exists, so a rerun must be the run the directory was started with: one whose
plan differs from `<out>/tree.txt` — another `--leaf`, `--budget`, `--fan-in` or
`--limit` — or whose `leaf` or `node` build differs from `<out>`'s `.elf` is refused,
since it would reuse proofs by ids that now name other nodes, or proofs of other
programs. A node killed mid-write leaves only its `.partial` and is proved again. A node
that fails stops the scheduler, naming its log, and the scheduler kills the nodes still
running first, the tree being unable to finish.

**At the root** the scheduler checks what a verifier of the tree owes beside the root's
own proof: the proof verifies under `<out>/leaf.vk` or `node.vk` by the root's kind, a
one-leaf tree's root being a leaf; its output is a node's journal, 47 cells; it covers
shards `0..` the planned count; an internal root requires the identities this run's
`leaf.vk` and `node.vk` carry; and its accumulator discharges, `e(A, [1]_2) = e(B, [x]_2)`
against the base key's `SrsVerifier`; and its statement cells — the global digest, the
four memory challenges, `io_digest`, the exit status and the shard count — are the
archive statement's, as the native global transcript computes them. It then says whether
the shards covered are the whole base statement or, under `--limit`, a prefix. The shape
digest is not recomputed, and the identities it compares are the run's own, not ones from
a channel the prover does not control.

It needs the `2^24` ceremony, `assets/ptau/ppot_0080_24.ptau`, ingested once and cached as
`apogee-ceremony-24.srs` in the system's temporary directory, which every node process
then loads. Every error either verb returns, a usage error included, exits 1 with the
reason and the usage on stderr.

**`prove --stateless <file>` proves one canonical stateless input with
`revm-block-stateless`**: an EEST fixture JSON's `statelessInputBytes` — a `tests-zkevm`
release, or a batch of the zkEVM benchmark's devnet datasets — or a file of nothing but
those bytes. The bytes reach the guest's advice **unchanged**; the guest is never told it
was a file. A fixture's `statelessOutputBytes` is the journal the proof must bind, held
natively before proving — the library is the guest's own code, so a mismatch it shows
would cost a whole proof to learn — and on the proof after it. A raw file has nothing to
hold the journal to, so it is printed. `--case` picks one input, by part of its JSON
path, out of a fixture holding several. A stateless proof carries a `2^18` `KECCAK_F`
shard, ~60 GB of forward pass, so it is a dev-server job.

**`prove` is `prover::prove_block_streaming`, and since S-STREAM there is no other
path** (`docs/spec/streaming.md`). `--in-flight <n>` no longer *selects* a path: it is
the prover's worker count — each worker holds one shard at a time, which is what bounds
the peak (`docs/spec/streaming.md` §5, S-PIPELINE) — and it defaults to
`block::DEFAULT_IN_FLIGHT` = **8**, measured under the batch shape on a 51-shard
mini-block at 77.10 GiB for four against 83.91 for eight, the extra four worth 14% of the
wall clock. The block does not depend on it.

There is no archive and so no five phase timings, so the report's clocks read differently
from a pre-S-STREAM one and the printed table says how. **Since S-PIPELINE** `commit` and
`gkr` are the two passes' **wall clocks** — pass 1's execution and commitments, and pass
2's execution and proofs, the GKR proof and the opening fused over one base layer — and
`execution` is the executor's time across both, which runs *inside* them while the
workers commit and prove, so `Phases::total_ms` leaves it out. `opening` and `final` are
0 because there is no phase boundary there to measure. A figure here is comparable with
neither a pre-S-STREAM report nor a pre-S-PIPELINE one. `BenchReport`'s `in_flight` field
is now always `Some`.

`--out <dir>` writes the verified block's four files through
`verifier::proof_archive::write_proof` — `<fixture>.vk`, `.identity`, `.public` and
`.block`. **It is the only thing a proving run archives**, and it is written only after
`host::verify` succeeds. `verifier block` reads the `.vk`, `.public` and `.block`; its
identity is 64 hex digits from a channel the prover does not control, and `.identity` is
only what the run claimed (`crates/verifier/CLAUDE.md`).

**`prove` exits 1 when it fails, whatever failed** — a fixture, witness, journal or
stateless input missing, an input empty or not picked out of its file, no ceremony
without `--toy-srs`, a guest that does not build or register, a block that does not
prove, a proved journal that is not the expected one, an `--out` that does not write —
with the reason on stderr; a usage error exits 2, and what it asserts still panics. The
journal and `--out` fail only after the report is printed, because the measurement is
still good and cost the whole run. Until S-STREAM's review each of these printed a line
and exited 0.

**The charter moved by one line at S25, and only one.** It used to read "no assertions, no
thresholds, no committed output"; the stage requires the report to be committed to its
handoff note, so *committed output* is now a thing this crate has. No thresholds and no
assertions still hold, with one exception the proving verbs make and state: they assert
that the proof **verifies** — `recurse` every node's, holding its journal to the native
one, and at the root what a verifier of the tree owes besides — because a timing for a
proof that does not verify is not a measurement of anything. A number that must not
regress still belongs in a test.

Numbers are internal and machine-dependent. Master rule 11 wants a benchmark in the same
commit as any optimization; this is where that benchmark goes.

## The shape
| File | Routine | Measures |
| --- | --- | --- |
| `src/fr_arith.rs` | `fr-arith` | S01: `Fr` mul, square, inverse, batch inverse against ark-bn254 |
| `src/poly_bind.rs` | `poly-bind` | S03 acceptance 10: lift plus the full bind chain at 2^20 |
| `src/msm.rs` | `msm` | S07 acceptance 9 and 10: MSM at 2^22 over real ceremony bases, against ark-bn254 |
| `src/mercury.rs` | `mercury` | S08 acceptance 11: Mercury commit/open/verify at 2^22, the opening's MSM accounting, and narrow-backed against Fr-backed commit |
| `src/zerocheck_prove.rs` | `zerocheck-prove` | S04 acceptance 9: prove wall-clock and peak polynomial memory at 2^20 |
| `src/zerocheck_verify.rs` | `zerocheck-verify` | S04: `verify_zerocheck` against recomputing every row, at 2^22 |
| `src/gkr_prove.rs` | `gkr-prove` | S13: the GKR engine's `forward`, `self_check`, `prove` and `verify`, separately, over a circuit built as data (32 narrow committed columns, 339 gates over 20 lists: cached, virtual, enforcing and `Quadratic` gates, then halving lists down to 16 product-tree roots) at 2^18; the forward pass's computed table memory |
| `src/square.rs` | — | the `A * A - B = 0` instance the two zerocheck routines share |
| `src/timing.rs` | — | the seed, `REPS`, `Best`, and the formatting helpers |
| `src/block.rs` | `prove` (a verb) | S25: one recorded block — or, since S-STATELESS, one stateless input — proved end to end and verified, filling a `BenchReport` |
| `src/recurse.rs` | `recurse`, `recurse-node` (verbs) | S-RECURSION: a base block proof's recursion tree, planned, proved node by node in worker processes, and its root checked |
| `src/report.rs` | — | the `BenchReport` schema, frozen at S25, and the machine facts it carries |
| `src/main.rs` | — | the registry, the verbs' dispatch, and the argument parsing |

## The rules
- **Routines are independent.** Each derives its own stream from the one `SEED`, builds
  its own data, and prints its own table. Running a routine alone must give the same
  number as running it with the others, because the reason for the split is that setup is
  not free: `zerocheck-prove` spends about nine seconds digesting a 2^20-row witness
  before it measures anything, and `zerocheck-verify` spends about forty on a 2^22-row
  one. Neither should be a reason to avoid running `fr-arith`.
- **`prove` is a verb and not a routine, deliberately.** A routine is `fn()` — no
  arguments, no output but stdout — and a proving job has to be told which block and what
  the hardware costs. Adding a parameter to the registry would have meant changing eight
  signatures for one caller; `main` matches the verbs before the table instead, `recurse`
  and `recurse-node` for the same reason.
- **The `prove` verb's per-stage timings come from the prover and not from this crate**,
  which is must-be-exact 5, *"not from ad-hoc stopwatches sprinkled in the prover"*. They
  were the `TraceArchive`'s five phase sections until S-STREAM; they are now
  `prover::StreamingReport`'s clocks, measured inside `prove_block_streaming` around each
  pass and around every step any worker takes of the executor. It enables **no cargo feature** to get them — they
  are in the default build, and a feature turned on from a dependency entry would be on
  for every `cargo build --workspace`. (There was a `prover/metrics` harness that measured
  the same job a second way; it was retired at S-STREAM with the archived path it
  instrumented, and nothing here depended on it.)
- **The phases do not sum to wall-clock, and the remainder is named.**
  `ProverSetup::new`, the plan check, `finish` and the block assembly sit outside every
  phase's span; the report carries `setup_ms` separately and `unattributed_ms` for the
  rest, rather than absorbing it into a total nobody could check against a clock.
- **Peak memory is reported where the platform gives one and refused where it does not,
  and `src/report.rs`'s `peak_rss` is where that rule is written down.** Linux's
  `/proc/self/status` carries `VmHWM` in plain text; macOS has no equivalent short of
  `unsafe`, which master anti-goal 4 bans, so the field is `None` and its `source` says why
  and names `/usr/bin/time -l` — this repository's ground truth for peak RSS, and what
  every handoff note's memory figure was taken with — as the thing to wrap the run in.
- **Adding a routine is a module plus a row in `ROUTINES`.** The registry in `main.rs` is
  `(selector, one line of what it measures, entry point)`. No trait, no registration
  macro, no dynamic dispatch beyond a function pointer.
- **Setup is never inside the timed region**, and anything excluded from a comparison is
  named in that routine's own output rather than left for the reader to infer.
- **A routine that compares two checkers proves both can fail first.** `zerocheck-verify`
  asserts that each of its two verifiers accepts the honest input and rejects a corrupted
  one before it times either. A benchmark of a checker that cannot reject is a benchmark
  of nothing.

`msm` and `mercury` are the routines that need an asset: `assets/ptau/ppot_0080_24.ptau`,
gitignored and 19 GB. Both measure over **real SRS bases** and do not substitute random
ones — each says so and returns when the file is absent. `ark-ec` and `ark-ff` carry their
`parallel` feature in the workspace manifest so that row compares two rayon
implementations rather than ours against a single-threaded reference; that would be a gate
passed by not being compared.

## The hazards
`zerocheck_verify.rs` holds a second copy of the frozen transcript script, so it can time
the sponge without the arithmetic. A copy of that script drifts, so this one carries a
tripwire: the replay's sponge state is compared against the real verifier's, and on a
mismatch the routine prints why it is withholding the breakdown instead of printing a
wrong one. If you change the script, either update that replay or delete it and the line
it feeds.

`mercury.rs` restates `pcs::open`'s MSM sizes so it can print the scalar-multiplication
accounting. Like `msm.rs`'s window rule, that table is printed and never used, so a drift
misreports a line rather than changing a measurement.
