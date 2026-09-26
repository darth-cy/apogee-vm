# `tools/bench`

## What this crate owns
One routine per thing worth measuring, and — since S25 — one **verb** that runs a real
proving job and emits a `BenchReport`.

```
cargo run --release -p bench                     # every routine, in registry order
cargo run --release -p bench -- zerocheck-verify # just that one
cargo run --release -p bench -- --list           # the registry, and the verb

cargo run --release -p bench -- prove mini-block --hourly-usd 2.36 --json report.json
```

**The charter moved by one line at S25, and only one.** It used to read "no assertions, no
thresholds, no committed output"; the stage requires the report to be committed to its
handoff note, so *committed output* is now a thing this crate has. No thresholds and no
assertions still hold, with one exception the `prove` verb makes and states: it asserts
that the proof **verifies**, because a timing for a proof that does not verify is not a
measurement of anything. A number that must not regress still belongs in a test.

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
| `src/block.rs` | `prove` (a verb) | S25: one recorded block proved end to end and verified, filling a `BenchReport` |
| `src/report.rs` | — | the `BenchReport` schema, frozen at S25, and the machine facts it carries |
| `src/main.rs` | — | the registry, the one verb, and the argument parsing |

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
  signatures for one caller; `main` matches the verb before the table instead.
- **The `prove` verb's per-stage timings are the `TraceArchive`'s own phase sections**,
  which S12 froze and S16 filled in — must-be-exact 5, *"not from ad-hoc stopwatches
  sprinkled in the prover"*. It does **not** enable `prover/metrics`: turning that on from
  a dependency entry would turn it on for every `cargo build --workspace`, and
  `docs/spec/metrics.md` §1's claim that the feature-off build is the code that was there
  before would stop holding. The archive's phase timings need no feature.
- **The five phases do not sum to wall-clock, and the remainder is named.**
  `ProverSetup::new`, the plan check, `finish` and the block assembly sit outside every
  phase's span; the report carries `setup_ms` separately and `unattributed_ms` for the rest,
  which is the discipline `docs/spec/metrics.md` §2 applies to its own stage tree.
- **Peak memory is reported where the platform gives one and refused where it does not.**
  Linux's `/proc/self/status` carries `VmHWM` in plain text; macOS has no equivalent short
  of `unsafe`, which master anti-goal 4 bans, so the field is `None` and its `source` says
  why and names `/usr/bin/time -l` as the thing to wrap the run in.
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
