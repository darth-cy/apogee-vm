# `tools/bench`

## What this crate owns
One routine per thing worth measuring. Nothing else — no assertions, no thresholds, no
committed output. A number that must not regress belongs in a test, not here.

```
cargo run --release -p bench                     # every routine, in registry order
cargo run --release -p bench -- zerocheck-verify # just that one
cargo run --release -p bench -- --list           # the registry
```

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
| `src/advice.rs` | `advice` | S25b: the advice region against the fd 0 `read` path, per word of witness — two hand-encoded programs summing the same `n` words, one through an ecall per word and one through an `lw` per word, with the shard plan each produces |
| `src/gkr_prove.rs` | `gkr-prove` | S13: the GKR engine's `forward`, `self_check`, `prove` and `verify`, separately, over a circuit built as data (32 narrow committed columns, 339 gates over 20 lists: cached, virtual, enforcing and `Quadratic` gates, then halving lists down to 16 product-tree roots) at 2^18; the forward pass's computed table memory |
| `src/square.rs` | — | the `A * A - B = 0` instance the two zerocheck routines share |
| `src/timing.rs` | — | the seed, `REPS`, `Best`, and the formatting helpers |
| `src/main.rs` | — | the registry and the argument parsing, and nothing else |

## The rules
- **Routines are independent.** Each derives its own stream from the one `SEED`, builds
  its own data, and prints its own table. Running a routine alone must give the same
  number as running it with the others, because the reason for the split is that setup is
  not free: `zerocheck-prove` spends about nine seconds digesting a 2^20-row witness
  before it measures anything, and `zerocheck-verify` spends about forty on a 2^22-row
  one. Neither should be a reason to avoid running `fr-arith`.
- **Adding a routine is a module plus a row in `ROUTINES`.** The registry in `main.rs` is
  `(selector, one line of what it measures, entry point)`. No trait, no registration
  macro, no dynamic dispatch beyond a function pointer.
- **Setup is never inside the timed region**, and anything excluded from a comparison is
  named in that routine's own output rather than left for the reader to infer.
- **A routine that compares two checkers proves both can fail first.** `zerocheck-verify`
  asserts that each of its two verifiers accepts the honest input and rejects a corrupted
  one before it times either. A benchmark of a checker that cannot reject is a benchmark
  of nothing.

`advice` is the one routine that runs a **guest program** rather than a kernel, and it
builds two by hand rather than compiling any: the property measured is the address map,
and no committed guest reaches `0x8000_0000`. It is also the one routine whose headline
number is deliberately incomplete and says so in its own output — the fd 0 path's dominant
cost is the exit-time `io_digest` over every byte it read, which a bare `EXIT` program does
not pay and the SDK is not present to add. `docs/handoff/S25b-advice.md` §6 carries the
end-to-end number on `guests/revm-block`, where both are present.

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
