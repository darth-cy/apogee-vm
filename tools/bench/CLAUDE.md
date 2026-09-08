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
| `src/zerocheck_prove.rs` | `zerocheck-prove` | S04 acceptance 9: prove wall-clock and peak polynomial memory at 2^20 |
| `src/zerocheck_verify.rs` | `zerocheck-verify` | S04: `verify_zerocheck` against recomputing every row, at 2^22 |
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

## The one hazard
`zerocheck_verify.rs` holds a second copy of the frozen transcript script, so it can time
the sponge without the arithmetic. `crates/sumcheck/CLAUDE.md` warns that a copy of that
script is a drift hazard, so this one carries its own tripwire: the replay's sponge state
is compared against the real verifier's, and on a mismatch the routine prints why it is
withholding the breakdown instead of printing a wrong one. If you change the script,
either update that replay or delete it and the line it feeds.
