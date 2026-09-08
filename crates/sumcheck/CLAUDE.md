# `crates/sumcheck`

## What this crate owns
The gate-based zerocheck: `Gate` (a degree-≤2 formula over named multilinear inputs),
`SumcheckProof`, `SumcheckClaim`, and the prover and verifier that discharge
`0 = sum_y eq(r, y) * G(y)`. Plus the witness digest that binds the columns to the
transcript before any challenge is drawn.

Nothing else. There is no commitment scheme here, no claim batching, no layer
management, no GKR. `prove_zerocheck` and `verify_zerocheck` are terminal standalone
entry points: they check a single gate over a single set of columns and hand the
resulting evaluation claim back for the caller to discharge.

## The protocol (frozen)
`G` is a sum of terms `coef * x_a * x_b`, the second factor optional, so `G` has degree
at most 2 in each variable. `eq` is multilinear, so `eq * G` has degree at most 3 per
variable and **a round message is exactly 4 coefficients, always** — no degree-adaptive
encoding, no data-dependent length.

The transcript script, in order. Prover and verifier run it identically; no challenge is
ever passed out of band.

| Step | Message | Tag | Kind |
| --- | --- | --- | --- |
| 1 | the witness digest, one scalar, absorbed by the **caller** | `WITNESS_DIGEST` | scalars |
| 2 | `n` eq-randomizers `r` | `SUMCHECK_CHALLENGE` | challenge |
| 3, per round `i` | the round cubic, 4 coefficients, as one message | `SUMCHECK_ROUND` | scalars |
| 3, per round `i` | the round challenge, binding **variable `i`** | `SUMCHECK_CHALLENGE` | challenge |
| 4 | `final_evals`, one per gate input | `SUMCHECK_FINAL_EVALS` | scalars |

Round `i` binds variable `i`, so `claim.point[j]` is the value bound to variable `j` —
the same little-endian order `crates/poly` freezes. Round 0's check is
`g_0(0) + g_0(1) == 0`, which *is* the zerocheck; every later round checks against the
previous cubic at its challenge. The last-layer check is
`eq_eval(r, point) * G(final_evals) == claim`.

## Frozen invariants
- **4 coefficients per round, ascending.** `rounds[i] = [c0, c1, c2, c3]` means
  `g(X) = c0 + c1 X + c2 X^2 + c3 X^3`. The proof shape is a function of `n` and the
  gate's arity alone.
- **The degree ceiling is structural.** A `GateTerm` names at most two factors, so no
  value of the type can express a cubic. `Gate::new` therefore has no degree to assert:
  a gate above the ceiling cannot be constructed. What `Gate::new` does reject is a
  malformed declaration — no inputs, a duplicate address, a term naming an undeclared
  input.
- **The witness digest is squeezed from its own sponge.** A fresh `Transcript` absorbs
  `(column count, n)` as one framed message, then one length-delimited message per
  column — columns in gate-input declaration order, cells in hypercube index order,
  each lifted to `Fr` — and the digest is a raw `sample()`. It is a raw squeeze, not a
  `challenge_scalar`, because `WITNESS_DIGEST` frames scalar messages and drawing a
  challenge under it would be one tag in two kinds, which S02 proved is a real
  collision. The protocol transcript sees the single scalar and never the columns.
- **`final_evals` are absorbed before they are checked**, and before any challenge a
  later stage would draw. They are never trusted silently.
- **`prove_zerocheck` consumes its columns.** Every column is left fully bound to the
  challenge point; that is where `final_evals` are read from. A caller that needs the
  originals clones first.
- **Errors are values on the verify path, panics on the prove path.** A malformed
  *proof* returns `SumcheckError`. A caller that pairs the wrong columns with a gate, or
  hands ragged columns to the digest, has broken an invariant and panics with a message
  naming it.
- **`#![no_std]` + `alloc`, forever.** The recursion guest links this crate.
  CI-equivalent check:
  `cargo build -p field -p constants -p transcript -p poly -p sumcheck --target riscv32imac-unknown-none-elf`.

## Deferred, deliberately
Verifying `final_evals` against commitments is the Mercury PCS's job and lands in a
later stage. `verify_zerocheck` returns the `SumcheckClaim` and stops. In the tests the
discharge is done by direct `evaluate` on the witness the digest was taken over; that
call site is exactly the one a commitment opening will replace.

## Wire formats
None serialised here. `SumcheckProof` is an in-memory struct; the `Fr` values it holds
cross a boundary only through `crates/field`'s canonical little-endian form.

## Tests
| File | Covers |
| --- | --- |
| `tests/zerocheck.rs` | The 2^20 honest run and its structural shape; the swapped-witness tamper and its literal twin; a tampered round coefficient at four rounds by four coefficients; tampered `final_evals`; wrong-shape and wrong-digest proofs; the digest's effect on the challenges; the unsatisfying witness; both wide-gate tampers; `n = 0` and `n = 1`. |
| `tests/oracle.rs` | Every round polynomial of both gates at `n <= 4`, against a direct sum over the cube that shares no code with the prover, plus the control proving that oracle can fail. |
| `tests/gate.rs` | `Gate::new`'s three rejections and their legal-edge controls, `evaluate` on both formulas, and every panic on the prove and digest paths. |
| `tests/script.rs` | The frozen transcript script and the witness-digest encoding, rebuilt from `docs/spec/transcript.md`'s pseudocode with raw `observe`/`sample` and compared to the real sponge, plus a near-miss battery for each that must not match. |
| `tests/common/mod.rs` | The two gates, their satisfying witnesses and tamper variants, the transcript harness, the challenge replay, and the discharge check. Test-only. |

No committed fixture: the independent oracle is `tests/oracle.rs`'s recomputation from
the definition, not a file. Every witness is seeded, so every test is deterministic.

`tests/script.rs` exists because every *other* test drives both sides of the protocol
through the same code, so a change to the transcript script changes the prover and the
verifier together and a symmetric comparison cannot see it. Mutation testing found eleven
such changes that left the whole suite green — including one that dropped column 0 from
the digest, leaving the first witness column bound by nothing. All eleven are killed now.
**A change to the script or the digest encoding must be made in `tests/script.rs` too, or
it is not a change anything checks.**

## Numbers
Two `tools/bench` routines cover this crate, each runnable on its own.

`cargo run --release -p bench -- zerocheck-prove` prints the acceptance-9 line:
`prove_zerocheck` at `n = 20`, the witness digest's own cost, and the peak polynomial
memory. The last is computed from the tables the algorithm holds, not read from an
allocator — there is no portable way to read peak RSS without a dependency or `unsafe`.

`cargo run --release -p bench -- zerocheck-verify` puts `verify_zerocheck` against a
verifier that just recomputes every row, on the same claim at `n = 22` — larger than the
acceptance, because `O(2^n)` against `O(n)` is worth reading where the two have room to
separate. The headline is the ratio; the line that matters is the breakdown under it,
which says the sumcheck verifier is ~99% Poseidon2 and well under 1% arithmetic. That routine holds a second copy of the frozen
transcript script, and checks it against the real verifier's sponge before reporting the
breakdown — if the two ever disagree it says so and prints no number.

See `docs/handoff/S04-sumcheck.md` for the recorded values.
