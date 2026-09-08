# S04 — Gate-Based Sumcheck with Real Transcript Randomness

Branch `s04-sumcheck`. Status: complete, all 9 acceptance items met.

The normative document for this crate is `crates/sumcheck/CLAUDE.md`; this note is the
frozen API, the new tag values, the wire shape, the bench numbers and the deviations.

## Frozen public API, as built

```rust
// crates/sumcheck/src/lib.rs   (#![no_std], extern crate alloc)

/// The identifier of a polynomial. Inert this stage: `prove_zerocheck` takes the
/// columns positionally, in the gate's declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyAddress(pub u32);

/// One term: `coef * inputs[a] * inputs[b]`, `b` optional, `b == Some(a)` a square.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateTerm { pub coef: Fr, pub a: usize, pub b: Option<usize> }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateError {
    NoInputs,
    DuplicateInput { input: usize },
    TermIndexOutOfRange { term: usize, index: usize },
}

#[derive(Clone, Debug)]
pub struct Gate { /* inputs + terms, private */ }
impl Gate {
    pub fn new(inputs: &[&PolyAddress], terms: Vec<GateTerm>) -> Result<Gate, GateError>;
    pub fn evaluate(&self, input_values: &[Fr]) -> Fr;   // declaration order; panics on arity
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SumcheckProof {
    pub rounds: Vec<[Fr; 4]>,   // ascending: c0 + c1 X + c2 X^2 + c3 X^3
    pub final_evals: Vec<Fr>,   // one per gate input, declaration order
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SumcheckClaim { pub point: Vec<Fr>, pub final_evals: Vec<Fr> }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SumcheckError {
    RoundCountMismatch { expected: usize, found: usize },
    FinalEvalCountMismatch { expected: usize, found: usize },
    RoundSumMismatch { round: usize },
    FinalEvalMismatch,
}

pub fn witness_digest(columns: &[MultilinearPoly]) -> Fr;
pub fn absorb_witness_digest(t: &mut Transcript, digest: Fr);

pub fn prove_zerocheck(gate: &Gate, polys: &mut [MultilinearPoly], t: &mut Transcript)
    -> SumcheckProof;
pub fn verify_zerocheck(gate: &Gate, n_vars: usize, proof: &SumcheckProof, t: &mut Transcript)
    -> Result<SumcheckClaim, SumcheckError>;
```

That is the stage's list, plus the two witness-digest functions the frozen signatures
force to exist outside `prove_zerocheck`/`verify_zerocheck` (see *Deviations*). The
library is 456 lines including its documentation; there are no other public items, no
traits, no macros, and no dependencies beyond `constants`, `field`, `poly` and
`transcript`.

```rust
// crates/constants/src/lib.rs   (additions; still zero logic, #![no_std])
pub mod transcript_tags {
    pub const WITNESS_DIGEST: u64 = 8;          // scalars
    pub const SUMCHECK_FINAL_EVALS: u64 = 9;    // scalars
}
```

## The new tag values

`SUMCHECK_ROUND = 4` and `SUMCHECK_CHALLENGE = 5` already existed: S02 allocated them,
with exactly the message kinds this stage needs. Tags are never renumbered and never
duplicated, so S04 reuses them and appends two. The tag table is now:

| Name | Value | Kind | Used by |
| --- | --- | --- | --- |
| `PROTOCOL_SUITE` | 1 | scalars | — (commit phase) |
| `PUBLIC_INPUTS` | 2 | bytes | — (commit phase) |
| `COMMITMENT` | 3 | scalars | — (PCS) |
| `SUMCHECK_ROUND` | 4 | scalars | one round's 4 coefficients |
| `SUMCHECK_CHALLENGE` | 5 | challenge | the `n` eq-randomizers, then each round challenge |
| `EVALUATION_CLAIM` | 6 | scalars | — (later stages) |
| `PCS_OPENING` | 7 | scalars | — (PCS) |
| `WITNESS_DIGEST` | 8 | scalars | the digest scalar, and the framing inside its own sponge |
| `SUMCHECK_FINAL_EVALS` | 9 | scalars | `final_evals` |

The eq-randomizers and the round challenges share `SUMCHECK_CHALLENGE`: they are the
same *kind* — one tag, one kind is the rule S02 froze — and they are separated by their
fixed position in the script, not by their tag. The repository owner chose this over a
fifth tag; the stage prompt's own list of tag roles has four entries and no separate
eq-randomizer role.

## The wire shape

A round message is **exactly 4 field elements, always**: `append_scalars(SUMCHECK_ROUND,
&[c0, c1, c2, c3])`, ascending, meaning `g(X) = c0 + c1 X + c2 X^2 + c3 X^3`. There is no
degree-adaptive encoding, and a proof's whole shape is a function of `n` and the gate's
arity: `rounds.len() == n`, every round 4 coefficients, `final_evals.len() == arity`.

The transcript script, run identically by both sides:

1. **the caller** absorbs the witness digest — `append_scalar(WITNESS_DIGEST, digest)`,
   via `absorb_witness_digest`;
2. `n` eq-randomizers `r`, each `challenge_scalar(SUMCHECK_CHALLENGE)`;
3. per round `i`: `append_scalars(SUMCHECK_ROUND, &coefficients)`, then
   `challenge_scalar(SUMCHECK_CHALLENGE)`, which binds **variable `i`**;
4. `append_scalars(SUMCHECK_FINAL_EVALS, &final_evals)`.

`claim.point[j]` is the value bound to variable `j`, the same little-endian order
`crates/poly` freezes. Round 0's check `g_0(0) + g_0(1) == 0` *is* the zerocheck; the
last-layer check is `eq_eval(r, point) * G(final_evals) == claim`.

The **witness digest** (must-be-exact 7) is squeezed from a sponge of its own: a fresh
`Transcript` absorbs `(column count, n)` as one `append_scalars(WITNESS_DIGEST, ..)`
message, then one `append_scalars(WITNESS_DIGEST, &cells)` per column — columns in
gate-input declaration order, cells in hypercube index order, each lifted to `Fr` — and
the digest is a raw `sample()`. The squeeze is raw rather than `challenge_scalar` on
purpose: `WITNESS_DIGEST` frames scalar messages, and a challenge under the same tag
would be one tag in two kinds, which `duplex.rs::a_tag_used_in_two_kinds_is_caught`
shows is a real collision. The protocol transcript sees one scalar and never the columns.

## What this freezes for every later stage

1. **The 4-coefficient round format and the round-order convention.** Round `i` binds
   variable `i`; `claim.point[j]` is variable `j`'s value.
2. **The degree ceiling is structural, not asserted.** A `GateTerm` names at most two
   factors, so no value of the type expresses a cubic. `Gate::new` has no degree to
   check — a gate above the ceiling cannot be constructed — and what it does reject is a
   malformed declaration: no inputs, a duplicate address, a term naming an undeclared
   input. This is stronger than the assertion master rule 4 asks for, and it is why no
   assertion appears.
3. **`prove_zerocheck` consumes its columns.** Each is left fully bound to the challenge
   point, which is where `final_evals` are read from. A caller that needs the originals
   clones first.
4. **Errors are values on the verify path, panics on the prove path.** A malformed
   *proof* returns `SumcheckError`; the verifier never panics on proof data. A caller
   that pairs the wrong columns with a gate, or hands ragged columns to the digest, has
   broken an invariant and panics with a message naming it.
5. **`final_evals` discharge is deferred to the PCS stages.** `verify_zerocheck`
   recomputes `eq_eval(r, point) * G(final_evals)` and checks it against the last
   round's claim — that is all. Nothing here checks those values against a commitment,
   because Mercury does not exist yet. The returned `SumcheckClaim` is the hand-off
   point, and in the tests it is discharged by direct `evaluate` on the witness the
   digest was taken over. **That call site is precisely the one a commitment opening
   will replace.**

## Bench (acceptance 9, no threshold)

`cargo run --release -p bench -- zerocheck-prove`, Apple Silicon (aarch64-apple-darwin), rustc 1.96.1,
best of 3, `A * A - B` over `n = 20` (1,048,576 rows), `A` in `U16` and `B` in `U32` —
acceptance 1's witness exactly. Internal numbers; no public claims.

| what | value |
| --- | ---: |
| `prove_zerocheck` | **413.6 ms** |
| `witness_digest` (once, outside `prove`) | **8,576.6 ms** |
| peak polynomial memory | **100.0 MiB** |

The digest dominates by 20x, and that is inherent to must-be-exact 7 rather than a
defect: it absorbs all `2^21` cells through Poseidon2, about `2^20` permutations. Two
things are worth recording for later stages. First, this is the toy stand-in for a
commitment; once Mercury lands, the binding is an MSM and this sponge disappears.
Second, roughly 44% of a permutation is S02's runtime hex decoding of the round
constants — 80 `Fr::from_hex` calls per permutation, measured there at 1.76x. S02
deliberately deferred a decoded table for want of a real-workload benchmark; this is the
first real workload that says it would matter, and it is recorded here rather than acted
on, because it is another stage's crate and the owner reverted exactly that change once
already.

**Peak polynomial memory is computed, not measured by an allocator.** Reading peak RSS
portably needs either a dependency or `unsafe`, and both are banned, so
`tools/bench/src/zerocheck_prove.rs::peak_poly_bytes` accounts for the tables the algorithm holds:
`eq` is a full `Fr` table for the whole proof; `bind` truncates a column's length
without releasing its capacity, so from its first bind each column costs a full `Fr`
table too; and the peak is the instant a column lifts, when its small backing and its
fresh `Fr` table are both alive. For this witness that is
`32*2^20` (eq) `+ 2 * 32*2^20` (A, B lifted) `+ 4*2^20` (B's `u32` backing, mid-lift)
`= 100 MiB`.

### Verification against recomputing every row

`cargo run --release -p bench -- zerocheck-verify`, same machine and same claim, at
`n = 22` (4,194,304 rows) rather than 20. The separation being measured is `O(2^n)`
against `O(n)`, so it is worth reading at a size the acceptance itself does not have to
pay for; the price is about 40 s of setup, which is affordable now that the routine can
be run alone. The naive verifier holds both columns lifted to `Fr` and checks
`A[i]^2 == B[i]` on every row, with no early return, because an honest verifier on a
satisfying witness sweeps the whole table anyway. The sumcheck verifier holds a digest
and a proof and never sees a row. Both are shown to accept the honest input and reject a
corrupted one before either is timed.

| verifier | time | input read |
| --- | ---: | ---: |
| naive: recompute every row in `Fr` | **49.3 ms** | 256.0 MiB |
| `verify_zerocheck` | **0.87 ms** | 2,880 B |
| speedup | **56.3x** | 93,207x |

Against the same routine at `n = 20` (12.3 ms, 0.79 ms, 15.5x) the scaling is exactly
what the asymptotics predict and worth recording as such: quadrupling the rows
quadrupled the naive verifier and added 10% to the sumcheck one, because two more rows
of `n` are two more rounds and nothing else.

The interesting number is not 56.3x, it is the split under it: **99.4% of
`verify_zerocheck` is the Poseidon2 transcript** and 0.6% — around 0.005 ms — is
arithmetic. The bench deliberately derives no speedup from that residual, because it is
the difference of two ~0.87 ms measurements and moves by a few percent between runs; what
it supports without one is the qualitative claim, which is that the permutation and not
the protocol is what caps the ratio. Note the shape: the proof-size win is 93,207x and
the time win is 56.3x, three orders of magnitude apart, and the whole gap is sponge. The
same runtime hex decode of the round constants named above is the second and sharper
real-workload datum for that deferred item — the digest number says a decoded table would
help the prover, and this one says it is very nearly the entire verifier.

Two caveats are printed with the numbers rather than left to the reader. Proving and the
digest are excluded from both sides because they are the prover's cost and the
commitment's. And discharging the returned claim — opening `final_evals` against a
Mercury commitment — does not exist yet, so the sumcheck figure is a floor and the naive
verifier is the only one of the two that is currently complete.

The sponge share is measured by replaying the verifier's message schedule with the
arithmetic removed. That replay is a second copy of the frozen script, so the routine
compares its sponge state against the real verifier's and prints why it is withholding
the breakdown if they ever disagree, rather than printing a wrong attribution.

## Verification performed

146 workspace tests, green in debug and release (113 from S01–S03, unchanged; 33 new).

- **Acceptance 1** — `honest_run_over_two_to_the_twenty_rows`: `A * A - B` over `2^20`
  rows, the backings asserted to be `U16` and `U32` *before* proving so the lazy lift is
  really exercised, `prove_zerocheck` then `verify_zerocheck` on a fresh transcript
  returning `Ok`, and `claim.final_evals` checked against direct `evaluate` of both
  columns at `claim.point`. `proving_binds_every_column_to_the_challenge_point` adds the
  other half: after proving, every column is a fully bound `Fr` table holding exactly the
  claimed value.
- **Acceptance 2** — `a_witness_swapped_after_the_digest_fails_the_discharge`: the
  digest is taken over one witness and the proof produced over another that also
  satisfies the gate, so the zerocheck cannot see the swap, `verify_zerocheck` returns
  `Ok`, and the failure lands exactly where the stage says it must — in the final-evals
  discharge against the digest-bound witness, as a returned error rather than a panic.
  The control beside it discharges the same claim against the witness it was proved
  over, so the rejection is about the binding and not about a broken discharge. See
  *Deviations* for why the stage's literal text cannot reach that check, and
  `the_literal_acceptance_two_tamper_is_caught_by_round_zero_instead` for its twin.
- **Acceptance 3** — `a_tampered_round_coefficient_is_rejected`: sixteen tampers, four
  rounds by four coefficient positions, each rejected with `RoundSumMismatch` naming
  that very round. Every single-coefficient change moves `g(0) + g(1) = 2c0+c1+c2+c3`,
  so the rejection is at the tampered round, never later.
  `tampered_final_evals_are_rejected` and `a_proof_of_the_wrong_shape_is_rejected` cover
  the other two error variants, and `a_proof_checked_against_the_wrong_digest_is_rejected`
  covers a verifier bound to the wrong witness.
- **Acceptance 4** — `the_digest_makes_the_challenges_witness_dependent`: two witnesses
  are first shown to differ in *exactly one cell* — the test enumerates the whole cube
  and asserts the differing-index list is a singleton — then their digests differ, and
  then every one of the `n` eq-randomizers differs, which is before round 0 exists.
  Both witnesses are then proved honestly and their **round challenges** compared, and
  those differ at every index including round 0 — read from the script by
  `round_challenges`, because the one-cell-apart witness does not satisfy the gate and so
  has no `SumcheckClaim` to read them from. (For `A*A - B` no single-cell change keeps a
  witness satisfying, so a one-cell pair can never be a pair of *verifying* proofs; the
  stage says "two honest proofs", and honestly produced is what these are.) A satisfying
  pair follows, every coordinate of its `claim.point` differs, and `round_challenges` is
  checked against the verifier's own `claim.point` on that pair, so the replay helper is
  itself controlled.
- **Acceptance 5** — `tests/oracle.rs`. Every round polynomial of both gates at
  `n = 1..4` is recomputed from the definition: a direct sum over the remaining cube of
  `eq_eval(r, point) * G(columns at point)`, with `G` written out by hand and every
  column read through `MultilinearPoly::evaluate`. It calls nothing of the prover's —
  not `round_evaluations`, not `interpolate_cubic`, not `Gate::evaluate` — and matches
  the proof at four distinct nodes, which pins a cubic coefficient for coefficient. The
  stage asks for round 0; every round is checked instead. `Formula::WideProduct` is
  written unexpanded as `A * (B + C) - D * E` where the gate carries the expansion
  `A*B + A*C`, so a transcription error in either direction shows up.
  `the_oracle_rejects_a_perturbed_round` is the control proving the oracle can fail.
- **Acceptance 6** — `a_non_satisfying_witness_fails_round_zero`: `B` is broken at one
  row and the digest is taken over *that* witness, so the binding is intact and the
  zerocheck itself must catch it, at round 0's `== 0`. The test goes further than a
  rejection: `G` is `-1` at exactly one row and zero elsewhere, so `g_0(0) + g_0(1)` must
  equal `-eq(r, row)` exactly — computed in the test from the eq-randomizers alone. The
  round-0 sum is the gate's defect, not merely some nonzero.
- **Acceptance 7** — asserted on the real `2^20` proof:
  `rounds.len() == 20`, 4 coefficients in every round, `final_evals.len() == 2`,
  `claim.point.len() == 20`.
- **Acceptance 8** — `the_wide_gate_proves_and_verifies` and
  `the_wide_gate_catches_both_tampers`: `A * (B + C) - D * E`, five inputs, three terms,
  at `n = 12`, with four `U32` columns and one `Fr` column. Both tamper kinds are run —
  a witness swapped after the digest, caught by the discharge with its own control, and
  a witness that does not satisfy the gate, caught at round 0.
- **Acceptance 9** — the table above.
- **Must-be-exact 4** — every honest run in `zerocheck.rs` goes through
  `prove_then_verify`, which asserts the prover's and the verifier's `event_log()` are
  equal *and* their `snapshot()`s are equal. Equal typed-message sequences and equal
  sponge states leave no room for a challenge to have been passed out of band.
- **Must-be-exact 8** —
  `cargo build -p field -p constants -p transcript -p poly -p sumcheck --target riscv32imac-unknown-none-elf`
  succeeds; `sumcheck` was added to that CI step.
- **Must-be-exact 1, 3, 5, 6 and 7** — `tests/script.rs`. Every message the protocol
  absorbs is rebuilt element by element from `docs/spec/transcript.md`'s own pseudocode,
  using nothing but raw `observe` and `sample`, and the resulting sponge is compared to
  the prover's and to the verifier's. Because it is an *independent* reconstruction rather
  than a comparison of the two sides to each other, it pins what the script actually is:
  the tag on every message, that a round is one message of four scalars and not four of
  one, that the eq-randomizers come before round 0, and that `final_evals` are absorbed at
  all. `the_witness_digest_is_the_documented_encoding` does the same for must-be-exact 7's
  wire spec, clause by clause. Both are followed by a battery of near-miss
  reconstructions that must *not* match, which is master rule 8's negative control, and
  `the_tag_values_this_stage_uses_are_frozen` pins the four tag values to literals so a
  renumbering cannot slip through the constants.

Beyond the acceptance list: `a_constant_witness_is_a_zero_round_proof` (`n = 0`, where
the last-layer identity is the only check there is) and `one_variable_proves_and_verifies`
(`n = 1`, the smallest cube with a round in it, and the size at which an off-by-one in
the round loop would still typecheck). `tests/gate.rs` covers `Gate::new`'s three
rejections with a legal-edge control on each, both formulas' `evaluate`, and the four
panics on the prove and digest paths, each matched on its message text.

**Mutation testing.** Single-edit mutants of `lib.rs` were built and the whole suite run
against each with `--no-fail-fast`, restoring the file every time. The first pass — before
`tests/script.rs` existed — found a real hole: mutants of the *transcript script* and of
the *witness-digest encoding* left every one of the 141 tests then in the suite green, because every other test drives
both sides of the protocol through the same code, so a change to the script changes the
prover and the verifier together and the symmetric log/snapshot comparison in
`prove_then_verify` cannot see it. The worst of them dropped column 0 from the digest
entirely, leaving the first witness column unbound by anything. `tests/script.rs` was
written to close that, and the battery was re-run:

| mutant | before | after |
| --- | --- | --- |
| both sides drop the `final_evals` absorb | survived | killed |
| a round sent as four one-scalar messages | survived | killed |
| a round framed under `EVALUATION_CLAIM` on both sides | survived | killed |
| the eq-randomizers drawn under `EVALUATION_CLAIM` on both sides | survived | killed |
| each round challenge drawn under `EVALUATION_CLAIM` on both sides | survived | killed |
| `absorb_witness_digest` framed under `EVALUATION_CLAIM` | survived | killed |
| the digest sponge drops its header message | survived | killed |
| the digest sponge's header framed under `SUMCHECK_ROUND` | survived | killed |
| the digest absorbs the columns in reverse order | survived | killed |
| the digest absorbs each column's cells in reverse index order | survived | killed |
| the digest skips column 0 entirely | survived | killed |
| no-op control edit | survives, as it must | survives |

One mutant survives and is left surviving: moving the verifier's `final_evals` absorb to
*after* the last-layer comparison. Nothing between the two statements touches the sponge,
so on the `Ok` path the resulting transcript is byte-identical and on the `Err` path the
transcript is abandoned — a genuinely equivalent mutant, not a coverage defect. The
substantive versions of it are both killed hard: dropping the verifier's absorb, and
dropping the prover's.

**Independent re-derivation.** Two Python models were written from the stage prompt,
consulting neither the Rust nor `tests/oracle.rs`. The first checks `interpolate_cubic`
against a completely different algorithm — Gaussian elimination on the Vandermonde matrix
over `Fr` — on 200,000 random cubics, every monomial, the zero cubic and 2,000 exact
integer cubics: zero mismatches, and every recovered cubic passes through its four input
values. The second is a bignum model of the whole protocol: over 300 runs spanning
`n = 1..6` and both gates it confirms the proof shape, that every round polynomial equals
the naive sum over the remaining cube at all four nodes, that `final_evals` are the
columns' multilinear extensions at the bound point, that a swapped *satisfying* witness
verifies but fails the discharge, and that an unsatisfying witness rejects at round 0 with
`g_0(0) + g_0(1)` equal to the gate's defect exactly.

**Adversarial review.** Seven reviewers went over the branch with disjoint lenses — the
mathematics derived from scratch, a malicious prover trying to forge an accepting proof,
the transcript and Fiat–Shamir, the acceptance list clause by clause, test vacuity by
mutation, the master prompt's rules and anti-goals, and edge cases and panics — and every
finding was then put to three further reviewers instructed to refute it. No correctness or
soundness finding survived and no attack on the verifier succeeded. Three findings were
acted on regardless of that verdict, because they were right about the *evidence* even
where the majority judged them not to be defects: the mutation survivors above, the stale
tag table in `docs/spec/transcript.md` §8, and acceptance 4's literal wording.

`cargo clippy --workspace --all-targets -- -D warnings` is clean, with **no `#[allow]`
in this crate's library code**.

## Additive extensions (everything beyond the stage's literal list)

1. **`witness_digest` and `absorb_witness_digest`.** Forced by the frozen signatures:
   `prove_zerocheck` and `verify_zerocheck` take no digest parameter, and the stage says
   the verifier is *handed* the digest as the toy's public input, so the absorb happens
   in the caller on both sides. `witness_digest` is how the prover-side caller computes
   it; `absorb_witness_digest` is the single place the tag and framing are chosen, so
   the two sides cannot diverge on must-be-exact 4 and 7. Both have two callers.
2. **`GateError::DuplicateInput`.** Two slots pointing at one column is a construction
   mistake, and with `PolyAddress` an identifier it is cheap to catch. A formula that
   uses a column twice repeats the *index* in its terms, which is how `A * A - B` is
   written and is explicitly allowed.
3. **`[profile.dev] opt-level = 2` in the workspace manifest.** Acceptance 1 proves at
   `2^20` and must-be-exact 7's digest absorbs every cell; unoptimized that is minutes
   per run and `cargo test --workspace` becomes unusable. `debug-assertions` and
   `overflow-checks` stay on, so the tests run with every check the default dev profile
   gives them and only code generation changes. It is a profile, not a cargo feature:
   the workspace still has exactly one build configuration.
4. **Derives.** `Clone, Debug, PartialEq, Eq` on the proof, claim and error types, so a
   test can compare a whole proof or assert an exact error in one line. `Gate` is
   `Clone, Debug` but deliberately **not** `PartialEq`: nothing needs it, and the test
   that wants an error compares `Gate::new(..).unwrap_err()`.
5. **The two new tags and their entries in `crates/transcript`'s `tag_by_name` and
   `tag_table_is_well_formed`**, so the existing distinctness and nonzero checks cover
   them. No committed transcript vector changes; the fixtures regenerate byte for byte.
6. **The bench line, `crates/sumcheck/CLAUDE.md`, and the `docs/GLOSSARY.md` entries**,
   per acceptance 9 and master rule 12.

## Deviations and notes for the reviewer

- **Acceptance 2 as written is self-contradictory, and the resolution was the owner's.**
  It says to absorb the honest digest, corrupt one cell of `B` by `+= 1`, prove over the
  corrupted witness, and expect the *final-evals discharge check in the test harness* to
  be what fails. But `B[i] += 1` leaves `A*A - B` nonzero at row `i`, so
  `sum_y eq(r,y) G(y) != 0` and the zerocheck rejects at round 0 — which is acceptance
  6's check, the one acceptance 6 calls "distinct from test 2". The discharge check is
  unreachable on that witness. Put to the repository owner, who chose to honour the
  stated intent: the tamper swaps in a *different satisfying* witness after the digest,
  so the sumcheck passes and the discharge is what catches it. The literal reading is
  kept as a twin test recording what `B[i] += 1` actually does. Both readings are
  covered and neither is silently dropped.
- **`PolyAddress` is `pub struct PolyAddress(pub u32)`, not the unit struct the stage's
  API listing shows.** The listing writes `pub struct PolyAddress;` while the comment
  beside it says "there will be a centralized registry (hash map) of PolyAddress ->
  Polynomials. PolyAddress is the identifier". A unit struct identifies nothing, and
  `&[&PolyAddress]` would then be a verbose way to pass an integer. Put to the owner,
  who chose the identifier. It is inert this stage — the columns are matched to gate
  inputs positionally — beyond arity and the duplicate check, and it is the registry key
  the GKR stage will need.
- **No committed fixture, unlike S01–S03.** The stage's acceptance list asks for none,
  and its oracle is an in-test recomputation rather than a file. Put to the owner, who
  chose to follow the acceptance list; a generator module plus a CI regenerate-and-diff
  line is exactly the "extra CI machinery" the anti-goals warn against, and the naive
  cube summation in `oracle.rs` is a stronger check than a self-generated vector file
  would have been. Every witness is seeded, so every test is deterministic and a
  regression still fails loudly.
- **Master rule 4 says the degree ceiling is "enforced by assertion at
  circuit-construction time"; there is no assertion.** There is nothing to assert: a
  `GateTerm` carries at most two factor indices, so the type cannot express a cubic and
  `Gate::new` cannot construct one. An assertion there would be unreachable code, which
  the deletion pass removes. The intent of the rule — no gate above degree 2 ever
  reaches the prover — is met more strongly than an assertion meets it, and it is
  recorded here because it is a rule discharged by construction rather than by the
  mechanism the rule names.
- **The interpolation constants are derived, not transcribed.**
  `interpolation_constants()` inverts 2, 3 and 6 once per proof rather than storing hex
  literals, so there is no constant to get wrong; at three inversions per proof against a
  400 ms round loop the cost does not appear. `interpolate_cubic` is Newton's forward
  differences on the nodes 0, 1, 2, 3, expanded once in the doc comment so the four
  coefficient formulas can be checked by eye.
- **`round_evaluations` walks the nodes incrementally.** Each column's value along the
  current variable is the line `lo + X * (hi - lo)`, so stepping `X` from 0 to 3 is one
  addition of `(hi - lo)` per column and no multiplication by the node ever appears.
  That is not an optimization reached for without a benchmark; it is the shorter and
  more obviously correct way to write the same four evaluations, and it is checked
  against the definition by `tests/oracle.rs`.
- **No parallelism.** The stage says to accumulate the point-evaluations across chunks
  of the hypercube; the accumulation is a single pass over the half-cube with four
  running sums, which is the chunked accumulation at chunk size one. `rayon` is not
  reachable anyway — the crate is `#![no_std]`. If a real workload says the round loop
  matters, master rule 11 wants the benchmark in the same commit.
- **No conflicts between the master prompt and the stage prompt were found.** The
  contradictions this stage raised were internal to the stage prompt (acceptance 2) or
  between the stage prompt's API listing and its own commentary (`PolyAddress`); both
  were decided by the repository owner and are recorded above.

## Open for the next stage

- **`final_evals` are an evaluation claim, not a proof.** Nothing verifies them against
  a commitment. The PCS stage replaces the tests' `discharge` helper with a Mercury
  opening; until it does, a `SumcheckClaim` binds the prover only through the witness
  digest, which is a hash and not a commitment.
- **`Gate::arity()` is private.** The frozen list does not name it, and a caller
  building a gate knows its own arity. The GKR stage is free to make it public when it
  has a caller that cannot.
- **There is no claim batching and no layer management here.** `prove_zerocheck` and
  `verify_zerocheck` are terminal standalone entry points, exactly as the stage says.
  The RLC batching, the product/fraction trees and the claim-merging sumcheck the master
  prompt's zerocheck-discharge invariant describes all belong to the GKR stage.
- **The witness digest is a stand-in.** It exists because commitments do not yet. When
  Mercury lands, the statement-binding absorb order in the master prompt's frozen
  invariants replaces it, and `WITNESS_DIGEST` should stop being used rather than be
  repurposed.
- **`transcript_tags` has 9 entries.** Later stages append; they never renumber, and
  they never reuse a tag across message kinds.
