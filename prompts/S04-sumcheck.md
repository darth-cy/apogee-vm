---
title: S04 — Gate-Based Sumcheck with Real Transcript Randomness

---

# S04 — Gate-Based Sumcheck with Real Transcript Randomness

## Depends on / Inputs
- S01 gives `Fr`.
- S02 gives `Transcript` and its typed layer, whose tags live in `constants::transcript_tags`. Extend that table additively with the sumcheck tags.
- S03 gives `MultilinearPoly` (small-type backing plus lazy lift), `eq_table`/`eq_eval`, and the frozen variable-order convention.

## Deliver
- `crates/sumcheck`, containing `Gate`, `SumcheckProof`, and the zerocheck prover and verifier.
- `crates/sumcheck` is a `#![no_std]` (+alloc) core.

Frozen public API:

```rust
pub struct PolyAddress;        // In production proving, there will be a centralized registry (hash map) of PolyAddress -> Polynomials. PolyAddress is the identifier.
pub struct Gate { /* degree-≤2 formula over named multilinear inputs, private */ }
impl Gate {
    // Formula = SUM { terms }, each term: coef * input_a * input_b (optional).
    pub fn new(inputs: &[&PolyAddress], terms: Vec<GateTerm>) -> Result<Gate, GateError>;
    pub fn evaluate(&self, input_values: &[Fr]) -> Fr;    // one point, inputs in declaration order
}
pub struct GateTerm { pub coef: Fr, pub a: usize, pub b: Option<usize> }  // indices into inputs

pub struct SumcheckProof {
    pub rounds: Vec<[Fr; 4]>,       // one cubic per round, 4 coefficients, fixed shape
    pub final_evals: Vec<Fr>,       // claimed evaluation of each input poly at the bound point
}
pub struct SumcheckClaim { pub point: Vec<Fr>, pub final_evals: Vec<Fr> }

pub fn prove_zerocheck(gate: &Gate, polys: &mut [MultilinearPoly], t: &mut Transcript) -> SumcheckProof;
pub fn verify_zerocheck(gate: &Gate, n_vars: usize, proof: &SumcheckProof, t: &mut Transcript)
    -> Result<SumcheckClaim, SumcheckError>;
```

## Core algorithm
Discharge the zerocheck as the master invariant: prove that 0 = Σ_y eq(r,y)·G(y). All randomness in the flow below comes from the S02 transcript.

1. The prover absorbs a binding digest of the witness columns through the typed layer. No commitments exist yet, so the digest hashes each column, length-delimited per message. The verifier absorbs that same digest, handed to it as the toy's public input.
2. Sample the n eq-randomizers r with `challenge_scalar`.
3. Run n rounds. A degree-2 gate times the eq factor makes the round polynomial cubic, so the prover sends exactly 4 coefficients as ONE typed message and then draws the round challenge. Bind all polys and the eq factor by it. Build the eq factor once from r with `eq_table` and bind it each round alongside the witness polys, rather than rebuilding a table per round. Extract the 4 coefficients by evaluating the round polynomial at 0, 1, 2 and 3, then interpolating with fixed precomputed constants. Accumulate those point-evaluations across chunks of the hypercube.
4. Each round the verifier checks that g_i(0) + g_i(1) == the previous claim (round 0: == 0), then evaluates g_i at the challenge to get the next claim.
5. At the last layer the prover explicitly computes `final_evals`, the value of every input poly at the fully bound point, and puts them in the proof. The verifier absorbs them, recomputes eq_eval(r, point)·G(final_evals), and checks that it equals the last round's claim. **Verifying `final_evals` against commitments is out of scope: the Mercury PCS arrives in a later stage.** Return the `SumcheckClaim` so the caller (a test, or a later stage) discharges the openings. The toy e2e test discharges them by direct `evaluate` on the witness polys. Last-layer opening *verification* is explicitly deferred to the PCS stages, so build no commitment scheme here.

`SumcheckError` carries one variant per failure the acceptance list names.

## Must-be-exact
1. A round message is exactly 4 coefficients, always. The proof shape is fixed, so no degree-adaptive encoding.
2. The degree-≤2 assertion fires at `Gate` construction, not at prove time.
3. The new tags (witness digest, sumcheck round, sumcheck challenge, final evals) go into `constants::transcript_tags`.
4. Prover and verifier drive the transcript identically: same typed messages, same order. Challenges are never passed around out-of-band.
5. Round challenges bind variables in the conventional order, variable 0 first.
6. `final_evals` live in the proof and are absorbed before any later challenge would be drawn. They are never trusted silently.
7. The witness digest is computed in a sponge separate from the protocol transcript. That sponge absorbs the column count and the variable count n as one framed message, then one length-delimited message per column: columns in gate-input declaration order, cells in hypercube index order as canonical `Fr`. Prover and verifier each absorb its single squeezed `Fr` under the witness-digest tag, so the verifier is handed one scalar, never the columns.
8. `crates/sumcheck` must build, prove and verify as `#![no_std]` (+alloc).

## Acceptance
1. E2E honest run: A·A − B = 0 over 2^20 rows, with A seeded random in `PolyBacking::U16` and B = A² in `PolyBacking::U32`, exercising the lazy lift through real sumcheck binding. `prove_zerocheck` then `verify_zerocheck` on a fresh transcript returns `Ok`, and the returned `SumcheckClaim.final_evals` match direct `evaluate` of A and B at `claim.point`.
2. Transcript-binding tamper twin: absorb the honest witness digest, THEN corrupt ONE cell of B (B[i] += 1 at a seeded random index) so that digest and witness no longer match, and prove over the corrupted witness. The exact check that must fail is the final-evals discharge check in the test harness: direct `evaluate` of the digest-bound original witness polys at `claim.point` does not equal the proof's `final_evals`. Expect an error class, not a panic.
3. Second tamper: corrupt one round-polynomial coefficient in an otherwise honest proof, and the verifier rejects at the g(0)+g(1) check of that round or later.
4. Transcript-binding test: two honest proofs over witnesses differing in one cell produce different round challenges from round 0, because the witness digest is binding.
5. Small-n exhaustive differential oracle: for n ≤ 4, the honest prover's round-0 polynomial matches a naive independent computation of Σ_y eq(r,y)·G(y) restricted per variable, by direct summation over the cube, sharing no code with the prover.
6. Non-satisfying witness: set B ≠ A² at one row, absorb the digest over that same unsatisfying witness, and prove honestly. The exact check that must fail is `verify_zerocheck`'s round-0 g(0)+g(1) == 0 check. It is distinct from test 2, since here the digest matches the witness and the zerocheck itself must catch it.
7. Structural assertions: on a real proof the test asserts `rounds.len() ==` num variables, 4 coefficients in every round, and `final_evals.len() ==` the gate's input count.
8. Nontrivial second gate: run one more e2e honest+tamper pair on a different degree-2 formula with ≥ 5 inputs (e.g. A * (B + C) − D * E) at n=12. This proves `Gate` is general, not hardcoded to A·A−B.
9. Bench print, with no threshold: measure prove wall-clock and peak-poly memory at 2^20, and record both in the handoff.

## Handoff
Write `docs/handoff/S04-sumcheck.md` covering the frozen API, the new tag values, the round-message wire shape, the bench numbers, and an explicit note that `final_evals` discharge is deferred to the PCS stages.
This stage freezes `Gate`, `SumcheckProof`, `SumcheckClaim`, the prover/verifier entry points, and the 4-coefficient round format. `prove_zerocheck` and `verify_zerocheck` are terminal standalone-zerocheck entry points. The surface later stages build on is `Gate`, `SumcheckProof`, `SumcheckClaim`, the 4-coefficient round wire format, and the round-order convention: round i binds variable i, and claim.point[j] is the value bound to variable j.
