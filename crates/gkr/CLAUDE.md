# `crates/gkr`

## What this crate owns
The prover half of the GKR engine: the forward pass, which materializes every layer
from the committed base; its self-check; the layer sumcheck's prover; and the backward
pass, `prove`. It is `std` because per-row work is split over rayon. It re-exports
`crates/gkr-verify` whole, so `gkr::verify`, `gkr::GkrProof`, `gkr::BaseClaim`,
`gkr::GkrError`, `gkr::OutputClaims` and `gkr::ExternalChallenges` are that crate's.
**`docs/spec/gkr.md` is normative.**

```rust
pub struct BaseLayer { /* committed columns by address */ }
impl BaseLayer { pub fn new(columns: Vec<(PolyAddress, MultilinearPoly)>) -> BaseLayer;
                 pub fn get(&self, address: PolyAddress) -> Option<&MultilinearPoly>; }
pub struct LayerValues { pub base: BaseLayer, pub layers: Vec<Vec<MultilinearPoly>> }
pub struct SelfCheckError { pub layer: usize, pub row: usize, pub relation: String }
pub struct LayerSummand<'a> { pub artifact: &'a CircuitArtifact, pub layer: usize,
                              pub weights: Vec<Fr>, pub challenges: &'a ExternalChallenges }
pub struct LayerTables { pub lower: Vec<MultilinearPoly>, pub upper: Vec<MultilinearPoly> }

pub fn forward(artifact: &CircuitArtifact, base: &BaseLayer, challenges: &ExternalChallenges) -> LayerValues;
pub fn self_check(artifact: &CircuitArtifact, values: &LayerValues, challenges: &ExternalChallenges)
    -> Result<(), SelfCheckError>;
pub fn prove_sumcheck(eq_point: &[Fr], summand: &LayerSummand, tables: &mut LayerTables,
                      t: &mut Transcript) -> (Vec<[Fr; 4]>, Vec<Fr>);
pub fn prove(artifact: &CircuitArtifact, values: &LayerValues, challenges: &ExternalChallenges,
             t: &mut Transcript) -> GkrProof;
```

## Frozen invariants
- **One `G` for both passes.** Every gate is evaluated through
  `gkr_verify::gate_values`, which calls the kernel: the forward pass per row, the
  prover at every node of every round, the verifier at the final check.
- **`prove` proves what `LayerValues` holds.** It never runs the self-check and never
  recomputes a table: wrong values make a proof a verifier rejects, which is what lets a
  tamper reach `verify`. The self-check is the caller's, after `forward`.
- **`prove` absorbs nothing of the base**, and follows `docs/spec/gkr.md` §5.2 step for
  step, exactly as `verify` does; the two end in one sponge state.
- **The layer sumcheck driver owns step L2 only**: one 4-coefficient cubic per variable of
  the eq point, S04's interpolation, `SUMCHECK_ROUND` then `SUMCHECK_CHALLENGE`. The
  caller draws the batch before it and absorbs the claims after it. The claim is not an
  input. S16's claim-merging sumcheck, over several points, extends it.
- **A cached entry is evaluated at every node, never bound as a table**; a virtual table
  is evaluated from its closed form at every node, never materialized.
- **Rayon splits rows and row pairs, never layers or rounds.** Field arithmetic is exact,
  so no split and no reduction order can change a value.

## Tests
| File | Covers |
| --- | --- |
| `tests/backward.rs` | acceptance 1 over both compilations and eight bases, base claims discharged against the columns; the proof's frozen shape; an all-zero output |
| `tests/tamper.rs` | acceptance 2's twin (layers 2 and 1 for inner flips, 0 for the enforcing-only cell, with the self-check naming the gate); acceptance 3's cancellation; a forged output table; a wrong child pair; every shape error, in order, touching no transcript |
| `tests/batching.rs` | acceptance 4: the whole event log against the schedule, and the outstanding-claim walk, with its negative controls |
| `tests/compilation.rs` | acceptance 7: cached and cache-free give the same shape, values and proof byte for byte; a degree-2 cached entry proves and verifies |
| `tests/oracle.rs` | every round of every transition recomputed from hand-written toy formulas, sharing no code with the kernel; the control that it can fail |
| `tests/common/mod.rs` | the pinned toy fixtures, a satisfying base, the binding, the harness and the discharge |
