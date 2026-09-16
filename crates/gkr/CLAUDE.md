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
- **A halving list reads both children of every column of its layer**, and a halving
  gate reads each operand there. `RowReader` loads the low half as child 0 and the high
  half as child 1 for every column, whatever the list's gates read, so S15's `TreeCross`
  — which reads a fraction's numerator and its denominator — needed nothing of the
  prover but the resolution `gkr-verify` owns.
- **One `G` for both passes.** Every gate is evaluated through a
  `gkr_verify::ResolvedList`, which calls the kernel: the forward pass and the self-check
  per row, the prover at every node of every round, the verifier — through `summand`,
  which wraps it — at the final check.
- **`prove` proves what `LayerValues` holds.** It never runs the self-check and never
  recomputes a table: wrong values make a proof a verifier rejects, which is what lets a
  tamper reach `verify`. The self-check is a debugging hook a caller may run after
  `forward`, never a step of proving: on `forward`'s own output its producing gates hold
  by construction, and it costs as much as `forward`.
- **`forward`, `self_check` and `prove` do not validate the artifact.** It is the circuit
  part of a proving key and is assumed to have passed `CircuitArtifact::validate`, once,
  where the key is loaded — a routine a later stage owes. On one that breaks a law their
  results mean nothing, and they may panic.
- **The prover checks nothing about its inputs at run time**, on the owner's instruction:
  not the base, the layer values, the sumcheck tables or the challenge slots. Soundness is
  `verify`'s alone — a cheating prover runs none of this code — so a check here could only
  give an honest prover's malformed input an earlier message. Without one, a missing base
  column, layer column or slot panics where it is first read; an extra column below the
  top makes a proof `verify` refuses by its claim count; a base column taller than the
  trace is read only up to the trace's height, and its base claims then cannot open
  against the committed column. The old checks are kept as debugging aids, uncalled or
  commented out: `check_slots`, `check_base`, `check_values`, `BaseLayer::new`'s and
  `prove_sumcheck`'s asserts, and in `gkr-verify` the kernel's operand count and
  `ResolvedList::summand`'s weight count, which sat on the per-row and per-node path.
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
- **No heap allocation per row, per row pair or per node.** Allocation happens per call,
  per gate list, per round or per rayon task, and nowhere else:
  - per gate list: one `ResolvedList` (operands resolved once) and, in `forward`, each
    output column, once, at its exact height; `forward` fills them column-major in place
    over blocks of `BLOCK` rows and evaluates producing gates only. There is no row-major
    table and no transpose. To hand each block to its rayon task, `forward` also allocates
    one list of column slices per `BLOCK` of rows, serially, before the parallel loop.
  - per transition in `prove`: one binding copy of each column of layer `k` and the eq
    table. A row-wise list's copy keeps the column's own width, and a narrow table's first
    `bind` folds it straight to half-size `Fr`; a halving list, which never reads the base,
    gets its two child tables copied straight from the column. Layer `k` is never lifted
    to a separate `Fr` copy first.
  - per rayon task: a `RowScratch` or `PairScratch`, built in `for_each_init`/`map_init`
    and overwritten row after row or pair after pair.
  - never inside the per-row or per-pair closure: rows are read with `get` into the
    scratch, virtual lines come from `virtual_at_point` over the task's point buffer, and
    `eval_gate`, `ResolvedList::cache`, `gate` and `summand` allocate nothing.
  - `LayerValues.base` shares the base's columns: `BaseLayer` holds them behind an `Arc`,
    so the forward pass does not copy the base.
  `tools/bench`'s `gkr-prove` is the measurement.

## Tests
| File | Covers |
| --- | --- |
| `tests/backward.rs` | acceptance 1 over both compilations and eight bases, base claims discharged against the columns; the proof's frozen shape; an all-zero output |
| `tests/tamper.rs` | acceptance 2's twin (layers 2 and 1 for inner flips, 0 for the enforcing-only cell, with the self-check naming the gate); acceptance 3's cancellation; a forged output table built at the point a transcript without the outputs would draw; a wrong child pair; a lying row-wise final eval at transitions 0 and 1; the self-check naming broken producing and halving gates; `MissingChallenge` for a slot in a producing or an enforcing gate; every shape error, in order, touching no transcript |
| `tests/forgery.rs` | every round held to the claim it inherits, directly on `verify_sumcheck`; an end-to-end forgery that repairs only the last round, rejected |
| `tests/edges.rs` | a circuit with `trace_vars` 1, a zero-variable layer, a width-0 top and an enforcing-only list, whose zero-round final check rejects a violation; two opposed enforcing gates in one list that do not cancel |
| `tests/kernel.rs` | `eval_gate` for every shape at non-unit literal and challenge coefficients and nonzero constants, against hand-written arithmetic; `Quadratic` also with an empty linear list, an empty products list and both |
| `tests/quadratic.rs` | the owner's `0 = a·b + c·d − e·f` as one enforcing `Quadratic`, beside a producing `Quadratic` with a constant, a linear term and a challenge whose column list 1 reads: honest forward values against hand arithmetic, self-check, proof, verify and discharge; one cell of `f` changed, named by the self-check and rejected at transition 0 |
| `tests/refusals.rs` | `ExternalChallenges::insert` refusing a slot set twice — the one refusal left, since the entry points check neither the artifact nor their inputs |
| `tests/batching.rs` | acceptance 4: the whole event log against the schedule, and the outstanding-claim walk reading halving and claim counts from the artifact, with its negative controls |
| `tests/compilation.rs` | acceptance 7: cached and cache-free give the same shape, values and proof byte for byte; degree-2 cached entries, in list 0 and in list 1, prove and verify |
| `tests/oracle.rs` | every round of every transition recomputed from hand-written toy formulas, sharing no code with the kernel; the control that it can fail |
| `tests/ram_live.rs` | `V[ram_live]`'s closed form against the extension of its table, at pseudo-random points and every cube point, over 14, 15, 16 and 18 variables; a 2^16-row circuit masking a product tree with it and enforcing a column zero below row 2^14: its root against a native product, proof, verify and discharge, and a violation on row 2^14 − 1 named by the self-check and rejected at transition 0 |
| `tests/memory.rs` | the `constraints::memory` artifacts' leaves through `gate_values` against the tuple in plain arithmetic, the address spaces, `Δ`, the per-family query lists and the column positions all written out again here rather than read from `constraints`: **all seven families' frames**, each leaf taking its AS and `Δ` from the query's **id** and its columns from its **slot**, 1 at mask 0 and the tuple at mask 1, each slot's mask alone at 1 and alone at 0 so a leaf reading another slot's mask fails, and the constant-1 pad leaves exactly 1 over random columns; each family's artifact pinned equal to `frame_artifact` of its hand-written query list, so a changed subset fails loudly; window leaves either side of row 2^14 and at a random window; `window_challenges`' slot 5 pinned by hand, and its panic on a missing slot; `boundary_factors` against §4.2's products; `reconciles` true, false on a changed root, a swapped pair or a zero root; honest proofs of both windows at 2^16 rows and of every family's frame at 2^4 over a satisfying base, and a write of 5 to `x0` named by the self-check and rejected at transition 0 |
| `tests/common/mod.rs` | the pinned toy fixtures, a satisfying base, the binding, the harness, the discharge, and the two small circuits `edges.rs` and `forgery.rs` share, and the `circuit` constructor that `quadratic.rs` builds its circuit from |

Every test written after the review states the mutant it kills, and each was run against that mutant.
