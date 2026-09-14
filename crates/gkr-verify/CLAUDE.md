# `crates/gkr-verify`

## What this crate owns
The verifier half of the GKR engine, and everything the verifier touches: the gate
kernel, the layer sumcheck's verifier, `verify`, and the types it takes and returns. It is
`#![no_std]` + `alloc` because the recursion guest links it; `crates/gkr` is the `std` +
rayon prover half and re-exports this crate whole, so `gkr::verify` is `verify` here.
**`docs/spec/gkr.md` §5 is normative.**

```rust
pub struct ExternalChallenges { /* slot -> Fr */ }
impl ExternalChallenges { pub fn new() -> Self; pub fn insert(&mut self, slot: u32, value: Fr);
                          pub fn get(&self, slot: u32) -> Option<Fr>; }
pub struct OutputClaims { pub tables: Vec<MultilinearPoly> }
pub struct BaseClaim { pub address: PolyAddress, pub point: Vec<Fr>, pub value: Fr }
pub struct GkrProof { pub layers: Vec<SumcheckProof> }       // SumcheckProof re-exported from sumcheck
pub enum GkrError { MissingChallenge { slot }, OutputShape, ProofShape { layer }, LayerInconsistency { layer } }

pub fn eval_gate(gate: &GateDef, values: &[Fr], challenges: &ExternalChallenges) -> Fr;   // THE kernel
pub fn gate_values(artifact, k, lower, upper, virtuals, challenges) -> Vec<Fr>;
pub fn summand(artifact, k, weights, lower, upper, virtuals, challenges) -> Fr;
pub fn coefficient(c: Coeff, challenges: &ExternalChallenges) -> Fr;
pub fn virtual_at_row(kind: VirtualKind, row: usize) -> Fr;
pub fn virtual_at_point(kind: VirtualKind, point: &[Fr]) -> Fr;
pub fn powers(lambda: Fr, n: usize) -> Vec<Fr>;
pub fn claim_count(artifact: &CircuitArtifact, k: usize) -> usize;
pub fn check_challenges(artifact, challenges) -> Result<(), GkrError>;
pub fn verify_sumcheck(claim: Fr, rounds: &[[Fr; 4]], t: &mut Transcript) -> Option<(Vec<Fr>, Fr)>;
pub fn verify(artifact: &CircuitArtifact, proof: &GkrProof, outputs: &OutputClaims,
              challenges: &ExternalChallenges, t: &mut Transcript) -> Result<Vec<BaseClaim>, GkrError>;
```

## Frozen invariants
- **The kernel is the semantic authority.** `eval_gate` is the one place a gate's formula
  is computed; the forward pass, the self-check, both halves of the layer sumcheck and the
  checker's witness-row evaluator reach it through `gate_values`. Where a comment and the
  kernel disagree, the kernel wins.
- **The transcript schedule of `docs/spec/gkr.md` §5.2**, step for step: outputs, point,
  then per transition batch, rounds, claims, and — halving only — the child challenge.
- **`verify` absorbs nothing of the base.** Its transcript arrives bound; that binding is
  the caller's.
- **`verify` never panics on proof or claim data.** Every shape, every slot and the output
  claims are checked before the transcript is touched, in the order
  `MissingChallenge`, `OutputShape`, `ProofShape`. A round or final check failing is
  `LayerInconsistency { layer }`, one variant for a wrong descending claim and a violated
  enforcing gate alike: a batched sum cannot say which term is wrong. An artifact that
  breaks a law panics — it is the verifier's own data.
- **Virtual tables are evaluated from their closed form**, never materialized.
- **`#![no_std]` + `alloc`, forever.** CI builds it for `riscv32imac-unknown-none-elf`.

## Tests
Exercised end to end through `crates/gkr/tests`, which is where proofs exist.
