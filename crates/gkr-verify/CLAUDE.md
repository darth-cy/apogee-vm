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
pub struct ResolvedList<'a> { /* gate list k, every operand resolved to an index once */ }
impl ResolvedList<'_> { pub fn new(artifact, k, challenges) -> Self; pub fn producing(&self) -> usize;
    pub fn enforcing(&self) -> usize; pub fn scratch(&self) -> Vec<Fr>;
    pub fn cache(&self, lower, upper, virtuals, scratch: &mut [Fr]);
    pub fn gate(&self, j, lower, upper, virtuals, scratch: &mut [Fr]) -> Fr;
    pub fn summand(&self, weights, lower, upper, virtuals, scratch: &mut [Fr]) -> Fr; }
pub fn gate_values(artifact, k, lower, upper, virtuals, challenges) -> Vec<Fr>;
pub fn summand(artifact, k, weights, lower, upper, virtuals, challenges) -> Fr;
pub fn virtual_at_row(kind: VirtualKind, row: usize) -> Fr;
pub fn virtual_at_point(kind: VirtualKind, point: &[Fr]) -> Fr;
pub fn powers(lambda: Fr, n: usize) -> Vec<Fr>;
pub fn check_challenges(artifact, challenges) -> Result<(), GkrError>;
pub fn verify_sumcheck(claim: Fr, rounds: &[[Fr; 4]], t: &mut Transcript) -> Option<(Vec<Fr>, Fr)>;
pub fn verify(artifact: &CircuitArtifact, proof: &GkrProof, outputs: &OutputClaims,
              challenges: &ExternalChallenges, t: &mut Transcript) -> Result<Vec<BaseClaim>, GkrError>;

// src/memory.rs, docs/spec/memory.md §3.3 and §4
pub struct BoundaryFinals { pub reg_ts: [u64; 32], pub pc_ts: u64, pub reg_values: [u32; 31] }
pub fn window_challenges(memory: &ExternalChallenges, window: u32, trace_vars: u32) -> ExternalChallenges;
pub fn boundary_factors(memory: &ExternalChallenges, entry_pc: u32, finals: &BoundaryFinals) -> (Fr, Fr);  // (W_b, R_b)
pub fn reconciles(read_roots: &[Fr], write_roots: &[Fr], factors: (Fr, Fr)) -> bool;
```

## Frozen invariants
- **The kernel is the semantic authority.** `eval_gate` is the one place a gate's formula
  is computed. The engine's passes — the forward pass, the self-check, both halves of the
  layer sumcheck — reach it through `ResolvedList`, which `gate_values` and `summand`
  wrap; the checker calls it directly over the flat relations. Where a comment and the
  kernel disagree, the kernel wins.
- **Evaluation checks nothing per point.** `eval_gate` trusts that it gets one value per
  operand and `ResolvedList::summand` one weight per gate — every caller builds them to
  that count, and neither comes from a proof — so both asserts are kept commented out as
  debugging aids, off the prover's per-row and per-node path.
- **Evaluation allocates nothing.** `eval_gate` reads the gate's fields, never `operands()`;
  `ResolvedList` resolves a list's operands once, in `new`, and its `cache`, `gate` and
  `summand` work in a caller-owned scratch buffer. It is public only because the prover
  half is another crate and must share this resolution rather than repeat it.
- **The transcript schedule of `docs/spec/gkr.md` §5.2**, step for step: outputs, point,
  then per transition batch, rounds, claims, and — halving only — the child challenge.
- **`verify` absorbs nothing of the base.** Its transcript arrives bound; that binding is
  the caller's.
- **`verify` never panics on proof or claim data**, for an artifact that has passed
  `CircuitArtifact::validate`. Every shape, every slot and the output claims are checked
  before the transcript is touched, in the order `MissingChallenge`, `OutputShape`,
  `ProofShape`. A round or final check failing is `LayerInconsistency { layer }`, one
  variant for a wrong descending claim and a violated enforcing gate alike: a batched sum
  cannot say which term is wrong.
- **`verify` does not validate the artifact.** The artifact is the circuit part of a
  verifying key, the verifier's own data, and validation belongs to the key, once, not to
  every proof. No routine loads a verifying key yet; the stage that introduces
  `VerifyingKey` must call `validate` there. On an artifact that breaks a law `verify`'s
  answer means nothing: it may panic, and it may accept.
- **Virtual tables are evaluated from their closed form**, never materialized:
  `virtual_at_row` and `virtual_at_point` for `V[row]` and `V[ram_live]`,
  `docs/spec/gkr.md` §2.1.
- **The memory argument's verifier share is `src/memory.rs`.** `window_challenges` copies
  slots 1–4 and derives slot 5, `γ_M + RAM + α_addr·4·2^trace_vars·window`, never read from a
  proof. `boundary_factors` evaluates every register and PC tuple through `eval_gate` on
  `constraints::memory::read_tuple` — the circuits' own tuple gate, at operand values
  `[1, addr, ts, value]` — with `x0`'s final value 0 and the pc's `HALT_PC`; `BoundaryFinals`
  documents the 64-scalar `MEMORY_BOUNDARY` order. `reconciles` is
  `Π read · R_b = Π write · W_b ≠ 0`. Nothing here decodes the finals or draws the
  challenges: S16's global transcript does.
- **`#![no_std]` + `alloc`, forever.** CI builds it for `riscv32imac-unknown-none-elf`.

## Tests
Exercised end to end through `crates/gkr/tests`, which is where proofs exist; the memory
functions in `crates/gkr/tests/memory.rs`.
