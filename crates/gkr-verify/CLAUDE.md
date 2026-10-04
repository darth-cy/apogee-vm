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
pub fn field_window_challenges(memory: &ExternalChallenges, window: u32, trace_vars: u32)
    -> ExternalChallenges;                         // S-RECURSION: FIELD_WINDOWS, docs/spec/recursion.md §2.2
pub fn boundary_factors(memory: &ExternalChallenges, entry_pc: u32, finals: &BoundaryFinals) -> (Fr, Fr);  // (W_b, R_b)
pub fn reconciles(read_roots: &[Fr], write_roots: &[Fr], factors: (Fr, Fr)) -> bool;

// src/lookup.rs, docs/spec/lookup.md §2 and §8
pub fn insert_lookup_challenges(into: &mut ExternalChallenges, g: Fr, beta: Fr, a: &CircuitArtifact);
pub fn channel_holds(root: (Fr, Fr)) -> bool;    // num == 0 AND den != 0, and neither alone
```

## Frozen invariants
- **A halving gate reads each of its operands at both children**, `lower[x]` then
  `upper[x]` in operand order, so `TreeProduct` gives two values and S15's `TreeCross`
  four. That generalization is `ResolvedList::new`'s halving branch and nothing else: the
  claim layout, L3's `2·w_k` message and L4's line-folding are what S13 froze.
- **The LogUp slots above `LOOKUP_BETA` are derived**, never read from a proof: a gate
  coefficient is one literal or one challenge, and `β^j` is neither
  (`docs/spec/lookup.md` §2). `insert_lookup_challenges` is where they come from, and a
  circuit with no decoder channel gets no `LOOKUP_DECODER_NEUTRAL`.
- **A channel's root check is both conditions**, `channel_holds`: a leaf pair of `(0, 0)`
  annihilates the whole tree, so `num == 0` alone would accept a channel proving nothing.
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
  `virtual_at_row` and `virtual_at_point` for all seven kinds, `docs/spec/gkr.md` §2.1.
  Six are weighted sums of the row's bits — `V[row]`, the two range tables, `V[xor8_a]` and
  `V[xor8_b]` — or a product over the high ones, `V[ram_live]`. **`V[xor8_out]` is the one
  that is not**: `Σ_{j<8} 2^j·(y_j + y_{j+8} − 2·y_j·y_{j+8})`, which is the multilinear
  extension of `(row & 0xff) ^ (row >> 8 & 0xff)` only because `y ^ z = y + z − 2yz` is
  multilinear in each of `y` and `z` (S26d, `docs/spec/lookup.md` §14). A closed form that is
  not its table's extension is a verifier evaluating a different polynomial than the prover
  committed, which no other check would see, so
  `crates/gkr/tests/lookup.rs::the_xor8_closed_forms_are_their_multilinear_extensions` holds
  all three against `MultilinearPoly::evaluate` over the materialized table at 8, 15, 16 and
  17 variables.
- **The memory argument's verifier share is `src/memory.rs`.** `window_challenges` copies
  slots 1–4 and derives slot 5, `γ_M + RAM + α_addr·4·2^trace_vars·window`, never read from a
  proof. `boundary_factors` evaluates every register and PC tuple through `eval_gate` on
  `constraints::memory::read_tuple` — the circuits' own tuple gate, at operand values
  placed by `constants::memory::PART_*`, the mask 1, `addr`, `ts`, `value` — with `x0`'s
  final value 0 and the pc's `HALT_PC`; `BoundaryFinals` documents the 64-scalar
  `MEMORY_BOUNDARY` order. `reconciles` is
  `Π read · R_b = Π write · W_b ≠ 0`. Nothing here decodes the finals or draws the
  challenges: S16's global transcript does.
- **`field_window_challenges` is `window_challenges` over the field memory** (S-RECURSION,
  `docs/spec/recursion.md` §2.2): slot 5 is `γ_M + FIELD + α_addr·2^trace_vars·window`, one cell
  a row where a RAM window's row is four bytes. Both are one private
  `strided_window_challenges(space, stride)`, `(RAM, 4)` and `(FIELD, 1)`. A field window's
  artifact names no address space — `constraints::memory::field_window_artifact` is
  `ZERO_WINDOWS`' circuit at a stride of one — so **this constant is the only place a field
  window's address space appears**, and its stride must be the artifact's.
  `verifier_core::shard_challenges` takes it for `FIELD_WINDOWS`, whose window is the shard's
  index, and `window_challenges` for every other window family.
- **`#![no_std]` + `alloc`, forever.** CI builds it for `riscv32imac-unknown-none-elf`.

## Tests
Exercised end to end through `crates/gkr/tests`, which is where proofs exist; the memory
functions in `crates/gkr/tests/memory.rs`.

Since S-RECURSION those suites also hold the recursion verifier's reading of `verify` to
`verify` itself: `crates/gkr/tests/common/mod.rs`' `tape_verify` replays the same binding over
cells through `verifier_core::tape::gkr_verify` and `tape::run`, and `assert_tape_agrees`
requires the same claims at the same point, or a refusal from both, over every proof
`tests/lookup.rs`' and `tests/memory.rs`' `prove_and_verify` makes — `memory.rs`' `x0` write
of 5 among them, refused by both. `field_window_challenges` has no test here, and **no suite
reads it above window 0**, where `α_addr·2^n·w` is 0: `crates/checker/tests/recursion.rs`
balances the field memory over one window, and the deferred `crates/prover/tests/field_ops.rs`
proves a statement with one field window, so a wrong stride in its slot-5 term would pass
both.
