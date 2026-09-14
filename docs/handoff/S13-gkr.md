# S13 — GKR engine, circuit artifact, checker suite

Branch `s13-gkr`. Status: complete. All eleven acceptance items are met, one of them
(Acceptance 2's "distinct `GkrError` variants") in the form the repository owner chose
instead. The deviations are at the end, and each one was put to the owner or is
recorded as the stage prompt's own ambiguity.

The normative document written this stage is **`docs/spec/gkr.md`**: the layer model,
the addresses, the six gate shapes, the artifact and its wire form, the laws, the
padding contract, and the backward pass's transcript schedule. The design records are
the four new crate `CLAUDE.md` files. This note is the frozen API, the artifacts, the
evidence and the deviations.

---

## Read these first

1. **The verifier half is its own crate, `crates/gkr-verify`.** The stage wanted
   gkr's verification half `#![no_std]` for the recursion guest *and* rayon in the same
   crate; rayon needs `std` and cargo features are banned, so one had to give. The owner
   chose a separate crate — a name outside the master's frozen layout — over a serial
   prover or an unchecked `no_std` claim. `gkr-verify` and `constraints` are
   `#![no_std]` and CI builds both for `riscv32imac-unknown-none-elf`; `gkr` is `std` +
   rayon and re-exports `gkr-verify` whole, so every frozen path — `gkr::verify`,
   `gkr::GkrProof`, `gkr::BaseClaim` — still resolves.
2. **Halving layers exist now.** Must-be-exact 6's "two child claims `L(r,0)`, `L(r,1)`"
   only arise in a product-tree layer, which a same-height model never produces. The owner
   chose to build it: each layer carries its own variable count, one `TreeProduct` shape,
   the child bit is the highest variable, a halving list halves every column of its layer
   in order, and the two children meet on a line at a challenge `τ` drawn after both are
   absorbed. The toy has one halving list, so Acceptance 4 tests the real mechanism.
3. **The engine absorbs the claimed outputs before it draws the top point.** `prove`
   takes no point and no output claim, so the point is drawn inside the engine; if the
   outputs were not absorbed first, a prover could compute the point in advance and forge
   a different output table with the same value there. `tests/tamper.rs` builds that
   forgery and it is rejected.
4. **Every failing round or final check is one `GkrError::LayerInconsistency { layer }`.**
   Acceptance 2 asks the inner-layer tamper and the enforcing-gate tamper to carry
   distinct variants. Inside one batched sumcheck a verifier cannot tell which term is
   wrong, and the owner's instruction was not to add proof data to pretend otherwise:
   *"In a regular verifier, it doesn't observe these two failure modes separately."* The
   two tampers fail at different layers (2 and 1 for inner flips, 0 for the enforcing
   cell), and the self-check names the broken gate before proving.

---

## Frozen public API, as built

```rust
// crates/constraints/src/lib.rs   (#![no_std] + alloc)
pub const FORMAT_VERSION: u32 = 0;
pub const COEFFICIENT_ENCODING_CANONICAL_LE: u32 = 0;
pub const MAX_TRACE_VARS: u32 = 30;
pub enum VirtualKind { RowIndex }
pub enum PolyAddress { Memory(u32), Witness(u32), Setup(u32), Virtual(VirtualKind),
                       Inner { layer: u32, offset: u32 }, Scratch(u32),
                       Cached { layer: u32, offset: u32 } }             // + Display: M[i] L{k}[j] ...
pub enum Coeff { Literal(Fr), Challenge(u32) }
pub enum GateDef {
    Linear { terms: Vec<(Coeff, PolyAddress)>, constant: Coeff },
    Product { coeff: Coeff, left: PolyAddress, right: PolyAddress },
    MaskIntoIdentity { input: PolyAddress, mask: PolyAddress },
    AffineProduct { left: Vec<(Coeff, PolyAddress)>, left_constant: Coeff,
                    right: Vec<(Coeff, PolyAddress)>, right_constant: Coeff },
    TreeProduct { input: PolyAddress },
    Quadratic { constant: Coeff, linear: Vec<(Coeff, PolyAddress)>,
                products: Vec<(Coeff, PolyAddress, PolyAddress)> },
}
impl GateDef { pub fn operands(&self) -> Vec<PolyAddress>; pub fn coefficients(&self) -> Vec<Coeff>; }
pub struct CatalogueEntry { pub variant, defined_in, evaluated_in, inputs, output, template, purpose: &'static str }
pub const CATALOGUE: [CatalogueEntry; 6];
pub struct CachedEntry { pub name: String, pub address: PolyAddress, pub gate: GateDef }
pub struct ProducingEntry { pub relation: u32, pub output: PolyAddress, pub gate: GateDef }
pub struct EnforcingEntry { pub relation: u32, pub gate: GateDef }
pub struct LayerSpec { pub halving: bool, pub num_vars: u32, pub width: u32, pub cached: Vec<CachedEntry>,
                       pub producing: Vec<ProducingEntry>, pub enforcing: Vec<EnforcingEntry> }
pub struct Relation { pub name: String, pub output: Option<u32>, pub gate: GateDef }
pub struct LookupExpr { pub name: String, pub channel: u32, pub tuple: Vec<GateDef> }
pub struct ScratchSlot { pub name: String, pub address: PolyAddress }
pub struct Padding { pub row: Vec<Fr>, pub zero_row_valid: bool }
pub struct CircuitArtifact { pub format_version: u32, pub coefficient_encoding: u32, pub trace_vars: u32,
    pub memory: Vec<String>, pub witness: Vec<String>, pub setup: Vec<String>,
    pub virtuals: Vec<(VirtualKind, String)>, pub layers: Vec<LayerSpec>, pub relations: Vec<Relation>,
    pub lookups: Vec<LookupExpr>, pub scratch: Vec<ScratchSlot>, pub outputs: Vec<PolyAddress>,
    pub padding: Padding }
impl CircuitArtifact {
    pub fn depth(&self) -> usize; pub fn layer_vars(&self, layer: usize) -> u32;
    pub fn layer_width(&self, layer: usize) -> u32; pub fn committed(&self) -> Vec<PolyAddress>;
    pub fn validate(&self) -> Result<(), ConstraintError>;
    pub fn inline_cached(&self) -> Result<CircuitArtifact, ConstraintError>;
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(bytes: &[u8]) -> Result<CircuitArtifact, String>;
}
pub enum ConstraintError { Locality { layer, gate, operand }, DerivedWidth { layer, detail },
    TopLayer { detail }, SingleSource { detail }, Degree { gate, degree }, NotInlinable { gate },
    Malformed { detail } }                                                   // + Display
```

```rust
// crates/gkr-verify/src/lib.rs   (#![no_std] + alloc; re-exported by gkr)
pub use sumcheck::SumcheckProof;
pub struct ExternalChallenges { /* slot -> Fr */ }
impl ExternalChallenges { pub fn new() -> Self; pub fn insert(&mut self, slot: u32, value: Fr);
                          pub fn get(&self, slot: u32) -> Option<Fr>; }
pub struct OutputClaims { pub tables: Vec<MultilinearPoly> }
pub struct BaseClaim { pub address: PolyAddress, pub point: Vec<Fr>, pub value: Fr }
pub struct GkrProof { pub layers: Vec<SumcheckProof> }
pub enum GkrError { MissingChallenge { slot: u32 }, OutputShape, ProofShape { layer: usize },
                    LayerInconsistency { layer: usize } }                     // + Display
pub fn eval_gate(gate: &GateDef, values: &[Fr], challenges: &ExternalChallenges) -> Fr;   // THE kernel
pub struct ResolvedList<'a> { /* gate list k, operands resolved once */ }
impl<'a> ResolvedList<'a> { pub fn new(artifact: &'a CircuitArtifact, k: usize, challenges: &'a ExternalChallenges) -> Self;
    pub fn producing(&self) -> usize; pub fn enforcing(&self) -> usize; pub fn scratch(&self) -> Vec<Fr>;
    pub fn cache(&self, lower: &[Fr], upper: &[Fr], virtuals: &[Fr], scratch: &mut [Fr]);
    pub fn gate(&self, j: usize, lower: &[Fr], upper: &[Fr], virtuals: &[Fr], scratch: &mut [Fr]) -> Fr;
    pub fn summand(&self, weights: &[Fr], lower: &[Fr], upper: &[Fr], virtuals: &[Fr], scratch: &mut [Fr]) -> Fr; }
pub fn gate_values(artifact: &CircuitArtifact, k: usize, lower: &[Fr], upper: &[Fr], virtuals: &[Fr],
                   challenges: &ExternalChallenges) -> Vec<Fr>;
pub fn summand(artifact: &CircuitArtifact, k: usize, weights: &[Fr], lower: &[Fr], upper: &[Fr],
               virtuals: &[Fr], challenges: &ExternalChallenges) -> Fr;
pub fn virtual_at_row(kind: VirtualKind, row: usize) -> Fr;
pub fn virtual_at_point(kind: VirtualKind, point: &[Fr]) -> Fr;
pub fn powers(lambda: Fr, n: usize) -> Vec<Fr>;
pub fn check_challenges(artifact: &CircuitArtifact, challenges: &ExternalChallenges) -> Result<(), GkrError>;
pub fn verify_sumcheck(claim: Fr, rounds: &[[Fr; 4]], t: &mut Transcript) -> Option<(Vec<Fr>, Fr)>;
pub fn verify(artifact: &CircuitArtifact, proof: &GkrProof, outputs: &OutputClaims,
              challenges: &ExternalChallenges, t: &mut Transcript) -> Result<Vec<BaseClaim>, GkrError>;
```

```rust
// crates/gkr/src/lib.rs   (std + rayon)
pub use gkr_verify::*;
pub struct BaseLayer { /* committed columns by address */ }
impl BaseLayer { pub fn new(columns: Vec<(PolyAddress, MultilinearPoly)>) -> BaseLayer;
                 pub fn get(&self, address: PolyAddress) -> Option<&MultilinearPoly>; }
pub struct LayerValues { pub base: BaseLayer, pub layers: Vec<Vec<MultilinearPoly>> }
pub struct SelfCheckError { pub layer: usize, pub row: usize, pub relation: String }
pub struct LayerSummand<'a> { pub artifact: &'a CircuitArtifact, pub layer: usize, pub weights: Vec<Fr>,
                              pub challenges: &'a ExternalChallenges }
pub struct LayerTables { pub lower: Vec<MultilinearPoly>, pub upper: Vec<MultilinearPoly> }
pub fn forward(artifact: &CircuitArtifact, base: &BaseLayer, challenges: &ExternalChallenges) -> LayerValues;
pub fn self_check(artifact: &CircuitArtifact, values: &LayerValues, challenges: &ExternalChallenges)
    -> Result<(), SelfCheckError>;
pub fn prove_sumcheck(eq_point: &[Fr], summand: &LayerSummand, tables: &mut LayerTables,
                      t: &mut Transcript) -> (Vec<[Fr; 4]>, Vec<Fr>);
pub fn prove(artifact: &CircuitArtifact, values: &LayerValues, challenges: &ExternalChallenges,
             t: &mut Transcript) -> GkrProof;
```

```rust
// crates/checker/src/lib.rs   (std) — and the `checker laws|padding|dump <artifact>` CLI
pub fn check_law1(a: &CircuitArtifact) -> Result<(), String>;   // and check_law2, 3, 4
pub fn check_laws(a: &CircuitArtifact) -> Result<(), String>;
pub fn check_padding(a: &CircuitArtifact) -> Result<(), String>;
pub struct WitnessRow { pub committed: Vec<Fr>, pub row: usize, pub scratch: Vec<Fr> }
pub fn violated_relations(a: &CircuitArtifact, w: &WitnessRow, challenges: &ExternalChallenges) -> Vec<String>;
pub fn dump(a: &CircuitArtifact) -> String;
pub struct VerifierConstants { /* see crates/checker/CLAUDE.md */ }
pub struct ReferenceRun { pub outputs: Vec<Vec<Fr>>, pub enforcing: Vec<(String, Vec<Fr>)> }
pub fn cross_check(a: &CircuitArtifact, expected: &VerifierConstants,
                   reference: fn(&[Vec<Fr>], &ExternalChallenges) -> ReferenceRun) -> Result<(), String>;
```

```rust
// crates/constants/src/lib.rs   (additions; still zero logic)
pub mod transcript_tags {
    pub const GKR_OUTPUTS: u64 = 25;       // scalars
    pub const GKR_OUTPUT_POINT: u64 = 26;  // challenge
    pub const GKR_BATCH: u64 = 27;         // challenge
    pub const GKR_LAYER_CLAIMS: u64 = 28;  // scalars
    pub const GKR_CHILD: u64 = 29;         // challenge
}
pub mod challenge_slot { pub const TOY: u32 = 0; pub const NAMES: [&str; 1] = ["toy"]; }   // append-only
```

## The transcript schedule (frozen; `docs/spec/gkr.md` §5.2)

After the caller has bound the base:

| step | op | tag | message |
| --- | --- | --- | --- |
| O1 | absorb | `GKR_OUTPUTS` | every output table, output-map order, one message |
| O2 | squeeze ×`n_N` | `GKR_OUTPUT_POINT` | the top point `r` |
| L1 | squeeze | `GKR_BATCH` | `λ`; claim `Σ_j λ^j v_j`, enforcing gates weighted `λ^{w+e}` with claim 0 |
| L2 | ×`n_{k+1}` absorb, squeeze | `SUMCHECK_ROUND`, `SUMCHECK_CHALLENGE` | S04's 4-coefficient cubic, then `ρ_i` |
| L3 | absorb | `GKR_LAYER_CLAIMS` | layer `k`'s claims: one per column, or both children per column |
| L4 | squeeze (halving only) | `GKR_CHILD` | `τ`; the claim point becomes `(ρ, τ)` |

L1 to L4 run for `k = N − 1` down to `0`; the base claims are layer 0's L3 values at
one point, in layout order. `tests/batching.rs` holds the prover's and the verifier's
event logs to this table event for event.

## What this freezes for every later stage

1. **`docs/spec/gkr.md`** in full: the layer model with its halving rule, the address
   placement rules, the six shapes and their kernel order, cached-entry substitution and
   the degree rule, the artifact fields and wire form, Laws 1–4 and the other refusals,
   the padding contract, the schedule and the error order.
2. **The kernel is `gkr_verify::eval_gate`**, reached through `ResolvedList` — which
   `gate_values` and `summand` wrap — by the forward pass, the self-check and both
   halves of the layer sumcheck, and directly by the checker.
3. **The transcript-seeding contract** of must-be-exact 11: the engine absorbs no
   base material; external challenges are drawn after everything their gates reach is
   bound.
4. **The layer sumcheck driver**: `gkr::prove_sumcheck` and `gkr_verify::verify_sumcheck`,
   each owning step L2; the caller draws the batch before and absorbs the claims after.
5. **Tags 25–29** and **challenge slot 0**, append-only.
6. **The toy circuit**, committed cached and cache-free.

## Artifacts

| Path | What |
| --- | --- |
| `docs/spec/gkr.md` | the normative GKR spec |
| `crates/constraints/tests/vectors/toy_cached.bin` | the toy circuit, 1,486 bytes |
| `crates/constraints/tests/vectors/toy_cache_free.bin` | its cache-free compilation, 1,500 bytes |
| `tools/kat-gen/src/gkr.rs` | the toy's only definition; `cargo run -p kat-gen -- gkr` |
| `crates/{constraints,gkr-verify,gkr,checker}/CLAUDE.md` | the design records |

Both `.bin` files are pinned by SHA-256 in every suite that reads them
(`crates/{constraints,gkr,checker}/tests/common/mod.rs`); CI regenerates and diffs them.
They are kat-gen's output, not an oracle. The toy:

```text
base      M[0] m   W[0] a   W[1] b   W[2] c   W[3] e   S[0] s   V[row]      16 rows
list 0    C{0}[0] shifted_a = γ·a + row                 (cached)
          L{1}[0] ab = a·b     L{1}[1] fingerprint = shifted_a·c     L{1}[2] masked_m = m·s + (1 − s)
          0 = e·s − a·s                                  (enforcing, Quadratic)
list 1    L{2}[0] abm = ab·masked_m      L{2}[1] fingerprint3 = fingerprint + 3
list 2    L{3}[0], L{3}[1]: the product trees of abm and fingerprint3   (halving)
outputs   L{3}[1], L{3}[0]
```

It is past the Acceptance-1 minimums, on purpose, in several places: the halving list,
without which Acceptance 4 and `TreeProduct` would test nothing; seven producing gates
rather than two, so that every shape appears and Acceptance 11's audit is not satisfied
by declaring variants reserved; a challenge coefficient, the virtual table, a constant
term and a non-identity output map, so that each mechanism the artifact freezes is
exercised; and an enforcing gate whose column `e` nothing else reads, which Acceptance
2's second tamper needs. Shapes the toy cannot show — two enforcing gates in one list, a
cached entry above list 0, a zero-variable top — are built inside the tests that need
them.

## Acceptance

| # | Item | Where | Result |
| --- | --- | --- | --- |
| 1 | toy as data; ≥3 layers, ≥2 producing, ≥1 enforcing, ≥1 cached, a product chain; honest run; base claims vs direct evaluation | `gkr/tests/backward.rs` | both compilations × 8 bases verify; all 6 base claims at one point, each equal to `MultilinearPoly::evaluate` of its column |
| 2 | tamper twin | `gkr/tests/tamper.rs` | inner flips rejected at transitions 2 and 1; `e` flipped on an active row rejected at 0 with the self-check naming `gated_equality`, and on an inactive row accepted; one variant, by the owner's decision |
| 3 | cancellation control | `tamper.rs` | `+v`/`−v` on two active rows: bare sum exactly 0, eq-weighted sum nonzero, `verify` rejects |
| 4 | batching invariant and event-log order | `gkr/tests/batching.rs` | both logs equal the schedule event for event; a walker asserts at most one outstanding point after each reduction and every batch or child challenge after its claims; both walker negative controls fail as they must |
| 5 | law validators' negative controls | `checker/tests/laws.rs`, `constraints/tests/laws.rs` | a gate two layers down (Law 1), a width the gates do not produce (Law 2), an address the output map lacks (Law 3), a flat list disagreeing in count and in meaning (Law 4): each refused by the checker and at construction; 36 checker mutants of both compilations and 4 cached-only, `check_laws` and `validate` agreeing on all 72 compared runs |
| 6 | degree-3 gate refused | `constraints/tests/laws.rs` | `Degree { gate: "define_ab", degree: 3 }` from a degree-2 cached entry inside a `Product` |
| 7 | cached vs cache-free | `gkr/tests/compilation.rs`, `constraints/tests/audit.rs` | same depth, widths, variables and gate totals; same forward values; **the same proof byte for byte** |
| 8 | witness-row evaluator | `checker/tests/witness.rs` | a satisfying row passes; 14 cells perturbed each report exactly their hand-derived relations; evaluators reporting nothing or everything fail |
| 9 | cross-check against an independent source | `checker/tests/cross_check.rs` | hand-written verifier constants and a plain-arithmetic reference pass; 24 perturbations, each on both compilations, each fail |
| 10 | dump; byte-identical round trip | `checker/tests/dump.rs`, `constraints/tests/wire.rs` | the dump's sections and two exact gate lines; bytes → artifact → bytes identical, plus every refusal of the reader and all 11,888 single-bit flips without a panic |
| 11 | dead-variant audit across compilations | `constraints/tests/audit.rs` | all six variants emitted; per-compilation counts pinned and shown to differ |

## Verification performed

**621 workspace tests, all green, plus 20 `#[ignore]`d** (495 and 20 at S12) — 126 new: 69
in `crates/constraints`, 36 in `crates/gkr`, 21 in `crates/checker`, about half of them
written to close the adversarial review's findings. `fmt` and
`clippy -D warnings` are clean across all four workspaces; `constraints` and `gkr-verify`
build for `riscv32imac-unknown-none-elf`; `cargo run -p kat-gen` regenerates every
committed fixture with no diff.

**An independent Python model, before the code settled.** Written from the spec alone
(standard library, its own transcript), it modelled both kinds of transition, cached
substitution and the virtual table, and ran 300 seeds per experiment: every honest proof
verified and every round node equalled the naive cube sum; inner flips, enforcing
violations, cancellations and wrong child pairs were all rejected; and each ordering the
spec relies on proved necessary by removal — without O1 an output forgery was accepted
300/300, with `τ` drawn before L3 a combined forgery was accepted 300/300, and with the
enforcing term unweighted every cancellation was accepted. It also found the one real
spec defect of the stage: the halving summand paired output `j` with input `j` while no
rule required it, so a legal permuted halving list failed honest proofs. The rule is now
that a halving list halves every column in order.

**The oracle.** `gkr/tests/oracle.rs` recomputes every round cubic of every transition
at all four nodes as a direct sum over the remaining cube, from hand-written toy
formulas and `MultilinearPoly::evaluate`, replaying the schedule itself: 44 nodes per
seed, three seeds, none of the kernel, `gate_values` or the prover's interpolation used.

**The two enforcement points agree.** `checker/tests/laws.rs` holds
`check_laws(a).is_ok() == a.validate().is_ok()` over 72 mutant runs.

## Adversarial review

Six lenses over commit `c94cff1`, each finding of medium severity or above then put to a
skeptic told to refute it:

- the mathematics derived from the spec alone, then held to the code line by line;
- a malicious prover in its own worktree;
- a clause-by-clause audit of the stage prompt against code and tests;
- two mutation sweeps, over the engine and over the validators and wire form;
- master-rule compliance, documentation truth, and a deletion pass.

**No soundness defect was found in the engine, and nothing panicked.** The math lens found
no divergence between spec, prover and verifier. The attacker generated 3,000 random lawful
circuits covering every unusual shape the spec admits — zero-width inner layers,
enforcing-only lists, zero-variable tops, width-0 halving lists, `trace_vars` 0 and 1, a
virtual table inside a cached entry, a challenge only in a cached entry — and every honest
run verified, every cached and cache-free pair proved byte-identically, and every single
tamper was rejected. 20,000 hostile byte-level mutants of the fixture went through
`from_bytes`, `validate`, `inline_cached` and every checker with no panic.

**47 findings: 0 high, 21 medium, 26 low. Every medium finding put to a skeptic survived.**
Almost all were the class this review exists for — **tests that would pass on a wrong
implementation**. The two mutation sweeps ran 58 engine mutants (40 killed) and 75
validator mutants (39 killed on the first pass), and the survivors named the gaps:

- **Two soundness-critical verifier checks could be deleted with the suite green**: the
  row-wise final check, and every round check after round 0. Every committed tamper was
  caught at round 0 or at the halving final check, so neither was ever exercised against a
  lying prover. The skeptic built a forgery each mutant accepts with base claims that still
  discharge. So was the final check of a zero-round transition, which no test circuit had.
- **A second enforcing gate's weight** was untested: the toy has one, so a verifier giving
  every enforcing gate the same weight — under which `a − b` and `b − a` cancel — passed.
- **The forged-output test could not see O1**: it built its forgery at the point drawn
  after the outputs were absorbed, so an engine that never absorbs them rejected it too.
- **`self_check`'s producing and halving paths**, the kernel's non-unit coefficients and
  nonzero constants, `MissingChallenge` for producing and enforcing gates, three shape
  checks, the `validate` panics, the prover's input refusals, cached entries above list 0,
  Law 4's normal form, and about a dozen validator, checker and dump rules had no test
  that could fail.

Four code findings, all acted on:

- **`validate` was quartic in a gate's size.** Law 4 multiplied whole expansions out before
  merging, so a 15 KB artifact took about 20 s — and at the time every engine entry point
  validated on every call (deviation 19 records why none does now).
  Every intermediate sum and product is now normalized as it is built, which is quadratic
  in a gate's distinct operands.
- **A zero coefficient bypassed the dropped-relation rule**: `0·x` named a column that
  nothing depended on. "Reads" is now decided on the normalized expansion, so `0·x` and
  `x − x` read nothing, and — asked by the test writer that closed this — an enforcing gate
  whose expansion is zero, such as a product with an emptied zero factor, is refused as
  constraining nothing. A short-lived rule refusing every zero-coefficient term was
  deleted again: the expansion rule covers everything it caught that mattered.
- **The checker's Law 2 accepted a halving list 0** that `validate` refuses — the two
  enforcement points disagreed on one artifact. Fixed in the checker.
- **The reader reserved up to 4,096 elements from an untrusted length**, against the spec's
  word. It now reserves nothing.

Documentation findings acted on: the claim that the checker reads gates through
`gate_values` (it calls the kernel directly), the claim that every wire integer is a varint
(a `u8` tag is a raw byte), an overstated dropped-relation rule in `CLAUDE.md`, and
overstated test counts. Deletions: `gkr_verify::coefficient` is private,
`GateDef::catalogue_index` and `VerifierConstants`' `rounds` and `claims` are gone.

Not acted on, and why: equivalent mutants that change no verdict (ten, all named in the
review record); the per-variant gate catalogue, read as the spec says (deviation 16); and
the witness-row evaluator's silence on product-tree scratch cells (deviation 17).

**The fixes, re-checked by mutation.** Every test written to close a finding was run against
the mutant it names, one at a time and reverted after:

- `crates/gkr` — 23 mutants, all killed. For the soundness mutants — the row-wise final
  check skipped, only round 0 checked, the zero-round final check skipped, every enforcing
  gate given one weight, the outputs never absorbed — the killing test's failure is `verify`
  returning `Ok` with base claims on the forgery, not some other assertion.
- `crates/constraints` — 20 mutants, all killed, including the reverted normalization,
  under which the cost test's `t = 128` artifact took 36.9 s against its 2 s bound.
- `crates/checker` — 15 mutants, all killed, the old Law 2 among them.
- The two rules added after the review — the identically zero enforcing gate, and reads
  on the normalized expansion — each killed by its test. Removing the normalization
  inside `product` alone survives and is equivalent: its factors are already normalized
  sums, so it can only leave duplicates unmerged, never a zero coefficient or a hidden
  column, and the comparison normalizes at the end. It stays, so the expansion is
  normalized everywhere the doc says it is.

Two disagreements between the enforcement points remain, both outside the laws and both
documented on `check_laws`: the checker does not refuse a relation whose `V[row]` terms
cancel while `virtuals` does not list the table, and it applies none of the rules beyond
the laws.

## The owner's review of PR #13

Three changes, made after the adversarial review above, each on the owner's instruction.

**1. A sixth gate shape, `Quadratic { constant, linear, products }`**, wire tag 5:
`c_0 + Σ a_i·x_i + Σ b_j·y_j·z_j`. The owner's reason: `a·b + c·d − e·f = 0` is degree 2
and no single earlier shape writes it, because it is no one product of affine forms.
Operands read `x_1..x_t, y_1 z_1..y_u z_u`; coefficients `c_0, a_1..a_t, b_1..b_u`, field
order like every other shape. Degree is the widest term after substitution, so a product
naming a degree-2 cached entry is refused. A `Quadratic` naming a cached entry refuses to
inline. The toy's gated equality is now `e·s − a·s`, relation and gate alike — the same
polynomial as before, so a capture of every forward value, proof and verify result for
both compilations, eight seeds each, and the two small test circuits was byte-identical
across the change; only the artifact bytes moved (`toy_cached.bin` 1,616 → 1,486 bytes,
`toy_cache_free.bin` 1,630 → 1,500). `gkr/tests/quadratic.rs` proves the owner's own
relation end to end and rejects it with one cell of `f` changed.

**2. The engine does not validate the artifact.** Deviation 19 is the contract; the first
item of "Open for the next stage" is what it leaves owed.

**3. The prover allocates per call, per gate list, per round and per rayon task — never
per row, row pair or node.** The owner read the forward pass as building row tables and
transposing them into columns. It did, and more: every column of layer `k` was lifted to a
fresh `Fr` copy per gate list (8× a `u32` column, 256× a bit column) in `forward`,
`self_check` and `prove`; every enforcing gate was evaluated in `forward` and thrown away;
the base was deep-cloned into `LayerValues`; and `gate_values` made about `3G` heap
allocations per row and per sumcheck node, `G` the gate count. Now:

- `gkr_verify::ResolvedList` resolves a gate list's operands to indices once. `eval_gate`
  is still the only formula evaluator and no longer allocates; `gate_values` and `summand`
  wrap `ResolvedList`, so the two passes and both sides of the sumcheck still share one
  `G`. It is the one new public item, public because the prover half is another crate.
- `forward` allocates each output column once, at its height, and fills it column-major in
  place over rayon blocks of 1,024 rows, reading layer `k` at its own width and evaluating
  producing gates only. `self_check` streams the same way and returns the same first
  failure. `BaseLayer` holds its columns behind an `Arc`.
- `prove` hands the sumcheck native-width clones; `poly`'s `bind` folds a narrow table
  straight to half-size `Fr`, so no full-size lifted copy exists (the `poly-bind` bench is
  about 4% slower for it: 28.95 → 30.1 ms at 2^20).
- No public signature changed, and nothing any pass outputs did: a 1.2 MB capture of
  forward values, 160 self-check failures, proofs, 127 rejected tampers and base claims
  over every test circuit was byte-identical before and after.

`tools/bench`'s `gkr-prove` routine is the measurement, run against the prover before and
after on the same circuit (32 narrow columns, 339 gates over 20 lists ending in 16
product-tree roots, 2^18 rows, best of 3, one machine):

| | before | after | |
| --- | --- | --- | --- |
| `forward` | 547.7 ms | 67.3 ms | 8.1× faster |
| `self_check` | 599.5 ms | 67.4 ms | 8.9× faster |
| `prove` | 2,228.5 ms | 998.0 ms | 2.2× faster |
| `verify` | 10.1 ms | 10.3 ms | unchanged, as it should be |
| maximum resident set size | 1.84 GB | 1.07 GB | 42% less |
| user CPU, whole routine | 121.8 s | 26.3 s | 4.6× less |

Still serial, and the obvious next step: binding a transition's tables one after another.

A second adversarial review — the `Quadratic` gate, the prover's equivalence and its
allocation contract, the validation contract, and a documentation sweep, each finding put
to a verifier told to refute it — confirmed seven findings, all minor and all fixed: the
refactor had dropped `prove_sumcheck`'s refusal of a halving list whose child tables do not
pair up (restored, with `tests/refusals.rs::prove_sumcheck_refuses_unpaired_children`
run against the mutant), and six counts and descriptions in the docs had gone stale.

## Deviations and notes for the reviewer

1. **A crate outside the frozen layout, `gkr-verify`.** See the top.
2. **Halving layers and a toy past the Acceptance-1 minimums.** See the top.
3. **One `LayerInconsistency` variant.** See the top.
4. **"A nonzero RLC-batched initial claim" is read as "an arbitrary batched claim".** An
   honest claim is exactly 0 whenever the outputs are zero, and a driver refusing it fails
   honest proofs; `tests/backward.rs::an_all_zero_output_verifies` proves one. Recorded in
   `docs/spec/gkr.md` §5.3 rather than edited into the prompt.
5. **The driver takes no claim.** An honest round 0 sums to the claim by construction, so
   `prove_sumcheck` takes the eq point, the summand and the tables; `verify_sumcheck`
   takes the claim. Each owns step L2 only.
6. **`OutputClaims` is the full output tables**, not evaluations: `prove` takes no point,
   so the verifier must be able to evaluate the outputs wherever the engine draws one.
   For a product-tree root that is one value.
7. **`GkrProof` is `Vec<SumcheckProof>`**, S04's own type, one per gate list, with
   `final_evals` holding the claims L3 absorbs.
8. **Challenge slots are numbers, not strings.** "name → Fr, with names in `constants`" is
   met as `constants::challenge_slot`: the number is the key and `NAMES` the display
   name, like tags, so master rule 12's "names are documentation, never semantics" holds.
9. **Virtual tables are never materialized**, including inside the prover's sumcheck,
   where their closed form is evaluated at `(bound, X, bits)`.
10. **`format_version` is in the artifact** beside the coefficient-encoding word the
    stage asks for, because a postcard layout is not self-describing: it is how a reader
    refuses a later, extended layout instead of misreading it.
11. **`lookups` must be empty** until S15 gives the element a meaning; its placeholder
    shape may change then, with a version bump.
12. **Two refusals beyond the laws**: an inner column no gate reads and a cached entry no
    gate names — a relation constructed and then dropped, which constrains nothing
    (must-be-exact 14). Found by the spec review, not asked for by name.
13. **The checker's laws are sampled, not symbolic.** Law 4 and the padding contract are
    checked by kernel evaluation at fixed-seed pseudo-random points, a different algorithm
    from `constraints`' symbolic expansion on purpose.
14. **The test harness draws the toy's challenge under `SUMCHECK_CHALLENGE`** right after
    the digest. No tag was added for a test harness; S14's global challenges bring their
    own.
15. **No `PROTOCOL_VERSION` bump**: S13 adds tags and fills placeholders.
16. **The gate catalogue is per `GateDef` variant.** Must-be-exact 3's "records per entry:
    name, where it is defined, where the prover evaluates it, its typed input and output
    addresses, its formula in that template, and one line on what it is FOR" is met in two
    halves: `constraints::CATALOGUE` holds, per variant, where it is defined and evaluated,
    its operand roles, its template and its purpose — identical defining and evaluating
    sites on every row, because every shape lives in one enum and one kernel — and
    `checker::dump` prints, per circuit entry, its name, its typed addresses and its formula
    in the template, then the catalogue. No circuit entry carries a purpose line of its own.
17. **The witness-row evaluator covers row-local relations only.** A product-tree scratch
    slot has no value on one row, so perturbing it reports nothing; Acceptance 8's "any
    single cell" is met over the cells a row has. `checker`'s doc says so.
18. **An identically zero enforcing gate is refused**, and a column counts as read only
    where it survives normalization — rules the stage does not name, both instances of
    must-be-exact 14's "no constraint is constructed and then dropped". Found by the review.
19. **No engine entry point validates the artifact.** `verify`, `forward`, `self_check`
    and `prove` assume an artifact that has passed `CircuitArtifact::validate` and do not
    check it again, on the owner's instruction: the artifact is the circuit part of a
    verifying or proving key, and validation belongs to the key, once, not to every proof.
    No routine loads a key yet, so at S13 whatever builds an artifact — `kat-gen`, the test
    harnesses — calls `validate` itself. On an artifact that breaks a law the engine's
    answer means nothing: it may panic, and `verify` may accept. Until the owner's review
    every entry point validated on every call; the two tests that held `verify` and `prove`
    to panicking on a lawless artifact went with it. The per-call checks stay, in their
    order: `MissingChallenge`, `OutputShape`, `ProofShape`, then the prover's shape
    refusals.

## Open for the next stage

- **The verifying-key and proving-key loading routines must call `validate`, once.**
  Nothing else does: the engine's entry points assume a validated artifact (deviation 19),
  and on one that breaks a law `verify` may accept. Until a stage introduces
  `VerifyingKey`, whatever builds an artifact is the only place it is checked.
- **Padding rows and product trees.** The padding contract says which relations an
  inactive row satisfies; it does not yet say a padding row contributes the
  multiplicative identity to every column a halving list reads (master rule 7), and the
  toy's does not. The stage that builds product trees over trace rows owes that clause.
- **Challenge provenance is a caller obligation, not a checked rule.** A gate combining a
  global memory challenge with any witness column it can reach lets a prover choose that
  column knowing the challenge. S14 should record, per slot, which subtrees must be bound
  before it, and check it.
- **S16's claim-merging sumcheck needs a multi-point driver.** Its claims sit at several
  points, and `prove_sumcheck` weights one `eq` table; S16 extends it to a weighted sum of
  `eq` tables.
- **The artifact is not yet bound into any transcript.** It is the verifier's own data,
  part of a verifying key; the stage that builds statement binding decides how it is
  committed to.
- **Trace heights must be even for Mercury**; the artifact allows any `trace_vars ≤ 30`,
  and S16 enforces evenness where it opens base claims.
- **`transcript_tags` has 29 entries** and **`challenge_slot` one**. Append, never
  renumber, never reuse a tag across kinds.
