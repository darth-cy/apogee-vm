---
title: 'S13 — GKR engine, circuit artifact, checker suite'

---

# S13 — GKR engine, circuit artifact, checker suite

## Depends on / Inputs
- S01 gives you `Fr` (with canonical LE serde) and `constants`.
- S02 gives you `Transcript`, with typed observe/sample and snapshot/restore.
- S03 gives you `MultilinearPoly`, with bind/fold/evaluate and eq machinery.
- S04 gives you the `sumcheck` crate, with `SumcheckProof` and 4-coefficient rounds.

This stage has no curve or PCS dependency. Its verifier discharges the final base-layer claims by direct evaluation of the known base columns, a test-side arrangement only; A later stage replaces that with Mercury openings.

## Deliver
- The `constraints` crate: the `PolyAddress` sum type, `GateDef` (the producing / enforcing / cached taxonomy), `LayerSpec` with derived widths, and the `CircuitArtifact` serde schema. Circuit families exist as DATA per the master.
- The `gkr` crate: the forward pass, which materializes all layers, and the backward pass, which reduces claims down to base-layer claims.
- The `checker` crate: the Laws 1–4 validators, the circuit dump tool, the witness-row evaluator and the artifact cross-check.
- GateDef kinds carry their own formula representation in `constraints`, with constant-term support. For example, MaskIntoIdentity's `out = in·mask + (1 − mask)` needs it. The forward/backward kernels are the semantic authority. `sumcheck::Gate` is NOT the lowering target and is not consumed by `gkr`; it remains S04's standalone-zerocheck formula type.
- gkr's verification half is `#![no_std]` (+alloc) compatible; the recursion guest links it.
- Freeze signatures:
  - `enum PolyAddress` — variants for: committed memory-subtree column, committed witness-subtree column, committed setup column, virtual setup table (closed-form kind), inner-layer `{layer, offset}`, scratch slot, cached `{layer, offset}`. A virtual setup table is never materialized or committed; its closed form is in the artifact.
  - `fn gkr::forward(&CircuitArtifact, base: &BaseLayer, challenges: &ExternalChallenges) -> LayerValues`
  - `gkr::prove(&CircuitArtifact, &LayerValues, &ExternalChallenges, &mut Transcript) -> GkrProof`
  - `gkr::verify(&CircuitArtifact, &GkrProof, &OutputClaims, &ExternalChallenges, &mut Transcript) -> Result<Vec<BaseClaim>, GkrError>` where `BaseClaim = {address: PolyAddress, point: Vec<Fr>, value: Fr}`.

## Core algorithm
- **Laws 1–4** describes the layer construction. **Law 1 (locality):** a gate whose output is at layer k+1 reads ONLY addresses at layer k, base columns and setup counting as layer 0. **Law 2 (derived width):** a layer's width is never declared independently — it is exactly the number of distinct output addresses the gates below produce, layer 0 excepted, whose size is the committed column counts. **Law 3 (top layer):** the last gate list writes a layer with no gate list of its own, holding exactly the declared outputs, nothing more and nothing less. **Law 4 (single source of truth):** the constraint set is stored twice, as a flat list and as gates, so the two encodings must have equal cardinality and identical semantics.
- The forward pass fills in values: start from the committed base layer, then for k = 0..N−1 apply every gate of layer k to produce layer k+1 row by row, using external challenges fixed in advance. Data flows base→top with no verifier interaction. There is one evaluation kernel per gate kind and the kernel is the semantic authority: if a comment and a kernel disagree, the kernel wins. Kernels are row-parallel, with no cross-row dependencies inside them. The pass ships self-check hooks recomputing the global identities from the materialized layers, so a broken gate is caught before proving.
- The backward pass reduces claims: begin with a claim about the top layer at a random point, and for k = N−1 down to 0 run one sumcheck per layer transition, turning a claim about layer k+1 into claims about layer k at a new random point. Claims flow top→base, and at the bottom only claims about committed base columns remain. The same G appears in both passes; write it once and use it from both.
- Enforcing gates are discharged as 0 = Σ_y eq(r,y)·G(y), with r from the local transcript, drawn only after the base layer is bound into the transcript. In this stage you bind it by absorbing a digest of the base columns; S16 substitutes real commitments. Never a bare sum.
- Enforcing claims enter the backward pass as side claims at their layer, RLC-batched with the descending claim when it reaches that layer.
- The per-layer sumcheck driver lives in gkr. It takes an externally supplied eq point, a nonzero RLC-batched initial claim, and a multi-claim summand of the descending claim plus the enforcing side claims. It builds on S03 bind/eq and S04's frozen wire artifacts: SumcheckProof shape, 4-coefficient round format, round-order convention. S04's prove_zerocheck/verify_zerocheck are standalone entry points deliberately NOT called by gkr, and this licensed non-use is not a fork. S16 reuses this driver for the final claim-merging sumcheck.
- Parallelism uses rayon: gate kernels split over row ranges, sumcheck rounds split their per-row evaluations the same way, and layers stay sequential. Fr arithmetic is exact, so any split and any reduction order give the same result; use rayon's default work-stealing reduction rather than a hand-tuned chunk size. 
- Keep the toy circuit at the Acceptance-1 minimums, since a small fixture keeps the cached versus cache-free diff readable.

## Must-be-exact
1. `PolyAddress` is the ONLY way any polynomial is named, and the committed subtrees, split by role (memory-argument-tied versus not), are visible in the type. The canonical short notation (M[i], W[i], S[i], V[..], L{k}[j], scratch[i], C{k}[j]) is used in every dump and diagnostic.
2. The scratch↔inner-layer bijection is stored IN the artifact, explicitly.
3. The gate taxonomy has three kinds. Producing gates write exactly one output address one layer up. Enforcing gates write nothing and contribute zero to width. Cached entries are layer-local shared sub-expressions. Every relation is presentable in ONE fixed shape, never simplified into a different-looking object for one entry: producing is `out(x) = Σ_y eq(x,y)·G(inputs at y)`, multi-output is one such line per output sharing the summand's parts, and enforcing is `0 = G(inputs at y)` for all y, discharged as the Core algorithm specifies. The gate catalogue records per entry: name, where it is defined, where the prover evaluates it, its typed input and output addresses, its formula in that template, and one line on what it is FOR. Cached and cache-free compilation of the same circuit yield identical layer count, widths and gate totals.
4. Laws 1–4 are enforced by construction-time assertions in `constraints` AND by standalone `checker` validators — two independent enforcement points.
5. Degree ceiling 2 is a master invariant: constructing a gate of degree ≥ 3 in the layer below is a construction-time error. The 4 below follows from the ceiling rather than standing beside it: the batched sumcheck polynomial per round has degree (gate degree) + 1 because of the eq factor, so a degree-2 gate gives cubic rounds and four coefficients. A relation that will not fit is SPLIT ACROSS LAYERS with an intermediate value rather than shoehorned, and the artifact documents the pattern once. Round messages are exactly 4 coefficients, the rounds per layer equal that layer's variable count, and no final round is silently skipped — whatever is not transmitted is explicitly recomputed and documented.
6. Per-layer claim batching works thus. Each layer transition that produces two child claims, L(r,0) and L(r,1), reduces to ONE claim via an RLC challenge drawn from the transcript AFTER both child claims are absorbed. At no point in the backward pass does the outstanding claim count per layer exceed one after batching.
7. `CircuitArtifact` contains at least: trace length; per-layer gate lists with typed addresses; derived widths; cached relations; the flat constraint list; the lookup-expression list; the scratch bijection; the output map; and the committed layout per subtree. Every polynomial also carries a human-readable name. The flat constraint list is checked for the Law-4 cardinality/semantics equivalence to the gate encoding. The lookup-expression list may be empty this stage, but the field exists. There is ONE coefficient encoding, canonical LE, declared in the file. Names are documentation, never semantics.
8. Checked-in toy artifacts are regenerated and diffed in CI.
9. Every checker states in its docs what it does NOT cover.
10. ExternalChallenges is an open container of named challenge slots, name -> Fr, with names in `constants`. Callers supply it on both the prove and verify sides, and later stages extend it additively. Verifier-side values come from the caller's own transcript replay or global phase, never from the proof. GateDef coefficient formulas may reference these named external-challenge symbols, resolved at forward/prove/verify time, and S14 builds its tuple-compression gates as data against that mechanism.
11. gkr::prove and gkr::verify never absorb base-layer binding material. They require a transcript the caller has already seeded with it. This stage's tests absorb the base-column digest caller-side, and S16 absorbs real commitments in its shard flow. The engine only exchanges round messages, claims, and challenges.
12. Every claim point is in the S03 variable order: point[j] is the value bound to variable j (index bit j, little-endian). Every layer sumcheck binds variable 0 first, per S04's round convention. BaseClaim.point is directly consumable by `MultilinearPoly::evaluate` and, downstream, by Mercury's u = (u1, u2) split.
13. `GateDef` is a closed Rust enum of gate shapes rather than a generically interpreted coefficient table, so that Acceptance 11's dead-variant audit has an enumerable variant set. Each variant names its operand `PolyAddress`es and carries its coefficients, constant term included, as a small closed `Coeff` type: a literal `Fr`, or a named external-challenge slot of Must-be-exact 10 resolved at forward/prove/verify time. A challenge slot is degree 0 in the layer below, so the Must-be-exact 5 degree check still reads a gate's shape statically. Later stages extend the enum additively.
14. The prohibition list is designed out, not documented around. No constraint is constructed and then dropped because its collecting vector was already consumed: assert nothing is pushed after a collection point. Variable names are injective and never encode a layer index that can drift. No count appears twice with different values without a stated relationship. Padding rows are never assumed free: the artifact states which constraints an inactive row must still satisfy, and says outright if an all-zero padding row is invalid. Reduced-width tests instantiate the same `Fr` as the shipped artifact.
15. The artifact file format is `serde` with `postcard`, and every `Fr` field is written as the canonical 32-byte little-endian of Must-be-exact 7. postcard is deterministic and not self-describing, so Acceptance 10's byte-identical round-trip tests the artifact rather than a formatter.

## Acceptance
1. The toy circuit is defined purely as a `CircuitArtifact` and never hard-coded in prover logic. It has ≥ 3 layers, ≥ 2 producing gates, ≥ 1 enforcing gate, ≥ 1 cached expression and ≥ 1 degree-2 product chain. An honest forward + prove + verify returns `Ok`, and the final `BaseClaim`s check against direct evaluation of the base columns.
2. Tamper twin: flipping one inner-layer value in `LayerValues` after the forward pass makes `verify` fail, and flipping one base-column cell touched only by the enforcing gate makes the eq-discharge fail. The two failures carry distinct `GkrError` variants.
3. Cancellation control: a base assignment violating the enforcing constraint by +v on one row and −v on another is rejected. This bare-sum cancellation attack shows that the eq(r,y) randomization is essential.
4. Batching structure test: over the full backward pass of the toy, assert the batched-claim invariant of Must-be-exact 6. Also assert from the transcript event log that each RLC challenge is sampled only after both child claims were absorbed.
5. Each law validator is negative-control tested with a hand-built bad artifact. Law 1 rejects a gate reading two layers down. Law 2 rejects a declared width that differs from the addresses actually produced below, the keccak_special5 defect class. Law 3 rejects a top layer holding an address absent from the output map. Law 4 rejects a flat list and gate encoding that disagree in count or semantics.
6. Degree-3 gate construction is rejected at construction time, and the test asserts the error.
7. The cached versus cache-free compilation equality test shows identical layer count, widths and gate totals, and identical forward-pass values.
8. Witness-row evaluator: a satisfying row passes, and perturbing any single cell reports the specific violated constraint by name. It is negative-control tested.
9. Artifact cross-check: the artifact agrees with an INDEPENDENTLY generated source, for example verifier-side constants emitted by a separate codepath, not a re-read of the same file. Perturbing one artifact field makes the cross-check fail.
10. Dump tool prints header, named columns, layers, gates and constraints; artifact serde round-trip is byte-identical.
11. Dead-variant audit: every `GateDef` variant is emitted by at least one test circuit, or is explicitly documented as reserved. The audit runs across ALL compilation variants, cached and cache-free, since a variant absent from one may be the one the other uses.

## Handoff
Freeze `PolyAddress` (all variants), `GateDef`, `LayerSpec`, the `CircuitArtifact` schema and file format, `LayerValues`, `GkrProof`, `BaseClaim`, `GkrError`, and the three `gkr` entry points above. Freeze `BaseLayer` too, constructed from a `PolyAddress -> MultilinearPoly` mapping, along with `ExternalChallenges` and `OutputClaims`. Each gets public construction APIs and stays additively extensible. Also freeze the checker validator CLIs/APIs and the toy artifact committed as a fixture.

`ExternalChallenges` freezes as the open, additively extended container of named challenge slots specified in Must-be-exact 10.

The per-layer sumcheck driver freezes exactly as the Core algorithm specifies it, licensed non-use of S04's prove_zerocheck/verify_zerocheck included, and S16 reuses it for the final claim-merging sumcheck.

The transcript-seeding contract of Must-be-exact 11 freezes with them: the engine only exchanges round messages, claims and challenges, and never absorbs base-layer binding material itself. S14/S15 add gate kinds and channels ON these types, and S16 consumes `BaseClaim`s into the Mercury opening.
