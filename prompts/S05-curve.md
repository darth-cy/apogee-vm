---
title: S05-fq-tower-curve.md

---

# S05 — Fq Tower + G1/G2 Arithmetic (Owned)

## Depends on / Inputs
- From S01: `field` supplies `Fr`.

## Deliver
Build the new crate `curve` with base-field tower level one and both curve groups. This stage is pure algebra: no pairing and no MSM. The whole stack is owned, so arkworks-bn254 appears only as a dev-dependency and fixture generator. Later stages compile against exactly this frozen public API:

```rust
pub struct Fq(/* 4×u64 Montgomery; layout private */);   // same surface as Fr: ops, square, pow,
                                                          // inverse, batch_inverse (mirroring S01's
                                                          // frozen Fr names exactly), sqrt,
                                                          // canonical LE serde
pub struct Fq2 { pub c0: Fq, pub c1: Fq }                 // Fq[u]/(u²+1); ops, inverse, sqrt,
                                                          // conjugate, mul_by_nonresidue
pub struct G1Affine { pub x: Fq, pub y: Fq, pub infinity: bool }
pub struct G1Projective(/* internal coords private */);
pub struct G2Affine { pub x: Fq2, pub y: Fq2, pub infinity: bool }

impl G1Affine {
    pub const GENERATOR: G1Affine;                        // (1, 2)
    pub fn is_on_curve(&self) -> bool;
    pub fn is_in_subgroup(&self) -> bool;                 // cofactor 1: on-curve ⇒ in subgroup; document
    pub fn to_bytes(&self) -> [u8; 64];                   // x ‖ y, each canonical 32-byte LE Fq
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<G1Affine>; // validates canonical + on-curve + subgroup
}
impl G1Projective {
    pub const IDENTITY: G1Projective;
    pub fn add(&self, other: &G1Projective) -> G1Projective;
    pub fn add_affine(&self, other: &G1Affine) -> G1Projective;  // mixed add (S07 hot path)
    pub fn double(&self) -> G1Projective;
    pub fn mul(&self, scalar: &Fr) -> G1Projective;
    pub fn to_affine(&self) -> G1Affine;
    pub fn batch_to_affine(points: &[G1Projective]) -> Vec<G1Affine>; // one batch_inverse
}
// Plus From/Neg/PartialEq conversions both directions; G2Affine mirrors G1Affine's constructors,
// checks, serde ([u8; 128], c0 ‖ c1 per coordinate), GENERATOR, plus add/double/mul methods.
```

## Core algorithm
- On BN254, G1 is y² = x³ + 3 over Fq and G2 is y² = x³ + 3/(9+u) over Fq2, the D-twist. The Fq modulus is fixed and defined once, in `constants`.
- `Fq` mirrors S01's `Fr` internally: 4×64-bit Montgomery with CIOS multiplication. Reuse the approach, not the type. `Fq` is its own concrete struct, per master rule 1.
- Projective arithmetic is Jacobian with the standard a=0 formulas `dbl-2009-l`, `add-2007-bl` and `madd-2007-bl`. `madd-2007-bl` is the mixed add later stage's MSM builds on. Edge-case handling is complete: identity, P + P, P + (−P), and mixed add against affine.
- Scalar multiplication uses a fixed 4-bit window over sixteen precomputed multiples. There is no constant-time requirement.
- The G2 subgroup check multiplies by the group order r and compares against the identity. Correctness is fixture-tested either way.
- An internal `G2Projective` in Jacobian Fq2 coordinates backs `G2Affine`'s add, double and mul, mirroring the G1 formulas. Only `G2Affine` is frozen.

## Must-be-exact
1. Tower and twist constants match arkworks-bn254 and EIP-197 exactly: nonresidue −1 for Fq2 (u²+1), ξ = 9+u reserved for next stage, G2 curve constant 3/(9+u), and standard G1/G2 generators. All live in `constants`, each verified by a fixture test.
2. Point serde is uncompressed affine, 64 bytes for G1 and 128 for G2, with coordinates canonical 32-byte LE. Infinity is all-zero bytes, which is unambiguous because (0,0) is off-curve. 
3. `from_bytes` rejects non-canonical coordinates (≥ p), off-curve points, on-curve-but-out-of-subgroup G2 points, and nonzero bytes violating the infinity pattern. It returns `None`, never panics.
4. `G1Affine::is_in_subgroup` documents and relies on cofactor 1. `G2Affine::is_in_subgroup` is a real check.
5. Group ops are total: identity and inverse edge cases produce correct results, not panics, for every public method.
6. A committed fixture-generator dev-tool in `tools/` emits all fixture files of the Acceptance section from arkworks-bn254. Fixtures are committed and pinned by hash, and tests read files only.
7. The frozen listing is a minimum public surface, not a ceiling. Additive conveniences are welcome: sum impls, precomputed doublings, a public `G2Projective`. No addition changes a frozen signature, and the handoff records each one.
8. `curve` is a std crate. Rayon is allowed may parallelise `batch_to_affine`.

## Acceptance
1. **Fq/Fq2 differential fixtures.** Each op (add/sub/mul/square/inverse/sqrt/mul_by_nonresidue) is checked on ≥1000 random vectors from the oracle, plus the edges 0, 1 and p−1, and Fq2 values with zero components. All pass.
2. **Fq serde pinning.** Canonical LE round-trip holds, ≥ p bytes are rejected, and one committed known-value byte fixture freezes the encoding.
3. **G1/G2 op fixtures.** ≥1000 random (P, Q, k) vectors cover P+Q, 2P, kP and −P from the oracle, in affine coordinates after normalization. All pass.
4. **Edge-case fixtures.** Dedicated committed vectors cover P + ∞, ∞ + ∞, P + P via the generic add path, and P + (−P) = ∞. Scalar cases cover k=0, k=1, k=r−1 and k=r (≡ ∞). One case is mixed-add where the affine point equals or negates the projective one. Each is exercised for G1 and G2.
5. **Subgroup negative controls.** The dev-tool generates committed fixtures of on-curve G2 points NOT in the r-subgroup, from random x with the cofactor un-cleared. On those points `is_in_subgroup` is false and `from_bytes` returns `None`. A same-shape G1 test uses off-curve points.
6. **Point serde.** Round-trip holds on random points and both infinities. The exact bytes of both GENERATORs match committed fixtures, which freezes the wire format. Every rejection class of Must-be-exact 3 has a failing fixture.
7. **Algebraic laws.** Property tests cover associativity/commutativity of point add, (a+b)P = aP + bP, a(bP) = (ab mod r)P, and batch_to_affine ≡ per-point to_affine, including identity entries.
8. **Differential test.** ≥500 random group ops are cross-checked live against arkworks-bn254 in one test run.
9. **Negative control.** One corrupted fixture byte fails the corresponding test. It is run once and noted in the handoff.

## Handoff
Write `docs/handoff/S05-fq-tower-curve.md`. Record the frozen API above as implemented, and the point wire format as a bytes-level spec. List the fixture file paths and the generator tool's usage. Name the G2 subgroup-check method chosen, every addition made under Must-be-exact 7.