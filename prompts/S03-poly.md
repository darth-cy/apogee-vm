---
title: S03 — Multilinear Polynomials + Small-Type Backing

---

# S03 — Multilinear Polynomials + Small-Type Backing

## Depends on / Inputs
- S01 supplies `Fr` with its ops and the canonical LE convention.

## Deliver
- `crates/poly` provides `MultilinearPoly` with small-type backing and lazy lift, bind/fold/evaluate, eq machinery.
- `crates/poly` is a `#![no_std]` (+alloc) core.

Frozen public API:

```rust
#[derive(Clone)]
pub enum PolyBacking { U1(/* bitset */), U8(Vec<u8>), U16(Vec<u16>), U32(Vec<u32>), Fr(Vec<Fr>) }

#[derive(Clone)]
pub struct MultilinearPoly { /* backing + num_vars, private */ }
impl MultilinearPoly {
    pub fn new(backing: PolyBacking) -> MultilinearPoly;   // len must be a power of two
    pub fn num_vars(&self) -> usize;
    pub fn len(&self) -> usize;                            // 2^num_vars over the remaining cube
    pub fn get(&self, index: usize) -> Fr;                 // on-cube read, lifted on the fly if still small
    pub fn bind(&mut self, r: Fr);                         // fix the current lowest variable to r; lifts to Fr backing on first call
    pub fn evaluate(&self, point: &[Fr]) -> Fr;            // off-cube, non-destructive, point.len() == num_vars
    pub fn backing(&self) -> &PolyBacking;                 // read-only borrow of the live backing; after any bind it is always the Fr variant
}

pub fn eq_table(r: &[Fr]) -> Vec<Fr>;                      // tensor expansion: eq(r, y) for all y, length 2^r.len()
pub fn eq_eval(r: &[Fr], y: &[Fr]) -> Fr;                  // closed form, O(n)
```

## Core algorithm
Evaluations are indexed over {0,1}^n, and **the variable-order convention is frozen, since every later stage builds on it.** Variable j is bit j of the index, so indexing is little-endian: index = Σ yⱼ·2ʲ. `bind(r)` fixes variable 0, the lowest bit, halving the table via `f'(i) = f(2i) + r·(f(2i+1) − f(2i))`. The old variable 1 then becomes the new variable 0.

`evaluate` is repeated binding, but it must leave the receiver untouched. It folds into a scratch `Vec<Fr>` rather than cloning: the first round lifts on the fly as `get` does, and later rounds halve it in place. At `num_vars` 0 it returns `get(0)`. `bind` folds the lifted table over its own first half and truncates.

eq(r,y) = Πⱼ (rⱼyⱼ + (1−rⱼ)(1−yⱼ)). `eq_table` builds the full table by iterative doubling, O(2ⁿ) mults total.

Small-type backing exists because trace columns are mostly narrow integers: bits, bytes, u32 words. Storage stays at native width, cheap to fill during trace generation, until the first challenge binding forces field arithmetic. Lift means the canonical embedding of the integer into `Fr`.

## Must-be-exact
1. The variable-order and bind conventions above hold exactly; document them in `docs/GLOSSARY.md` and the crate `CLAUDE.md`.
2. `bind` on a small backing lifts the whole table to `PolyBacking::Fr` first; after any bind the backing is `Fr` forever. No dual representations exist.
3. `get` and `evaluate` on a small backing do NOT mutate it: lazy means bind-triggered, not read-triggered.
4. All five backing variants are implemented and behave identically to their pre-lifted `Fr` equivalents.
5. Binding beyond `num_vars`, a wrong `point` length, and a non-power-of-two `new` are loud errors. All three panic: the frozen signatures return values, not `Result`.
6. The crate has no trait-generic polynomial abstractions: one concrete type, one enum.
7. `PolyBacking::U1` carries a bitset: `Vec<u64>` limbs plus an entry count. Entry i is bit i%64 of limb i/64, little-endian to match the frozen index convention. That count is a power of two, fixes `num_vars`, and bits past it in the final limb are zero.
8. `crates/poly` must build and run as `#![no_std]` (+alloc).
9. The frozen API pins the listed signatures, not the whole public surface: read-only accessors and iterators may sit beside them; record any you add in the handoff.

## Acceptance
1. Commit fixture file(s) under `crates/poly/tests/vectors/`: for a fixed seeded 10-variable poly they hold expected results of bind chains, `evaluate` at 20 points and `eq_table` prefixes. Generate once, review, commit; tests replay byte-exact.
2. Run a differential oracle: for n ≤ 12, `evaluate` must match a naive independent implementation on 100 seeded random polys/points. The naive one sums Σₓ f(x)·eq(point,x) directly, using `eq_eval` only. For the small-size corpus a cross-check against arkworks' `DenseMultilinearExtension` as a dev-dependency is required; it pins the variable-order/endianness convention against an external authority. Commit those vectors too.
3. Backing equivalence: the same value table expressed as U1/U8/U16/U32/Fr, where the width fits, gives identical `get`, `evaluate`, and post-`bind` tables. Test all 2^8 tables exhaustively for n=3 at U1, seeded-random for wider types.
4. Bind/evaluate consistency: for random n=10 polys, binding all n variables to point r one at a time leaves a single value equal to `evaluate(r)`.
5. Laziness is observable: a U16-backed poly reports small backing after `get`/`evaluate`, and `Fr` backing after one `bind`. Expose a test-visible discriminant accessor.
6. Test the eq machinery at n=6 with random r: `eq_table(r)[index_of(y)]` equals `eq_eval(r, y)` for all y, `Σ_y eq_table(r)[y]` equals 1, and `eq_eval(r, r')` equals `eq_eval(r', r)`.
7. A test pins the index convention: for n=3, `get(0b011)` reads the evaluation at y₀=1, y₁=1, y₂=0. That literal test will break loudly if anyone flips endianness later.
8. Error cases from Must-be-exact 5 each have a test.
9. Negative control: a corrupted copy of the fixture file fails the replay test.
10. Print a bench line, no threshold: time the lift plus full bind chain wall-clock at n=20 for U32 backing, and record it in the handoff.

## Handoff
Write `docs/handoff/S03-poly.md`: frozen API, the variable-order/bind convention in one unambiguous paragraph, fixture paths, bench numbers. It freezes `MultilinearPoly`, `PolyBacking`, eq machinery and the index convention for every later circuit stage.