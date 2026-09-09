# `crates/curve`

## What this crate owns
BN254's base field `Fq`, the whole extension tower
`Fq2 = Fq[u]/(u^2+1)`, `Fq6 = Fq2[v]/(v^3 - xi)`, `Fq12 = Fq6[w]/(w^2 - v)`, both curve
groups `G1` and `G2` in affine and Jacobian coordinates, the **optimal ate pairing**, and
the **windowed Pippenger MSM** the prover leans on.

Scalars are `field::Fr`. Coordinates are `Fq`. The two moduli agree in their top 128
bits, so they are easy to confuse by eye and impossible to confuse by type.

## Frozen invariants
- **Concrete types, duplicated arithmetic.** `Fq`'s Montgomery kernel is a deliberate
  literal copy of `crates/field`'s with `FQ_*` constants substituted. There is no
  generic field and there never will be. `g2.rs` is likewise a literal mirror of
  `g1.rs` over `Fq2`. Two copies of a proven kernel are cheaper to review than one
  abstraction over a field with two instances.
- **One encoding.** Every `Fq` on the wire is the canonical (non-Montgomery) 32-byte
  little-endian integer, and `from_bytes` rejects `>= q` with `None` rather than
  reducing. Source literals are the one exception and use `Fq::from_hex`: `0x` plus 64
  lowercase hex digits, big-endian, as `field::Fr::from_hex` defines.
- **Point wire format — uncompressed affine, and nothing else.**
  ```text
  G1Affine   64 bytes   x || y
  G2Affine  128 bytes   x.c0 || x.c1 || y.c0 || y.c1
  infinity             all bytes zero
  ```
  All-zero is unambiguous because `(0, 0)` is off both curves. There is no compressed
  form and no decompression anywhere in the protocol. This is *not* how a point enters
  a transcript — that is four ~128-bit `Fr` limbs per point, a later stage's business.
- **`from_bytes` validates everything and never panics.** Non-canonical coordinate,
  off-curve point, on-curve-but-out-of-subgroup G2 point, and any nonzero byte in an
  otherwise-zero encoding all return `None`.
- **`infinity == true` means the coordinates carry no meaning.** The affine structs have
  public fields, so a caller can build an infinity with stale coordinates; every method
  ignores them, `to_bytes` emits zeros, and `PartialEq` holds against any other
  infinity. That is why `PartialEq` is written out rather than derived.
- **G1's cofactor is 1**, so `G1Affine::is_in_subgroup` is `is_on_curve` under another
  name. **G2's is `2q - r`**, so `G2Affine::is_in_subgroup` is real arithmetic: one
  256-bit window ladder against the identity.
- **Which square root comes back is unspecified.** A nonzero square has two and nothing
  normalises the sign. Nothing in the protocol depends on the choice, because points are
  never compressed.
- **`final_exponentiation` is the exact `(q^12 - 1)/r` power**, never a fixed multiple of
  it. That rules out the Fuentes-Castañeda hard part, which is what arkworks-bn254's own
  `final_exponentiation` computes — so the committed fixtures raise a Miller output to the
  literal 2,790-bit exponent rather than reading arkworks' pairing back.
- **`miller_loop` is the only Miller implementation.** `pairing` and `pairing_check` both
  go through it, it precomputes no G2 line coefficients, and `pairing_check` performs
  exactly one `final_exponentiation` whatever the pair count.
- **Pairs with a point at infinity contribute the identity** and are skipped, never
  rejected. An empty slice gives `Fq12::ONE` and `true`.
- **The pairing validates nothing.** On-curve and subgroup checks belong at decode time,
  in `from_bytes`. Feeding `miller_loop` a point off the curve yields a meaningless
  `Fq12`, not an error.
- **`msm` never dispatches on scalar magnitude.** `msm` always runs the general 254-bit
  path and `msm_small_u32` is the only door to the cheaper one, which is a source-level
  fact rather than something a test can observe: the two agree on every value, and the
  only difference is what they cost. S03 backs trace columns with `u8`/`u16`/`u32`, so the
  small case is the prover's common one and it earns its own entry point.
- **The window width is arkworks' heuristic, verbatim.** `3` below 32 points,
  `log2(n) * 69 / 100 + 2` above it. Copying the rule rather than inventing one is what
  makes the S07 acceptance-9 benchmark a comparison of implementations.
- **The recoding needs one more window than `ceil(bits / w)`.** Digits are signed into
  `[-2^(w-1), 2^(w-1)]`, and the carry must not escape the top window, so the window count
  is `ceil((bits + 1) / w)`. For every width the heuristic can pick this is the same
  number, because no `w` in `3..=29` divides 254 or 32 — but the `+1` is the reason it is
  provable rather than lucky.
- **Fq6 has no `conjugate`.** It is a cubic extension of Fq2, so it has no order-two
  automorphism over it; coefficientwise Fq2-conjugation is not even a ring homomorphism,
  since it would have to move `xi = 9 + u` while fixing `v^3`. Conjugation is an Fq12
  operation, where it is the `q^6` Frobenius.

## Numbers the code relies on
Each is re-derived in `tests/constants_check.rs` rather than trusted, because none of
them is visible in the code that leans on it:

| Fact | What it licenses |
| --- | --- |
| `q = 3 mod 4` | a square root is one exponentiation by `(q+1)/4` |
| `-1` is a nonresidue mod `q` | `u^2 = -1` is a valid extension, and `Fq2::sqrt`'s branches are exhaustive |
| `#E(Fq) = r`, an odd prime | G1 cofactor 1; no on-curve point has `y = 0` |
| `2q - r` is odd | `#E'(Fq2)` is odd too, so the twist has no 2-torsion either |
| `3` is a nonresidue mod `q` | `x = 0` has no on-curve `y`, which is part of why all-zero is unambiguous |

## Layout
```
src/fq.rs      Montgomery Fq: ops, square, pow, inverse, batch_inverse, sqrt, serde
src/fq2.rs     Fq2: ops, square, inverse, sqrt, conjugate, norm, mul_by_nonresidue (x xi)
src/fq6.rs     Fq6: ops, square, pow, inverse, mul_by_nonresidue (x v), frobenius_map
src/fq12.rs    Fq12: ops, square, pow, inverse, conjugate, frobenius_map
src/g1.rs      G1Affine + G1Projective (Jacobian): dbl-2009-l, add-2007-bl, madd-2007-bl
src/g2.rs      G2Affine + G2Projective, a literal mirror over Fq2 with the real subgroup check
src/pairing.rs miller_loop, final_exponentiation, pairing, pairing_check
src/msm.rs     windowed Pippenger: msm (254-bit) and msm_small_u32, MsmError
```

`Fq6` and `Fq12` are re-exported at the crate root beside `Fq` and `Fq2`; the four pairing
functions live in the public `curve::pairing` module. One spelling per item.

**The pairing is written for audit, not for speed**, because nothing in the prover ever
computes one (S06's own priority statement). Line functions are materialised as full
`Fq12` elements and multiplied in generically rather than through a sparse `mul_by_034`;
squarings are generic rather than cyclotomic; no G2 line coefficients are precomputed; and
the final exponentiation's hard part evaluates the `lambda` decomposition directly instead
of the addition chain that computes it in a third of the multiplications. Each of those is
a deliberate constant factor traded for a formula a reader can check.

`Fq2::mul_by_nonresidue` multiplies by **`xi = 9 + u`**, the Fq6 nonresidue the pairing
stage needs — not by the Fq2 nonresidue `-1`, which as an `Fq2 -> Fq2` operation would be
a second spelling of `Neg`. That reading was confirmed with the user and cross-checked
against `ark_bn254::Fq6Config::NONRESIDUE`.

## Artifacts
| Path | What |
| --- | --- |
| `tests/vectors/fq_kats.txt` | Fq and Fq2: an edge grid, 1,000 random vectors per field, `pow`, wire canonicity |
| `tests/vectors/g1_kats.txt` | G1: generator bytes, 1,000 random `(P, Q, k)`, addition/mixed-add/scalar edges, every rejection class |
| `tests/vectors/g2_kats.txt` | the same for G2, plus on-curve points outside the order-`r` subgroup |
| `tests/vectors/fq6_kats.txt` | Fq6: an 8x8 edge grid, 1,000 random vectors, every Frobenius power, `pow` |
| `tests/vectors/fq12_kats.txt` | the same for Fq12, plus `conjugate` and 207 exact final exponentiations |
| `tests/vectors/pairing_kats.txt` | 6 named cases including `e(G1, G2)`, and 120 random `(P, Q, e(P,Q))` |
| `tests/vectors/msm_kats.txt` | 13 MSM cases from ark-bn254's `VariableBaseMSM`, at sizes 0, 1, 2, 100, 2^10, 2^16 and over four input patterns |

Regenerate all seven with `cargo run -p kat-gen`, or one group with
`cargo run -p kat-gen -- <field|poly|curve|tower|pairing|msm>`; either prints each file's
SHA-256. The six older files' digests are pinned in `tests/kats.rs::FILES`;
`msm_kats.txt`'s is pinned in `tests/msm.rs::KAT_SHA256`, beside the only suite that
reads it. Refreshes are deliberate, and CI regenerates and diffs every file.

`msm_kats.txt` is the one fixture that encodes its inputs as a seed and a pattern rather
than writing them out: the 2^16-point case would otherwise be 12 MB of hex. Both sides
expand the same seed independently — arkworks in `tools/kat-gen/src/msm.rs`, `curve` in
`tests/msm.rs` — so a drift in either expansion changes the expected point and fails.

The six older files are **18 MB**, of which S06's three are 14 MB. That is the price of
Acceptance 1's "at least 1,000 random vectors per op" being committed rather than sampled
live: an `Fq12` token is 768 hex characters and an `fq12_ops` line carries eleven of them.
It is the largest single cost this stage adds to the repository and is recorded here so
nobody has to rediscover it.

## Tests
| File | What it pins |
| --- | --- |
| `constants_check.rs` | every constant re-derived, every load-bearing fact proven |
| `kats.rs` | the committed corpus, through one evaluator, plus the corruption sweep |
| `laws.rs` | associativity, commutativity, bilinearity of the scalar action, `batch_to_affine`, point *dis*equality one witness per conjunct, totality on every degenerate input |
| `wire.rs` | canonicity, round-trips, `from_hex`'s single spelling, serde, every rejection class at the API level |
| `differential.rs` | 1,500 live group operations, 2,000 live field vectors, 50 tower rounds and 23 live pairings against ark-bn254 |
| `tower.rs` | the field axioms for Fq6/Fq12, the tower relations `v^3 = xi` and `w^2 = v`, the Frobenius re-derived as `a^(q^i)` with no oracle, equality *dis*equality |
| `pairing.rs` | bilinearity, non-degeneracy, unitarity, infinity handling, the multi-pair product relations, a toy KZG opening with its negative twins, and `final_exponentiation` against the literal `(q^12-1)/r` applied bit by bit |
| `msm.rs` | the committed corpus, 100 live MSMs against ark-bn254 across every window-width boundary, small-path equivalence to 2^14, boundary scalars against a naive sum, and totality on every degenerate input |

`curve` is a **std** crate (S05 Must-be-exact 8) and is deliberately absent from CI's
guest-target build line: the recursion guest defers all pairing work through the
accumulator and never performs curve arithmetic.
