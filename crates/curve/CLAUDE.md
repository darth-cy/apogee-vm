# `crates/curve`

## What this crate owns
BN254's base field `Fq`, tower level one `Fq2 = Fq[u]/(u^2+1)`, and both curve groups
`G1` and `G2` in affine and Jacobian coordinates. Pure algebra: **no pairing and no
MSM** — those are later stages, and they compile against exactly the surface frozen
here.

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
src/fq.rs    Montgomery Fq: ops, square, pow, inverse, batch_inverse, sqrt, serde
src/fq2.rs   Fq2: ops, square, inverse, sqrt, conjugate, norm, mul_by_nonresidue (x xi)
src/g1.rs    G1Affine + G1Projective (Jacobian): dbl-2009-l, add-2007-bl, madd-2007-bl
src/g2.rs    G2Affine + G2Projective, a literal mirror over Fq2 with the real subgroup check
```

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

Regenerate all three with `cargo run -p kat-gen`, which prints each file's SHA-256; the
digests are pinned in `tests/kats.rs::FILES` and refreshed deliberately. CI regenerates
and diffs them.

## Tests
| File | What it pins |
| --- | --- |
| `constants_check.rs` | every constant re-derived, every load-bearing fact proven |
| `kats.rs` | the committed corpus, through one evaluator, plus the corruption sweep |
| `laws.rs` | associativity, commutativity, bilinearity of the scalar action, `batch_to_affine`, point *dis*equality one witness per conjunct, totality on every degenerate input |
| `wire.rs` | canonicity, round-trips, `from_hex`'s single spelling, serde, every rejection class at the API level |
| `differential.rs` | 1,500 live group operations and 2,000 live field vectors against ark-bn254 |

`curve` is a **std** crate (S05 Must-be-exact 8) and is deliberately absent from CI's
guest-target build line: the recursion guest defers all pairing work through the
accumulator and never performs curve arithmetic.
