# Primitives: the field, polynomials, sumcheck

The A64-C5 field and its quadratic extension, multilinear polynomials and the zerocheck. The byte
encoding of a field element (§1) and the polynomial index convention (§2) are defined here.

- All of it is this repository's code: concrete types, no field trait, no `unsafe`, assembly or
  intrinsics. `field`, `poly` and `sumcheck` are `#![no_std]` and build for the guest
  target.
- The field is tested against Rust's own `u128` arithmetic; `poly` against arkworks over the same
  two fields, live and through vectors `tools/kat-gen` generates. arkworks is a test oracle only.
- Nothing is constant-time: reductions branch on their operands, and an inverse takes as many
  Euclidean steps as its operand needs. No proof is zero-knowledge, so no witness is secret.

## 1. The field and its extension

```text
p = 2^64 − 59 = 0xFFFFFFFFFFFFFFC5 = 18446744073709551557,   the A64-C5 prime
p − 1 = 2^2 · 11 · 137 · 547 · 5594472617641
```

Two types, never mixed implicitly:

- **`Fp`**, the integers mod `p`, the **base field**: every committed column, every gate literal,
  every statement scalar and every transcript lane. An element is held as its canonical
  representative below `p`, so equal values are equal words. `from_u64` reduces the 59 words at
  and above `p`; since `2^64 ≡ 59`, `from_u128` reduces any `x < 2^128`, a product or a lane of a
  linear layer, by folding its high word down twice, which leaves less than `2^64 + 3481 < 2p`, and
  subtracting `p` at most once. `Fp::inverse` is the extended Euclidean algorithm on `(p, x)`,
  `None` at 0.
- **`Fp2`**, `F_p[x]/(x^2 − 2)`, the **challenge field**: every transcript challenge and every
  value a challenge reaches — the GKR layers above the base, every claim, round and output, the
  memory roots. `p ≡ 5 (mod 8)` makes 2 a non-square, so `x^2 − 2` is irreducible and this is a
  field of `p^2 ≈ 2^128` elements. An element `c0 + c1·x` multiplies as
  `(a0·b0 + 2·a1·b1) + (a0·b1 + a1·b0)·x`, each coordinate's products summed in 128 bits, a carry
  folding back as `2^128 ≡ 3481`, and reduced once; `Fp2Sum` adds many products the same way,
  counting the carries, and reduces once when read. `Fp2::inverse` is
  `(c0 − c1·x)/(c0^2 − 2·c1^2)`, the norm lying in `Fp`. `From<Fp>` is the embedding, and `Fp2`
  with an `Fp` on either side is the embedding's arithmetic in two base products where a full
  product takes four.

| byte form | | used in |
| --- | --- | --- |
| `Fp` | the canonical value as 8 little-endian bytes: `Fp::to_bytes`. `Fp::from_bytes` is `None` for a value `≥ p` and never reduces; serde goes through both | artifacts, statements, keys |
| `Fp2` | `c0` then `c1`, each as `Fp`'s 8 bytes: 16 bytes, `Fp2::to_bytes` and `Fp2::from_bytes` | proofs, statements |

`crates/field`'s `tests/arithmetic.rs` holds `+`, `−`, `×`, negation, inversion and both
reductions to Rust's own `u128` remainder, `F_{p^2}`'s product to the schoolbook rule mod `p`, and
2 to a non-square by Euler's criterion. The transcript's permutation is over `Fp`
([transcript.md](transcript.md) §1).

## 2. Multilinear polynomials

`poly::MultilinearPoly` is a table of `2^n` evaluations over `{0,1}^n`, the type of every column.

**Index convention.** Variable `j` is bit `j` of the index: the evaluation at
`y = (y_0, …, y_{n−1})` is entry `Σ_j y_j·2^j`. `bind(r)` fixes variable 0, the low bit,

```text
f′(i) = f(2i) + r·(f(2i + 1) − f(2i))
```

and the old variable 1 becomes variable 0. So binding `r_0, r_1, …` in order leaves
`evaluate(&[r_0, r_1, …])`, whose `point[j]` is variable `j`. Sumcheck round `i` binds variable
`i` (§3), so a claim's point lists its challenges in variable order, the order `evaluate` takes.

**Backing.** `PolyBacking` holds a **base** table as a bitset (`U1`), `u8`, `u16`, `u32` or `Fp`,
and a bound or derived one as `Fp2`. A trace column is filled at its integer width, or as `Fp` where
none holds it. `get` and `evaluate` embed an entry in `Fp2` as they read it and leave the table
alone; `get_base` reads a base table's entry as `Fp` and panics on an `Fp2` one. The first `bind`,
at a challenge in `Fp2`, folds the base table straight into an `Fp2` table of half the length, each
`r·(f(2i + 1) − f(2i))` a product by a base difference, and the backing is `Fp2` from then on.

**`eq`.** `eq_table(r)` tabulates `eq(r, ·)` over the cube in the same index order; `eq_eval(r, y)`
is its closed form, for any `r` and `y`.

`new`, `get`, `bind`, `evaluate` and `eq_eval` panic on a table, index or point of the wrong size
rather than return an error.

## 3. The sumcheck

`crates/sumcheck` proves that a gate vanishes on the cube. A `sumcheck::Gate` is a sum of
`GateTerm`s `coef·x_a·x_b`, the second factor optional, over input columns of `n` variables:
degree at most 2 in each variable, by construction.

`G(y) = 0` on all of `{0,1}^n` is proved as the sumcheck `0 = Σ_y eq(r, y)·G(y)` at a random
`r ∈ Fp2^n`. `eq·G` has degree at most 3 in each variable, so a round polynomial is a cubic and a
round message its four `Fp2` coefficients `[c0, c1, c2, c3]`, ascending — four whatever the gate,
so a proof's shape depends on `n` and the number of inputs alone. A coefficient `coef` is a base
literal; the rounds, the challenges and `final_evals` are `Fp2`.

`prove_zerocheck` and `verify_zerocheck` run one schedule, under the tags of
[transcript.md](transcript.md) §4:

```text
1   the caller binds the columns to the transcript
2   r_0 … r_{n−1}                                      n × SUMCHECK_CHALLENGE
3   for i in 0..n:   g_i, one message of four          SUMCHECK_ROUND
                     ρ_i, binding variable i           SUMCHECK_CHALLENGE
4   final_evals: each input column at ρ, one message   SUMCHECK_FINAL_EVALS
```

The verifier checks the proof's shape, then `g_0(0) + g_0(1) = 0` and
`g_i(0) + g_i(1) = g_{i−1}(ρ_{i−1})`, each before absorbing `g_i`, and, with `final_evals`
absorbed, `g_{n−1}(ρ_{n−1}) = eq(r, ρ)·G(final_evals)`. It returns
`SumcheckClaim { point: ρ, final_evals }` or a `SumcheckError`, and does not panic on a proof.

That last check is one equation over all the claimed evaluations and ties none of them to its
column: the caller owes a binding of each at `ρ`, as it owes step 1. The step 1 its callers use is
`witness_digest`, a hash and not a commitment: a sponge of its own absorbs `[column count, n]` and
each column's base cells under `WITNESS_DIGEST`, ends in `digest()`, and its 8 lanes enter the
transcript under the same tag.

**What uses it.** No proof in the system is this zerocheck, and no circuit is made of its `Gate`
([gkr.md](gkr.md) §3). The proving stack takes one type from the crate,
`SumcheckProof { rounds: Vec<[Fp2; 4]>, final_evals }`, as each layer of a `gkr_verify::GkrProof`.
The GKR layer sumcheck ([gkr.md](gkr.md) §5) repeats step 3's rounds and checks under the same two
tags, from a batched claim instead of 0 and to a final check of its own, in `gkr::prove_sumcheck`
and `gkr_verify::verify_sumcheck`. `prove_zerocheck` and `verify_zerocheck` are called only by
tests and `tools/bench`.
