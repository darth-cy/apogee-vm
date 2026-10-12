# Primitives: the field, polynomials, sumcheck

BN254's scalar field `Fr`, multilinear polynomials and the zerocheck. The byte encoding of a field
element (§1) and the polynomial index convention (§2) are defined here.

- All of it is this repository's code: concrete types, no field trait, no `unsafe`, assembly or
  intrinsics. `field`, `poly` and `sumcheck` are `#![no_std]` and build for the guest target.
- arkworks is a test oracle only, for `field` and `poly`, live and through vectors `tools/kat-gen`
  generates; the tests of `field` re-derive every arithmetic constant the crate reads.
- Nothing is constant-time: reductions and exponentiations branch on their operands. No proof is
  zero-knowledge, so no witness is secret.

## 1. Fr

```text
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

`field::Fr` is the integers mod `p` (`constants::FR_MODULUS`), 254 bits. In memory an element is
four little-endian 64-bit limbs of `x·R mod p`, `R = 2^256 mod p`, always reduced below `p`, so
equal limbs are equal values. Multiplication is CIOS Montgomery over `u128` intermediates.
`Fr::inverse` is `x^(p−2)`, `None` at 0; `field::batch_inverse` is Montgomery's trick and leaves a 0
entry 0.

| byte form | | used in |
| --- | --- | --- |
| wire | the value, not `x·R`, as 32 little-endian bytes: `Fr::to_bytes`. `Fr::from_bytes` is `None` for a value `≥ p` and never reduces; serde goes through both | every proof, key and artifact |
| source literal | `0x` and exactly 64 lowercase hex digits, big-endian: `Fr::from_hex`, `None` for any other spelling or a value `≥ p` | constants in `crates/constants` |

The field stays BN254's scalar field until a later stage moves it
([architecture.md](../architecture.md) §0).

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

**Backing.** `PolyBacking` holds the table as a bitset (`U1`), `u8`, `u16`, `u32` or `Fr`. A trace
column is filled at its integer width. `get` and `evaluate` embed an entry in
`Fr` as they read it and leave the table alone; the first `bind` folds the integer table straight
into an `Fr` table of half the length, and the backing is `Fr` from then on.

**`eq`.** `eq_table(r)` tabulates `eq(r, ·)` over the cube in the same index order; `eq_eval(r, y)`
is its closed form, for any `r` and `y`.

`new`, `get`, `bind`, `evaluate` and `eq_eval` panic on a table, index or point of the wrong size
rather than return an error.

## 3. The sumcheck

`crates/sumcheck` proves that a gate vanishes on the cube. A `sumcheck::Gate` is a sum of
`GateTerm`s `coef·x_a·x_b`, the second factor optional, over input columns of `n` variables:
degree at most 2 in each variable, by construction.

`G(y) = 0` on all of `{0,1}^n` is proved as the sumcheck `0 = Σ_y eq(r, y)·G(y)` at a random `r`.
`eq·G` has degree at most 3 in each variable, so a round polynomial is a cubic and a round message
its four coefficients `[c0, c1, c2, c3]`, ascending — four whatever the gate, so a proof's shape
depends on `n` and the number of inputs alone.

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
each column's cells under `WITNESS_DIGEST`, and its raw squeeze enters the transcript under the
same tag.

**What uses it.** No proof in the system is this zerocheck, and no circuit is made of its `Gate`
([gkr.md](gkr.md) §3). The proving stack takes one type from the crate,
`SumcheckProof { rounds: Vec<[Fr; 4]>, final_evals }`, as each layer of a `gkr_verify::GkrProof`.
The GKR layer sumcheck ([gkr.md](gkr.md) §5) repeats step 3's rounds and checks under the same two
tags, from a batched claim instead of 0 and to a final check of its own, in `gkr::prove_sumcheck`
and `gkr_verify::verify_sumcheck`. `prove_zerocheck` and `verify_zerocheck` are called only by
tests and `tools/bench`.
