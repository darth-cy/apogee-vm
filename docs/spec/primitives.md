# Primitives: fields, curve, pairing, polynomials, sumcheck

BN254's scalar field `Fr`, its base field `Fq` and the tower to `Fq12`, the groups G1 and G2, the
optimal ate pairing, multi-scalar multiplication, multilinear polynomials and the zerocheck. The
byte encodings of field elements and points (§1–§3) and the polynomial index convention (§6) are
defined here.

- All of it is this repository's code: concrete types, no field trait, no `unsafe`, assembly or
  intrinsics. `field`, `poly` and `sumcheck` are `#![no_std]` and build for the guest target;
  `curve` is `std`, with rayon, and no guest links it.
- arkworks is a test oracle only, for `field`, `curve` and `poly`, live and through vectors
  `tools/kat-gen` generates; the tests of `field` and `curve` re-derive every arithmetic constant
  those crates read.
- Nothing is constant-time: reductions, exponentiations, point additions and scalar ladders branch
  on their operands. No proof is zero-knowledge, so no witness is secret; the one secret this code
  handles, a decider ceremony contributor's factor ([recursion.md](recursion.md) §9), goes through
  the same variable-time ladder (§3).

## 1. Fr

```text
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

`field::Fr` is the integers mod `p` (`constants::FR_MODULUS`), 254 bits; `p` is also the order of
G1 and G2, `r` in §3–§4. In memory an element is four little-endian 64-bit limbs of `x·R mod p`,
`R = 2^256 mod p`, always reduced below `p`, so equal limbs are equal values. Multiplication is
CIOS Montgomery over `u128` intermediates. `Fr::inverse` is `x^(p−2)`, `None` at 0;
`field::batch_inverse` is Montgomery's trick and leaves a 0 entry 0. `p − 1 = 2^28·c` with `c`
odd, and every FFT domain is a subgroup of the one `constants::FR_TWO_ADIC_ROOT_OF_UNITY`
generates.

| byte form | | used in |
| --- | --- | --- |
| wire | the value, not `x·R`, as 32 little-endian bytes: `Fr::to_bytes`. `Fr::from_bytes` is `None` for a value `≥ p` and never reduces; serde goes through both | every proof, key and artifact |
| source literal | `0x` and exactly 64 lowercase hex digits, big-endian: `Fr::from_hex`, `None` for any other spelling or a value `≥ p` | constants in `crates/constants` |
| memory | the four limbs: `Fr::to_memory_bytes`, `Fr::from_memory_bytes`, `None` at or above `p` | the `FR_ARITH` delegation's frame alone |

On the guest target (`cfg(target_arch = "riscv32")`) addition, Montgomery multiplication and
inversion call the `FR_ARITH` delegation through `guest_sdk::recursion::fr_arith`
([delegation.md](delegation.md) §10). Its circuit proves these three functions of the memory form
the frame carries ([delegation-circuits.md](delegation-circuits.md) §4), so a delegated result is
the software result bit for bit.

## 2. The Fq tower

```text
q    = 21888242871839275222246405745257275088696311157297823662689037894645226208583
Fq2  = Fq[u]/(u^2 + 1)
Fq6  = Fq2[v]/(v^3 − ξ)       ξ = 9 + u
Fq12 = Fq6[w]/(w^2 − v)
```

`curve::Fq` is the field of coordinates (`constants::FQ_MODULUS`). Its limb arithmetic is `Fr`'s,
copied literally over `q`'s constants, and so are its wire and source-literal forms. `Fq2` encodes
as `c0 ‖ c1`; nothing above it has a byte form.

Products are schoolbook and squarings above `Fq2` are products. A Frobenius map multiplies
coefficients by powers of `ξ` tabulated in `constants` (`FQ6_FROBENIUS_C1`, `FQ6_FROBENIUS_C2`,
`FQ12_FROBENIUS_C1`); `Fq12::conjugate` is the `q^6` one. Nothing in the tower or the pairing is
sparse, cyclotomic or precomputed: a pairing is only ever computed to verify something, and the
code is written to be read.

## 3. G1, G2 and their encodings

```text
G1 = E(Fq)                E:   y^2 = x^3 + 3        #E  = r             generator (1, 2)
G2 ⊂ E′(Fq2), order r     E′:  y^2 = x^3 + 3/ξ      #E′ = r·(2q − r)    generator EIP-197's
```

`G1Affine { x, y, infinity }` is a point and `G1Projective` its Jacobian form, `Z = 0` the
identity, under the EFD formulas `dbl-2009-l`, `add-2007-bl` and `madd-2007-bl`, with the
identity, `P = Q` and `P = −Q` branched on explicitly. Scalar multiplication is a fixed 4-bit
window. `G2Affine` and `G2Projective` are the same code over `Fq2`.

A point's wire form is uncompressed affine, and there is no compressed one:

```text
G1Affine    64 bytes    x ‖ y
G2Affine   128 bytes    x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1        x = x.c0 + x.c1·u
infinity                every byte zero
```

Each coordinate is an `Fq` in wire form; `(0, 0)` is on neither curve, so zero is unambiguous.
`G1Affine::from_bytes` and `G2Affine::from_bytes` return `None` unless the bytes are all zero, or
every coordinate is below `q`, the point satisfies its curve's equation and, in G2, whose cofactor
`2q − r` is not 1, `[r]P` is the identity — by the window ladder, with no endomorphism.

Nothing else validates: the affine structs' fields are public, and the group law, `msm` and the
pairing compute on whatever they are given. A point's transcript form is
[transcript.md](transcript.md) §4's; a `.ptau` file ([srs.md](srs.md) §2) and the contract
([recursion.md](recursion.md) §9) have encodings of their own.

## 4. The pairing

```text
e(P, Q) = f_{6x+2, Q}(P)^((q^12 − 1)/r)        x = 4965661367192848881
```

`curve::pairing::miller_loop(pairs)` is Algorithm 1 of Beuchat et al. (ePrint 2010/354) with
homogeneous projective line formulas: the 66-digit NAF of `6x + 2` (`constants::ATE_LOOP_NAF`),
then the two lines adding `ψ(Q)` and `−ψ(ψ(Q))`, `ψ` the untwist-Frobenius-twist map. For a `Q`
of order `r` no step adds a point to itself, to its negative or to the identity, so the line
formulas have no exceptional case.

`final_exponentiation` returns exactly `f^((q^12 − 1)/r)`: the easy part `(q^6 − 1)(q^2 + 1)`,
then the hard exponent `(q^4 − q^2 + 1)/r` as its base-`q` expansion `λ0 + λ1·q + λ2·q^2 + q^3`, by
three exponentiations (`constants::FINAL_EXP_LAMBDA_0` to `FINAL_EXP_LAMBDA_2`, the two negative
ones conjugated) and three Frobenius maps. The Fuentes-Castañeda hard part, which arkworks uses,
returns this value raised to `2x(6x^2 + 3x + 1)`: the two libraries agree on every pairing check
and on no pairing value but 1, and the test vectors are arkworks' Miller outputs raised to the
literal exponent.

`pairing_check(pairs)` is `Π e(P_i, Q_i) = 1` by one Miller loop, whose `Fq12` squarings the pairs
share, and one final exponentiation: the form of every pairing equation in the system. A pair
holding a point at infinity contributes 1 and is skipped; an empty product is 1.

## 5. MSM

`curve::msm::msm(bases, scalars)` is `Σ scalars_i·bases_i` in G1 by windowed Pippenger, and
`msm_small_u32` the same sum over `u32` scalars, recoded from 32 bits instead of 254. Neither
looks at a scalar's size: the caller chooses, and `pcs::commit` chooses by a column's backing
(§6). G2 has no MSM here; `crates/groth16` carries its own.

- **Width.** `w = 3` below 32 points, otherwise `⌊0.69·⌈log2 n⌉⌋ + 2`: arkworks' rule.
- **Digits.** A scalar is recoded into signed digits in `[−2^(w−1), 2^(w−1)]`, one a window, over
  `⌈(bits + 1)/w⌉` windows; the sign costs a negated base and halves the buckets to `2^(w−1)`. At
  `2^20` points `w = 15`: 17 windows for an `Fr`, 3 for a `u32`.
- **Parallelism.** Each (window, chunk of the input) is a rayon task that adds bases into buckets
  by mixed addition and reduces them by a running sum; the tasks' sums are combined serially, `w`
  doublings a window. Group sums are exact, so the point does not depend on the thread count.

## 6. Multilinear polynomials

`poly::MultilinearPoly` is a table of `2^n` evaluations over `{0,1}^n`, the type of every column.

**Index convention.** Variable `j` is bit `j` of the index: the evaluation at
`y = (y_0, …, y_{n−1})` is entry `Σ_j y_j·2^j`. `bind(r)` fixes variable 0, the low bit,

```text
f′(i) = f(2i) + r·(f(2i + 1) − f(2i))
```

and the old variable 1 becomes variable 0. So binding `r_0, r_1, …` in order leaves
`evaluate(&[r_0, r_1, …])`, whose `point[j]` is variable `j`. Sumcheck round `i` binds variable
`i` (§7), so a claim's point lists its challenges in variable order, the order `evaluate` and a
Mercury opening ([mercury.md](mercury.md) §1) take.

**Backing.** `PolyBacking` holds the table as a bitset (`U1`), `u8`, `u16`, `u32` or `Fr`. A trace
column is filled and committed at its integer width (§5). `get` and `evaluate` embed an entry in
`Fr` as they read it and leave the table alone; the first `bind` folds the integer table straight
into an `Fr` table of half the length, and the backing is `Fr` from then on.

**`eq`.** `eq_table(r)` tabulates `eq(r, ·)` over the cube in the same index order; `eq_eval(r, y)`
is its closed form, for any `r` and `y`.

`new`, `get`, `bind`, `evaluate` and `eq_eval` panic on a table, index or point of the wrong size
rather than return an error.

## 7. The sumcheck

`crates/sumcheck` proves that a gate vanishes on the cube. A `sumcheck::Gate` is a sum of
`GateTerm`s `coef·x_a·x_b`, the second factor optional, over input columns of `n` variables:
degree at most 2 in each variable, by construction.

`G(y) = 0` on all of `{0,1}^n` is proved as the sumcheck `0 = Σ_y eq(r, y)·G(y)` at a random `r`.
`eq·G` has degree at most 3 in each variable, so a round polynomial is a cubic and a round message
its four coefficients `[c0, c1, c2, c3]`, ascending — four whatever the gate, so a proof's shape
depends on `n` and the number of inputs alone.

`prove_zerocheck` and `verify_zerocheck` run one schedule, under the tags of
[transcript.md](transcript.md) §5:

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
column: the caller owes an opening of each at `ρ`, as it owes step 1. The step 1 its callers use
is `witness_digest`, a hash and not a commitment: a sponge of its own absorbs `[column count, n]`
and each column's cells under `WITNESS_DIGEST`, and its raw squeeze enters the transcript under
the same tag.

**What uses it.** No proof in the system is this zerocheck, and no circuit is made of its `Gate`
([gkr.md](gkr.md) §3). The proving stack takes one type from the crate,
`SumcheckProof { rounds: Vec<[Fr; 4]>, final_evals }`, as each layer of a `gkr_verify::GkrProof`.
The GKR layer sumcheck ([gkr.md](gkr.md) §5) repeats step 3's rounds and checks under the same two
tags, from a batched claim instead of 0 and to a final check of its own, in `gkr::prove_sumcheck`
and `gkr_verify::verify_sumcheck`. `prove_zerocheck` and `verify_zerocheck` are called only by
tests and `tools/bench`.
