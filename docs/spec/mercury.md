# Mercury

Every committed column is opened with Mercury (Eagen and Gabizon, ePrint 2025/385), finished by
the batched KZG opening of BDFG20 (Boneh, Drake, Fisch and Gabizon, ePrint 2020/081). This page
pins what the papers leave open, and adds a batch of `k` columns at one point and the deferred
form the recursion tree folds. `crates/pcs` is the prover, the curve side and the pairings;
`crates/pcs-verify`, `no_std`, is the verifier's field side, which the recursion guest links.

## 1. Parameters and the variable split

`n = 2^{2t}` evaluations with `1 ≤ t ≤ 27`, `b = 2^t = √n`, `s = 2t` variables; `u ∈ Fr^s` is the
opening point and `v` the claimed value. `pcs_verify::check_num_vars` refuses every other variable
count (`PcsError::UnsupportedNumVars`) and never pads, which is why every trace height is an even
power of two ([program.md](program.md) §7). The ceiling, `pcs_verify::MAX_NUM_VARS = 54`, is where
`Fr`'s 2-adicity of 28 runs out of the `2b`-th roots of unity §3.1 needs, and it keeps `2^{|u|}` in
range for a `u` the verifier is handed.

The evaluation table is read as coefficients, and variable `m` is bit `m` of an index
([primitives.md](primitives.md) §6). Write an index `i + j·b` with `i` the low `t` bits, as
Mercury §3.1 does; its evaluation is the coefficient of `X^{i+j·b}`. The point splits the same way:
**`u1`** is its first half, `u_0..u_{t−1}`, and pairs with `i`; **`u2`** is `u_t..u_{2t−1}` and
pairs with `j`.

```text
f(X) = Σ_{i<b} X^i·f_i(X^b),    f_i(X) = Σ_{j<b} f_{i+j·b}·X^j
f̂(u) = Σ_{i,j<b} eq(i, u1)·eq(j, u2)·f_{i+j·b}
```

`pcs::open` returns what `poly::MultilinearPoly::evaluate` gives at `u`, and a verifier handed the
two halves swapped rejects.

## 2. Commitment

`pcs::commit` returns `[f(x)]_1` for §1's `f(X)`, an MSM over the first `n` SRS powers: exactly the
KZG commitment of the evaluation table read as coefficients (`srs::kzg::kzg_commit`), with no second
scheme behind it. It refuses an SRS of fewer than `n` powers (`SrsTooSmall`). A column backed by
`U1`, `U8`, `U16` or `U32` (`poly::PolyBacking`) is widened to `u32` and committed through
`curve::msm::msm_small_u32`, never lifted to `Fr`; an `Fr` backing goes through `curve::msm::msm`.

The map from a table to its commitment is `Fr`-linear, which §5 uses, and a zero coefficient adds
nothing: a column extended by zero rows keeps its commitment. So the generic table's commitments
serve every height that holds the table ([lookup.md](lookup.md) §9), and `pcs::commit_stack`
commits a recursion stack without building it.

## 3. The opening protocol

### 3.1 The polynomials

| | definition | coefficients | sent as |
| --- | --- | --- | --- |
| `h` | `Σ_i eq(i, u1)·f_i(X)`; its `X^j` coefficient is `f̂(u1, j)` | `b` | `h` |
| `q`, `g` | `f = (X^b − α)·q + g`, so `g = Σ_i f_i(α)·X^i` | `n − b`, `b` | `q`, `g` |
| `S` | the symmetrized witness below | `b − 1` | `s` |
| `D` | `X^{b−1}·g(1/X)`: `g` reversed | `b` | `d` |
| `H` | `(f − (z^b − α)·q − g_z)/(X − z)` | `n − 1` | `pi_z` |
| `W`, `W′` | §3.3 | `b − 1` each | `w`, `w_prime` |

`P_u(X) = Σ_{i<b} eq(i, u)·X^i = Π_{m<t}(u_m·X^{2^m} + 1 − u_m)`, so `⟨P_u, g⟩ = ĝ(u)` for `g` of
fewer than `b` coefficients (Mercury §4.2). The prover uses its coefficients, `poly::eq_table(u)`;
the verifier evaluates the product in `O(t)`.

The fold (Mercury §5) divides every `f_i` by `X − α`, `b` Horner divisions advanced together in
one pass over the rows, with no transform. Then `ĝ(u1) = h(α)` and `ĥ(u2) = f̂(u) = v`, and one
`S` proves both inner products (Mercury §4.1), the left side's constant coefficient being
`2·(⟨g, P_u1⟩ + γ·⟨h, P_u2⟩)`:

```text
g(X)·P_u1(1/X) + g(1/X)·P_u1(X) + γ·(h(X)·P_u2(1/X) + h(1/X)·P_u2(X))
    = 2·(h(α) + γ·v) + X·S(X) + S(1/X)/X
```

`S` is coefficients `b..2b−2` of `X^{b−1}` times the left side, computed with four forward
transforms of size `2b` and one inverse; no transform in an opening is larger
(`crates/pcs/src/fft.rs`, over `constants::FR_TWO_ADIC_ROOT_OF_UNITY`).

### 3.2 The transcript schedule

`pcs::open` and `pcs_verify::scalars` run this Fiat–Shamir schedule step for step. A point or a
list of points is one message ([transcript.md](transcript.md) §4).

| # | | tag | message |
| --- | --- | --- | --- |
| 1 | absorb | `MERCURY_INSTANCE` | `n` |
| 2 | absorb | `COMMITMENT` | `cm`, as passed: `open` never recommits it |
| 3 | absorb | `EVALUATION_CLAIM` | `u_0..u_{s−1}`, then `v` |
| 4 | absorb | `PCS_OPENING` | `h` |
| 5 | squeeze | `MERCURY_ALPHA` | `α` |
| 6 | absorb | `PCS_OPENING` | `[q, g]` |
| 7 | squeeze | `MERCURY_GAMMA` | `γ` |
| 8 | absorb | `PCS_OPENING` | `[s, d]` |
| 9 | squeeze | `MERCURY_Z` | `z`, by §3.4's rule |
| 10 | absorb | `PCS_OPENING` | `g_z, g_{1/z}, h_z, h_{1/z}, s_z, s_{1/z}`, one message |
| 11 | absorb | `PCS_OPENING` | `pi_z`, before `δ` although the batch does not read it |
| 12 | squeeze | `BDFG_BATCH` | `δ` |
| 13 | absorb | `PCS_OPENING` | `w` |
| 14 | squeeze | `BDFG_POINT` | `z′` |
| 15 | absorb | `PCS_OPENING` | `w_prime` |
| 16 | squeeze | `PAIRING_MERGE` | `ρ`, after all eight points and six values |

The prover draws `ρ` too and discards it, so both sides leave the transcript in one state and an
opening composes inside a larger transcript, the shard transcript ([proof.md](proof.md) §4).

### 3.3 The BDFG20 batch

Mercury §6 step 4(e) leaves the batched KZG opening to BDFG20 §4. The point set is
`T = {z, 1/z, α}`, and the four polynomials are batched in this order, which fixes the power of
`δ` each carries (`pcs_verify::bdfg::items`, which both sides read):

| `i` | `f_i` | `S_i` | `Z_{T∖S_i}` | `r_i` interpolates |
| --- | --- | --- | --- | --- |
| 0 | `g` | `{z, 1/z}` | `X − α` | `g_z`, `g_{1/z}` |
| 1 | `h` | `{z, 1/z, α}` | `1` | `h_z`, `h_{1/z}`, `h_α` |
| 2 | `S` | `{z, 1/z}` | `X − α` | `s_z`, `s_{1/z}` |
| 3 | `D` | `{z}` | `(X − 1/z)(X − α)` | `D_z` |

```text
F(X) = Σ_i δ^i·Z_{T∖S_i}(X)·(f_i(X) − r_i(X))                          W  = [(F/Z_T)(x)]_1
L(X) = Σ_i δ^i·Z_{T∖S_i}(z′)·(f_i(X) − r_i(z′)) − Z_T(z′)·(F/Z_T)(X)    W′ = [(L/(X − z′))(x)]_1
```

Both divisions are exact for an honest prover, and `open` asserts it
(`pcs_verify::bdfg::{quotient, linearization}`).

### 3.4 Challenges and derived values

Mercury draws `z ∈ F*`; here `z` is drawn again under `MERCURY_Z` while it is zero
(`pcs_verify::challenge_z`). `T` needs three distinct points, so both sides refuse with
`PcsError::DegenerateChallenge` when `z² = 1`, `z = α` or `z·α = 1` (`pcs_verify::degenerate`):
probability about `2^−252`, and a loss of completeness only. The recursion tape draws `z` once and
asserts all four conditions (`verifier_core::tape::mercury_scalars`).

The verifier is not sent `h(α)` or `D(z)`: it derives them, as Mercury §6 step 4(c) does
(`pcs_verify::derive_h_alpha`), and the prover builds the batch around the same derived values.

```text
D_z = z^{b−1}·g_{1/z}
h_α = (g_z·P_u1(1/z) + g_{1/z}·P_u1(z) + γ·(h_z·P_u2(1/z) + h_{1/z}·P_u2(z) − 2v)
       − z·s_z − s_{1/z}/z) / 2
```

Opening `D` at `z` to `D_z` is the degree check on `g` (Mercury §4.3); opening `h` at `α` to `h_α`
is §3.1's identity at `z`.

## 4. The proof and the verifier's checks

`pcs::MercuryProof` is eight points and six values. Its field order is its byte order and its
transcript order, and `to_bytes` writes `pcs::PROOF_BYTES = 704` bytes for every `n` and `k`:

```text
h  q  g  s  d  pi_z  w  w_prime                 8 × 64 bytes, G1 uncompressed (primitives.md §3)
g_z  g_inv_z  h_z  h_inv_z  s_z  s_inv_z        6 × 32 bytes, canonical Fr (primitives.md §1)
```

`from_bytes` returns `None` unless every point decodes through `curve::G1Affine::from_bytes`
(canonical and on the curve; G1's cofactor is 1) and every value through `field::Fr::from_bytes`.

Two relations are checked, each written `e(A, [1]_2) = e(B, [x]_2)` so that both G2 arguments are
SRS constants: the fold identity at `z` (Mercury §6 step 4(f), its `z` term moved into G1) and the
BDFG20 batch (BDFG20 §4.1). They merge under `ρ` into one `curve::pairing::pairing_check` of two
pairs:

```text
A1 = cm − (z^b − α)·q − g_z·[1]_1 + z·pi_z                  B1 = pi_z
A2 = Σ_i c_i·cm_i − K·[1]_1 − Z_T(z′)·w + z′·w_prime        B2 = w_prime
     cm_i = g, h, s, d    c_i = δ^i·Z_{T∖S_i}(z′)    K = Σ_i c_i·r_i(z′)
     Z_T(z′) = (z′ − z)(z′ − 1/z)(z′ − α)
accept iff  e(A1 + ρ·A2, [1]_2)·e(−(B1 + ρ·B2), [x]_2) = 1
```

If either relation is false the merged one holds for at most one `ρ`, and `ρ` follows every proof
element. The verifier reads three SRS points, `srs::SrsVerifier`'s `[1]_1`, `[1]_2` and `[x]_2`,
and does no G2 arithmetic.

`pcs::verify` refuses, in order: a `u` whose length is not an instance's (§1), before anything is
absorbed (`UnsupportedNumVars`); a proof point or `cm` off the curve (`InvalidPoint`), checked
again because a proof built in memory has met no decoder; a degenerate `T`
(`DegenerateChallenge`); a failed pairing check (`VerificationFailed`), which does not say which
relation failed.

## 5. Batching `k` columns at one point

Not in the papers. `k` commitments to columns of one size, opened at one point `u`, are one
Mercury instance with one proof (`pcs::batch_open`, `pcs::batch_verify`); a shard proof's opening
is one such batch ([proof.md](proof.md) §5). Three steps precede §3.2's sixteen
(`pcs_verify::batch_preamble`):

| # | | tag | message |
| --- | --- | --- | --- |
| B1 | absorb | `COMMITMENT` | `cm_0..cm_{k−1}`, as passed, one message of `4k` limbs |
| B2 | absorb | `EVALUATION_CLAIM` | `u_0..u_{s−1}`, then `v_0..v_{k−1}` |
| B3 | squeeze | `MERCURY_BATCH` | `ρ` |

The opening then runs on `(cm*, u, v*)`, with `cm* = Σ_i ρ^i·cm_i` and `v* = Σ_i ρ^i·v_i`.

- `ρ` follows every commitment and every claimed value. Column `i` carries `ρ^i`, column 0
  carrying 1, so a reordered or shortened list is a different statement.
- The list is one message, so its length `4k` fixes `k`, and then `s` from B2's `s + k` scalars:
  the absorbed stream is injective.
- `ρ = 0` is not redrawn: it checks column 0 alone, and is one of the roots the bound below
  counts.
- A batch of one is a different transcript from a bare opening; their proofs do not interchange.

The batch is sound: by §2's linearity `cm*` commits to `f* = Σ_i ρ^i·f_i`, and evaluation at `u`
is linear, so `v* − f̂*(u) = Σ_i (v_i − f̂_i(u))·ρ^i`, a polynomial in `ρ` of degree at most
`k − 1` fixed before `ρ` is drawn. A false claim survives with probability at most `(k − 1)/|Fr|`.

The prover builds `f*` as one `Fr` column and opens it once; mixed sizes are refused
(`MixedColumnSizes`). The verifier refuses an empty list (`EmptyBatch`) or a value count that
differs (`BatchLengthMismatch`), checks every `cm_i` on the curve before summing, derives `cm*` by
a `k`-point MSM and runs §4 on it. `pcs::batch_open_stacked` opens recursion stacks at `u ‖ r`
([recursion.md](recursion.md) §1.3); `batch_open` is it at `r = []`, one column a stack.

## 6. Deferred verification and the accumulator

### 6.1 The twelve entries

Deferring a verification runs every check of §4 but the pairing and keeps the relation's terms:
twelve `pcs::AccumulatorEntry { side, scalar, point }`, `side` a `pcs::PairingSide`, `G2One` for
`[1]_2` or `G2X` for `[x]_2`. The points are `[cm, h, q, g, s, d, pi_z, w, w_prime, [1]_1]`, as
`pcs_verify::ENTRY_POINTS` indexes them, and the scalars are `pcs_verify::scalars`'s, in §4's
notation:

| # | side | point | scalar | # | side | point | scalar |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | `G2One` | `cm` | `1` | 6 | `G2One` | `pi_z` | `z` |
| 1 | `G2One` | `h` | `ρ·c_1` | 7 | `G2One` | `w` | `−ρ·Z_T(z′)` |
| 2 | `G2One` | `q` | `−(z^b − α)` | 8 | `G2One` | `w_prime` | `ρ·z′` |
| 3 | `G2One` | `g` | `ρ·c_0` | 9 | `G2One` | `[1]_1` | `−(g_z + ρ·K)` |
| 4 | `G2One` | `s` | `ρ·c_2` | 10 | `G2X` | `pi_z` | `1` |
| 5 | `G2One` | `d` | `ρ·c_3` | 11 | `G2X` | `w_prime` | `ρ` |

The `G2One` terms sum to `A1 + ρ·A2` and the `G2X` terms to `B1 + ρ·B2`; entry 9 carries both
relations' `[1]_1`, and entry 2 is zero exactly when `z^b = α`, which is legal. A batch derives
`cm*` first, so entry 0 is `cm*` and a check is `ENTRIES_PER_CHECK = 12` entries whatever `k`.
`pcs::verify` and `pcs::batch_verify` spend the entries at once; `pcs::verify_deferred` and
`pcs::batch_verify_deferred` return them.

### 6.2 What uses it

- Base verification pairs: `crates/verifier` runs `pcs::batch_verify` for each shard, and no
  `ShardProof` or `BlockProof` carries an entry.
- The recursion tree folds. A shard's tape computes the twelve scalars over field cells
  (`verifier_core::tape::mercury_scalars`), `cm*` being a hint; the node folds them with the batch
  check `cm* = Σ_i ρ^i·cm_i` ([recursion.md](recursion.md) §8.3), and one pairing check at the top
  discharges every shard's ([recursion.md](recursion.md) §9). Natively, `host::recursion` runs
  `pcs::batch_verify_deferred` on each shard for its `cm*`.
- Nothing else: `pcs::verify_deferred`, §6.3's word form, `pcs::accumulator_digest` and
  `pcs::discharge` are called only by `crates/pcs`'s tests and `tools/kat-gen`.

### 6.3 The word form and `discharge`

A list is grouped into deferred checks, `checks[j]` being group `j`'s entry count, and written as
canonical `Fr` words (`pcs::accumulator_words`, inverse `pcs::accumulator_from_words`):

```text
group:  count  entry_0 .. entry_{count−1}
entry:  side  scalar  x_lo  x_hi  y_lo  y_hi       side 0 = G2One, 1 = G2X; ENTRY_WORDS = 6
```

A word is 32 bytes, so an entry is 192, and the limbs are the point's transcript form
([transcript.md](transcript.md) §4). There is no header, so two lists concatenate into a list whose
checks keep their groups. Decoding refuses a count of `2^64` or more or one that overruns, a side
other than 0 or 1, a limb of `2^128` or more other than the sentinel, a partial sentinel, the
all-zero quadruple (infinity has one spelling), and a point that is not canonical or not on the
curve. The digest is the words as one `ACCUMULATOR_DIGEST` message in a fresh sponge, then a raw
`sample`; covering the count words, it binds the grouping.

```text
discharge(vsrs, entries, checks):
  every entry's point on the curve, before anything else
  ν = fresh sponge: absorb ACCUMULATOR_DIGEST [digest], challenge ACCUMULATOR_MERGE
  A = Σ_j ν^j·(group j's G2One terms)      B = Σ_j ν^j·(group j's G2X terms)
  accept iff e(A, [1]_2)·e(−B, [x]_2) = 1
```

An entry's point is a claim: absorption binds only its limbs, and an entry built in memory has met
no decoder. The weight keeps the checks apart: at weight 1, two checks with equal and opposite
errors pass together, and weighted, a false group passes only where `ν` is a root of a nonzero
polynomial of degree below the group count. `ν` is a function of the words because `discharge`
takes no transcript. An empty list discharges.

## 7. Cost and security

| | |
| --- | --- |
| prover, field | `O(n)`: a pass for `h`, the fold, `H`'s division; `S` in `O(b log b)` |
| prover, MSMs | `2n + 5b − 4` scalar multiplications: `q` `n − b`, `pi_z` `n − 1`, `h`, `g`, `d` `b` each, `s`, `w`, `w_prime` `b − 1` each. A commitment is one more MSM of `n` |
| batch of `k` | `k` multiply-adds a coefficient for `f*` and a `k`-point MSM for `cm*`, then one opening |
| verifier | `O(t)` field operations, MSMs of ten points and of two (and of `k`), one two-pair pairing check |
| measured | `n = 2^22`: commit 1.30 s, open 2.89 s. 16 columns of `2^20`: a batch opens in 1.01 s and verifies in 4.8 ms, 16 single openings take 9.79 s and 62 ms. 18-core Apple M5 Pro; `bench mercury`, `bench mercury-batch` |

Knowledge soundness holds in the algebraic group model under q-DLOG (Mercury §6, BDFG20 §4), with
Fiat–Shamir over the Poseidon2 transcript in the random-oracle model and an SRS whose `x` nobody
knows ([srs.md](srs.md) §3). The statistical terms are Schwartz–Zippel over `α`, `z` and `z′`, of
order a committed polynomial's degree over `|Fr|`, a few `1/|Fr|` for `γ`, `δ` and the merge `ρ`,
`(k − 1)/|Fr|` for a batch and the group count over `|Fr|` for `ν`: each is below `2^−220` for
every instance in use, and the level is BN254's ([architecture.md](../architecture.md) §4).
Nothing is hiding and nothing is blinded.

Mercury's SRS has exactly `n` powers; here one SRS serves every size, so a prover can commit to a
polynomial of degree `n` or more, and no degree bound is checked. None is needed: Mercury §6's
argument goes through with its Schwartz–Zippel terms over that degree, and the opening at `u` is
the multilinear extension of the polynomial's first `n` coefficients. A commitment binds that
truncation, which is linear, so §5's argument holds for it too.
