# Mercury: the multilinear polynomial commitment scheme

Frozen as of S08 for the single-polynomial case. Changing anything here is a
protocol-version change.

Normative sources: **Mercury**, Eagen and Gabizon, ePrint 2025/385, whose §6 is
the protocol; and **BDFG20**, Boneh, Drake, Fisch and Gabizon, ePrint 2020/081,
whose §4 (in the "cleaned up" form of §4.1) is the batched-KZG finish. Both are
in `docs/publication/`. Where this document pins something those papers leave
implicit — the variable order, the transcript schedule, the BDFG20 challenge
positions, the `z != 0` rule, the point encoding — **this document is the
authority**, and §6 in particular is normative for S09 and the recursion
stages.

Implementation: `crates/pcs`. Depends on `docs/spec/transcript.md` for the
duplex and its typed framing, and on `docs/spec/srs.md` for the SRS and the
underlying KZG.

---

## 1. Parameters and notation

| Symbol | Meaning |
| --- | --- |
| `n = 2^(2t)` | the number of evaluations; `t >= 1` |
| `b = 2^t` | `sqrt(n)`; every polynomial but `f`, `q` and `H` has `O(b)` coefficients |
| `s = 2t` | the number of variables |
| `f` | the multilinear being opened, as its `n` evaluations over `{0,1}^s` |
| `u = (u1, u2)` | the opening point, `u1, u2` in `Fr^t` |
| `v` | the claimed value `fhat(u)` |

`n` must be an **even** power of two, at least `2^2` and at most `2^54`. An odd
variable count is rejected, never padded; `n = 1` is rejected too, because
`b = 1` leaves `S` and the degree check with no room to exist. The supported
heights include the master prompt's trace-height menu
`{2^16, 2^18, 2^20, 2^22}`.

The upper bound is `2t <= 2 * (FR_TWO_ADICITY - 1) = 54`, from the `2b`-th root
of unity §3.2 needs, and it is checked on all three entry points rather than
assumed. It is far above any instance that can exist — no SRS this repository
reads holds more than `2^30` powers — but a verifier is handed `u` by its
caller, and `1 << u.len()` is a shift that must not be allowed to run off the
end of a machine word: with `overflow-checks` on that is a panic out of a
verifier, and with them off it is a silently wrong `n`. Rejecting the shape is
one comparison; not rejecting it is two behaviours.

A univariate polynomial is a dense coefficient vector, little-endian in the
degree: `c[i]` multiplies `X^i`. `F_<d[X]` is the set of polynomials with fewer
than `d` coefficients.

## 2. The variable-order convention — frozen

**This is the integration bug this specification exists to prevent.**

`f`'s evaluation table is read directly as a coefficient vector: the evaluation
at index `k` is the coefficient of `X^k`. Under `crates/poly`'s frozen index
convention, variable `j` is bit `j` of the index, so the evaluation at
`y = (y_0, ..., y_(s-1))` sits at `index = sum_j y_j 2^j`.

Split the index as `k = i + j*b` with `0 <= i, j < b`. Then:

- **`i` is the low `t` bits** of the index — the *least* significant digit, as
  Mercury §3.1 states — and `j` the high `t`.
- **`u1` is the FIRST `t` coordinates** of `u`, that is `u_0 .. u_(t-1)`: the
  variables that pair with `i`.
- **`u2` is the LAST `t` coordinates**, `u_t .. u_(s-1)`: the variables that
  pair with `j`.

Writing `f_{i,j}` for the evaluation at `i + j*b` and `f_i(X)` for the
polynomial with coefficients `(f_{i,0}, ..., f_{i,b-1})`,

```text
    f(X) = sum_{i<b} X^i f_i(X^b) = sum_{i<b} sum_{j<b} f_{i,j} X^(i + j*b)
```

and `eq((w1,w2), (u1,u2)) = eq(w1,u1) eq(w2,u2)` splits the same way.

A commitment is therefore **exactly** the univariate KZG commitment of the
evaluation table taken as coefficients: `com(f) = [f(x)]_1`. There is no
separate Mercury commitment scheme.

The consequence a caller must not get wrong: `open` returns the same value
`poly::MultilinearPoly::evaluate(u)` does, and a verifier handed `u1` and `u2`
the other way round rejects.

## 3. Notation for the protocol's polynomials

| Name | Definition | Coefficients | Sent as |
| --- | --- | --- | --- |
| `h` | `sum_{i<b} eq(i, u1) f_i(X)` | `b` | `h = [h(x)]_1` |
| `q`, `g` | `f(X) = (X^b - alpha) q(X) + g(X)`, `g` in `F_<b[X]` | `n - b`, `b` | `q`, `g` |
| `P_u` | `sum_{i<b} eq(i, u) X^i` | `b` | not sent |
| `S` | the symmetrized inner-product witness of §3.2 below | `b - 1` | `s = [S(x)]_1` |
| `D` | `X^(b-1) g(1/X)`, i.e. `g`'s coefficients reversed | `b` | `d = [D(x)]_1` |
| `H` | `(f(X) - (z^b - alpha) q(X) - g_z) / (X - z)` | `n - 1` | `pi_z` |
| `W`, `W'` | the two BDFG20 elements of §6 | `b - 1` each | `w`, `w_prime` |

`h`'s coefficient of `X^j` is `fhat(u1, j)` with `j` read little-endian in
binary, so `h` is the restriction of `fhat` to its last `t` variables.

`P_u` has two equal descriptions, and the protocol uses both: its coefficient
vector is `poly::eq_table(u)`, which the prover uses, and

```text
    P_u(X) = prod_{k<t} ( u_k X^(2^k) + 1 - u_k )
```

which the verifier evaluates in `O(t)` operations. `<P_u, g> = ghat(u)` for any
`g` in `F_<b[X]`.

### 3.1 The fold — Mercury §5

`g_i = f_i(alpha)`, and `q(X) = sum_{i<b} X^i q_i(X^b)` where
`f_i(X) = q_i(X)(X - alpha) + f_i(alpha)`. The `b` divisions are `O(n)` field
operations in total and need no transform of any size.

Two consequences the protocol rests on: `ghat(u1) = h(alpha)`, and
`hhat(u2) = fhat(u) = v`.

### 3.2 The symmetrized witness `S` — Mercury §4.1 and §4.2

`S` is the unique polynomial satisfying, as a rational identity,

```text
    g(X) P_u1(1/X) + g(1/X) P_u1(X)
  + gamma ( h(X) P_u2(1/X) + h(1/X) P_u2(X) )
  = 2( h(alpha) + gamma v ) + X S(X) + (1/X) S(1/X)
```

Both inner products are proven at once: the constant coefficient of the left
side is `2(<g,P_u1> + gamma <h,P_u2>) = 2(ghat(u1) + gamma hhat(u2))`, so a
`gamma` drawn after `g` and `h` are committed batches the two claims
`ghat(u1) = h(alpha)` and `hhat(u2) = v` at a soundness cost of `1/|Fr|`.

Multiplying by `X^(b-1)` makes it a polynomial identity of degree `2b - 2`:

```text
    T(X) = g(X) rev(P_u1)(X) + rev(g)(X) P_u1(X)
         + gamma ( h(X) rev(P_u2)(X) + rev(h)(X) P_u2(X) )
```

where `rev` reverses a length-`b` coefficient vector, and then
`T[b-1] = 2(h(alpha) + gamma v)`, `T[b+k] = S[k]` for `k < b - 1`, and `T` is
symmetric: `T[k] = T[2b-2-k]`.

`T` is computed with **four size-`2b` forward transforms and one inverse**, and
no transform anywhere in an opening exceeds `2b` — that is the ceiling, and it
is a property of the constructor rather than of a convention: the only way to
build a domain is `for_product(half)`, which builds size `2 * half`, and the
only call passes `b`. The reversal costs no second product, because for `A, B`
in `F_<b[X]`,

```text
    rev_(2b-1)( A * rev_b(B) ) = rev_b(A) * B
```

so with `R = g * rev(P_u1) + gamma * h * rev(P_u2)` — the four operands
transformed, one pointwise combination in the evaluation domain, one inverse
transform — `T = R + rev(R)`, and the symmetry is structural rather than
something to check for.

The transform is a radix-2 Cooley-Tukey over the `2b`-th root of unity in
`Fr`'s two-adic subgroup. `Fr`'s 2-adicity is 28
(`constants::FR_TWO_ADICITY`), and `constants::FR_TWO_ADIC_ROOT_OF_UNITY` is
`5^((p-1)/2^28)`, a generator of the order-`2^28` subgroup; the `2^k`-th root
is that constant squared `28 - k` times. This caps `n` at `2^54`, far above
anything an SRS this repository reads can commit to.

## 4. G1 transcript absorption — a transcript addendum, frozen

`docs/spec/transcript.md` deliberately has no G1 form; this is it, and it is an
**additive** extension of that document's typed layer, implemented in
`crates/pcs` as `append_g1` / `append_g1_list`.

An affine G1 point absorbs as **four `Fr` limbs**:

```text
    [ x_lo, x_hi, y_lo, y_hi ]
```

where a coordinate's canonical 32-byte little-endian encoding (`curve::Fq`'s
`to_bytes`) is split at byte 16, and each half is zero-extended to 32 bytes and
read as a canonical `Fr`. `x_lo` and `y_lo` are the bottom 128 bits; `x_hi` and
`y_hi` are the top 126. Every limb is below `2^128 < p`, so every limb is a
canonical `Fr` with no reduction.

The **point at infinity** absorbs four copies of
`constants::G1_INFINITY_SENTINEL`, which is `2^128`. That value cannot be any
real point's limb, because every limb is strictly below `2^128` — the
non-collision is a property of the split, not of the curve equation, so it
holds even for a claimed point that is not on the curve.

`append_g1(tr, tag, p)` is one typed message of 4 limbs.
`append_g1_list(tr, tag, ps)` is **one** typed message of `4k` limbs for `k`
points — not `k` messages. `append_g1(tr, tag, p)` is exactly
`append_g1_list(tr, tag, &[p])`. The typed framing's length field is what keeps
a `k`-point list apart from any other list and from `k` separate messages, so
S09's commitment-list absorption is `append_g1_list` and nothing else.

This binds the **claimed** limbs. On-curve and subgroup validation is a
separate obligation of the verifier; see §8.

## 5. The transcript schedule — frozen

Every challenge in an opening comes from `docs/spec/transcript.md`'s duplex,
under the tags below. `open` and `verify` run this schedule identically and
leave the transcript in the same state, so an opening composes inside a larger
transcript.

| # | Operation | Tag | Message |
| --- | --- | --- | --- |
| 1 | absorb | `MERCURY_INSTANCE` | 1 scalar: `n` |
| 2 | absorb | `COMMITMENT` | `append_g1` of `cm` |
| 3 | absorb | `EVALUATION_CLAIM` | `s + 1` scalars: `u_0 .. u_(s-1)`, then `v` |
| 4 | absorb | `PCS_OPENING` | `append_g1` of `h` |
| 5 | **squeeze** | `MERCURY_ALPHA` | `alpha` |
| 6 | absorb | `PCS_OPENING` | `append_g1_list` of `[q, g]` |
| 7 | **squeeze** | `MERCURY_GAMMA` | `gamma` |
| 8 | absorb | `PCS_OPENING` | `append_g1_list` of `[s, d]` |
| 9 | **squeeze** | `MERCURY_Z` | `z`, resampled per §7 |
| 10 | absorb | `PCS_OPENING` | 6 scalars: `g_z, g_1/z, h_z, h_1/z, s_z, s_1/z` |
| 11 | absorb | `PCS_OPENING` | `append_g1` of `pi_z` |
| 12 | **squeeze** | `BDFG_BATCH` | `delta` |
| 13 | absorb | `PCS_OPENING` | `append_g1` of `w` |
| 14 | **squeeze** | `BDFG_POINT` | `z_prime` |
| 15 | absorb | `PCS_OPENING` | `append_g1` of `w_prime` |
| 16 | **squeeze** | `PAIRING_MERGE` | `rho` |

Rules this schedule obeys, each load-bearing:

1. **`cm` is absorbed as passed.** `open` never recommits `f`; a commitment
   that does not match the witness produces a proof that fails.
2. **The six values are one message.** They are sent together, so they are
   framed together.
3. **Every proof element is absorbed before the challenge that could be chosen
   to defeat it.** In particular `pi_z` is absorbed at step 11, before `delta`,
   even though the BDFG20 batch does not read it.
4. **`rho` is squeezed last**, after all eight `G1` elements and all six values.
   Merging two pairing relations under a challenge drawn before either side was
   fixed would be unsound.
5. **The prover squeezes `rho` too**, and discards it, so that a transcript
   shared with later messages advances identically on both sides.

## 6. BDFG20 — pinned

Mercury §6 step 4(e) says only "a batched KZG opening proof as described in
Section 4 of [BDFG20]". This section is the pin; it is normative for S09 and
the recursion stages.

The point set is `T = {z, 1/z, alpha}`, three **distinct** points (§7). Four
polynomials are batched, **in this order**, which fixes the power of `delta`
each carries:

| `i` | polynomial | commitment | `S_i` | `Z_{T \ S_i}` | `r_i` |
| --- | --- | --- | --- | --- | --- |
| 0 | `g` | `g` | `{z, 1/z}` | `X - alpha` | interpolates `(z, g_z), (1/z, g_1/z)` |
| 1 | `h` | `h` | `{z, 1/z, alpha}` | `1` | interpolates `(z, h_z), (1/z, h_1/z), (alpha, h_alpha)` |
| 2 | `S` | `s` | `{z, 1/z}` | `X - alpha` | interpolates `(z, s_z), (1/z, s_1/z)` |
| 3 | `D` | `d` | `{z}` | `(X - 1/z)(X - alpha)` | the constant `D_z` |

`r_i` is the Lagrange interpolation through those points, of degree `< |S_i|`.
`h_alpha` and `D_z` are **derived, not sent** — see §7 — so both sides build
the same `r_i`.

**The linearization and the two proof elements.**

```text
    F(X)  = sum_i delta^i * Z_{T \ S_i}(X) * ( f_i(X) - r_i(X) )
    W     = [ (F / Z_T)(x) ]_1                                     (proof element)

    L(X)  = sum_i delta^i * Z_{T \ S_i}(z') * ( f_i(X) - r_i(z') )
            - Z_T(z') * (F / Z_T)(X)
    W'    = [ (L(x) / (x - z')) ]_1                                (proof element)
```

`Z_T` divides `F` exactly when every `r_i` interpolates its `f_i` over `S_i`,
because `Z_{T \ S_i} * Z_{S_i} = Z_T`; `L(z') = F(z') - Z_T(z') (F/Z_T)(z') = 0`
always. Both divisions are exact and a prover asserts it rather than assuming
it.

**The verifier's accumulation.**

```text
    Fpt = sum_i delta^i Z_{T \ S_i}(z') * cm_i
        - [ sum_i delta^i Z_{T \ S_i}(z') * r_i(z') ]_1
        - Z_T(z') * W
```

and the batch holds when `e(Fpt + z' W', [1]_2) = e(W', [x]_2)`.

Every polynomial in the batch has fewer than `b` coefficients, so `W` and `W'`
are `O(b)` work; the verifier spends 7 scalar multiplications here and 2 more
on §7's check A.

## 7. Challenges, degeneracy, and the derived values

**`z` is in `F*`.** `z` is squeezed under `MERCURY_Z`; **while it is zero it is
squeezed again under the same tag**, so `1/z` exists. The probability of even
one resample is about `2^-254`.

**Degeneracy.** `T = {z, 1/z, alpha}` must have three distinct members, or
`Z_T` has a repeated root and `r_1` is not determined. Both `open` and `verify`
reject — with `PcsError::DegenerateChallenge`, deterministically and on the
same input — when any of

```text
    z = 0     z^2 = 1     z = alpha     z * alpha = 1
```

holds. The total probability is about `2^-252`, and the four conditions are
checked rather than assumed because the alternative is a division by zero.
This is a **completeness** gap, not a soundness one: an honest prover fails to
produce a proof, and no dishonest prover gains anything. Closing it would mean
resampling `z` until the set is non-degenerate; that is a protocol change and
is deliberately not made here, because the stage prompt pins the rule as
resample-on-zero.

**The two derived values.** The verifier does not receive `h(alpha)` or `D(z)`;
it computes them, and the prover computes them the same way so that the batch
is built around identical values:

```text
    D_z = z^(b-1) * g_1/z

    h_alpha = ( g_z P_u1(1/z) + g_1/z P_u1(z)
              + gamma ( h_z P_u2(1/z) + h_1/z P_u2(z) - 2v )
              - z s_z - (1/z) s_1/z ) / 2
```

The first is the degree check of Mercury §4.3; the second is §3.2's identity
solved for `h(alpha)` at `X = z`. Both are then *enforced* by the BDFG20 batch,
which opens `h` at `alpha` to `h_alpha` and `D` at `z` to `D_z`.

## 8. The proof, the pairing checks, and the verifier's obligations

### 8.1 Shape and serialization — frozen

A proof is **8 `G1` points and 6 `Fr` values**, in this field order, with no
options and no data-dependent lengths:

```text
    h, q, g, s, d, pi_z, w, w_prime,
    g_z, g_inv_z, h_z, h_inv_z, s_z, s_inv_z
```

Serialized, that is the eight points in `crates/curve`'s uncompressed affine
form (64 bytes each, `x || y`, canonical little-endian per coordinate, all-zero
for infinity) followed by the six values in `Fr`'s canonical 32-byte
little-endian form: **704 bytes, for every `n`**. Decoding runs every point
through `G1Affine::from_bytes` and every value through `Fr::from_bytes`, so a
decoded proof is already known to hold canonical, on-curve, in-subgroup points.

### 8.2 The two relations, both in `e(A, [1]_2) = e(B, [x]_2)` form

The fold identity at `z` (Mercury §6 step 4(f)), with the `z` term moved into
G1 so both G2 arguments are SRS constants:

```text
    A1 = cm - (z^b - alpha) q - g_z [1]_1 + z * pi_z        B1 = pi_z
```

The BDFG20 batch (§6):

```text
    A2 = Fpt + z' * w_prime                                 B2 = w_prime
```

### 8.3 The merge

With `rho` from schedule step 16, the verifier accepts iff

```text
    e( A1 + rho A2, [1]_2 ) * e( -(B1 + rho B2), [x]_2 ) == 1
```

one `curve::pairing::pairing_check` with two pairs. If either relation fails,
the merged one holds for at most a single `rho`, and `rho` was drawn after
every proof element was absorbed. Computing the two relations separately is
equally acceptable provided `rho` is still squeezed where §5 puts it, because
S09 is handed this shape either way.

The verifier reads exactly three SRS points — `[1]_1`, `[1]_2`, `[x]_2`, that
is `srs::SrsVerifier` — and does no G2 arithmetic beyond passing those two.

### 8.4 Obligations

1. Reject any `u` whose length is not `2t` for `1 <= t <= 27`, before absorbing
   anything.
2. Check that every one of the eight proof points, **and the commitment the
   statement names**, is on the curve and in the order-`r` subgroup, before any
   of them is used. A proof built in memory has not been through
   `from_bytes`, so `verify` cannot assume the decoder ran.
3. Draw `z` by §7's rule and reject a degenerate challenge set.
4. Never accept on a failed pairing, and never distinguish which relation
   failed: the merge makes that unavailable, deliberately.

## 9. Cost

| Prover | |
| --- | --- |
| field operations | `O(n)`: one pass for `h`, one interleaved pass of `b` Horner divisions for `q` and `g`, one for `H`'s numerator and its division |
| transforms | four size-`2b` forward and one inverse; **nothing larger than `2b`** |
| scalar multiplications | `2n + O(b)`: `n - b` for `q`, `n - 1` for `pi_z`, and `b`, `b`, `b-1`, `b`, `b-1`, `b-1` for `h`, `g`, `s`, `d`, `w`, `w'` |
| commitment | one MSM of size `n`, which for a `U1`/`U8`/`U16`/`U32` column goes through `curve::msm::msm_small_u32` on the widened integers and is never lifted to `Fr` |

| Verifier | |
| --- | --- |
| field operations | `O(t) = O(log n)`: two `P_u` product formulas at two points each, `z^b`, and the `O(1)` interpolations |
| group operations | about 12 scalar multiplications in G1, and **2 pairings** |

## 10. Security

Knowledge soundness in the AGM under Q-DLOG, with a trusted powers-of-tau SRS
(`docs/spec/srs.md`). Mercury's own analysis bounds the Schwartz-Zippel term at
`6n/|Fr|` and each batching challenge at `1/|Fr|`; the pairing merge of §8.3
adds one more `1/|Fr|`. On BN254 that is roughly 100 to 103 bits of security,
and no claim beyond that is made anywhere.

**Not hiding, no zero knowledge.** Mercury is not a hiding commitment and this
implementation adds no blinding. Nothing in this protocol may be described as
zero-knowledge.

**SRS substitution is not detected.** `docs/spec/srs.md` §4: the SRS digest was
dropped, so nothing binds a proof to a particular SRS. That is a repository-wide
gap, not a Mercury one, and it is recorded here because a Mercury proof is the
first artifact that would carry the binding.
