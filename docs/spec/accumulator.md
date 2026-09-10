# The deferred-pairing accumulator

Frozen as of S09. `AccumulatorEntry`, `PairingSide` and the wire form below are
**frozen forever**: they ride a proof's public I/O, they are hash-bound there,
and a recursion chain concatenates lists produced by different versions of this
software. Changing any of it is a protocol-version change.

Implementation: `crates/pcs`. Depends on `docs/spec/mercury.md` for the
verification whose terms it carries, and on `docs/spec/transcript.md` for the
Poseidon2 sponge the digest uses.

---

## 1. What an accumulator is

A Mercury verification ends in exactly one pairing relation
(`docs/spec/mercury.md` §8.3):

```text
    e(A, [1]_2) = e(B, [x]_2)
```

and both `A` and `B` are small multi-scalar multiplications of G1 points the
verifier already holds — the statement's commitment, the eight proof points, and
`[1]_1` — against scalars it has just derived from the transcript.

**Deferring** the verification means running every field-side check and then
emitting those terms instead of computing the pairings. The terms are
`AccumulatorEntry` items. Nothing downstream combines them: a party that holds
two accumulators **concatenates** them, and only the final verifier spends the
result.

```rust
pub enum PairingSide { G2One, G2X }              // pairs against [1]_2 vs [x]_2
pub struct AccumulatorEntry { pub side: PairingSide, pub scalar: Fr, pub point: G1Affine }
```

A **deferred check** is one such relation. Its entries are one **group**, and
a group's boundaries travel with the list: on the wire as a count word (§3), and
in memory as the `checks: &[usize]` argument that `discharge` and
`accumulator_words` take beside the flat entry slice.

## 2. The twelve entries of one Mercury verification — frozen

Writing `t = |u|/2`, `b = 2^t`, and taking `alpha, gamma, z, delta, z', rho`
from `docs/spec/mercury.md` §5's schedule, `h(alpha)` and `D(z)` from its §7,
and the BDFG20 order `g, h, S, D` from its §6:

```text
    c_i     = delta^i * Z_{T \ S_i}(z')          i = 0..3, over g, h, S, D
    K       = sum_i c_i * r_i(z')
    Z_T(z') = (z' - z)(z' - 1/z)(z' - alpha)
```

| # | side | point | scalar |
| --- | --- | --- | --- |
| 0 | `G2One` | `cm` | `1` |
| 1 | `G2One` | `h` | `rho * c_1` |
| 2 | `G2One` | `q` | `-(z^b - alpha)` |
| 3 | `G2One` | `g` | `rho * c_0` |
| 4 | `G2One` | `s` | `rho * c_2` |
| 5 | `G2One` | `d` | `rho * c_3` |
| 6 | `G2One` | `pi_z` | `z` |
| 7 | `G2One` | `w` | `-rho * Z_T(z')` |
| 8 | `G2One` | `w_prime` | `rho * z'` |
| 9 | `G2One` | `[1]_1` | `-(g_z + rho * K)` |
| 10 | `G2X` | `pi_z` | `1` |
| 11 | `G2X` | `w_prime` | `rho` |

The point order is `cm`, then the eight proof points in the field order
`docs/spec/mercury.md` §8.1 froze, then `[1]_1`; the two `G2X` terms follow. The
ten `G2One` scalars sum to §8.2's `A1 + rho * A2` and the two `G2X` scalars to
`B1 + rho * B2`, so the accumulator says exactly what the verifier's own pairing
check says.

Entries 0, 2, 6 are check A's terms and carry no `rho`; entries 1, 3, 4, 5, 7, 8
and 11 are check B's and all carry it; entry 9 carries both checks' `[1]_1`
contributions, which is why it is one entry and not two. Entry 2's scalar is
zero exactly when `z^b = alpha`, which is legal — see `docs/spec/mercury.md`
§3.1 and the committed instance in `crates/pcs/tests/vectors/z_pow_b_alpha.txt`.

**`ENTRIES_PER_CHECK = 12`, for every instance and every batch width.** A
batched verification derives `cm*` before it reaches the verification core
(§11 of `docs/spec/mercury.md`), so entry 0 is `cm*` and `k` does not appear.

## 3. The wire form — frozen

An accumulator is a **flat array of canonical 32-byte little-endian `Fr`
words**. A replay reads `Fr`s and never decodes bytes.

```text
    group j:  [ count_j ]  entry  entry  ...        count_j entries
    entry:    [ side ] [ scalar ] [ x_lo ] [ x_hi ] [ y_lo ] [ y_hi ]
```

- `side` is `0` for `G2One` and `1` for `G2X`.
- `scalar` is the entry's `Fr`.
- the four limbs are the point in `docs/spec/mercury.md` §4's encoding: each
  `Fq` coordinate's canonical little-endian bytes split at byte 16, low half
  first, and the point at infinity written as four copies of
  `constants::G1_INFINITY_SENTINEL = 2^128`.

**An entry is six words, 192 bytes, always.** A group is `1 + 6 * count` words.
There is **no header and no total count**, so the byte concatenation of two
lists is itself a valid list, and so is the concatenation of their
`(entries, checks)` pairs. A `count` of `0` is legal and names an empty group.

Decoding rejects: a count word that is not a length; a count that overruns the
remaining words; a side word other than `0` or `1`; a limb at or above `2^128`
that is not the sentinel; a limb quadruple with *some* but not all lanes equal to
the sentinel; the all-zero quadruple; and any reassembled point that is
non-canonical, off the curve, or outside the order-`r` subgroup.

The all-zero quadruple is rejected rather than read as infinity. `crates/curve`'s
64-byte affine form does read all-zero bytes as infinity — that is unambiguous
there because `(0, 0)` is off the curve — but in *this* format infinity is the
sentinel, and admitting a second spelling would make the encoding non-injective
and the digest of §5 non-binding.

## 4. Validation — the one rule, stated once

**An accumulator entry's point is a claim, and `discharge` is what checks it.**

Nobody upstream does. Transcript and digest absorption bind the *claimed* limbs
(`docs/spec/mercury.md` §4), the native deferred verifier's on-curve checks
belong to the verification it ran rather than to the entries it emitted, an
entry built in memory has been through no decoder, and the in-VM replay does no
curve arithmetic at all. So `discharge` validates **every** entry's point — on
the curve, and in the order-`r` subgroup — before the digest, before the merge
challenge, and before any group operation. A single invalid point rejects the
whole discharge.

On G1 the subgroup check *is* the curve check, because BN254's G1 cofactor is 1
and `#E(Fq) = r`; both are called anyway so the call site reads like every other
one in the crate, and a reader should not go looking for a cofactor clearing that
does not exist. The point at infinity is on the curve and passes: a zero
polynomial commits to it, and it contributes nothing to either MSM.

Later stages cite this section rather than restating the rule.

## 5. The digest — the hash-binding rule, frozen once

```text
    digest = Poseidon2 sponge:  append_scalars(ACCUMULATOR_DIGEST, words)
                                sample()
```

over exactly the words of §3, in order, as **one** typed message. A proof that
carries an accumulator on its public I/O binds it with this value and no other.

The squeeze is a raw `sample`, **not** a `challenge_scalar`, for the reason
`sumcheck::witness_digest`'s is: `ACCUMULATOR_DIGEST` frames a scalar message,
and a challenge under the same tag would be one tag in two message kinds, which
`docs/spec/transcript.md` §8 forbids.

Because the words include each group's count word, the digest binds the
**grouping** as well as the entries. Two lists that hold the same entries in the
same order but split into different groups have different digests. A committed
test vector lives in `crates/pcs/tests/vectors/accumulator.txt`.

## 6. Discharge

```text
    words = the word array of section 3, from (entries, checks)
    digest = section 5
    nu     = fresh sponge:  append_scalar(ACCUMULATOR_DIGEST, digest)
                            challenge_scalar(ACCUMULATOR_MERGE)

    A = sum_j nu^j * ( sum over entries of group j with side = G2One of scalar * point )
    B = sum_j nu^j * ( sum over entries of group j with side = G2X   of scalar * point )

    accept iff  e(A, [1]_2) * e(-B, [x]_2) == 1
```

One MSM per side and one two-pairing check, whatever the list holds.

**The per-check weight is load-bearing.** Without it — every group at weight `1`
— the accepted statement is `sum_j (A_j - x B_j) = 0`, which two deferred checks
can satisfy with equal and opposite errors. That is not a negligible-probability
event; it is an identity a prover can arrange, and
`crates/pcs/tests/accumulator.rs::the_per_check_weight_separates_the_checks`
constructs it. With the weights, a list containing a false relation passes only
if `nu` is a root of a nonzero polynomial of degree `< m` in the `m` groups, so
the loss is `< m/|Fr|` per attempt.

`nu` is derived from the accumulator's own words because `discharge` takes no
transcript: it must be a deterministic function of what it is handed. An
adversary that grinds the list to move `nu` must recompute the affected proofs,
since group size, entry order and every scalar are functions of the verifier's
code and the proof, not free parameters; and the whole list is hash-bound
upstream by §5, so a list that reaches the final verifier is the list the
recursion committed to.

**An empty accumulator discharges successfully.** `A` and `B` are both the
identity and the pairing check is vacuously true — the honest answer for an empty
conjunction of relations. What stops a prover from truncating a list to nothing
is the §5 digest binding, not `discharge`, which has no way to know what it was
not given.

## 7. Where lists come from, and where they go

- `pcs::verify_deferred` and `pcs::batch_verify_deferred` are the **only**
  producers. They run every field-side check of `docs/spec/mercury.md` §8.4 —
  the instance shape, the point validation, the challenge draw and its degeneracy
  rule, both derived values, and the whole BDFG20 batch — and defer only the two
  group relations.
- `pcs::verify` and `pcs::batch_verify` reach the same core and spend the terms
  immediately, as one group at weight `1`. That is the same arithmetic
  `discharge` does on a single group, so the two paths cannot disagree, and
  `crates/pcs/tests/accumulator.rs` holds them to it over a corpus of honest and
  tampered proofs.
- **`ShardProof` and `BlockProof` carry no accumulator entries.** Base
  verification executes its pairings inside `pcs`. Entry lists exist only during
  recursion, where a guest verifying a base proof defers, and they are discharged
  once at the very end.

## 8. Open for the recursion stage

The in-VM replay binds claimed limbs and performs no curve math. One thing that
costs is **`cm*`**: `docs/spec/mercury.md` §11's preamble absorbs `cm*` into the
transcript at schedule step 2, so a batched verification cannot proceed without
its limbs, and deriving them is a `k`-point MSM. A native
`batch_verify_deferred` simply does it. A guest cannot, and has two options, both
expressible in the format above and neither chosen here:

1. take `cm*` as a hint and add a second deferred check enforcing
   `cm* - sum rho^i cm_i = O` — a group whose `G2X` side is empty; or
2. emit the `k` commitments as their own entries and change the preamble so the
   inner opening does not absorb `cm*`, which is a protocol-version change.

The count word of §3 exists so that a group of a size other than 12 is
representable when that stage arrives.
