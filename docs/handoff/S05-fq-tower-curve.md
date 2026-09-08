# S05 — Fq Tower + G1/G2 Arithmetic (Owned)

Branch `s05-curve`. Status: complete, all acceptance items met.

## Frozen public API, as built

```rust
// crates/curve/src/lib.rs   (std; re-exports the four modules below)
pub use fq::{batch_inverse, Fq};
pub use fq2::Fq2;
pub use g1::{G1Affine, G1Projective};
pub use g2::{G2Affine, G2Projective};
```

```rust
// crates/curve/src/fq.rs
pub struct Fq(/* [u64; 4], Montgomery, always reduced to [0, q); pub(crate) */);

impl Fq {
    pub const ZERO: Fq;
    pub const ONE: Fq;
    pub const MINUS_ONE: Fq;                        // q - 1; also the Fq2 nonresidue

    pub fn from_u64(x: u64) -> Fq;
    pub fn square(&self) -> Fq;
    pub fn pow(&self, exp: &[u64; 4]) -> Fq;        // exp is a plain 256-bit LE integer
    pub fn inverse(&self) -> Option<Fq>;            // None for zero
    pub fn sqrt(&self) -> Option<Fq>;               // one of the two roots; which is unspecified
    pub fn to_bytes(&self) -> [u8; 32];             // canonical LE
    pub fn from_bytes(b: &[u8; 32]) -> Option<Fq>;  // None if >= q; never reduces
    pub fn from_hex(s: &str) -> Option<Fq>;         // "0x" + 64 lowercase digits, big-endian
}

pub fn batch_inverse(xs: &mut [Fq]);                // zero entries stay zero

// Derives:  Clone, Copy, PartialEq, Eq
// Manual :  Debug (canonical big-endian hex), serde::Serialize, serde::Deserialize
// Operators: Add, Sub, Mul for all four owned/by-ref combinations;
//            AddAssign, SubAssign, MulAssign for Fq and &Fq; Neg for Fq and &Fq.
```

```rust
// crates/curve/src/fq2.rs   Fq2 = Fq[u]/(u^2 + 1)
pub struct Fq2 { pub c0: Fq, pub c1: Fq }

impl Fq2 {
    pub const ZERO: Fq2;
    pub const ONE: Fq2;

    pub fn new(c0: Fq, c1: Fq) -> Fq2;
    pub fn from_fq(c0: Fq) -> Fq2;
    pub fn square(&self) -> Fq2;
    pub fn conjugate(&self) -> Fq2;
    pub fn norm(&self) -> Fq;                       // c0^2 + c1^2; zero only for zero
    pub fn inverse(&self) -> Option<Fq2>;           // None for zero
    pub fn mul_by_nonresidue(&self) -> Fq2;         // self * xi, xi = 9 + u
    pub fn sqrt(&self) -> Option<Fq2>;              // one of the two roots
    pub fn to_bytes(&self) -> [u8; 64];             // c0 || c1
    pub fn from_bytes(b: &[u8; 64]) -> Option<Fq2>;
}

// Derives:  Clone, Copy, PartialEq, Eq
// Manual :  Debug; the same operator set as Fq (no serde).
```

```rust
// crates/curve/src/g1.rs   E/Fq: y^2 = x^3 + 3
pub struct G1Affine { pub x: Fq, pub y: Fq, pub infinity: bool }
pub struct G1Projective(/* Jacobian (X, Y, Z), private */);

impl G1Affine {
    pub const IDENTITY: G1Affine;                   // (0, 0, infinity)
    pub const GENERATOR: G1Affine;                  // (1, 2)
    pub fn is_on_curve(&self) -> bool;
    pub fn is_in_subgroup(&self) -> bool;           // cofactor 1: == is_on_curve
    pub fn to_bytes(&self) -> [u8; 64];             // x || y, canonical LE
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<G1Affine>;
}

impl G1Projective {
    pub const IDENTITY: G1Projective;               // (1 : 1 : 0)
    pub const GENERATOR: G1Projective;
    pub fn is_identity(&self) -> bool;
    pub fn add(&self, other: &G1Projective) -> G1Projective;      // add-2007-bl
    pub fn add_affine(&self, other: &G1Affine) -> G1Projective;   // madd-2007-bl
    pub fn double(&self) -> G1Projective;                         // dbl-2009-l
    pub fn mul(&self, scalar: &Fr) -> G1Projective;               // fixed 4-bit window
    pub fn to_affine(&self) -> G1Affine;
    pub fn batch_to_affine(points: &[G1Projective]) -> Vec<G1Affine>;  // one batch_inverse
}

impl From<G1Affine> for G1Projective;               // and the reverse
impl From<G1Projective> for G1Affine;
impl Neg for G1Affine / &G1Affine / G1Projective / &G1Projective;
impl PartialEq + Eq for G1Affine;                   // infinity-aware, hand-written
impl PartialEq + Eq for G1Projective;               // X1 Z2^2 == X2 Z1^2, Y1 Z2^3 == Y2 Z1^3
// Derives: Clone, Copy, Debug on both.
```

```rust
// crates/curve/src/g2.rs   E'/Fq2: y^2 = x^3 + 3/(9+u), the D-type sextic twist
pub struct G2Affine { pub x: Fq2, pub y: Fq2, pub infinity: bool }
pub struct G2Projective(/* Jacobian over Fq2, private */);

impl G2Affine {
    pub const IDENTITY: G2Affine;
    pub const GENERATOR: G2Affine;                  // EIP-197's G2
    pub fn is_on_curve(&self) -> bool;
    pub fn is_in_subgroup(&self) -> bool;           // real check: r * self == O
    pub fn to_bytes(&self) -> [u8; 128];            // x.c0 || x.c1 || y.c0 || y.c1
    pub fn from_bytes(bytes: &[u8; 128]) -> Option<G2Affine>;
    pub fn add(&self, other: &G2Affine) -> G2Affine;
    pub fn double(&self) -> G2Affine;
    pub fn mul(&self, scalar: &Fr) -> G2Affine;
}

impl G2Projective {                                  // the blessed addition of Must-be-exact 7
    pub const IDENTITY: G2Projective;
    pub const GENERATOR: G2Projective;
    pub fn is_identity(&self) -> bool;
    pub fn add(&self, other: &G2Projective) -> G2Projective;
    pub fn add_affine(&self, other: &G2Affine) -> G2Projective;
    pub fn double(&self) -> G2Projective;
    pub fn mul(&self, scalar: &Fr) -> G2Projective;
    pub fn to_affine(&self) -> G2Affine;
}
// The same From / Neg / PartialEq / Eq / Clone / Copy / Debug set as G1.
```

New in `crates/constants` (zero logic, as always): `FQ_MODULUS`,
`FQ_MODULUS_MINUS_TWO`, `FQ_MODULUS_PLUS_ONE_DIV_FOUR`, `FQ_R`, `FQ_R2`, `FQ_INV` as
`[u64; 4]`/`u64` limbs, and `FQ2_NONRESIDUE`, `FQ6_NONRESIDUE_C0`, `FQ6_NONRESIDUE_C1`,
`G1_B`, `G2_B_C0`, `G2_B_C1`, `G1_GENERATOR_X`, `G1_GENERATOR_Y`, `G2_GENERATOR_X_C0`,
`G2_GENERATOR_X_C1`, `G2_GENERATOR_Y_C0`, `G2_GENERATOR_Y_C1` as big-endian hex string
literals read by `Fq::from_hex`.

## The point wire format, at the byte level

Uncompressed affine. One spelling per point, and it is the only one.

```text
G1Affine, 64 bytes
  [ 0..32)  x   canonical little-endian Fq, value in [0, q)
  [32..64)  y   canonical little-endian Fq, value in [0, q)

G2Affine, 128 bytes
  [  0.. 32)  x.c0     x = x.c0 + x.c1 * u
  [ 32.. 64)  x.c1
  [ 64.. 96)  y.c0     y = y.c0 + y.c1 * u
  [ 96..128)  y.c1

point at infinity   every byte zero (64 zeros for G1, 128 for G2)
```

`to_bytes` emits zeros for infinity whatever the struct's coordinates hold. `from_bytes`
returns `Some` only for: the all-zero encoding, which decodes to `IDENTITY`; or a pair of
canonical coordinates that is on the curve **and** in the order-`r` subgroup. Everything
else is `None`, and nothing panics. The four rejection classes are

| Class | Example |
| --- | --- |
| non-canonical coordinate | any 32-byte half whose value is `>= q` |
| off-curve | a valid `x` with `y + 1`; or `x = 0` with any nonzero `y`, since `3` is a nonresidue mod `q` |
| on-curve, out of subgroup | a random G2 `x` with the cofactor `2q - r` un-cleared (G1 cannot have these) |
| a nonzero byte in an otherwise-zero encoding | not infinity, and every such coordinate pair is off the curve; fixture reason `nonzero_infinity_pattern` |

All-zero is unambiguous because `(0, 0)` is off both curves: `0 != 3` in G1 and
`0 != 3/(9+u)` in G2.

This byte form is **not** how a point enters a transcript. The master prompt's frozen
G1-absorption rule is four ~128-bit `Fr` limbs per point; that conversion belongs to the
stage that needs it and does not exist here.

## Choices this stage made

**The G2 subgroup check is the direct one.** `r * P == O` by the same fixed 4-bit window
ladder that `mul` uses, fed `r`'s canonical little-endian bytes. No endomorphism
shortcut, no cofactor-clearing trick. It is ~320 `Fq2` group operations per call, which
is why the ladder takes bytes rather than an `Fr`: `r` is `Fr`'s modulus and therefore
not an `Fr` value. Cross-checked against `is_in_correct_subgroup_assuming_on_curve` on
random subgroup points *and* on 16 un-cleared points, where the interesting answer lives.

**`Fq2::mul_by_nonresidue` multiplies by `xi = 9 + u`**, the Fq6 nonresidue the pairing
stage needs — not by the Fq2 nonresidue `-1`. S05's frozen listing puts the method on the
`Fq2` line and Must-be-exact 1 defines both constants, so this was ambiguous; it was
**raised with the user and resolved in favour of `xi`** before any code was written. The
reasons: it is the universal convention at this tower level (`bls12_381`'s
`Fp2::mul_by_nonresidue`, gnark's `E2.MulByNonResidue`), the `-1` reading would make the
method a second spelling of `Neg`, and it makes `xi`'s constant load-bearing and tested
now rather than dead until S06. Pinned against `ark_bn254::Fq6Config::NONRESIDUE`.

**Fq's Montgomery kernel is a literal duplicate of `field::Fr`'s**, with `FQ_*`
constants substituted and `sqrt` added. S05 says "reuse the approach, not the type"; the
master prompt's rule 1 forbids a generic field and its anti-goals prefer duplication to
abstraction. `q < 2^254` exactly as `p` is, so every bound the `Fr` kernel relies on
holds unchanged: two reduced operands sum inside four limbs, and the CIOS accumulator
stays below `2q < 2^255`. `g2.rs` is a literal mirror of `g1.rs` on the same reasoning.

**The Montgomery-form literals live privately in `crates/curve`.** A frozen
`pub const GENERATOR: G1Affine` needs Montgomery limbs at const-evaluation time and
`Fq::from_hex` is not a `const fn`; making it one would mean rewriting the CIOS kernel
into `while` loops with const-compatible assertions, which is more machinery than the
problem deserves. So the canonical values live in `constants` as big-endian hex — where
they diff against EIP-197 by eye, as Must-be-exact 1 requires — and their opaque
Montgomery counterparts sit beside the code that needs them, each pinned against the
canonical hex by `tests/constants_check.rs`. This follows S01's precedent for
`MINUS_ONE_MONTGOMERY`.

**`Fq2::sqrt` is the closed form, not Adj–Rodríguez-Henríquez.** Matching coefficients in
`(x0 + x1 u)^2 = a0 + a1 u` and eliminating `x1 = a1/(2 x0)` gives
`x0^2 = (a0 ± lambda)/2` with `lambda^2 = norm(a)`. Three facts make the branches
exhaustive and the `expect`s unreachable, and all three are proven in
`tests/constants_check.rs` rather than asserted in a comment:

1. `a` is a square in Fq2 iff `norm(a)` is a square in Fq — because `norm(a) = a^(1+q)`,
   so the two Euler criteria are the same statement. A `None` from `lambda` is therefore
   a genuine non-square, and the only `None` the function returns.
2. With `a1 != 0` the two candidates multiply to `-a1^2/4`, a nonresidue, so **exactly
   one** is a square and neither is zero — the second branch always succeeds when the
   first fails, and `1/(2 x0)` always exists.
3. With `a1 == 0` exactly one of `a0` and `-a0` is a square, so the root is either real or
   purely imaginary.

Facts 2 and 3 both rest on `-1` being a nonresidue mod `q`, which holds because
`q = 3 mod 4`. **Which** root comes back is unspecified in both fields and documented as
such; nothing in the protocol needs a normalised sign, because points are never
compressed and no decompression exists.

## Artifacts

| Path | What |
| --- | --- |
| `crates/curve/tests/vectors/fq_kats.txt` | 2,229 vectors: the Fq and Fq2 edge grids, 1,000 random vectors per field, `pow`, wire canonicity, `from_u64` |
| `crates/curve/tests/vectors/g1_kats.txt` | 1,022 vectors: generator bytes, 1,000 random `(P, Q, k)`, 6 addition edges, the mixed-add edge, 4 scalar edges, 10 rejections |
| `crates/curve/tests/vectors/g2_kats.txt` | 1,026 vectors: the same shapes, with 4 of the 14 rejections being on-curve points outside the subgroup |
| `tools/kat-gen/src/curve.rs` | the generator, `cargo run -p kat-gen` |

`cargo run -p kat-gen` regenerates all three (plus S01's and S03's) and prints each
file's SHA-256; the digests are pinned in `crates/curve/tests/kats.rs::FILES` and
refreshed deliberately. Verified reproducible: a second run produced byte-identical files.
CI regenerates and diffs them. The three files are 4.2 MB in total, which is the price of
Acceptance 1's and 3's "≥ 1000 random vectors" being committed rather than sampled live;
it is recorded here because it is the largest single cost this stage adds to the repo.

Fixture encoding: one token per value, in the wire form the crate emits — 64 hex
characters for an `Fq`, 128 for an `Fq2` or a G1 point, 256 for a G2 point. A value that
does not exist is the token `none`, so every line kind has a fixed arity. Point tokens are
therefore wire-format fixtures too, and the tests parse them coordinate-wise rather than
through `from_bytes`, because the off-curve and out-of-subgroup lines are precisely the
values `from_bytes` must refuse.

## Verification performed

41 new tests, 180 in the workspace, green in debug and release.

- **Every constant re-derived** (`tests/constants_check.rs`, 11 tests): the modulus
  against `ark_bn254::Fq::MODULUS` and against its decimal from both sides, `R` and `R^2`
  as `2^256`/`2^512 mod q`, `FQ_INV` by `q · FQ_INV ≡ -1 mod 2^64`, `(q+1)/4` by
  multiplying it back by 4, every private Montgomery literal against `Fq::from_hex` of its
  canonical constant, `b' = 3/(9+u)` derived rather than copied, both generators against
  `ark_bn254`'s, `xi` against `ark_bn254::Fq6Config::NONRESIDUE`, and the G2 cofactor
  against `2q - r` computed in plain limb arithmetic. Three of these caught real
  transcription errors while the stage was being built, including one in this handoff's
  own byte-order literal.
- **The load-bearing facts proven, not assumed**: `q = 3 mod 4`; `-1` and `3` are
  nonresidues mod `q`; `#E(Fq) = r` with cofactor exactly `[1]`; `2q - r` odd, so neither
  group has 2-torsion and no on-curve point has `y = 0`.
- **The committed corpus** (`tests/kats.rs`): 4,277 vectors through one evaluator, with an
  exact-count assertion per line kind so a truncated or half-regenerated file fails rather
  than passing with less coverage than it claims. Each random `(P, Q)` pair is also a
  `from_bytes` acceptance case, and each random vector additionally exercises what the
  fixtures cannot hand the formulas — a generic add with **both** operands at `Z != 1`,
  checked against `2(P+Q)`, and a mixed add against a `Z != 1` accumulator, checked against
  the generic path.
- **The edge lines are held to their own names.** `p_plus_neg_p` must really have
  `B == -A`, `k_one`'s scalar must really be one, `gen_plus_neg_gen`'s first point must
  really be the generator. A corpus that silently stopped covering a branch fails.
- **Algebraic laws** (`tests/laws.rs`): associativity and commutativity in both groups
  including through `O` and `P + (-P)`, `(a+b)P = aP + bP`, `a(bP) = (ab mod r)P`,
  `2P` three ways, `(r-1)P = -P`, and `batch_to_affine` against the per-point path over
  seven shapes — empty, a lone identity, identities at both ends and in the middle, and a
  200-point mixed run.
- **Totality on every degenerate input** (Must-be-exact 5): `O + O`, `O + P`, `P + O`,
  `P + (-P)`, `P + P` through the generic path, `2O`, `k * O`, and all of it again through
  `add_affine` and again with an accumulator whose `Z != 1`; plus an affine point with
  `infinity = true` and *stale coordinates*, which the public fields let a caller build —
  it compares equal to `IDENTITY`, serializes to zeros, and converts to the projective
  identity.
- **`Fq2::sqrt` beyond the fixtures**: 500 random squares must have a root, on both
  branches, plus the real-square and real-nonresidue cases of the `c1 == 0` branch, plus
  `sqrt(-1) = u`.
- **The wire rules at the API level** (`tests/wire.rs`): round-trips on 500 random `Fq`,
  200 random `Fq2`, 200 G1 and 50 G2 points; the `q - 1` / `q` boundary checked exactly;
  `from_hex`'s single accepted spelling against six near-misses; serde through postcard,
  including that `q` fails to deserialize rather than reducing; and the infinity pattern
  checked at **every one** of the 64 and 128 byte positions rather than sampled.
- **Live differential** (`tests/differential.rs`, Acceptance 8): 1,500 random group
  operations — add, mixed add, double, scalar mul, neg, over 200 G1 and 100 G2 rounds —
  plus `is_on_curve`, `is_in_subgroup`, and `batch_to_affine` against arkworks'
  `normalize_batch` with both sides built from the same scalars rather than from each
  other. Also 2,000 live field vectors: `Fq` sqrt matches arkworks *exactly* (both compute
  `a^((q+1)/4)`), while `Fq2` sqrt is compared up to sign because arkworks uses a
  different algorithm.
- **The subgroup check where it counts**: 16 on-curve, un-cleared G2 points where our
  verdict and arkworks' must agree, and both must say "no".
- **Negative control** (Acceptance 9): `corrupted_vectors_are_rejected` sweeps every field
  of every line kind — and of every named edge case and rejection reason — at three
  character positions, and asserts that at least one vector of that kind fails. The
  per-kind quantifier is deliberate: a single line can be mathematically insensitive to a
  corruption without the harness being at fault (the first `fq_pow` vector is `0^0 = 1`,
  and `1^0` is 1 too). Four `(kind, case, field)` triples are exempt and each is a
  genuinely free parameter — the byte string of a *canonical* `fq_bytes` line and the point
  of an `off_curve` or `not_in_subgroup` rejection are inputs to a predicate, so a
  corrupted one is a different, equally valid case of the same predicate. Renamed operators
  and truncated lines must also fail. Two findings came out of building this sweep and both
  are fixed: the addition and scalar edges now validate their own names, and a scalar edge's
  `P` must be a real point (without which the `k = r` line's point was unchecked, since
  `r * P = O` whatever `P` is).
- **Acceptance 9's manual run, performed once.** Flipping one hex digit in the first
  `g1_ops` line's `-P` field on disk fails `every_committed_vector_passes` at the SHA-256
  pin. Re-pinning the digest so the pin cannot be what catches it, the same flip fails the
  evaluator, which names the field: `g1_kats.txt:25 (g1_ops): G1 neg affine: expected
  ad7e…8820, got ad7e…8828`. Both files restored and re-diffed clean afterwards.
- **Mutation testing, on a scratch copy of the tree.** Ten realistic single-token bugs
  were introduced one at a time and the suite re-run. Nine are caught: dropping `dbl`'s
  `8C` term, using `Z1` where `Z2` belongs in `add`, flipping the sign of `madd`'s `r`,
  making G2's `is_in_subgroup` return `is_on_curve`, dropping the subgroup check from
  `from_bytes`, reversing the ladder's nibble order, negating the wrong component in
  `conjugate`, taking `Fq2::sqrt`'s branches in the wrong order, and multiplying by `u`
  instead of `9 + u`. One survives, and it is recorded below.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean with no `#[allow]` in
  library code (one in `tests/common/mod.rs`, on the shared helper module, as the other
  crates have).

## Adversarial review, and what it changed

The finished crate was put through a six-lens read-only audit — the Jacobian formulas
term by term against the explicit-formulas database, edge-case and totality analysis,
the field arithmetic and `sqrt`'s exhaustiveness proof, an independent recomputation of
every constant, spec compliance item by item, and a test-quality lens tasked with
finding checks that cannot fail. Four findings came out of it and all four are addressed.
Double adversarial verification confirmed one as a real defect and refuted the other
three — refuted on *severity*, not on fact: each verifier agreed the observation was
correct and argued it fell below a defect bar. All three were fixed regardless, because
they were false or misplaced documentation in a repository whose own rule 8 is "checkers,
not prose", and the fixes cost a handful of lines:

1. **A comment in `crates/constants` stated the Fq/Fr modulus relationship backwards** —
   "the two moduli differ only from the 128th bit up", when in fact `q` and `p` are
   identical in their top two limbs and differ only below. The sentence's own point
   ("easy to confuse by eye") only works the right way round. Fixed, and now
   machine-checked: `constants_check.rs` asserts `FQ_MODULUS[2..] == FR_MODULUS[2..]`
   and `FQ_MODULUS[..2] != FR_MODULUS[..2]`, so the claim cannot drift again.
2. **`crates/curve/CLAUDE.md` pointed at a checker that was not there.** Its table of
   load-bearing facts says each is re-derived in `tests/constants_check.rs`, but "3 is a
   nonresidue mod q" was asserted inside the fixture generator instead. That assertion
   *does* run in CI — `cargo run -p kat-gen` is a required step — so the fact was
   enforced; it simply was not enforced where the documentation said to look, which is
   the same defect at a smaller size. Master rule 8 is "checkers, not prose"; the
   assertion now lives in the named file too, from both our `sqrt` and arkworks'.
3. **A comment in `laws.rs` made a false mathematical claim** about `-1` being the only
   element whose norm is a square while it is not itself one. Every assertion in that
   test was correct; the sentence was not. Rewritten to say what it meant — `-1` is a
   nonresidue in Fq and a square in Fq2 because it is `u^2`, which is why `sqrt`'s
   `c1 == 0` branch has two cases — with the nonresidue half now asserted.
4. **All four hand-written point equalities could be replaced by `|_, _| true` and the
   whole suite stayed green.** This was the real find. Nearly every `assert_eq!` in the
   crate's tests routes through one of those impls, so a broken `eq` would not fail the
   suite — it would silently empty it. Nothing anywhere asserted that two points are
   *unequal*. `laws.rs::point_equality_distinguishes_points` now pins the disequality
   direction with one witness per conjunct of each impl: distinct points, `P != -P` both
   affine and projective (the `Y` conjunct, since `P` and `-P` share an `x`), the same at
   `Z != 1`, finite-versus-infinity in both argument orders, and a same-`y`/different-`x`
   pair — deliberately off-curve, since equality does not consult the curve equation and
   two on-curve points sharing a `y` would need a cube root to construct. It also pins the
   one positive case nothing else reaches: a `Z == 1` and a `Z != 1` representation of the
   same point must compare equal. Eight mutations of the four impls were then confirmed
   caught, including the two the auditor demonstrated surviving.

The audit also established, independently of the tests in this branch, that the three
facts `Fq2::sqrt`'s exhaustiveness rests on hold: the same branch structure was brute
forced over **every element of Fp2 for 27 small primes `= 3 mod 4`** — roughly 630,000
elements — plus 10,000 structured inputs at the real `q`, with no missed root, no returned
non-root, and no supposedly-unreachable branch reached. Both branches of Fact 2 and the
purely-imaginary case of Fact 3 were confirmed genuinely reachable rather than dead code.

### The one thing no test covers

`G2Affine::is_in_subgroup` is `is_on_curve() && r * self == O`. **Removing the
`is_on_curve` conjunct leaves the entire suite green**, and that is not fixable with a
test. The conjunct is what makes the method a complete validity predicate rather than an
"assuming on-curve" one: without it, an off-`E'` input would be judged only by the ladder,
and the a = 0 Jacobian formulas compute in the group of whatever curve the point actually
lies on — so a point whose implied curve has order divisible by `r` would be accepted.
Constructing that witness means finding a curve over Fq2 whose order `r` divides, which is
not something a test can do. The conjunct stays as deliberate defence in depth, the reason
is written at the method, and it is recorded here so no later reader assumes CI protects
it. `from_bytes` checks the curve equation separately, so the two are independent and a
regression in the guard alone would not weaken decoding.

## Additive extensions (everything beyond the stage's literal listing)

Must-be-exact 7 invites these and asks that each be recorded.

1. **`G2Projective` is public**, with the full `G1Projective` method set except
   `batch_to_affine`. Must-be-exact 7 names it explicitly; Acceptance 4's "mixed-add where
   the affine point equals or negates the projective one … exercised for G1 and G2"
   requires projective-level access on G2 anyway.
2. `G1Affine::IDENTITY` and `G2Affine::IDENTITY` — the frozen listing has
   `G1Projective::IDENTITY` but no affine spelling, and every edge case wants one.
3. `G1Projective::GENERATOR` and `G2Projective::GENERATOR` — `Z = 1` lifts of the affine
   generators, used by every property test.
4. `G1Projective::is_identity` and `G2Projective::is_identity` — the `Z == 0` predicate,
   which the subgroup check needs and callers will.
5. `Fq2::new`, `Fq2::from_fq`, `Fq2::norm`, `Fq2::to_bytes`, `Fq2::from_bytes` —
   constructors, the norm the inverse and the square root both use, and the coordinate
   layout G2's serde is built from.
6. `Fq::from_hex` — not in S05's listing but required by Must-be-exact 1: the tower and
   curve constants live in `constants` as hex string literals and something has to read
   them. It is `field::Fr::from_hex`'s contract, character for character.
7. `Fq::MINUS_ONE` — part of "mirroring S01's frozen `Fr` names exactly", and the value
   `FQ2_NONRESIDUE` is checked against.
8. `constants::FQ_MODULUS_MINUS_TWO` and `constants::FQ_MODULUS_PLUS_ONE_DIV_FOUR` —
   properties of the modulus, beside it, exactly as S01 placed `FR_MODULUS_MINUS_TWO`.
9. `postcard` added to `crates/curve`'s dev-dependencies, featureless, to exercise `Fq`'s
   serde over a real wire format as S01 does for `Fr`. `ark-ec` added to the workspace's
   test/tool dependencies for the group-level oracle.
10. `docs/GLOSSARY.md` gained *Fq2*, *twist*, *xi* and *uncompressed affine*, and the
    *Montgomery form* entry now names both fields.

## Deviations and notes for the reviewer

- **py_ecc was dropped as a second oracle, at the user's instruction.** Must-be-exact 6
  and Acceptance 1/3 originally asked for fixtures from arkworks-bn254 **and** py_ecc. The
  wiring was raised with the user as a decision — py_ecc is Python, so it cannot live
  inside the Rust generator, and the options were a byte-identical Python regenerator run
  manually, the same plus a `pip install` step in CI, or two committed fixture sets. The
  user's answer was to **use arkworks-bn254 as the only oracle and remove py_ecc from the
  prompt set**. `prompts/00-master.md` rules 2 and 10 and `prompts/S05-curve.md` lines 12,
  54, 59, 64 and 66 are edited accordingly, in this branch's diff. This is a deliberate
  reduction in differential breadth, made by the user, and it is the one place S05 as
  originally written is not satisfied literally.
- **`rayon` is not used.** Must-be-exact 8 says rayon "is allowed may parallelise
  `batch_to_affine`" — allowed, not required — and anti-goal 11 forbids unmeasured
  optimization. `batch_to_affine` is one `batch_inverse` plus a map; the MSM stage that
  will actually care arrives later and can add rayon with a benchmark attached. `curve`
  therefore has no rayon dependency.
- **No bench routine was added.** S05's acceptance section asks for none, and anti-goal 11
  forbids optimizing without a benchmark that shows it matters on the real workload. The
  MSM stage is where curve throughput first becomes a real number worth measuring.
- **`curve` is absent from CI's guest-target build line**, deliberately: Must-be-exact 8
  makes it a std crate, and the recursion guest defers all pairing material through the
  accumulator and never performs curve arithmetic.
- **`Fq`'s limbs are `pub(crate)`, not private.** The stage's listing says "layout
  private", and it is — nothing outside the crate can see it. `g1.rs` and `g2.rs` need the
  Montgomery limbs to write their frozen `GENERATOR` constants at const-evaluation time,
  and they are sibling modules rather than descendants, so a fully private field would not
  reach them.
- **No conflicts between the master prompt and the stage prompt were found**, beyond the
  `mul_by_nonresidue` ambiguity and the py_ecc question, both of which the user resolved
  before implementation.

## Open for the next stage

S06 gets `Fq`, `Fq2` and both groups with `xi = 9 + u` already defined, tested, and
`mul_by_nonresidue` already implemented against it — the three things an Fq6/Fq12 tower
needs first. Nothing in `curve` knows about pairings, Miller loops or the Frobenius beyond
`Fq2::conjugate`, and `G2Projective`'s coordinates stay private so a pairing can choose its
own internal representation without touching a frozen signature.
