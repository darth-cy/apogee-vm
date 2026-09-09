# S06 — Pairing: Fq6/Fq12 Tower, Miller Loop, Final Exponentiation

Branch `s06-pairing`. Status: complete, every acceptance item met.

## Frozen public API, as built

```rust
// crates/curve/src/lib.rs   (std; the tower types join Fq/Fq2 at the root,
//                            the four pairing functions live in `pairing`)
pub use fq::{batch_inverse, Fq};
pub use fq12::Fq12;
pub use fq2::Fq2;
pub use fq6::Fq6;
pub use g1::{G1Affine, G1Projective};
pub use g2::{G2Affine, G2Projective};
pub mod pairing;
```

```rust
// crates/curve/src/fq6.rs   Fq6 = Fq2[v]/(v^3 - xi), xi = 9 + u
pub struct Fq6 { pub c0: Fq2, pub c1: Fq2, pub c2: Fq2 }

impl Fq6 {
    pub const ZERO: Fq6;
    pub const ONE: Fq6;

    pub fn new(c0: Fq2, c1: Fq2, c2: Fq2) -> Fq6;
    pub fn from_fq2(c0: Fq2) -> Fq6;
    pub fn square(&self) -> Fq6;
    pub fn mul_by_nonresidue(&self) -> Fq6;      // self * v
    pub fn pow(&self, exp: &[u64; 4]) -> Fq6;    // exp is a plain 256-bit LE integer
    pub fn inverse(&self) -> Option<Fq6>;        // None for zero
    pub fn frobenius_map(&self, power: usize) -> Fq6;   // self^(q^power), power mod 6
}

// Derives:  Clone, Copy, PartialEq, Eq
// Manual :  Debug; Add/Sub/Mul in all four owned/by-ref combinations,
//           AddAssign/SubAssign/MulAssign for Fq6 and &Fq6, Neg for both.
```

```rust
// crates/curve/src/fq12.rs   Fq12 = Fq6[w]/(w^2 - v), so w^6 = xi
pub struct Fq12 { pub c0: Fq6, pub c1: Fq6 }

impl Fq12 {
    pub const ZERO: Fq12;
    pub const ONE: Fq12;

    pub fn new(c0: Fq6, c1: Fq6) -> Fq12;
    pub fn square(&self) -> Fq12;
    pub fn conjugate(&self) -> Fq12;             // c0 - c1 w, the q^6 Frobenius
    pub fn pow(&self, exp: &[u64; 4]) -> Fq12;
    pub fn inverse(&self) -> Option<Fq12>;       // None for zero
    pub fn frobenius_map(&self, power: usize) -> Fq12;  // self^(q^power), power mod 12
}

// The same derive / operator set as Fq6.
```

```rust
// crates/curve/src/pairing.rs
pub fn miller_loop(pairs: &[(G1Affine, G2Affine)]) -> Fq12;
pub fn final_exponentiation(f: &Fq12) -> Fq12;
pub fn pairing(p: &G1Affine, q: &G2Affine) -> Fq12;
pub fn pairing_check(pairs: &[(G1Affine, G2Affine)]) -> bool;
```

New in `crates/constants` (zero logic, as always): `FQ6_FROBENIUS_C1`,
`FQ6_FROBENIUS_C2` as `[[&str; 2]; 6]`, `FQ12_FROBENIUS_C1` as `[[&str; 2]; 12]`,
`TWIST_FROBENIUS_X`, `TWIST_FROBENIUS_Y` as `[&str; 2]`, `BN_PARAMETER_X: u64`,
`ATE_LOOP_NAF: [i8; 66]`, and `FINAL_EXP_LAMBDA_0/_1/_2` as `[u64; 4]`.

## What was built, and the citations

**The loop is Beuchat et al., ePrint 2010/354, Algorithm 1**, line for line —
`docs/publication/2010-354.pdf`, committed with this branch. `T <- Q`, `f <- 1`, then for
`i = L-2` down to `0`: square `f`, multiply in the tangent line, double `T`, and on a
nonzero digit multiply in the chord line and add `+-Q`. Then `Q1 <- pi_q(Q)`,
`Q2 <- pi_{q^2}(Q)`, and two closing steps against `Q1` and `-Q2`. `x` is positive for
BN254, so `f` needs no conjugation before them.

**The loop parameter is the true NAF of `6x + 2`**, 66 digits, least-significant first,
digits in `{-1, 0, 1}` with no two adjacent nonzero, leading digit 1 at index 65 — which
is the `T <- Q` initialisation, so the loop runs 65 doublings over indices 64..0. All four
properties are asserted in `tests/constants_check.rs`. arkworks' own `ATE_LOOP_COUNT` is a
different 65-digit signed form of the same integer with adjacent nonzero digits at the
top; either is correct, since the Miller function depends on the integer and not on the
expansion, and the canonical NAF is what S06 names.

**The G2 accumulator is homogeneous projective over Fq2**, `Y^2 Z = X^3 + b' Z^3`, with
the standard `a = 0` doubling-and-line and mixed-addition-and-line formulas written out in
the doc comments of `doubling_step` and `addition_step`. Beuchat et al. section 4.1 writes
the same lines in *Jacobian* coordinates; the homogeneous chart is what S06 asks for and
what ark-bn254 implements, so the differential test compares two independent codes over
the same formulas rather than one code against itself.

**Line evaluations are materialised as full `Fq12` elements** and accumulated with the
generic multiplication. BN254's twist is the D type, which puts the three nonzero
coefficients in the `1`, `w` and `v w` slots — flat positions 0, 3, 4 of
`(c0.c0, c0.c1, c0.c2, c1.c0, c1.c1, c1.c2)`. No sparse `mul_by_034`, no cyclotomic
squaring, no precomputed G2 line coefficients, exactly as S06's D5 note asks.

**The final exponentiation is the exact `(q^12 - 1)/r` power.** Easy part
`(q^6 - 1)(q^2 + 1)` by conjugation, one inversion and one Frobenius. Hard part
`d = (q^4 - q^2 + 1)/r`, evaluated **as the base-`q` decomposition itself**:

```text
  d = lambda_0 + lambda_1 q + lambda_2 q^2 + q^3

  lambda_0 = -(36x^3 + 30x^2 + 18x + 2)
  lambda_1 = -(36x^3 + 18x^2 + 12x - 1)
  lambda_2 =    6x^2 + 1
```

The reference is Scott, Benger, Charlemagne, Dominguez Perez and Kachisa, *On the final
exponentiation for calculating pairings on ordinary elliptic curves*, ePrint 2008/490 —
the procedure Beuchat et al. section 4.2 states it follows, and the decomposition S06 calls
the Devegili-style one. What that paper builds on top is a vectorial addition chain
evaluating the same exponent in 13 multiplications and 4 squarings; this stage
**deliberately evaluates the decomposition directly** instead — four Frobenius maps, three
`pow` calls with the exponents above, three multiplications — because S06's priority
statement asks for auditable over fast and a reader can check three exponents but not an
addition chain. It costs several times the hard part's multiplications, on a routine the prover never
runs.

`lambda_0` and `lambda_1` are negative. `constants` stores magnitudes and the sign is
applied by `conjugate()`, which is inversion on the cyclotomic subgroup the easy part lands
in — for *any* nonzero input, since `(q^6-1)(q^2+1)(q^4-q^2+1) = q^12 - 1`.

**Fuentes-Castañeda is excluded, and that has a consequence for the oracle.**
`ark_bn254`'s own `final_exponentiation` *is* Fuentes-Castañeda: it returns `f^(m d)` with
`m = 2x(6x^2 + 3x + 1)`, verified experimentally before any code was written. So
`Bn254::pairing` is **not** a drop-in oracle for this stage, and the committed fixtures
instead raise ark's `multi_miller_loop` output to the literal 2,790-bit integer
`(q^12 - 1)/r` — the definition, independent of any library's decomposition. The generator
asserts both cross-checks on every fixture it writes: the value has order dividing `r`, and
ark's own pairing is exactly that value to the `m`.

## Artifacts

| Path | What |
| --- | --- |
| `crates/curve/tests/vectors/fq6_kats.txt` | 1,264 vectors: an 8x8 edge grid, 1,000 random pairs, every Frobenius power `0..6`, `pow` |
| `crates/curve/tests/vectors/fq12_kats.txt` | 1,591 vectors: the same shape plus `conjugate`, powers `0..12`, and 207 exact final exponentiations |
| `crates/curve/tests/vectors/pairing_kats.txt` | 126 vectors: 6 named cases including `e(G1, G2)`, and 120 random `(P, Q, e(P,Q))` |
| `tools/kat-gen/src/tower.rs` | the tower generator, `cargo run -p kat-gen -- tower` |
| `tools/kat-gen/src/pairing.rs` | the pairing generator, `cargo run -p kat-gen -- pairing` |
| `docs/publication/2010-354.pdf` | the provided reference, now committed |

**The tool subcommands.** `kat-gen` grew the interface S06's Must-be-exact 5 asks for:
`cargo run -p kat-gen` still regenerates everything, which is what CI runs and is
unchanged; `cargo run -p kat-gen -- <group>` regenerates one of `field`, `poly`, `curve`,
`tower`, `pairing`. Splitting it moved the `Fr` generator out of `main.rs` into `field.rs`,
gave every group one `generate()`, and folded the four copies of the hex codec into
`shared.rs`. **The S01, S03 and S05 fixtures regenerate byte-identically** — their pinned
SHA-256 digests are unchanged in this branch's diff, which is the check that the refactor
moved code and nothing else.

The three new files are **14 MB** (about 6.7 MB packed), on top of S05's 4.2 MB. That is
the price of Acceptance 1's "at least 1,000 random vectors per op" being committed rather
than sampled: an `Fq12` token is 768 hex characters and an `fq12_ops` line carries eleven
of them. It is by a wide margin the largest cost this stage adds to the repository, and it
is recorded here and in `crates/curve/CLAUDE.md` so nobody has to rediscover it.

## Verification performed

25 new tests, 205 in the workspace, green in debug and release. Every CI step passes
locally.

- **The whole pairing was prototyped and validated before a line of crate code was
  written.** Fq6, Fq12, the Miller loop, the twist Frobenius and the final exponentiation
  were built once in a scratch program on top of *arkworks' `Fq2` only*, and checked
  against ark's Miller output raised to the literal exponent — single pairs, multi-pair,
  bilinearity, non-degeneracy, unitarity, infinity, and the `pairing_check` relations. That
  separated "are my formulas right" from "is my tower right", so the crate port was a
  transcription whose typos the fixtures would catch. It passed on the first run of the
  real code.
- **Every new constant re-derived three or four ways** (`tests/constants_check.rs`, 5 new
  tests): `q` and `r` from `BN_PARAMETER_X` via their BN polynomials; each Frobenius entry
  as `xi^((q^i-1)/3)`, `xi^((2q^i-2)/3)`, `xi^((q^i-1)/6)` computed as integer exponents;
  the relations that tie the tables together (`C2 = C1^2`, `FQ12_C1[i]^2 = FQ6_C1[i mod 6]`,
  `gamma_x = FQ6_C1[1]`, `gamma_y = FQ12_C1[1]^3`); and each against arkworks' own table.
  Then `tests/tower.rs::frobenius_is_the_q_power_map` checks all 24 entries a **fourth**
  way with no oracle at all, by raising random elements to `q` repeatedly and comparing
  against `frobenius_map(i)` for every `i`, including that the map has order 6 on Fq6 and
  12 on Fq12.
- **The lambda decomposition checked as an integer identity**: each lambda re-derived from
  `x` by Horner, and `(lambda_0 + lambda_1 q + lambda_2 q^2 + q^3) * r == q^4 - q^2 + 1`
  over the 1,016-bit integers. My first attempt at these constants had `lambda_1`'s
  constant term at `+1` rather than `-1`; the identity caught it before any code used them.
- **`final_exponentiation` checked against its own definition**, not only against a
  fixture: `tests/pairing.rs::final_exponentiation_is_the_literal_exponent` builds
  `(q^12 - 1)/r` from `constants`' moduli, asserts it is 2,790 bits, and applies it one bit
  at a time with `square`/`mul`, on seven inputs including `ONE`, a Miller output and
  random `Fq12` elements. A Fuentes-Castañeda-style shortcut fails this test, which is the
  whole point of Must-be-exact 6.
- **The committed corpus** (`tests/kats.rs`): 2,981 new vectors through the same single
  evaluator S05 built, with an exact-count assertion per line kind, so a truncated or
  half-regenerated file fails rather than passing with less coverage than it claims. Each
  random pairing point is also a `from_bytes` acceptance case, and each named pairing case
  is checked to really *be* the case its name claims before its value is compared.
- **The negative control extends to every new line kind for free**, because they went into
  the existing evaluator: `corrupted_vectors_are_rejected` renames the operator, truncates
  the line, and corrupts every field of every kind at three positions, and asserts each is
  caught. No new `INSENSITIVE` exemptions were needed. Building it did find one real
  weakness: the Frobenius fixtures originally led with the zero and one edges, whose
  Frobenius is themselves, so corrupting the *power* index changed nothing. The generator
  now emits random elements first — they are the ones that actually read a table entry —
  and the sweep catches it.
- **Acceptance 8's manual run, performed twice.** Flipping one hex digit in the first
  `pairing_random` line's value fails at the SHA-256 pin. Re-pinning the digest so the pin
  cannot be what catches it, the evaluator fails and names the field:
  `pairing_kats.txt:28 (pairing_random): pairing: expected ...40e2c110, got ...40e2c114`.
  The same on the first `fq12_final_exp` line: `fq12_kats.txt:1415 (fq12_final_exp): fq12
  final exponentiation: expected 010000000000...`. Both files and both digests restored and
  re-diffed clean afterwards.
- **Live differential** (`tests/differential.rs`, 2 new tests): 50 rounds of Fq6 and Fq12
  add/sub/mul/square/inverse/conjugate and *every* Frobenius power against whatever
  arkworks is in the graph today; then 20 random pairings and three multi-pair loops
  compared **twice over** — once against the literal-exponent definition, and once against
  arkworks' entirely independent pipeline (precomputed line coefficients, sparse
  `mul_by_034`, cyclotomic squarings, Fuentes-Castañeda), which requires raising our value
  to `m` first. `m` is asserted nonzero mod the prime `r`, so that comparison is an
  equality test and not a weaker one.
- **The tower as a field** (`tests/tower.rs`): associativity, commutativity,
  distributivity, the identities, negation, `square == a*a`, `a * a^-1 == 1`, double
  inverse, `pow` at 0/1/3, `inverse(ZERO) == None`; the defining relations `v^3 = xi`,
  `w^2 = v`, `w^6 = xi`, `w^12 = xi^2`; `mul_by_nonresidue` against an explicit multiply by
  `v` and by `xi`; conjugation as an involution and a ring homomorphism; the Frobenius as a
  ring homomorphism at every power; and `Fq6::inverse`'s adjugate identity
  `a * (t0 + t1 v + t2 v^2) == norm(a)` recomputed independently rather than left in a
  comment.
- **Equality is not vacuous.** S05's audit found that four hand-written point equalities
  could all be replaced by `|_, _| true` with the suite still green. `Fq6` and `Fq12`
  *derive* `PartialEq`, which is much harder to get wrong, but nothing else in the stage
  asserts two tower elements are different — so `equality_distinguishes_every_coefficient`
  pins one witness per coefficient, down to the last `Fq` of an `Fq12`, which is exactly
  what a wrong Frobenius constant would move.
- **The pairing's laws** (`tests/pairing.rs`): bilinearity in both arguments and in the
  product `ab`; additivity `e(P + P', Q) = e(P,Q) e(P',Q)` and its mirror;
  `e(P,Q)^r = 1`; `e(G1, G2) != 1`; unitarity three ways (`conj = inverse`,
  `conj = frobenius_map(6)`, `f * conj(f) = 1`); `final_exponentiation(ONE) = ONE`; the
  infinity rules including a `G1Affine` with `infinity = true` and *stale coordinates*,
  which the public fields let a caller build; the `[(aP,Q), (-P,aQ)]` relation and a toy
  KZG opening, each with negative twins that must fail; and multi-pair against the product
  of single pairs for `k` in `{2, 3, 5}`.
- **Must-be-exact 3, both ways.** By code inspection: `pairing_check` is the single
  expression `final_exponentiation(&miller_loop(pairs)) == Fq12::ONE`, and
  `final_exponentiation` has exactly two call sites in the whole crate,
  `pairing` and `pairing_check`, one each, and none inside `miller_loop`. Instrumenting a counter
  would have meant global mutable state, which the master prompt's anti-goal 7 forbids, so
  the code inspection is recorded here as S06 allows. It is also pinned behaviourally:
  `pairing_check_is_one_miller_loop_and_one_final_exponentiation` asserts the equality with
  that expression over pair counts 0..6, on lists that fail and lists that pass.
- **No degenerate step, proven and then measured.** An early draft of `addition_step`'s doc
  comment claimed the *last* closing step is always degenerate. That was simply wrong, and
  checking it before writing it down is what caught it: the accumulator's multiplier `m`
  starts at 1, is strictly increasing under `m -> 2m + d`, and stays in `[1, 6x+2]`, far
  below `r`; an addition degenerates only at `m == +-1 mod r`, and `m >= 2` at every
  addition; and `6x + 2` and `6x + 2 + q` are congruent to none of `+-q`, `+-q^2` mod `r`.
  Then it was measured: over 40 random `Q`, zero degenerate additions, the accumulator
  never `O`, and the final `T` not the identity.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean with **no `#[allow]`
  anywhere in library or tool source**, and `cargo fmt --all -- --check` is clean.

## Choices this stage made

**`curve::pairing` is a public module; `Fq6` and `Fq12` are re-exported at the crate
root.** S06's Deliver section groups the two tower types with the four functions under
"Module `curve::pairing`", while S05's precedent is a flat root re-export with private
modules. **Raised with the user and resolved** in favour of the tower types sitting beside
`Fq` and `Fq2` at the root, with the pairing functions in `curve::pairing`. Every item has
exactly one spelling either way.

**arkworks is the only oracle, and the exact value is derived from its Miller loop.**
Must-be-exact 5 and Acceptance 2 ask for fixtures from arkworks **and** py_ecc. S05 had
already dropped py_ecc at the user's instruction; the question was **raised again** because
S06 restates it, and because the Fuentes-Castañeda discovery changes the shape of the
arkworks side regardless. The user's answer was again **arkworks only**. This is the one
place S06 as written is not satisfied literally, and it is a deliberate reduction in
differential breadth made by the user. What replaces the second oracle, in part, is that
the two arkworks comparisons in `differential.rs` go through *different* arkworks code
paths, and that the Frobenius tables and the final exponent are each checked once against
no oracle at all.

**Fq6 has no `conjugate`, and that is not a gap.** S06's API listing says "Both: ops,
square, inv, conjugate, frobenius_map(power), pow", and Acceptance 1 lists `conjugate`
among the ops to fixture "for Fq6 and Fq12". There is no such operation: Fq6 is a *cubic*
extension of Fq2, so `Gal(Fq6/Fq2)` has order three and no element of order two.
Coefficientwise Fq2-conjugation is not even a ring homomorphism — it would have to send
`xi = 9 + u` to `9 - u` while fixing `v^3 = xi`. The one order-two automorphism Fq6 has is
`a^(q^3)`, which is `frobenius_map(3)` and needs no second name. The listing is read as the
union of the two types' operations, which is the only reading under which it is
satisfiable; `conjugate` is fixtured on Fq12, where it is the `q^6` Frobenius and where the
final exponentiation actually uses it. Recorded rather than silently dropped.

**Frobenius constants are parsed from hex at the point of use, not stored as Montgomery
literals in `curve`.** Must-be-exact 4 says no magic literals may appear in `curve`, and
S05 had put Montgomery-form literals there because a `const GENERATOR` needs limbs at
const-evaluation time and `Fq::from_hex` is not a `const fn`. The Frobenius tables are not
`const` items — they are read inside functions — so that pressure does not exist here, and
`fq2_from_hex` reads them from `constants` on each call. That is about fifty 64-digit hex parses
per pairing — four `Fq12` Frobenius maps at ten each, plus the twist constant twice per
`psi` and the curve constant once — against the hundred thousand-odd `Fq` multiplications
a pairing already costs, on a routine the prover never runs. Every literal is parsed by `constants_check.rs`, so a
malformed one fails a test rather than an `expect` in production.

**`Fq6::square` and `Fq12::square` are the general multiplication.** The specialised
squaring formulas save two and one `Fq2` multiplications respectively and cost a second set
of coefficient identities to audit; on a verification-side routine that is the wrong trade.

**`num-bigint` was added, test- and tool-only.** `kat-gen` needs it to state the exact
final exponent as an integer, and `crates/curve`'s tests need it for the lambda identity
and the definitional final-exponentiation check. It is in the same class as arkworks —
a reference implementation reachable only from fixtures and tests, never from the prover,
the verifier or a guest — and it was already in the tree as an `ark-ff` dependency. Master
rule 2's exhaustive list governs *runtime* dependencies, which are unchanged.

**`two_inv` is computed once per `miller_loop` and passed down.** The doubling formula
halves twice; computing `1/2` inside the step would put a full Fermat inversion in the
inner loop and roughly double the Miller loop's cost for nothing.

## Additive extensions (everything beyond the stage's literal listing)

1. `Fq6::ZERO`, `Fq12::ZERO` — the listing names `Fq12::ONE`; both types get both
   constants, as `Fq2` has.
2. `Fq6::new`, `Fq6::from_fq2`, `Fq12::new` — constructors mirroring `Fq2::new` /
   `Fq2::from_fq`. `from_fq2` is the embedding the tower relations are stated with.
3. `Fq6::mul_by_nonresidue` — multiplication by `v`. `Fq12`'s multiplication needs it, and
   it is public for the same reason `Fq2::mul_by_nonresidue` is: it is a named operation of
   the tower, and making it public makes it fixture-testable.
4. `curve::pairing` is a `pub mod` rather than four root re-exports; see above.
5. `tools/kat-gen` gained `field.rs` (the `Fr` generator moved out of `main.rs`) and
   `shared.rs` (the hex codec and exponents, previously duplicated in `curve.rs`), plus the
   `write_vectors` and `assert_distinct` helpers on `main`. The output is byte-identical.
6. `docs/GLOSSARY.md` gained *Fq6, Fq12*, *Frobenius map*, *Pairing*, *Miller loop*,
   *Final exponentiation*, *Cyclotomic subgroup* and *Pairing check*.

## Deviations and notes for the reviewer

- **py_ecc, again.** See "Choices" above. Raised, and the user's answer was arkworks only.
- **arkworks' `Bn254::pairing` cannot be used as an oracle for this stage.** This is worth
  repeating because it is the trap: it looks like the obvious oracle and it is off by a
  fixed 190-bit power. Anything later that compares a pairing value against arkworks must
  either raise ark's Miller output to the literal exponent or correct by `m`.
- **`psi`'s infinity branch is unreachable.** `miller_loop` filters infinite pairs before
  the loop, so `psi` is never called with one. The branch returns `IDENTITY`, which is the
  mathematically correct value rather than a fudge, and it keeps `psi` total; it is
  recorded here because no test can cover it, in the spirit of S05's "the one thing no test
  covers".
- **`curve` remains absent from CI's guest-target build line**, deliberately and now more
  pointedly: the recursion guest defers all pairing material through the accumulator and
  never computes a pairing, which is the reason this stage was allowed to be slow.
- **No bench routine was added.** S06's acceptance section asks for none, and anti-goal 11
  forbids optimizing without a benchmark showing it matters. A pairing takes on the order
  of a millisecond here, which is irrelevant to a proof that runs a handful of them; the
  stage that should measure curve throughput is the MSM one.
- **No conflicts between the master prompt and the stage prompt were found**, beyond the
  Fq6 `conjugate` impossibility and the py_ecc question, both recorded above.

## Open for the next stage

The verifier shape S06 froze is `pairing_check(&[(G1Affine, G2Affine)]) -> bool`: multi-pair,
one shared Miller loop, one final exponentiation, compared to `Fq12::ONE`. That is exactly
the shape the deferred-pairing accumulator is discharged in — the master prompt's
`AccumulatorEntry` list becomes an RLC and an MSM, then two pairs through this function —
so the SRS and Mercury stages have the target they need and nothing about it should move.
`Fq12` has no wire format, deliberately: nothing in the protocol serializes a target-group
element, and the day something does, the encoding should be designed then rather than
guessed now.
