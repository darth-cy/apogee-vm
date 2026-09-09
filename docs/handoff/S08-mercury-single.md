# S08 — Mercury I: single-polynomial commit / open / verify

Branch `s08-mercury-single`. Status: complete, all 12 acceptance items met.

The normative document is **`docs/spec/mercury.md`**, written this stage: the protocol,
the variable-order convention, the full transcript schedule, the G1-absorption addendum,
the BDFG20 pins, the `z ∈ F*` rule, the proof shape and the two pairing rewrites. This
note is the frozen API, the artifacts, the numbers and the deviations.

---

## The one thing to read before anything else

**`u1` is the FIRST `t` coordinates of `u`.**

`n = 2^{2t}`, `b = 2^t`, and the evaluation at index `i + j·b` is the coefficient of
`X^{i+j·b}` with **`i` the low `t` bits** of the index. `u1 = u_0..u_{t-1}` is what pairs
with `i`; `u2 = u_t..u_{2t-1}` pairs with `j`. Mercury §3.1 calls this "non-standard" and
it is the one thing a later stage can get backwards while everything still compiles.

Three things hold it in place: `open` returns exactly `MultilinearPoly::evaluate(u)`
(acceptance 1), a verifier handed the two halves swapped rejects (acceptance 6), and
`docs/spec/mercury.md` §2 states it three ways.

---

## Frozen public API, as built

```rust
// crates/pcs/src/lib.rs   (std)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcsError {
    UnsupportedNumVars { num_vars: usize },
    PointLengthMismatch { point: usize, num_vars: usize },
    SrsTooSmall { needed: usize, available: usize },
    InvalidPoint { field: &'static str },
    DegenerateChallenge,
    VerificationFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MercuryCommitment(pub G1Affine);

/// 8 G1 then 6 Fr, in this field order. Nothing optional, nothing sized by `n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MercuryProof {
    pub h: G1Affine,        // [h(x)]_1, the restriction
    pub q: G1Affine,        // [q(x)]_1, the fold quotient
    pub g: G1Affine,        // [g(x)]_1, the fold remainder
    pub s: G1Affine,        // [S(x)]_1, the symmetrized inner-product witness
    pub d: G1Affine,        // [D(x)]_1, D(X) = X^{b-1} g(1/X)
    pub pi_z: G1Affine,     // [H(x)]_1, the fold identity opened at z
    pub w: G1Affine,        // BDFG20 W
    pub w_prime: G1Affine,  // BDFG20 W'
    pub g_z: Fr,
    pub g_inv_z: Fr,
    pub h_z: Fr,
    pub h_inv_z: Fr,
    pub s_z: Fr,
    pub s_inv_z: Fr,
}

/// 8 * 64 + 6 * 32 = 704, for every n.
pub const PROOF_BYTES: usize = 704;

impl MercuryProof {
    pub fn to_bytes(&self) -> [u8; PROOF_BYTES];
    pub fn from_bytes(b: &[u8; PROOF_BYTES]) -> Option<MercuryProof>;
}

pub fn commit(srs: &Srs, f: &MultilinearPoly) -> Result<MercuryCommitment, PcsError>;

pub fn open(srs: &Srs, f: &MultilinearPoly, cm: &MercuryCommitment, u: &[Fr],
            tr: &mut Transcript) -> Result<(Fr, MercuryProof), PcsError>;

pub fn verify(vsrs: &SrsVerifier, cm: &MercuryCommitment, u: &[Fr], v: Fr,
              proof: &MercuryProof, tr: &mut Transcript) -> Result<(), PcsError>;

/// The typed G1 absorption S02 deliberately left out, frozen here.
pub fn append_g1(tr: &mut Transcript, tag: Tag, p: &G1Affine);
pub fn append_g1_list(tr: &mut Transcript, tag: Tag, ps: &[G1Affine]);
```

That is the whole public surface: the stage's list, plus `PROOF_BYTES` and the proof's
`to_bytes`/`from_bytes`, which are the serialization the Handoff section asks to be
frozen. Three private modules — `uni`, `fft`, `bdfg` — and no traits, no macros, no
`dyn`, no features. The library is 700 lines including its documentation.

```rust
// crates/constants/src/lib.rs   (additions; still zero logic, #![no_std])

/// p - 1 = 2^28 * c, c odd. The ceiling on every radix-2 FFT in the protocol.
pub const FR_TWO_ADICITY: u32 = 28;
/// 5^((p-1)/2^28): a generator of the order-2^28 subgroup of Fr*.
pub const FR_TWO_ADIC_ROOT_OF_UNITY: &str = "0x2a3c...19f0";   // 64 lowercase hex, big-endian
/// 2^128, the limb a point at infinity absorbs in each of its four lanes.
pub const G1_INFINITY_SENTINEL: &str = "0x0000...0000";        // ditto

pub mod transcript_tags {
    pub const MERCURY_INSTANCE: u64 = 10;   // scalars
    pub const MERCURY_ALPHA: u64 = 11;      // challenge
    pub const MERCURY_GAMMA: u64 = 12;      // challenge
    pub const MERCURY_Z: u64 = 13;          // challenge
    pub const BDFG_BATCH: u64 = 14;         // challenge
    pub const BDFG_POINT: u64 = 15;         // challenge
    pub const PAIRING_MERGE: u64 = 16;      // challenge
}
```

Tags 1–9 are unchanged. The three existing tags S08 reuses are `COMMITMENT` (3) for the
statement's commitment and for every `append_g1_list`, `EVALUATION_CLAIM` (6) for
`u ‖ v`, and `PCS_OPENING` (7) for every proof element and the six values. Every one of
them is a *scalars* message, so no tag gains a second message kind.

## The transcript schedule (frozen; `docs/spec/mercury.md` §5)

| # | Op | Tag | Message |
| --- | --- | --- | --- |
| 1 | absorb | `MERCURY_INSTANCE` | `n` |
| 2 | absorb | `COMMITMENT` | `append_g1(cm)` |
| 3 | absorb | `EVALUATION_CLAIM` | `u_0..u_{s-1}, v` |
| 4 | absorb | `PCS_OPENING` | `append_g1(h)` |
| 5 | squeeze | `MERCURY_ALPHA` | `alpha` |
| 6 | absorb | `PCS_OPENING` | `append_g1_list([q, g])` |
| 7 | squeeze | `MERCURY_GAMMA` | `gamma` |
| 8 | absorb | `PCS_OPENING` | `append_g1_list([s, d])` |
| 9 | squeeze | `MERCURY_Z` | `z`, resampled while zero |
| 10 | absorb | `PCS_OPENING` | the 6 evaluations, one message |
| 11 | absorb | `PCS_OPENING` | `append_g1(pi_z)` |
| 12 | squeeze | `BDFG_BATCH` | `delta` |
| 13 | absorb | `PCS_OPENING` | `append_g1(w)` |
| 14 | squeeze | `BDFG_POINT` | `z'` |
| 15 | absorb | `PCS_OPENING` | `append_g1(w_prime)` |
| 16 | squeeze | `PAIRING_MERGE` | `rho` |

`open` and `verify` run all 16 steps and leave the transcript in the same state — the
prover squeezes `rho` and discards it — so an opening composes inside a larger transcript.
`tests/kats.rs::a_transcript_with_a_prefix_stays_in_step` holds them to it, including the
next challenge drawn after the opening.

## G1 absorption (frozen; `docs/spec/mercury.md` §4)

Four `Fr` per point: `x` low, `x` high, `y` low, `y` high, splitting each coordinate's
canonical little-endian encoding at byte 16. Every limb is below `2^128 < p`.

The point at infinity absorbs four copies of `G1_INFINITY_SENTINEL = 2^128`. **The
non-collision is a property of the split, not of the curve equation**: no 128-bit half can
reach `2^128`, so the sentinel is distinct from any claimed point's limbs whether or not
that point is on the curve. All-zero limbs would also have been unambiguous, but only
because `(0,0)` is off-curve — an argument that stops holding the moment a caller absorbs
a point it has not validated, which S09's commitment lists will do.

`append_g1_list` is **one** typed message of `4k` limbs, and `append_g1(t, p)` is exactly
`append_g1_list(t, &[p])`.

## Acceptance

| # | Item | Where | Result |
| --- | --- | --- | --- |
| 1 | round trip at 2^16 + the KZG differential | `roundtrip.rs` | `commit` is exactly `kzg_commit` of the table; `v == evaluate(u)` |
| 2 | 2^16, 2^18, 2^20, 2^22 | `roundtrip.rs` | menu heights over the real ceremony; 2^2–2^18 over the toy SRS in CI |
| 3 | odd variable count | `sizes.rs` | 2^15 and a 15-element `u` on all three entry points, plus 0/1/3/5/7/9 |
| 4 | witness-tamper twin | `tamper.rs` | 4 flipped indices, each checked with the tampered *and* the honest `v` |
| 5 | proof-tamper sweep | `tamper.rs` | all 14 fields, and the sweep asserts it covered 14 |
| 6 | statement tamper | `tamper.rs` | `v+1`, each of the 8 coordinates, swapped halves, a different `cm` |
| 7 | internal identities + t=1 oracle | `identities.rs` | every polynomial rebuilt from its definition at `t = 1, 2, 3` |
| 8 | transcript binding | `kats.rs` | byte-identical reopening; `cm`, `u`, `v`, `h` and `n` each move `alpha` |
| 9 | committed proof bytes at 2^4 | `kats.rs` | replayed byte-exact; CI regenerates and diffs |
| 10 | structure assertions | `structure.rs` | the one transform, at `b`; 704 bytes at four heights |
| 11 | bench at 2^22 | `tools/bench -- mercury` | below |
| 12 | `append_g1` KAT | `kats.rs` | 8 single + 2 pair cases, arkworks-derived |

Beyond the list: a full second reconstruction of the proof in `identities.rs` (all eight
polynomials, not the four the stage names), negative controls for both fixture replayers,
and 18 unit tests inside `src/` for the pieces integration tests cannot reach.

## Acceptance 7, in more detail

`identities.rs` does not check four identities; it **rebuilds the entire proof**. It
transcribes the transcript schedule a second time to recover `alpha`, `gamma`, `z`,
`delta` and `z'`, then constructs `h`, `q`, `g`, `S`, `D`, `H`, `W` and `W'` from their
definitions — schoolbook multiplication, one Horner division per column, `eq` from its
product form — commits each with S07's `kzg_commit`, and compares against the proof's
eight points. It also checks the six sent values, `hhat(u2) = fhat(u)`, `ghat(u1) = h(α)`,
`h_j = fhat(u1, j)` for every `j`, the fold identity as polynomials, the symmetry of `T`,
the symmetrized identity at four random points, `D(X) = X^{b-1} g(1/X)`, `P_u`'s two
descriptions, both BDFG divisions' exactness, and the verifier's routes to `h(α)` and
`D(z)`.

The routes really differ: the crate computes `S` through a size-`2b` transform and the
fold through one interleaved pass over rows, and the test does neither.

## Bench (acceptance 11)

Machine: **Apple M5 Pro, 18 cores, 48 GB, macOS 26.6.2**, rustc 1.96.1, `--release`,
best of 3. `n = 2^22`, `b = 2^11`, bases from the real ceremony file. Internal numbers;
no public claims.

| operation | time |
| --- | ---: |
| `commit` | 1303 ms |
| `open` | 2893 ms |
| `verify` | **3.84 ms** |

Setup — reading and validating 2^22 ceremony points — is 143 ms and outside every timed
region.

**The opening's scalar-multiplication accounting**, which is what `2n + O(√n)` means
concretely:

| MSM | size |
| --- | ---: |
| `q` | 4,192,256 |
| `pi_z` | 4,194,303 |
| `h`, `g`, `d` | 2,048 each |
| `s`, `w`, `w'` | 2,047 each |
| **total** | **8,398,844** |

`= 2n + 10,236 = 2n + 5.0·√n`, against `n = 4,194,304`. The commitment is one further MSM
of size `n`.

**Narrow backing against `Fr` backing**, the same `u32` values twice, at 2^22:

| backing | path | time | ratio |
| --- | --- | ---: | ---: |
| `U32` | `msm_small_u32` | 167 ms | **0.36** |
| `Fr` | general `msm` | 468 ms | 1.00 |

The two are asserted to commit to the same point before either is timed.

## Artifacts

| Path | What | Kind |
| --- | --- | --- |
| `crates/pcs/tests/vectors/g1_absorb_kats.txt` | 8 single points and 2 pairs with their `Fr` limbs | **oracle**: arkworks points, arkworks limbs, `2^128` derived as an integer |
| `crates/pcs/tests/vectors/mercury_proof.txt` | a full opening at `n = 2^4`, witness included | **regression pin** on the transcript schedule |
| `docs/spec/mercury.md` | the normative specification | — |
| `tools/kat-gen/src/pcs.rs` | the generator (`cargo run -p kat-gen -- pcs`) | — |
| `tools/bench/src/mercury.rs` | the acceptance-11 routine | — |

Both files are pinned by SHA-256 in `crates/pcs/tests/kats.rs`. The digests are
deliberately not repeated here — they are a function of the generator's content, and a
copy in a handoff goes stale the first time it changes. Refresh is manual:
`cargo run -p kat-gen -- pcs` then update the two constants. Verified reproducible; CI
runs exactly that and diffs.

**`mercury_proof.txt` is the first fixture in this repository generated by the code it
tests**, and that is stated in the file's own header. There is no second Mercury
implementation to ask. What it freezes is the schedule: any change to the absorb order,
a tag, or an encoding moves every challenge and every byte. The half of it that *is*
independent is the SRS — kat-gen builds the toy powers with arkworks and hands them to
`Srs::load`, while `crates/pcs`'s suite builds the same SRS with `crates/curve`, so the
proof only replays if the two constructions agree.

## Verification performed

**301 workspace tests**, green in debug and release (251 from S07, unchanged; 50 new: 18
unit tests inside `crates/pcs/src`, 32 integration tests).

- **Every acceptance item above**, plus the extras named there.
- **A Python model of the whole protocol**, written before any Rust: it runs `open` and
  `verify` over `F_p` with KZG commitments modelled as the field value `f(x)` for a secret
  `x`, which turns `e(A,[1]_2) = e(B,[x]_2)` into `a == x·b` and makes both pairing checks
  and their RLC merge checkable in integers. It confirmed every identity at `t = 1..4`,
  rejected all 14 proof-field perturbations, all three statement tampers and a substituted
  commitment, and showed the merged check rejecting a broken relation across 200
  independent `rho` draws. That model found the shape of the protocol before the
  implementation existed, rather than agreeing with it afterwards.
- **A third implementation of the fixtures, in Python**, reading no Rust: BN254 curve
  arithmetic mod `q` and field arithmetic mod `p` from the spec text alone. It re-derived
  every limb of all ten absorption records, confirmed the generator `(1,2)` absorbs as
  `[1, 0, 2, 0]`, confirmed no real limb reaches `2^128`, re-derived the committed
  commitment as `[f(tau)]_1` from the witness, re-derived the committed claim as `fhat(u)`
  under the little-endian convention, and checked that all eight proof points are
  canonical and on the curve and all six values canonical.
- **The FFT against the naive `O(m²)` DFT** at every size up to 2^9, the inverse against
  the forward, and pointwise multiplication against schoolbook — and
  `FR_TWO_ADIC_ROOT_OF_UNITY` re-derived from `5^((p-1)/2^28)` with its order shown to be
  exactly `2^28` rather than trusted.
- **Adversarial review**, five independent reviewers with disjoint lenses — the
  mathematics derived from the papers from scratch, a malicious prover, a line-by-line
  audit of the stage prompt, test vacuity and mutation testing, and master-prompt
  compliance — each finding then put to three refutation attempts. Results in *Findings*
  below.
- **A mutation sweep on the finished tree.** Ten single-line mutants, each reverted after
  its run, with a no-op control that must survive and does:

  | mutant | caught by |
  | --- | --- |
  | `u1`/`u2` swapped in `open` | `identities.rs`, both reconstructions |
  | `S` extraction range off by one | `identities.rs`, both reconstructions |
  | `D` not reversed | `identities.rs`, both reconstructions |
  | `U8` widening sign-extended | `sizes.rs::every_backing_commits_to_the_same_point` |
  | `open` recommits instead of absorbing the passed `cm` | `sizes.rs::open_absorbs_the_commitment_it_is_given` |
  | `rho` squeezed but ignored in the merge | `structure.rs::the_merge_challenge_is_what_merges` |
  | `rho` squeezed one step early, symmetrically on both sides | `structure.rs::both_sides_run_the_frozen_schedule`, and the fixture's `probe` |
  | the `num_vars` upper bound removed | the instance unit test, and `sizes.rs::an_oversized_point_is_an_error_and_not_a_panic` |
  | infinity absorbs zeros instead of the sentinel | the limb unit test, and the arkworks-derived absorption fixture |
  | the limb split moved off byte 16 | both committed fixtures |
  | *(control)* a comment reworded | nothing, as it must not |

  The default runner stops after the first failing test binary, so the table names every
  killer only where `--no-fail-fast` was used; the two rows with two entries are those.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean, with **no `#[allow]`
  in `crates/pcs` library code**.

## Findings from the adversarial pass

Five reviewers raised **12 findings**. Every one had its facts confirmed; three refutation
attempts per finding then rejected all 12 on impact, mostly as "true but unreachable" or
"a coverage wish, not a defect". Both judgements are recorded here because both are useful,
and **six were acted on anyway** — each is a few lines, and a stage that leaves a known
true statement uncorrected because it is currently harmless is how the next stage inherits
a surprise.

The math lens returned **clean**: it derived the protocol from the papers before opening
the source, then rebuilt this crate's own committed proof fixture from its independent
model and matched all 24 intermediate values, with the swapped-halves control correctly
failing to match.

### Acted on

1. **`check_num_vars` could shift a `usize` off its end.** With `verify` handed a `u` of
   64 or more coordinates, `1usize << num_vars` panicked under `overflow-checks` and was
   masked without them. Found independently by two lenses and by the author before the
   review. **Fixed**: `num_vars` is now bounded above by `2 * (FR_TWO_ADICITY - 1) = 54`,
   the ceiling the opening's transform imposes anyway, with a compile-time assertion that
   the bound keeps the shift in range.

   The refutations were right about two things and they are recorded rather than argued
   with: **the release behaviour was `Err(VerificationFailed)`, not a silent accept** — the
   original finding overstated it — and nothing in this repository can supply such a `u`,
   since a proof carries no length field and the largest loadable SRS is `2^30` powers. It
   was fixed because a verifier entry point that panics on one build profile and not
   another is worth two lines to remove, not because it was reachable.

2. **`G1_INFINITY_SENTINEL` was inserted between `transcript_tags`' doc comment and the
   module**, so rustdoc attached the tag-allocation rules — "never renumber", "one tag, one
   message kind" — to a field element, and the module was left undocumented. Cosmetic, and
   exactly the doc a later stage is sent to read before adding a tag. **Fixed** by moving
   the constant above the block.

3. **`docs/spec/transcript.md` §8's tag table still ended at 9.** That table is the
   normative registry and its own closing line says later stages append to it. **Fixed**:
   tags 10 to 16 are in it with their kinds, plus a note that S08 gave `COMMITMENT`,
   `EVALUATION_CLAIM` and `PCS_OPENING` new messages in their existing kind.

4. **`open` recommitting `f` instead of absorbing the passed `cm` was untestable.** Both
   behaviours failed the only test that paired a commitment with a non-matching witness.
   Must-be-exact 4 pins this. **Fixed** by a discriminator: two different commitments must
   give two different proofs for one witness, which a recommitting `open` cannot do.

5. **Nothing checked where `rho` is squeezed, or that it is used.** Two mutants survived
   the whole suite: `rho` drawn and then ignored in favour of a constant, and `rho` drawn
   one step early on both sides. Must-be-exact 4 pins both. **Fixed** two ways, because the
   two halves are observable in different places:
   - the proof fixture gained a `probe` record — `Transcript::sample()` after the opening —
     which pins the terminal sponge state and so every squeeze position, including ones
     nothing reads back;
   - `tests/structure.rs` gained the whole 16-step schedule, read out of `open`'s and
     `verify`'s source as `(kind, tag)` pairs, plus assertions that `rho` is the last
     transcript operation on both sides and appears in both halves of the merge.

   The second is a source-level test on purpose. An implementation that squeezes `rho`
   where the schedule says and then merges with a constant produces an identical transcript
   and an identical proof; **no black-box test can see it**, only an adversary exploiting
   the unrandomized sum. `structure.rs` already existed for exactly this class of claim.

6. **The `U8`/`U16` commit path was exercised only on 0 and 1**, the two values where every
   plausible widening slip gives the right answer, and the vacuous `assert_ne!(rho, ZERO)`
   in `identities.rs` claimed coverage it did not have. **Fixed**: full-width and
   per-width-maximum cases for both narrow backings, and the vacuous assertion replaced by
   one that holds the replayed schedule's terminal state to the real one. Two dead fixture
   helpers in `tests/common/mod.rs` were deleted in the same pass, and the
   `#[allow(clippy::too_many_arguments)]` on `derive_h_alpha` was removed by bundling the
   six evaluations it takes — which also made an earlier claim in this note true.

### Raised, examined, not acted on

The remaining findings were documentation-placement observations already fixed by the
above, or restatements of decisions this note records under *Deviations*. Two attacks the
adversary lens constructed are worth recording as **checked and sound**, because both look
like the S07 `pairing_check`-skips-infinity bug and neither is:

- **An all-infinity proof.** `cm = O`, all eight points `O`, all six values zero. It is
  accepted for `v = 0` — which is the *true* statement, since `O` is the commitment to the
  zero polynomial — and rejected for `v != 0`. Forcing both merged terms to infinity for a
  false statement would require the polynomial identities to hold exactly.
- **The degree check on `g`.** Genuinely enforced: `D_z = z^(b-1) g(1/z)` is pinned as
  `r_3` in the batch and `g_1/z` as `g(1/z)`, and multiplying the resulting identity by
  `X^m` for `m = deg g` gives `X^m D(X) = X^(b-1) rev_m(g)(X)` with `rev_m(g)(0) = g_m != 0`,
  which forces `m <= b - 1`.

## Additive extensions (everything beyond the stage's literal list)

1. **`PROOF_BYTES`, `MercuryProof::to_bytes` and `from_bytes`.** The stage's Handoff asks
   for the proof's *serialization* to be frozen; this is it. `from_bytes` routes every
   point through `G1Affine::from_bytes` and every value through `Fr::from_bytes`, so a
   decoded proof is already canonical, on-curve and in-subgroup. **No serde**: nothing
   needs it yet, and anti-goal 10 rules out adding it speculatively.
2. **`constants::FR_TWO_ADICITY` and `FR_TWO_ADIC_ROOT_OF_UNITY`.** The size-`2b`
   transform needs a root of unity and there was no way to name one. Re-derived in
   `src/fft.rs`'s unit tests rather than trusted.
3. **`PcsError::DegenerateChallenge` and `PointLengthMismatch`.** Neither is named by the
   acceptance list. The first is the `{z, 1/z, alpha}` degeneracy of `docs/spec/mercury.md`
   §7; the second is the length check `open` needs because it sees both `f` and `u`.
4. **`verify` validates the commitment too**, not only the eight proof points that
   must-be-exact 8 names. One curve equation, and an off-curve `cm` reaching the pairing
   would make check A mean something other than it says.
5. **The toy SRS in `crates/pcs/tests/common/mod.rs`.** See *Deviations*.
6. **The `mercury` bench routine and the `pcs` kat-gen group**, which acceptance 11 and 9
   respectively require.
7. **`crates/pcs/CLAUDE.md`, `docs/spec/mercury.md` and the `docs/GLOSSARY.md` entries**,
   per master rule 12.

## Deviations and notes for the reviewer

1. **The stage prompt cites `sources/publication/2025-385.pdf`; the papers are in
   `docs/publication/`.** Both are there, along with 2020/081. No conflict, just a path.

2. **A toy SRS was built for the tests, rather than skipping them.** `crates/srs`'s suite
   returns quietly without the 19 GB gitignored ceremony file, and S07 accepted that for
   a crate whose subject *is* that file. Accepting it here would have left the whole of
   Mercury untested in CI, and acceptance 9 explicitly wants CI to regenerate and diff the
   proof fixture. So `tests/common/mod.rs` builds an SRS from a written-down `tau` — real
   and structurally valid, `Srs::validate` accepts it, and completely insecure by
   construction. It is built by writing the archive of `docs/spec/srs.md` §5 and loading it
   through `Srs::load`, so **no constructor was added to `crates/srs`** and every point
   still goes through `crates/curve`'s validating decoder. The one test that needs the real
   ceremony is `every_menu_height_round_trips_over_the_ceremony`, and it says so and
   returns when the file is absent.

3. **`tools/kat-gen` now links `pcs`.** It was arkworks-only before. The proof fixture
   cannot be generated any other way — there is no second Mercury — and the alternative
   was a second binary and a second CI line for one file. The `g1_absorb_kats.txt` half of
   the group stays a genuine oracle; only `mercury_proof.txt` is self-generated, and both
   the file header and this note say so.

4. **The residual `z` degeneracy is an error, not a resample.** Must-be-exact 6 pins the
   rule as "squeeze-and-resample-on-zero", and that is what is implemented. But `1/z`
   existing is not quite enough: the BDFG20 batch needs `{z, 1/z, alpha}` to have three
   *distinct* members, which also fails when `z² = 1`, `z = alpha` or `z·alpha = 1`. Rather
   than silently widen a rule the stage pinned, those three cases return
   `PcsError::DegenerateChallenge` from both `open` and `verify`, deterministically and on
   the same input. Total probability about `2^-252`.

   **This is a completeness gap, not a soundness one** — an honest prover fails to produce
   a proof; no dishonest prover gains anything — and no test can reach it, so it has a
   direct unit-test negative control on the predicate instead.
   `docs/spec/mercury.md` §7 records both the rule and the extension that would close it.
   **A later stage may prefer to widen the resample rule**; that is a protocol-version
   change and is deliberately not made here.

5. **Six challenge tags, not one.** S02's `SUMCHECK_CHALLENGE` covers two roles separated
   by position; S08 gives `alpha`, `gamma`, `z`, `delta`, `z'` and `rho` a tag each,
   because must-be-exact 5 asks for the BDFG20 items to "each get an exact squeeze position
   and tag" and a uniform rule beats a split one. Tags are frozen constants and cost
   nothing.

6. **Two size-`n` MSMs is what the stage asked for, and what it got** — `q` and `pi_z`.
   `commit` is a third, but it is a separate call and the stage counts it separately.

7. **`open` squeezes `rho` and throws it away.** Necessary, not tidy: the verifier draws
   it, so a transcript shared with later messages would otherwise diverge. The test for it
   draws a further challenge on both sides after the opening.

8. **`crates/pcs` has unit tests inside `src/`**, which no earlier crate does. Acceptance 7
   and acceptance 10 both want internals checked directly — the transform against a naive
   DFT, the degeneracy predicate that no end-to-end test can reach — and the alternative
   was making `fft` and `uni` public, which is surface area for a test's convenience.
   Nothing in `src/` is `pub` that was not already required.

9. **No SRS digest, still.** `docs/spec/srs.md` §4 and the S07 handoff: nothing binds a
   Mercury proof to a particular SRS. Recorded in `docs/spec/mercury.md` §10 because a
   Mercury proof is the first artifact that would carry that binding.

10. **No conflicts between the master prompt and the stage prompt were found.**

## Open for the next stage

- **S09 gets `append_g1_list` for its commitment lists**, under `COMMITMENT`, as one
  message of `4k` limbs. `docs/spec/mercury.md` §6 is normative for its RLC batching: the
  BDFG20 order, the `Z_{T\S_i}` polynomials, the challenge positions and the two proof
  elements are all pinned there, and a multi-polynomial batch extends the item list rather
  than changing the shape.
- **`transcript_tags` has 16 entries.** Later stages append; they never renumber and never
  reuse a tag across message kinds.
- **`pcs` is `std` and absent from the guest-target build line**, for the same reason
  `curve` and `srs` are. The recursion guest will eventually need a `no_std` verifier path;
  that is a later stage's problem and it will need `curve` to move first.
- **There is no batching, no accumulator extraction and no deferred pairing here.** `verify`
  computes its two pairings itself. The master's `AccumulatorEntry` shape — raw
  `(scalar, G1-limbs)` pairs, concatenated and discharged by the final verifier — is what
  §8.2's `(A, B)` rewrite exists to feed, and building it is S09's or a later stage's work.
