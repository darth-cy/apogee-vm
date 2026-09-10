# `crates/pcs`

## What this crate owns
Mercury: the multilinear polynomial commitment scheme. Commit, open and verify one
polynomial; batch `k` same-size columns at one point; defer a verification's two pairings
into accumulator entries and discharge a concatenated list of them. Plus the typed G1
transcript absorption the rest of the protocol uses.

The normative documents are **`docs/spec/mercury.md`** and
**`docs/spec/accumulator.md`**. This crate is those specifications in code; when they
disagree, the spec is right and the code is a bug.

```rust
pub struct MercuryCommitment(pub G1Affine);
pub struct MercuryProof { /* 8 G1 then 6 Fr, in a fixed field order */ }
pub const PROOF_BYTES: usize = 704;
pub enum PcsError { /* ten variants, one per failure class */ }

pub fn commit(srs: &Srs, f: &MultilinearPoly) -> Result<MercuryCommitment, PcsError>;
pub fn open(srs: &Srs, f: &MultilinearPoly, cm: &MercuryCommitment, u: &[Fr],
            tr: &mut Transcript) -> Result<(Fr, MercuryProof), PcsError>;
pub fn verify(vsrs: &SrsVerifier, cm: &MercuryCommitment, u: &[Fr], v: Fr,
              proof: &MercuryProof, tr: &mut Transcript) -> Result<(), PcsError>;

pub fn batch_open(srs: &Srs, cols: &[MultilinearPoly], cms: &[MercuryCommitment], u: &[Fr],
                  tr: &mut Transcript) -> Result<(Vec<Fr>, MercuryProof), PcsError>;
pub fn batch_verify(vsrs: &SrsVerifier, cms: &[MercuryCommitment], u: &[Fr], vs: &[Fr],
                    proof: &MercuryProof, tr: &mut Transcript) -> Result<(), PcsError>;

pub enum PairingSide { G2One, G2X }                                   // FROZEN FOREVER
pub struct AccumulatorEntry { pub side: PairingSide, pub scalar: Fr, pub point: G1Affine }
pub const ENTRY_WORDS: usize = 6;
pub const ENTRIES_PER_CHECK: usize = 12;

pub fn verify_deferred(/* verify's params */) -> Result<Vec<AccumulatorEntry>, PcsError>;
pub fn batch_verify_deferred(/* batch_verify's params */) -> Result<Vec<AccumulatorEntry>, PcsError>;
pub fn discharge(vsrs: &SrsVerifier, entries: &[AccumulatorEntry], checks: &[usize])
    -> Result<(), PcsError>;

pub fn accumulator_words(entries: &[AccumulatorEntry], checks: &[usize])
    -> Result<Vec<Fr>, PcsError>;
pub fn accumulator_from_words(words: &[Fr])
    -> Result<(Vec<AccumulatorEntry>, Vec<usize>), PcsError>;
pub fn accumulator_digest(words: &[Fr]) -> Fr;

pub fn append_g1(tr: &mut Transcript, tag: Tag, p: &G1Affine);
pub fn append_g1_list(tr: &mut Transcript, tag: Tag, ps: &[G1Affine]);

impl MercuryProof {
    pub fn to_bytes(&self) -> [u8; PROOF_BYTES];
    pub fn from_bytes(b: &[u8; PROOF_BYTES]) -> Option<MercuryProof>;
}
```

That is the whole public surface. Four private modules — `uni` (dense univariate
helpers), `fft` (the size-`2b` transform), `bdfg` (the batched opening, curve-free since
S09), `accumulator` (entries, their wire form, discharge) — and no traits, no macros, no
`dyn`, no features.

## Frozen invariants
- **`u1` is the FIRST `t` coordinates of `u`.** The evaluation at index `i + j*b` is the
  coefficient of `X^(i + j*b)` with `i` the low `t` bits, and `u1` is what pairs with `i`.
  Getting this backwards is the integration bug this crate exists to not have;
  `docs/spec/mercury.md` §2. `tests/tamper.rs` and `tests/sumcheck_bridge.rs` both have the
  swapped-halves negative control, the second on a point a real zerocheck produced.
- **A commitment IS a plain KZG commitment** of the evaluation table read as coefficients.
  `tests/roundtrip.rs` asserts exact equality with `srs::kzg::kzg_commit`, no tolerance.
- **`n = 2^(2t)` with `1 <= t <= 27`, or an error.** Never padded, never truncated. The
  ceiling is the two-adic subgroup's, and checking it is also what keeps `1 << u.len()`
  from shifting off a `usize` in a verifier, whose `u` comes straight from a caller.
- **The transcript schedule of `docs/spec/mercury.md` §5** — 16 steps, absorb order and
  tags — and **§11's three-step batch preamble** before it. Both sides run each identically
  and leave the transcript in the same state, so an opening composes inside a larger
  transcript. The prover squeezes the pairing-merge challenge and throws it away for
  exactly that reason.
- **A G1 point absorbs as four Fr limbs**, `x` low / `x` high / `y` low / `y` high, split
  at 128 bits; infinity absorbs four copies of `constants::G1_INFINITY_SENTINEL` = `2^128`,
  which no real limb can equal. A list is **one** message of `4k` limbs.
- **The proof is 704 bytes for every `n` and every `k`.** A batched proof is a
  `MercuryProof` and nothing else: batching changes the statement, never the shape.
- **`rho^0` sits on list index 0.** Column `i` of a batch carries `rho^i`, so reordering
  the commitment list is a different statement and fails.
- **One deferred check is `ENTRIES_PER_CHECK = 12` entries**, in the frozen order of
  `docs/spec/accumulator.md` §2: `cm`, the eight proof points in field order, `[1]_1`, then
  the two `G2X` terms. An entry is six words and 192 bytes, always.
- **`discharge` validates every entry's point.** It is the last place anyone looks;
  `docs/spec/accumulator.md` §4 is the rule later stages cite.
- **No transform larger than `2b`.** `fft::Domain::for_product(half)` is the only
  constructor and builds size `2 * half`; `tests/structure.rs` checks the one call site.
- **Every verifier path reads three SRS points.** `SrsVerifier`, and no G2 arithmetic
  beyond passing `[1]_2` and `[x]_2` to one `pairing_check`.

## The rules
- **One verification path.** `accumulate` runs every field-side check and emits the twelve
  terms; `verify` and `batch_verify` spend them on the pairings, `verify_deferred` and
  `batch_verify_deferred` return them. The four public entry points contain no transcript
  operation at all — `tests/structure.rs` reads that out of the source — so there is
  nothing in them to drift.
- **The batch paths derive `cm*` before reaching the core**, so `k` never reaches it and a
  deferred group is twelve entries whatever the batch width. That derivation is forced:
  §5's schedule absorbs `cm*` at step 2, so a verifier cannot proceed without its limbs.
  `docs/spec/accumulator.md` §8 records what that costs the recursion guest.
- **Errors are `PcsError`, panics are broken invariants.** A malformed instance, a
  malformed batch, a malformed accumulator and a failed check are all `Err`. The `assert!`s
  in `open` and `batch_open` fire only when an internal identity that cannot fail for a
  well-formed input has failed, and each names it.
- **`commit` dispatches on the backing.** `U1`/`U8`/`U16`/`U32` widen to `u32` and go
  through `curve::msm::msm_small_u32`; only `Fr` takes the general path.
- **Parallelism is rayon over indexed data**, in four places: reading `f`'s table, the
  restriction's row dot products, the fold's per-column carry, and `batch_open`'s
  combination of `k` columns into `f*`. All four are exact and indexed, so the answer does
  not depend on the thread count. The transform is serial on purpose.
- **The BDFG20 batch is built once, by `bdfg::items`**, and read by the prover and the
  verifier. A drift between the two sides is the failure mode that would be silent.

## Tests
| File | What |
| --- | --- |
| `src/{fft,uni}.rs` unit tests | the transform against the naive DFT, the frozen root's exact order, and each univariate helper against its definition |
| `src/lib.rs` unit tests | the instance rule, the degenerate-challenge predicate, the limb bound, `P_u`'s two descriptions, and the `z` draw's resample rule |
| `src/accumulator.rs` unit tests | the word round trip, every malformed word sequence, and the limb decoder's one spelling of infinity |
| `tests/roundtrip.rs` | the round trip, the KZG differential, every menu height |
| `tests/sizes.rs` | odd and unsupported sizes, mismatched points, a short SRS, backing agreement |
| `tests/tamper.rs` | the witness twin, all 14 proof fields, the statement twins, invalid points |
| `tests/identities.rs` | every polynomial rebuilt from its definition and compared against the proof, at `t = 1, 2, 3` |
| `tests/batch.rs` | the batched round trip, the four batch twins, the zero polynomial, every degenerate batch input, and the committed `k = 1` schedule |
| `tests/accumulator.rs` | the twelve entries rebuilt from the spec, deferred equivalence over the whole tamper corpus, concatenation and discharge, the per-check weight attack, and the committed accumulator |
| `tests/sumcheck_bridge.rs` | a real zerocheck's reduced claim opened at its own point, single and batched, with the transposed-point control |
| `tests/edge_cases.rs` | the committed `z^b = alpha` instance, through the production discharge |
| `tests/kats.rs` | the committed G1-absorption oracle, the committed proof, transcript binding |
| `tests/structure.rs` | the one transform, both frozen schedules read out of the source, that the entry points hold no transcript operation, and the constant proof length at four heights and three batch widths |

`tests/common/mod.rs` builds a **toy SRS** from a written-down `tau`, by writing the
archive of `docs/spec/srs.md` §5 and loading it. That is what lets CI test Mercury at all.
It also holds a **second, naive transcription of the verifier's arithmetic** — the schedule
replay, the two derived values, and the twelve accumulator terms — which `accumulator.rs`
checks against a live verification and `edge_cases.rs` drives with forced challenges.

## Fixtures
| Path | What | Kind |
| --- | --- | --- |
| `tests/vectors/g1_absorb_kats.txt` | 8 single points and 2 pairs, with their Fr limbs | oracle: arkworks points, arkworks limbs |
| `tests/vectors/mercury_proof.txt` | a full opening at `n = 2^4`, its witness, and `Transcript::sample()` after it | regression pin on the §5 schedule |
| `tests/vectors/mercury_batch.txt` | a `k = 1` batched opening at `n = 2^4`, and its probe | regression pin on the §11 preamble |
| `tests/vectors/z_pow_b_alpha.txt` | a harness-built instance with `alpha = z^b` | the edge case no honest run reaches |
| `tests/vectors/accumulator.txt` | two deferred verifications, their concatenated words, and the digest | regression pin on the accumulator layout |

`cargo run -p kat-gen -- pcs` regenerates all five; the SHA-256 pins live beside their
replayers. Four are generated by the implementation they test, because there is no second
Mercury to ask; what they freeze is the schedule and the layout, which any change to an
absorb order, a tag or an encoding moves. Their independent half is the SRS — kat-gen
builds it with arkworks, this suite builds it with `crates/curve`, and a fixture only
replays if the two agree. `z_pow_b_alpha.txt` is further independent: its polynomials are
built from their definitions with schoolbook arithmetic, never through `open`.

**What no black-box test could see, and now can.** In S08 an implementation that squeezed
the pairing-merge challenge where the schedule says and then merged with a constant produced
an identical transcript and an identical proof; only `tests/structure.rs`'s source reading
could tell. Since S09 that challenge is the *scalar of an accumulator entry*, so
`tests/accumulator.rs` catches it by value. What is left at source level is where it is
squeezed, and that there is exactly one pairing check and one MSM per side to merge into.
