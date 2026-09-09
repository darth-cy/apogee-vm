# `crates/pcs`

## What this crate owns
Mercury: the multilinear polynomial commitment scheme, single polynomial. Commit, open,
verify, and the typed G1 transcript absorption the rest of the protocol uses.

The normative document is **`docs/spec/mercury.md`**. This crate is that specification in
code; when the two disagree, the spec is right and the code is a bug.

```rust
pub struct MercuryCommitment(pub G1Affine);
pub struct MercuryProof { /* 8 G1 then 6 Fr, in a fixed field order */ }
pub const PROOF_BYTES: usize = 704;
pub enum PcsError { /* six variants, one per failure class */ }

pub fn commit(srs: &Srs, f: &MultilinearPoly) -> Result<MercuryCommitment, PcsError>;
pub fn open(srs: &Srs, f: &MultilinearPoly, cm: &MercuryCommitment, u: &[Fr],
            tr: &mut Transcript) -> Result<(Fr, MercuryProof), PcsError>;
pub fn verify(vsrs: &SrsVerifier, cm: &MercuryCommitment, u: &[Fr], v: Fr,
              proof: &MercuryProof, tr: &mut Transcript) -> Result<(), PcsError>;

pub fn append_g1(tr: &mut Transcript, tag: Tag, p: &G1Affine);
pub fn append_g1_list(tr: &mut Transcript, tag: Tag, ps: &[G1Affine]);

impl MercuryProof {
    pub fn to_bytes(&self) -> [u8; PROOF_BYTES];
    pub fn from_bytes(b: &[u8; PROOF_BYTES]) -> Option<MercuryProof>;
}
```

That is the whole public surface. Three private modules — `uni` (dense univariate
helpers), `fft` (the size-`2b` transform), `bdfg` (the batched opening) — and no traits, no
macros, no `dyn`, no features.

## Frozen invariants
- **`u1` is the FIRST `t` coordinates of `u`.** The evaluation at index `i + j*b` is the
  coefficient of `X^(i + j*b)` with `i` the low `t` bits, and `u1` is what pairs with `i`.
  Getting this backwards is the integration bug this crate exists to not have;
  `docs/spec/mercury.md` §2, and `tests/tamper.rs` has the swapped-halves negative control.
- **A commitment IS a plain KZG commitment** of the evaluation table read as coefficients.
  `tests/roundtrip.rs` asserts exact equality with `srs::kzg::kzg_commit`, no tolerance.
- **`n = 2^(2t)` with `1 <= t <= 27`, or an error.** Never padded, never truncated. The
  height menu `{2^16, 2^18, 2^20, 2^22}` and the small even sizes are all supported. The
  ceiling is the two-adic subgroup's, and checking it is also what keeps `1 << u.len()`
  from shifting off a `usize` in `verify`, whose `u` comes straight from a caller.
- **The transcript schedule of `docs/spec/mercury.md` §5** — 16 steps, absorb order and
  tags. `open` and `verify` run it identically and leave the transcript in the same state,
  so an opening composes inside a larger transcript. The prover squeezes the
  pairing-merge challenge and throws it away for exactly that reason.
- **A G1 point absorbs as four Fr limbs**, `x` low / `x` high / `y` low / `y` high, split
  at 128 bits; infinity absorbs four copies of `constants::G1_INFINITY_SENTINEL` = `2^128`,
  which no real limb can equal. A list is **one** message of `4k` limbs.
- **The proof is 704 bytes for every `n`.** 8 uncompressed G1 points then 6 canonical Fr
  values, canonical little-endian throughout.
- **No transform larger than `2b`.** `fft::Domain::for_product(half)` is the only
  constructor and builds size `2 * half`; `tests/structure.rs` checks the one call site.
- **`verify` reads three SRS points.** `SrsVerifier`, and no G2 arithmetic beyond passing
  `[1]_2` and `[x]_2` to one `pairing_check`.

## The rules
- **Errors are `PcsError`, panics are broken invariants.** A malformed instance, a
  malformed proof and a failed check are all `Err`. The `assert!`s in `open` fire only when
  an internal identity that cannot fail for a well-formed input has failed — a nonzero
  division remainder, a symmetrized identity that does not close — and each names it.
- **`commit` dispatches on the backing.** `U1`/`U8`/`U16`/`U32` widen to `u32` and go
  through `curve::msm::msm_small_u32`; only `Fr` takes the general path. A narrow column is
  never lifted to `Fr` to be committed. This is a source-level fact, not one a test can
  observe: the two paths agree on every value and differ only in cost.
- **Parallelism is rayon over indexed data**, in three places in `open`: reading `f`'s
  table, the restriction's row dot products, and the fold's per-column carry. All three are
  exact and indexed, so the answer does not depend on the thread count. The transform is
  serial on purpose.
- **The BDFG20 batch is built once, by `bdfg::items`**, and called by both the prover and
  the verifier. A drift between the two sides is the failure mode that would be silent, so
  there is one definition of the four polynomials, their point sets and their
  interpolations, and both sides read it.

## Tests
| File | What |
| --- | --- |
| `src/{fft,uni}.rs` unit tests | the transform against the naive DFT, the frozen root's exact order, and each univariate helper against its definition |
| `src/lib.rs` unit tests | the instance rule, the degenerate-challenge predicate, the limb bound, and `P_u`'s two descriptions |
| `tests/roundtrip.rs` | the round trip, the KZG differential, every menu height |
| `tests/sizes.rs` | odd and unsupported sizes, mismatched points, a short SRS, backing agreement |
| `tests/tamper.rs` | the witness twin, all 14 proof fields, the statement twins, invalid points |
| `tests/identities.rs` | every polynomial rebuilt from its definition and compared against the proof, at `t = 1, 2, 3` |
| `tests/kats.rs` | the committed G1-absorption oracle, the committed proof, transcript binding |
| `tests/structure.rs` | the one transform, the frozen schedule read out of both sides' source, that `rho` is squeezed last and is what merges, and the constant proof length |

`tests/common/mod.rs` builds a **toy SRS** from a written-down `tau`, by writing the
archive of `docs/spec/srs.md` §5 and loading it. That is what lets CI test Mercury at all:
`crates/srs`'s own suite needs a 19 GB gitignored ceremony file and skips without it.
`tests/roundtrip.rs::every_menu_height_round_trips_over_the_ceremony` is the one test here
that needs that file, and it says so and returns when it is absent.

The toy SRS is insecure by construction — its `tau` is four lines from where it is used —
and exists only to exercise the protocol. `tools/kat-gen`'s `pcs` group builds the same SRS
with arkworks, so the committed proof only replays if the two constructions agree.

## Fixtures
| Path | What | Kind |
| --- | --- | --- |
| `tests/vectors/g1_absorb_kats.txt` | 8 single points and 2 pairs, with their Fr limbs | oracle: arkworks points, arkworks limbs |
| `tests/vectors/mercury_proof.txt` | a full opening at `n = 2^4`, its witness, and `Transcript::sample()` after the opening | regression pin on the transcript schedule |

`cargo run -p kat-gen -- pcs` regenerates both; the SHA-256 pins live in `tests/kats.rs`.
The proof fixture is the one file in this repository generated by the implementation it
tests, because there is no second Mercury to ask. What it freezes is the schedule: any
change to the absorb order, a tag, or an encoding moves every challenge and every byte.
Its `probe` record — one raw duplex sample past the end of the opening — extends that to
the steps the proof bytes cannot see: a squeeze moved within the schedule, or one the
prover stops drawing, changes the terminal sponge state and nothing else.

**What no black-box test can see.** An implementation that squeezes `rho` where the
schedule says and then merges with a constant instead produces the same transcript and the
same proof; only an adversary exploiting the unrandomized sum could tell. `structure.rs`
reads that out of the source, the same way it reads the transform's size.
