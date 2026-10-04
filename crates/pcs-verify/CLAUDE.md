# `crates/pcs-verify`

## What this crate owns
The verifier half of Mercury: everything a verification computes that is not a curve
operation. It is `#![no_std]` + `alloc` because the recursion guest links it; `crates/pcs`
is the `std` half — commit, open, point validation, the `cm*` MSM and the pairings — and
re-exports everything public here, so a native verification and a guest's run **one**
definition of the transcript schedule, the two derived values and the twelve accumulator
terms. The owner chose a crate of its own over moving this into `verifier-core` or keeping
a second copy there (the recursion stage). **`docs/spec/mercury.md` §5–§8 and §11 and
`docs/spec/accumulator.md` §2, §3 and §5 are normative.**

```rust
pub enum PcsError { /* ten variants, one per failure class; pcs re-exports it */ }
pub const MAX_NUM_VARS: usize = 54;
pub fn check_num_vars(num_vars: usize) -> Result<usize, PcsError>;
pub fn check_batch(k: usize, values: usize, num_vars: usize) -> Result<(), PcsError>;

pub fn batch_preamble(cms: &[[u8; 64]], u: &[Fr], vs: &[Fr], tr: &mut Transcript)
    -> (Vec<Fr> /* rho^i */, Fr /* v* */);
pub fn scalars(cm: &[u8; 64], u: &[Fr], v: Fr, points: &[[u8; 64]; 8], evals: &[Fr; 6],
               tr: &mut Transcript) -> Result<[Fr; ENTRIES_PER_CHECK], PcsError>;

pub enum PairingSide { G2One, G2X }                                   // FROZEN FOREVER
impl PairingSide { pub fn word(self) -> Fr; pub fn from_word(w: Fr) -> Option<PairingSide>; }
pub const ENTRY_WORDS: usize = 6;
pub const ENTRIES_PER_CHECK: usize = 12;
pub const ENTRY_POINTS: [(PairingSide, usize); 12];   // entry i's side and point index
pub fn entry_words(side: PairingSide, scalar: Fr, point: &[u8; 64]) -> [Fr; ENTRY_WORDS];
pub fn accumulator_digest(words: &[Fr]) -> Fr;

// shared with the prover
pub fn challenge_z(tr: &mut Transcript) -> Fr;  pub fn degenerate(alpha: Fr, z: Fr) -> bool;
pub fn derive_h_alpha(u1, u2, z, z_inv, gamma, v, evals: &[Fr; 6]) -> Fr;
pub fn dot(a: &[Fr], b: &[Fr]) -> Fr;  pub fn powers(x: Fr, k: usize) -> Vec<Fr>;
pub mod uni;   // dense univariate helpers, prover and verifier
pub mod bdfg;  // the BDFG20 batch: `items`, the one definition both sides read
```

## Frozen invariants
- **A point is its 64-byte encoding here, and nothing here validates one.** The transcript
  reads limbs (`transcript::g1_limbs`), and whoever spends a term owes the curve check:
  `pcs`'s native paths before they absorb, `pcs::discharge` for every accumulator entry
  (`docs/spec/accumulator.md` §4).
- **`scalars` is §5's sixteen-step schedule and nothing else touches the transcript in a
  verification**; `pcs`'s `accumulate` validates the points and calls it, and
  `crates/pcs/tests/structure.rs` reads both facts out of the source.
- **`batch_preamble` leaves `cm*` to its caller.** `pcs` derives it with an MSM; the
  recursion guest takes it as a hint and defers `cm* - sum rho^i cm_i = O` as a check of its
  own, `docs/spec/accumulator.md` §8's option 1. `check_batch` runs before either.
- **The entry layout is `ENTRY_POINTS`**: `[cm, h, q, g, s, d, pi_z, w, w_prime, [1]_1]`
  indexed in `docs/spec/accumulator.md` §2's order, then `pi_z` and `w_prime` on `G2X`.

## Tests
| File | What |
| --- | --- |
| `src/lib.rs` unit tests | the instance rule, the `z` draw's resample rule, the degenerate-challenge predicate, and `P_u`'s two descriptions |
| `src/uni.rs` unit tests | each univariate helper against its definition |
| `tests/tape.rs` | S-RECURSION: `verifier_core::tape`'s batch preamble and twelve scalars against this crate's over random instances — an infinity commitment among them — replayed natively, to the weights, `v*`, every scalar and a last challenge, so the two sponges end in one state |

Everything else is `crates/pcs`'s suite, which runs every native verification through this
crate's `scalars` and `batch_preamble`.
