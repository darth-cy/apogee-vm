# S09 — Mercury II: RLC batching, transcript integration, accumulator extraction

Branch `s09-mercury-batching`. Status: complete. All 11 acceptance items met; two
deliberate deviations from the stage prompt, both decided by the user and recorded below.

The normative documents are **`docs/spec/mercury.md` §11** (the batching lemma, the batch
transcript schedule, the caller obligation) and **`docs/spec/accumulator.md`** (new: the
entry, the wire form, the validation rule, the digest, the discharge equation). This note
is the frozen API, the artifacts, the numbers and the deviations.

---

## The two things to read before anything else

**`AccumulatorEntry` and `PairingSide` are FROZEN FOREVER.** Not "frozen until a later
stage needs something": an accumulator rides a proof's public I/O, it is hash-bound there,
and a recursion chain concatenates lists produced by different builds of this software.
The struct, the enum, the field order, the twelve-entry table, the six-word entry and the
per-group count word are all part of the protocol.

**`rho^0` sits on list index 0.** Column `i` of a batch carries `rho^i`, so the first
commitment carries `1`. Reordering the list is a different statement, and `batch_verify`
rejects it. The same convention as `docs/spec/mercury.md` §6's BDFG20 order and
`crates/poly`'s index rule: geometric weights start at exponent 0 on index 0, everywhere.

---

## Frozen public API, as built

```rust
// crates/pcs/src/lib.rs   (std)

pub fn batch_open(srs: &Srs, cols: &[MultilinearPoly], cms: &[MercuryCommitment], u: &[Fr],
                  tr: &mut Transcript) -> Result<(Vec<Fr>, MercuryProof), PcsError>;

pub fn batch_verify(vsrs: &SrsVerifier, cms: &[MercuryCommitment], u: &[Fr], vs: &[Fr],
                    proof: &MercuryProof, tr: &mut Transcript) -> Result<(), PcsError>;

pub fn verify_deferred(vsrs: &SrsVerifier, cm: &MercuryCommitment, u: &[Fr], v: Fr,
                       proof: &MercuryProof, tr: &mut Transcript)
    -> Result<Vec<AccumulatorEntry>, PcsError>;

pub fn batch_verify_deferred(vsrs: &SrsVerifier, cms: &[MercuryCommitment], u: &[Fr],
                             vs: &[Fr], proof: &MercuryProof, tr: &mut Transcript)
    -> Result<Vec<AccumulatorEntry>, PcsError>;

pub fn discharge(vsrs: &SrsVerifier, entries: &[AccumulatorEntry], checks: &[usize])
    -> Result<(), PcsError>;

/// FROZEN FOREVER.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingSide { G2One, G2X }          // pairs against [1]_2 vs [x]_2; wire 0 and 1

/// FROZEN FOREVER.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccumulatorEntry {
    pub side: PairingSide,
    pub scalar: Fr,
    pub point: G1Affine,
}

/// Six words, 192 bytes, for every entry.
pub const ENTRY_WORDS: usize = 6;
/// One deferred Mercury verification, whatever `n` and whatever a batch's `k`.
pub const ENTRIES_PER_CHECK: usize = 12;

pub fn accumulator_words(entries: &[AccumulatorEntry], checks: &[usize])
    -> Result<Vec<Fr>, PcsError>;
pub fn accumulator_from_words(words: &[Fr])
    -> Result<(Vec<AccumulatorEntry>, Vec<usize>), PcsError>;
pub fn accumulator_digest(words: &[Fr]) -> Fr;
```

`PcsError` gains four variants; the six S08 froze are untouched, in place and unrenamed.

```rust
    EmptyBatch,
    BatchLengthMismatch { commitments: usize, paired: usize },
    MixedColumnSizes { expected: usize, found: usize },
    MalformedAccumulator { length: usize, at: usize },
```

```rust
// crates/constants/src/lib.rs   (additions; still zero logic, #![no_std])

pub mod transcript_tags {
    pub const MERCURY_BATCH: u64 = 17;       // challenge: the column-batching rho
    pub const ACCUMULATOR_DIGEST: u64 = 18;  // scalars:   the accumulator's words
    pub const ACCUMULATOR_MERGE: u64 = 19;   // challenge: the per-check RLC weight
}
```

Tags 1–16 are unchanged. S09 gives `COMMITMENT` and `EVALUATION_CLAIM` new messages in
their existing kind — the batch's commitment list and its `u ‖ v_0..v_{k-1}` — so no tag
gains a second message kind.

## The batch transcript schedule (frozen; `docs/spec/mercury.md` §11.1)

| # | Op | Tag | Message |
| --- | --- | --- | --- |
| B1 | absorb | `COMMITMENT` | `append_g1_list(cms)` — **one** message of `4k` limbs |
| B2 | absorb | `EVALUATION_CLAIM` | `s + k` scalars: `u_0..u_{s-1}`, then `v_0..v_{k-1}` |
| B3 | squeeze | `MERCURY_BATCH` | `rho` |

Then `cm* = Σ ρ^i cm_i`, `v* = Σ ρ^i v_i`, and §5's sixteen steps run on `(cm*, u, v*)`.

**Injectivity rests on the first message's length word.** The typed framing writes `4k`,
which is the only thing that pins `k`; `s` then follows as `(s + k) − k` from the second
message. Splitting the commitment list into `k` messages, or dropping the length, would
make "`k` commitments" and "`k−1` commitments plus a longer claim" the same absorbed
stream — and dropping one commitment would be free. `append_g1_list` is one message and
must stay one.

**`rho` is not resampled on zero.** `rho = 0` leaves columns `1 .. k-1` unchecked, which is
a *soundness* event and not a completeness one — but it is already inside the `(k-1)/|Fr|`
bound, being one of the error polynomial's at most `k-1` roots. Resampling would remove one
root out of `k-1`. §7's rule for `z` is different in kind: without `1/z` there is no proof
at all.

**A `k = 1` batch is not a bare single opening**, and the two are not interchangeable in
either direction. `crates/pcs/tests/batch.rs` asserts the single verifier rejects a `k = 1`
batched proof, and `mercury_batch.txt` pins the bytes.

## The twelve accumulator entries (frozen; `docs/spec/accumulator.md` §2)

With `c_i = δ^i · Z_{T\S_i}(z')` over the BDFG20 order `g, h, S, D`, `K = Σ c_i r_i(z')`
and `Z_T(z') = (z'−z)(z'−1/z)(z'−α)`:

| # | side | point | scalar |
| --- | --- | --- | --- |
| 0 | `G2One` | `cm` | `1` |
| 1 | `G2One` | `h` | `ρ·c_1` |
| 2 | `G2One` | `q` | `−(z^b − α)` |
| 3 | `G2One` | `g` | `ρ·c_0` |
| 4 | `G2One` | `s` | `ρ·c_2` |
| 5 | `G2One` | `d` | `ρ·c_3` |
| 6 | `G2One` | `pi_z` | `z` |
| 7 | `G2One` | `w` | `−ρ·Z_T(z')` |
| 8 | `G2One` | `w_prime` | `ρ·z'` |
| 9 | `G2One` | `[1]_1` | `−(g_z + ρ·K)` |
| 10 | `G2X` | `pi_z` | `1` |
| 11 | `G2X` | `w_prime` | `ρ` |

The point order is `cm`, then the eight proof points in field order, then `[1]_1`, then the
two `G2X` terms — so it is `[cm] ++ proof.points() ++ [g1_gen]` with no reordering
anywhere. Entry 9 carries both checks' generator contributions, which is why it is one
entry. Entry 2's scalar is zero exactly when `z^b = α`, which is legal.

The wire form is a flat array of canonical 32-byte LE `Fr` words: each group opens with its
entry count, each entry is `[side, scalar, x_lo, x_hi, y_lo, y_hi]`. No header, no total
count, so byte concatenation of two lists is a valid list.

## Acceptance

| # | Item | Where | Result |
| --- | --- | --- | --- |
| 1 | k=8 at 2^16, values are `evaluate(u)` | `batch.rs::a_batch_of_eight_round_trips_at_two_to_the_sixteen` | Ok both sides; all 8 values checked |
| 2 | witness twin + 3 binding twins | `batch.rs::every_batch_twin_is_rejected` | 2 flipped columns × 2 value sets, all 4 values, swap (twice), drop |
| 3 | k=1 verifies; schedule fixture-pinned | `batch.rs::{a_batch_of_one…, the_committed_batch_replays}` | `mercury_batch.txt`, proof bytes and probe |
| 4 | sumcheck round-trip cross-check | `sumcheck_bridge.rs` | single **and** batched, transposed control on both |
| 5 | z resample | `src/lib.rs::a_rejected_z_draw_takes_the_next_squeeze` | rejected draw discarded, next taken, event log checked |
| 6 | `z^b = α` vector | `edge_cases.rs` + `z_pow_b_alpha.txt` | through the production `discharge` |
| 7 | zero polynomial | `batch.rs::{the_zero_polynomial…, a_corrupted_infinity_encoding…}` | single, batched, all-zero batch, and the decode controls |
| 8 | deferred equivalence | `accumulator.rs::{deferral_changes_no_verdict, batch_deferral…}` | 27 single cases, 7 batch cases, `assert_eq!` on the `Result` |
| 9 | accumulator vectors + digest | `accumulator.rs` + `accumulator.txt` | two verifications, concatenated, word-exact, digest pinned |
| 10 | structural | `structure.rs`, `accumulator.rs::the_entry_length_is_constant`, `transcript/tests/duplex.rs` | 192 bytes, 704-byte proof at 4 heights and 3 widths, tags distinct **and sequential** |
| 11 | bench | `tools/bench -- mercury-batch` | below |

Beyond the list: `accumulator.rs::the_entries_are_the_two_relations` rebuilds all twelve
scalars from the papers' definitions and a second transcription of the schedule, and
`the_per_check_weight_separates_the_checks` constructs the concrete attack the per-check
weight exists to stop — two deferred checks with equal and opposite errors, which pass an
unweighted sum and fail a weighted one.

## Bench (acceptance 11)

Machine: **Apple M5 Pro, 18 cores, 48 GB, macOS 26.6.2**, rustc 1.96.1, `--release`.
16 columns of `n = 2^20`, one point, bases from the real ceremony file. Internal numbers;
no public claims.

| route | open | verify | proof bytes |
| --- | ---: | ---: | ---: |
| one batch of 16 | **1010 ms** | **4.84 ms** | **704** |
| 16 single openings | 9792 ms | 62.43 ms | 11264 |
| ratio | 0.10× | 0.08× | 0.06× |

Committing the 16 columns is 4128 ms and is shared by both routes, outside every timed
region. The batch is not quite 1/16 of the opening cost because it also pays for
materialising `f*` — 16 multiply-adds per coefficient over `2^20` coefficients — and for
one 16-point MSM.

## Artifacts

| Path | What | Kind |
| --- | --- | --- |
| `docs/spec/accumulator.md` | the normative accumulator specification | — |
| `docs/spec/mercury.md` §11 | the batching lemma, schedule and cost | — |
| `crates/pcs/tests/vectors/mercury_batch.txt` | a `k = 1` batched opening at `2^4`, with its probe | regression pin on §11's preamble |
| `crates/pcs/tests/vectors/z_pow_b_alpha.txt` | a harness-built instance with `α = z^b` | the edge case no honest run reaches |
| `crates/pcs/tests/vectors/accumulator.txt` | two deferred verifications, their words, their digest | regression pin on the accumulator layout |
| `tools/kat-gen/src/pcs.rs` | the generator (`cargo run -p kat-gen -- pcs`) | — |
| `tools/bench/src/mercury_batch.rs` | the acceptance-11 routine | — |

The three new files are pinned by SHA-256 beside their replayers — `batch.rs`,
`edge_cases.rs` and `accumulator.rs` — rather than all in `kats.rs`, so a fixture's pin
sits with the test that reads it. CI already diffs `crates/pcs/tests/vectors/` as a
directory, so the new files are regenerated and diffed with no CI change.

**`g1_absorb_kats.txt` and `mercury_proof.txt` are byte-identical to S08's.** That is the
mechanical proof of must-be-exact 7: rebuilding `verify` around a shared core changed no
challenge, no proof byte, and not the verifier's terminal sponge state.

`z_pow_b_alpha.txt` is the only new fixture with an independent half beyond the SRS: its
eight polynomials are built from their definitions with schoolbook arithmetic in kat-gen
and never pass through `open`.

## Verification performed

**341 workspace tests**, green in debug and release (301 from S08, unchanged except for
`structure.rs`'s rewritten source-level assertions; 40 new).

- **Every acceptance item above**, plus the extras named there.
- **An independent derivation pass before any code was written.** Six reviewers with
  disjoint lenses — the algebra of the twelve scalars derived from the papers, the batching
  argument and its transcript injectivity, the accumulator's soundness and wire form, the
  edge cases, everything S08 froze, and the `no_std` question below — each finding then put
  to a refutation attempt. It confirmed the twelve-row table term by term, confirmed the
  `(k−1)/|Fr|` bound and the exact degree of the error polynomial, confirmed the preamble's
  injectivity and that no extra scalar is needed, and produced two blocking findings, both
  about `discharge` and both acted on: it must validate every entry's point, and it must
  reject a bad partition without panicking or overflowing.
- **A third fixture implementation.** `tests/common/mod.rs` holds a second, naive
  transcription of the verifier's arithmetic — the schedule replay, `h(α)`, `D(z)` and all
  twelve entry scalars — written from the specification. `accumulator.rs` checks it against
  a live verification; `edge_cases.rs` drives it with forced challenges. Agreement is not a
  tautology: the crate reaches the same values through `bdfg::items` and an FFT-built `S`,
  and the transcription through Lagrange written out and schoolbook multiplication.
- **The `discharge` decoder against every malformed input** it can be handed: a count that
  overruns, `usize::MAX` as a count, a count wider than a `usize`, a bad side tag, a
  truncated group, a partial infinity sentinel in each of the four lanes, the all-zero
  quadruple, a limb at or above `2^128`, and an off-curve point. All errors, no panics.
- **Adversarial review of the finished tree**, five lenses with three refutation attempts
  per finding, including a mutation sweep. Results in *Findings* below.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean, with **no `#[allow]` in
  `crates/pcs` library code**.

## Deviations, both decided by the user

1. **`discharge` takes a third parameter.** The stage prompt freezes
   `discharge(vsrs, entries)`; this is `discharge(vsrs, entries, checks)`, where
   `checks[j]` is deferred check `j`'s entry count — the same numbers the wire's count
   words carry.

   The problem it solves is real. Must-be-exact 4 requires entries to be "grouped per
   deferred check, so the final verifier can weight each check with its own RLC challenge",
   and that weighting is not optional: two deferred checks with equal and opposite errors
   satisfy an unweighted sum *identically*, not with negligible probability
   (`accumulator.rs::the_per_check_weight_separates_the_checks` builds one). But
   `AccumulatorEntry` is frozen with no group field and the signature takes a flat slice,
   so the grouping has nowhere else to live. Recovering it by convention — "twelve entries
   per group", or "a group ends at its last `G2X` entry" — would make the wire's count word
   decoration and would bind a future group of a different size to a rule chosen today.

   **The user's instruction was to add an explicit input.** `accumulator_words` and
   `accumulator_from_words` carry the same pair, so the in-memory form and the wire form
   hold exactly the same information and are inverses.

2. **The factoring rule was not implemented.** The stage's Deliver section asks for pcs's
   field-side verification logic to be extracted into "a curve-free `#![no_std]`-compatible
   module that the recursion guest links". **The user's instruction was "Leave it be right
   now. Don't factor."**

   Everything else that rule was for is still here: `verify_deferred` and
   `batch_verify_deferred` exist, `bdfg.rs` lost its one curve-dependent function and is now
   curve-free, and `docs/spec/accumulator.md` §4 states the in-VM replay's obligation as a
   rule later stages cite. What does not exist is a module a guest can link, and no guest
   exists to link it.

   The user also asked, in the same breath, whether `crates/curve` and `crates/srs` could
   simply be made `no_std`. **Measured, not guessed** — a reviewer built a copy of
   `crates/curve` with `#![no_std]`, `extern crate alloc` and rayon deleted:

   - **`crates/curve` compiles for `riscv32imac-unknown-none-elf`** that way, and its full
     76-test suite passes. **rayon is the only thing forcing `std` in it** — there is no
     other `std::` reference in the crate.
   - **Deleting rayon costs a measured 8.6× on the MSM at `2^22`**, and 9.0× / 8.0× on
     Mercury `commit` / `open`. Anti-goal 1 bans cargo features, so "parallel for the
     prover, serial for the guest" cannot be a flag.
   - **`crates/srs` cannot be `no_std` as a whole.** `ptau.rs`, `save`/`load` and
     `validate` are irreducibly filesystem code. `SrsVerifier` and the `kzg` module are
     `core` + `alloc` and could move.
   - The smallest honest split is a **serial `curve::msm` with the ~15-line rayon fan-out
     moved up to `srs::kzg`**, measured at 0.81× of today's wall clock at `2^22` — i.e.
     slightly *faster*, because the chunking heuristic that fan-out currently applies is
     tuned for the wrong level.

   **Recommendation: do it as its own stage, not inside a Mercury stage.** It touches
   `crates/curve`'s public performance characteristics, it needs its own before-and-after
   benchmark, and the recursion guest that would consume it does not exist yet.

## Findings from the adversarial pass

Five reviewers with disjoint lenses — the mathematics derived from the papers, a malicious
prover, a line-by-line audit of the stage prompt, test vacuity and mutation testing, and
master-prompt compliance — each finding then put to three refutation attempts. The
adversary lens did not finish (it exhausted its budget mid-run); everything else did.

The math lens returned **clean on the arithmetic**: it derived the batching argument and
the deferred-scalar table from the papers before opening the source, and confirmed all
twelve rows term by term, the `(k-1)/|Fr|` bound and its exact degree, §11.1's injectivity
claim, and §6's discharge equation. The stage lens found every Deliver item, every
Must-be-exact clause and every Acceptance item satisfied. The master lens found no
anti-goal violated and nothing it would delete.

**Eight findings survived refutation. All eight were acted on.**

### The one that mattered

1. **`discharge`'s merge challenge had no coverage at all.** Four single-line mutants
   survived the whole suite: hard-coding `nu = 7`; digesting the wrong grouping; seeding
   the merge sponge with the words instead of their digest; and applying the group weights
   in reverse. The production code was right; nothing could see it change.

   The reviewer's proposed fix — build a two-group accumulator that balances only under the
   true `nu` — **is not constructible**, and working out why is the useful part. The
   balancing scalar is `-1/nu`; that scalar is one of the words the digest covers; `nu`
   comes from the digest. The construction chases its own tail, and no fixed pair of group
   errors separates the honest weighting from a reversed or constant one either.

   **Fixed two ways**, because the claim has an observable half and an unobservable one:
   - `tests/accumulator.rs::a_predictable_merge_challenge_would_be_forgeable` builds the
     forgery for a *guessable* `nu` — two false checks whose errors cancel exactly under
     the weights `1` and `7` — shows by hand that it passes against those weights, and
     asserts the real `discharge` rejects it. A `discharge` with a predictable challenge
     accepts it.
   - `tests/structure.rs::the_merge_challenge_is_derived_from_the_digest` pins the
     derivation at source level: the digest is over `accumulator_words(entries, checks)`,
     the sponge is seeded with `digest`, `nu` is one challenge under `ACCUMULATOR_MERGE`,
     and the weights reach the merge as `&crate::powers(nu, checks.len())` and nothing
     else. That is the instrument S08 used on the pairing-merge challenge, for the same
     reason and with the same justification.

   All four mutants are now killed; a reworded-comment control still survives.

### The rest

2. **`docs/spec/accumulator.md` §4 stated an ordering the code did not have.** §4 is the
   section later stages are told to cite, and it said validation runs "before the digest,
   before the merge challenge, and before any group operation" — but `discharge` validated
   inside `check_pairings`, after both. **Fixed by making the code true**: `discharge` now
   calls `validate` as its first statement. `check_pairings` keeps its own call, because
   `verify` and `batch_verify` reach it directly.
3. **`docs/spec/mercury.md` §11.1 rule 4 mislabelled `rho = 0`** as "a completeness
   accident". It is a soundness event, already counted as one of the error polynomial's
   `k-1` roots. **Fixed**, with the contrast to §7's `z` rule spelled out.
4. **`PcsError::MalformedAccumulator` carried two unit systems in one variant.**
   `partition` filled `entries`/`declared` with entry counts; `accumulator_from_words`
   filled the same fields with a word count and a word index, so a corrupted count word
   reported "146 entries, 73 declared" — wrong twice. **Fixed** by renaming the fields to
   the unit-neutral `length`/`at`, and saying in the doc comment which unit each caller
   means. The variant is new this stage, so nothing was frozen.
5. **`small_usize`'s 64-bit bound was unpinned.** Widening it to 96 bits was invisible: the
   unit test probed 0, 12, `u64::MAX`, `~2^254` and `2^128 + 1`, every one of which gives
   the right answer for a bound anywhere between byte 12 and byte 16. The untested interval
   is exactly where truncation turns an absurd count into a plausible one. **Fixed**: `2^64`
   and two neighbours in the unit test, and a decoder-level case whose count word is `2^64`.
6. **`assert_eq!(proof.to_bytes().len(), PROOF_BYTES)` is a tautology** — `to_bytes` returns
   `[u8; PROOF_BYTES]`, so the length is a fact about the type. **Fixed**: every one of
   those is now a round trip through `from_bytes`, which validates every point and every
   value and can fail. The constant is still checked once against the shape it claims.
7. **Three assertions compared a local constant against itself**, and two comments
   overclaimed what the line beneath them checked. **Fixed**: the schedule claims are now
   made against the source (`schedule("batch_preamble").last()`, and the same for the
   core's `PAIRING_MERGE`), the redundant arithmetic line is gone, and the two comments say
   what is actually asserted — that reordering two *true* checks is accepted, and that what
   distinguishes the orders is the digest.
8. **"An empty accumulator discharges successfully" was normative and untested.** It is
   right — an empty conjunction of relations is true — but it held only because
   `curve::msm` short-circuits an empty slice and `pairing_check` is vacuously true on two
   infinities, either of which a later stage could change into a panic out of the final
   verifier. **Fixed**: asserted directly, for `&[]` and for two empty groups.

### The mutation sweep

34 single-line mutants against `crates/pcs/src/{lib,accumulator}.rs`, each reverted after
its run, with a reworded-comment control that must survive and does. Thirty were killed on
the first pass — swapped entry scalars, a dropped `rho` factor, a negated scalar, entry 9
with half its scalar, a preamble that squeezes before it absorbs, `rho^(i+1)` weights, a
`discharge` that weights every group by 1, a dropped validation loop, an omitted count
word, a limb decoder that accepts the all-zero quadruple, a partition that does not
exhaust — by the independent second transcription in `tests/common/mod.rs`, the committed
fixtures, and the decoder's unit tests. The four survivors were finding 1 and the fifth was
finding 5; all five are killed now.

## Open for the next stage

- **Shard provers call `batch_open` once per shard**, passing the commitments produced in
  their commit phase, at the point their final claim-merging sumcheck reduced to.
  `crates/pcs/tests/sumcheck_bridge.rs` is that flow end to end at `2^8`, including the
  transposed-point negative control.
- **`AccumulatorEntry` lists are produced ONLY by deferred verification** —
  `verify_deferred` and `batch_verify_deferred` — during recursion, and discharged at the
  very end. **`ShardProof` and `BlockProof` carry no accumulator entries**, because base
  verification executes its pairings inside `pcs`.
- **The recursion guest's one hard problem is `cm*`.** §11's preamble absorbs it at
  schedule step 2, so a batched verification cannot proceed without its limbs, and deriving
  them is a `k`-point MSM the guest may not do. `docs/spec/accumulator.md` §8 states the two
  options and picks neither; the wire's per-group count word exists so that both are
  representable.
- **`transcript_tags` has 19 entries.** Later stages append; they never renumber and never
  reuse a tag across message kinds. `crates/transcript/tests/duplex.rs` now asserts the
  table is sequential from 1 with no holes, so an allocated-but-unregistered tag fails.
- **There is still no SRS digest.** `docs/spec/srs.md` §4: nothing binds a proof to a
  particular SRS, and an accumulator inherits that — its entries name points, and which SRS
  they came from is not part of the statement.
