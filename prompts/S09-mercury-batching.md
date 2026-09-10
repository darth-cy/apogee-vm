---
title: S09-mercury-batching.md

---

# S09 — Mercury II: RLC batching, transcript integration, accumulator extraction

Provided reference: `sources/2025-385.pdf` (Mercury) and ePrint 2020/081 (BDFG20) in `./sources/publication`.

## Depends on / Inputs
- S08's `pcs` supplies `MercuryCommitment`, `MercuryProof`, `commit`/`open`/`verify`, and `docs/spec/mercury.md`, holding the transcript schedule, the BDFG20 pins and the z ∈ F* rule. S08 also froze the typed G1-limb absorption: `append_g1` writes 2×~128-bit limbs per affine coordinate, 4 Fr per point, infinity sentinel per `constants::G1_INFINITY_SENTINEL`.
- S02's `transcript` supplies `Transcript`, the typed framing and the tag table in `constants`.
- S04's `sumcheck` supplies the prover and verifier, used only in the cross-check test of Acceptance 4.
- S01/S03/S05/S06/S07 supply `Fr`, `MultilinearPoly`, the curve, the pairing, the MSM and `Srs`.

## Deliver
In `pcs`:
```rust
pub fn batch_open(srs: &Srs, cols: &[MultilinearPoly], cms: &[MercuryCommitment], u: &[Fr], tr: &mut Transcript)
    -> Result<(Vec<Fr>, MercuryProof), PcsError>;
pub fn batch_verify(vsrs: &SrsVerifier, cms: &[MercuryCommitment], u: &[Fr], vs: &[Fr],
    proof: &MercuryProof, tr: &mut Transcript) -> Result<(), PcsError>;
pub struct AccumulatorEntry { pub side: PairingSide, pub scalar: Fr, pub point: G1Affine }
pub enum PairingSide { G2One, G2X } // pairs against [1]_2 vs [x]_2
pub fn verify_deferred(/* same params as verify */) -> Result<Vec<AccumulatorEntry>, PcsError>;
pub fn batch_verify_deferred(/* same params as batch_verify */) -> Result<Vec<AccumulatorEntry>, PcsError>;
pub fn discharge(vsrs: &SrsVerifier, entries: &[AccumulatorEntry]) -> Result<(), PcsError>; // RLC + MSM + 2 pairings
```
Per S08's rule, `batch_verify`, `verify_deferred`, `batch_verify_deferred` and `discharge` each take S07's frozen `&SrsVerifier`, not `&Srs`. `batch_open` keeps the full `&Srs`.

A factoring rule comes with that. Factor pcs's field-side verification logic, meaning the deferred-scalar computation and the transcript schedule replay, into a curve-free `#![no_std]`-compatible module that the recursion guest links. Inside it, G1 points are opaque 4-Fr limb blobs. Curve-dependent commit, open and discharge stay std-side.

You also deliver a batching-lemma section appended to `docs/spec/mercury.md`, a new `docs/spec/accumulator.md`, and Mercury and accumulator tags added to `constants`.

## Core algorithm
**Batching.** This argument is not in the paper: k same-size column commitments opened at ONE point u. `batch_open` absorbs the PASSED commitments through `append_g1_list` as one length-delimited message, and derives cm* = Σ ρ^i·cm_i homomorphically from them; it never recommits. Absorb all k commitments, u, and all k claimed values (one message), then squeeze ρ. Combine cm* by homomorphic KZG linearity and v* = Σ ρ^i·v_i. The prover forms f* = Σ ρ^i·f_i and runs ONE S08 single-poly opening of (cm*, u, v*). Materialize f* into one column, combining rows in parallel with rayon; recombining lazily inside the opening would multiply k into every pass S08 makes over the polynomial. Results must not depend on thread count or scheduling.

**Deferral.** S08 pinned both pairing checks in the shape e(A,[1]_2)=e(B,[x]_2), with A and B verifier-derivable as small MSMs of proof elements with known scalars. `verify_deferred` runs the identical verification computation. Instead of executing the pairings it emits those MSM terms as `AccumulatorEntry` items of the form (side, scalar, G1 point). A downstream verifier does zero group ops until final discharge, which applies a per-check RLC weight, one MSM per side and one 2-pairing check. between discharges: concatenation only, never combination.

Structure this as one verification core. One routine runs every field-side check and emits the two per-side term sets; its caller either executes the pairings or returns the entries. The batch paths reach it after deriving cm* and v*.

## Must-be-exact
1. **Batching lemma in mercury.md.** State it for same-size columns opened at one point, and sketch the proof from KZG homomorphism plus Schwartz–Zippel over ρ, which adds at most (k−1)/|F| soundness loss. Pin the rule that ρ is squeezed only AFTER all commitments AND all claimed values are absorbed.
2. **Transcript integration.** Every absorption is typed TYPE/LABEL/LENGTH per message, never per scalar. All tags are frozen in `constants`. G1 points are absorbed as 4 Fr limbs with the infinity sentinel `constants::G1_INFINITY_SENTINEL` from S08, never as compressed bytes. The commitment list is length-delimited.
3. **Edge cases handled and spec'd.** (a) z is squeezed from F*, so resample on zero per the S08 rule, using a unit-testable draw helper. (b) z^b = α is legal and must verify, because the (z^b−α)q term vanishes. (c) The zero polynomial commits to the point at infinity, and byte-wire serialization of an infinity commitment follows S05's frozen all-zero 64-byte affine encoding. `constants::G1_INFINITY_SENTINEL` applies ONLY where points are expressed as transcript or accumulator Fr limbs (S08 absorption, the accumulator.md entry format). Then commit/open/verify/batch all succeed on it. (d) Identity-point serialization round-trips everywhere a G1 point crosses a wire, and a corrupted infinity encoding is a deserialization error.
4. **`AccumulatorEntry` — FROZEN.** Its wire form lives in `docs/spec/accumulator.md` as a raw list of (scalar, G1-limb) entries. The scalar is canonical 32-byte LE Fr, and the point is affine limbs in S08's 4-Fr encoding, with infinity written as `constants::G1_INFINITY_SENTINEL` from S08. Each entry is tagged with its `PairingSide`. Entries are grouped per deferred check, so the final verifier can weight each check with its own RLC challenge before the merged MSM. Write the discharge semantics as an equation in the spec, and commit byte-exact test vectors. Concatenation of two lists is a valid list. The hash-binding rule is frozen here, once. The accumulator digest = Poseidon2 over the canonical wire bytes of the length-delimited concatenated entry list, laid out exactly as docs/spec/accumulator.md has them. Poseidon2 here is the transcript-crate sponge under a dedicated tag in constants, and a digest test vector is committed. Later stages cite this rule.
5. **One verification path**: `verify_deferred`/`batch_verify_deferred` share all logic with `verify`/`batch_verify` up to the single execute-pairings-versus-emit-entries branch. All field-side checks (evaluations, derived D_z and h_α) still run in deferred mode; only pairings are deferred. On-curve and subgroup checks run in the NATIVE deferred verifier. The in-VM replay binds claimed limbs only and performs no curve math. Validation of every accumulator point is guaranteed at final discharge. State this rule once in `docs/spec/accumulator.md` so downstream stages cite one rule.
6. Degenerate batch inputs give an error and never a panic: k=0, `cms.len() != cols.len()` in `batch_open`, mismatched `cms`/`vs` lengths, mixed column sizes.
7. You change no signature and no serialization of anything S08 froze; extensions to it are additive.
8. **Accumulator framing.** `docs/spec/accumulator.md` encodes the list as a flat array of canonical 32-byte LE Fr words, so a replay needs no byte-level decoding and Must-be-exact 4's digest absorbs those same words. Each per-check group opens with one word holding its entry count. Each entry is six words and a constant 192 bytes: the `PairingSide` tag, written 0 for `G2One` and 1 for `G2X`, then the scalar, then the four point limbs. The file carries no header and no total count, so byte concatenation of two lists is itself a valid list.

## Acceptance
1. Batched round-trip: k=8 random 2^16 columns at one random u give Ok from `batch_open` and `batch_verify`, and each returned v_i equals its column's `MultilinearPoly::evaluate(u)`.
2. Witness-tamper twin: flip ONE evaluation in ONE column after the commitments are absorbed, re-open honestly, and `batch_verify` fails. Three more must fail: one claimed v_i perturbed; two commitments swapped in the list (order binding); k reported as k−1 with one commitment dropped (length binding).
3. Consistency: a batch of k=1 verifies, and its transcript schedule matches the spec'd batch schedule (fixture-pinned bytes).
4. **Sumcheck round-trip cross-check (the #1 integration bug)**: run the S04 sumcheck prover and verifier over a random committed `MultilinearPoly` to produce a reduced claim (point r, value c), then open the commitment at r via Mercury. Assert the opened value equals both c and `MultilinearPoly::evaluate(r)`, with NO coordinate reversal outside the one convention documented in mercury.md. A deliberately transposed r (u1/u2 swapped) must fail — negative control.
5. z resample: a unit test of the draw helper shows that a zero squeeze is rejected and the next squeeze used, matching the mercury.md rule.
6. z^b = α vector: a harness-constructed instance with α forced equal to z^b passes all verifier equations and is committed as a fixture. The forcing is a test-only bypass of the challenge draw; the production path stays untouched.
7. Zero polynomial: commit yields the point at infinity (S05's all-zero 64-byte affine wire encoding); single and batched openings including a zero column verify; a corrupted infinity encoding gives a deserialization error (negative control).
8. Deferred equivalence: over a corpus of honest AND tampered proofs (reuse the S08 tamper sweep), `verify` and `verify_deferred`+`discharge` return the same Ok/Err class in every case; likewise the batch variants.
9. Accumulator vectors: byte-exact `AccumulatorEntry` list fixtures for two independent verifications, whose concatenation discharges with exactly one MSM per side plus one 2-pairing check. CI regenerates them and diffs against accumulator.md's layout. Add a committed digest test vector for the accumulator hash-binding rule (Must-be-exact 4) over the concatenated list.
10. Structural: the entry byte length is constant, the batched proof shape is identical to `MercuryProof` with no data-dependent sections, and all new tags are present in `constants` with no duplicates.
11. Bench printout (internal only, no public claims): the bench opens 16 × 2^20 columns as one batch, then as 16 single openings, and prints both wall-clocks.

## Handoff
Freeze the six signatures above, plus `AccumulatorEntry` and `PairingSide`. Those two are FROZEN FOREVER, and the handoff must say so. Freeze `docs/spec/accumulator.md`, the completed `docs/spec/mercury.md` with its batching lemma and batch transcript schedule, the new tags and all fixture paths. Note three things for later prover stages. Shard provers call `batch_open` once per shard, passing the commitments produced in their commit phase. AccumulatorEntry lists are produced ONLY by deferred verification (`batch_verify_deferred`) during recursion, and discharged at the very end. ShardProof and BlockProof carry no accumulator entries, because base verification executes its pairings inside pcs.