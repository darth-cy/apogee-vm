---
title: S08-mercury-single-poly.md

---

# S08 — Mercury I: single-polynomial commit / open / verify

Provided reference: `sources/publication/2025-385.pdf` (Mercury, Eagen–Gabizon), whose §6 is the normative protocol, and ePrint 2020/081 (BDFG20), whose §3–4 give the batched-KZG finish.

## Depends on / Inputs
- S01 `field` provides `Fr`.
- S02 `transcript` provides `Transcript`, the source of all challenges. G1 absorption is NOT provided by S02, which deliberately excludes it; this stage implements and freezes it (see Deliver).
- S03 `poly` provides `MultilinearPoly` in evaluation form under the little-endian index convention, including the frozen `backing()` accessor (`PolyBacking`).
- S05/S06 `curve` provide `G1Affine`, `G1Projective` and `pairing_check`.
- S07 provides `curve::msm` (Pippenger, including `msm_small_u32`) and `srs`: `Srs` (powers through 2^24), `SrsVerifier` (`Srs::verifier()`), and the KZG commit/open core.

## Deliver
Build the crate `pcs` with:
```rust
pub struct MercuryCommitment(pub G1Affine);
pub struct MercuryProof { /* exactly 8 named G1Affine + 6 named Fr, fixed field order */ }
pub fn commit(srs: &Srs, f: &MultilinearPoly) -> Result<MercuryCommitment, PcsError>;
pub fn open(srs: &Srs, f: &MultilinearPoly, cm: &MercuryCommitment, u: &[Fr], tr: &mut Transcript)
    -> Result<(Fr, MercuryProof), PcsError>;
pub fn verify(vsrs: &SrsVerifier, cm: &MercuryCommitment, u: &[Fr], v: Fr,
    proof: &MercuryProof, tr: &mut Transcript) -> Result<(), PcsError>;
```
`verify` takes S07's frozen `&SrsVerifier`, not `&Srs`, while `commit` and `open` keep `&Srs`. The same substitution applies to every S09 verifier-side function.

Deliver too the typed G1-limb absorption frozen in S08, implemented here in `pcs` as an additive extension of S02's typed layer:
```rust
pub fn append_g1(tr: &mut Transcript, tag: Tag, p: &G1Affine);
pub fn append_g1_list(tr: &mut Transcript, tag: Tag, ps: &[G1Affine]);  // list = ONE typed length-delimited message of 4·k Fr limbs
```
`append_g1` absorbs 2×~128-bit limbs per affine coordinate, so 4 Fr per point, with the infinity sentinel per `constants::G1_INFINITY_SENTINEL`. Spec the encoding normatively in `docs/spec/mercury.md`, as a transcript addendum. S09 cites `append_g1_list` for its commitment-list absorption.

Also deliver `docs/spec/mercury.md` (new): the protocol steps, the variable-order convention, the full single-opening transcript schedule, the BDFG20 challenge schedule, the pairing-merge RLC and the z ∈ F* rule.

## Core algorithm
Follow Mercury §6, exactly. The coefficient layout places f_{i,j} at X^{i+j·b} with i the LEAST significant digit; n = 2^{2t} and b = 2^t.

Open at u in four rounds. (1) Send h = [h(x)] for h(X) = Σ_{i<b} eq(i,u1)·f_i(X). (2) Take challenge α and fold f(X) = (X^b−α)q(X)+g(X) by b independent Horner divisions, yielding g_i = f_i(α) in O(n) field ops with no size-n FFT; send q and g. (3) Take challenge γ and run the batched symmetric inner-product argument with tensor polynomial Pu(X) = Π(u_i X^{2^i}+1−u_i), proving ĝ(u1)=h(α) and ĥ(u2)=v via one S (a size-2b FFT), plus the degree check D(X)=X^{b−1}g(1/X); send s and d. (4) Take challenge z and send the 6 evaluations g_z, g_{1/z}, h_z, h_{1/z}, s_z, s_{1/z}. The verifier derives D_z = z^{b−1}g_{1/z} and h_α from the symmetrized identity. Send π_z for the quotient H(X)=(f(X)−(z^b−α)q(X)−g_z)/(X−z), then finish with a BDFG20 batched KZG opening of g@{z,1/z}, h@{z,1/z,α}, S@{z,1/z} and D@{z}. The verifier evaluates Pu1 and Pu2 at z and 1/z by the O(t) product formula, and merges its two pairing checks with an RLC challenge into one `pairing_check` call.

Hold polynomials as dense coefficient `Vec<Fr>` in little-endian index order. Take the b blocks f_i as strided views over f's evaluation vector rather than copies, and build the eq(i,u1) tensor once as an O(b) table through S03's frozen eq machinery. Implement the size-2b FFT as an iterative radix-2 Cooley–Tukey transform with precomputed twiddles over the 2b-th root of unity in Fr's two-adic subgroup, and its inverse on inverted twiddles scaled by (2b)^{-1}. Accumulate in `G1Projective` and batch-invert to `G1Affine` once per batch, since only affine coordinates are absorbed or serialized. Apply rayon to the two size-~n MSMs and the b Horner divisions, and keep the size-2b FFT serial as it sits off the hot path. Every result must be independent of thread count and scheduling. `PcsError` is one crate-wide enum with a variant per failure the acceptance list names.

## Must-be-exact
1. **Even variable count enforced**: `commit`, `open` and `verify` reject any u with odd length and any f whose size is not 2^{2t}, returning an error — never a panic, never silent padding. Support at minimum the master's height menu {2^16, 2^18, 2^20, 2^22} plus even-variable small test sizes {2^2, 2^4, 2^6, 2^8}.
2. **Variable-order convention** (the #1 integration bug — pin it in `docs/spec/mercury.md`): u = (u1, u2), where u1 is the FIRST t coordinates (u_0..u_{t−1}), the low-order variables matching the least-significant coefficient index i. Index the multilinear identically to `MultilinearPoly::evaluate`, with i in little-endian binary. One round-trip test (Acceptance 1) proves `verify`'s v equals `MultilinearPoly::evaluate(u)`.
3. **Prover cost shape**: compute q and H by Horner division, O(n) field ops each, and S by one size-2b FFT plus inverse. No FFT anywhere may exceed 2b. The opening MSMs are 2 of size ~n plus O(1) of size ~b.
4. **Transcript schedule**: spec it in mercury.md, keep the tags in `constants`, and frame every message per master. The order is: absorb (n, cm, u, v), then h; squeeze α; absorb q and g; squeeze γ; absorb s and d; squeeze z; absorb the 6 evaluations as one message; draw the BDFG20 challenges. Squeeze the pairing-merge RLC challenge last, after ALL proof elements are absorbed. `open` absorbs the PASSED `cm` and never recommits.
5. **BDFG20 internals pinned in mercury.md** — the paper leaves them implicit. The BDFG20 opening-batch challenge, its second evaluation point, its linearization, its 2 G1 proof elements and the pairing-merge RLC challenge each get an exact squeeze position and tag. This section of mercury.md is normative for S09 and the recursion stages.
6. **z ∈ F***: the spec defines squeeze-and-resample-on-zero for z (1/z must exist). Write the rule now; the dedicated tests land in S09.
7. **Fixed proof shape**: the proof carries exactly 8 G1 + 6 Fr in named fields, with no options, and serializes as canonical 32-byte LE. Rewrite both verifier pairing checks into e(A,[1]_2)=e(B,[x]_2) form, keeping the verifier G1-only with no G2 arithmetic beyond the two SRS points.
8. `verify` performs on-curve and subgroup checks on every deserialized proof point before use.
9. **Typed G1-point transcript absorption is implemented here**, as an additive extension of S02's typed layer. `append_g1` absorbs affine coordinates as 2×~128-bit limbs each, 4 Fr per point, and the infinity-sentinel encoding is pinned as a named constant `constants::G1_INFINITY_SENTINEL`. Spec that encoding normatively in `docs/spec/mercury.md`.
10. `commit` dispatches on `PolyBacking` (S03's frozen `backing()` accessor): the U1/U8/U16/U32 backings go through `curve::msm::msm_small_u32` on the raw integers, widened and never lifted to Fr, and only the Fr backing uses the general msm.
11. **Pairing-check merge**: by default `verify` merges its two pairing relations into one 2-pairing `pairing_check` call. Computing them separately inside `verify` stays acceptable, provided the pairing-merge RLC challenge is squeezed where Must-be-exact 4 fixes it. Either way, this is the shape Must-be-exact 7 hands S09.

## Acceptance
1. Round-trip: a random f at n=2^16 gives commit/open/verify Ok, and the opened v equals `MultilinearPoly::evaluate(u)` for a random u (proving the variable-order convention end to end). Differential oracle: `pcs::commit(f)` equals S07's KZG commit of f's evaluation vector taken as coefficients (a Mercury commitment IS the plain KZG commitment — exact equality, no tolerance).
2. All menu sizes: commit/open/verify pass at 2^16, 2^18, 2^20 and 2^22.
3. Odd variable count: a size-2^15 input and a 15-element u each return an error; no panic.
4. Witness-tamper twin: flip ONE evaluation of f and re-run `open` honestly against the ORIGINAL commitment; verify fails.
5. Proof-tamper sweep: perturb each of the 14 proof fields (8 G1, 6 Fr) individually; verify fails for every one.
6. Statement tamper: verify with v+1 fails; verify at a u differing in one coordinate fails; verify with u1/u2 halves swapped fails (the order-convention negative control).
7. Internal identities on a small random instance (t ≤ 3), checked directly: g's coefficients equal f_i(α); ĥ(u2) = f̂(u1,u2); the symmetrized inner-product identity holds at random points; D(X)=X^{b−1}g(1/X) as polynomials. Differential oracle: at t=1 (n=4) the whole protocol is cross-checked against a naive direct implementation of every polynomial identity.
8. Transcript binding: opening the same (f,u) twice yields byte-identical proofs; changing any absorbed input (cm, u, v) changes α.
9. Committed test vector: the full proof bytes for a fixed f at n=2^4 are checked in as a fixture; CI regenerates and diffs them, freezing the transcript schedule.
10. Structure assertions: no FFT size > 2b is reachable in `open` (assert it); the proof byte length is constant per n.
11. Bench printout, with no public claims: print wall-clock commit/open/verify at 2^22, plus MSM-size accounting showing opening cost ≈ 2n + O(√n) scalar mults. Also print commit wall-clock for a U32-backed vs an Fr-backed column of equal values at 2^22; the small-backed commit must be faster.
12. Committed KAT for `append_g1`: one known G1 point and the infinity point absorb to their expected Fr limbs, and a 2-point `append_g1_list` case, one length-delimited message of 8 Fr limbs, absorbs to its expected limbs. Both live in a fixture file, and tests replay them byte-exact.

## Handoff
Freeze `MercuryCommitment`, `MercuryProof` with its field names and serialization, the three signatures above, and the `PcsError` variants they use. Freeze the typed G1-limb absorption that `pcs` gains here in S08. `append_g1` and `append_g1_list` take 2×~128-bit limbs per affine coordinate, so 4 Fr per point. A list is one typed length-delimited message of 4·k Fr limbs, and the infinity sentinel is `constants::G1_INFINITY_SENTINEL`. Freeze the single-poly sections of `docs/spec/mercury.md`: protocol, variable-order convention, transcript schedule with its G1-absorption addendum, BDFG20 pins and the z ∈ F* rule.