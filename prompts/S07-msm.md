---
title: S07-msm-srs-kzg.md

---

# S07 — Pippenger MSM + ptau Ingestion + KZG Toy

Prepare asset: a snarkjs `.ptau` format description (section layout, point encoding) AND a perpetual-powers-of-tau / Hermez ceremony `.ptau` file of power ≥ 24. See: https://github.com/iden3/snarkjs/blob/master/README.md

## Depends on / Inputs

- S01 `field`: `Fr` and `constants`.
- S05 `curve`: `Fq`, `G1Affine`, `G1Projective` (including `add_affine` and `batch_to_affine`), and `G2Affine`.
- S06 `curve::pairing`: `pairing_check`.

## Deliver

You deliver the module `curve::msm` and the new crate `srs`. This stage carries carry performance expectations: MSM is the prover's second-largest cost.

Frozen public API:

```rust
// curve::msm
pub fn msm(bases: &[G1Affine], scalars: &[Fr]) -> Result<G1Projective, MsmError>;      // len mismatch → Err
pub fn msm_small_u32(bases: &[G1Affine], scalars: &[u32]) -> Result<G1Projective, MsmError>;
// (u16 inputs go through msm_small_u32; a separate u16 entry is optional)

// srs
pub struct Srs { /* g1 powers [x^0..x^(n-1)], g2_gen = [1]_2, g2_tau = [x]_2, cached digest */ }
impl Srs {
    pub fn from_ptau(path: &Path, power: u32) -> Result<Srs, SrsError>;  // snarkjs .ptau, first 2^power G1 powers + 2 G2 points
    pub fn validate(&self) -> Result<(), SrsError>;                      // structure check via pairing_check (see below)
    pub fn max_degree(&self) -> usize;
    pub fn save(&self, path: &Path) -> Result<(), SrsError>;             // own archive format (fast reload, digest included)
    pub fn load(path: &Path) -> Result<Srs, SrsError>;
    pub fn g1(&self) -> &[G1Affine];
    pub fn g2_gen(&self) -> G2Affine;  pub fn g2_tau(&self) -> G2Affine;
}

pub struct SrsVerifier { pub g1_gen: G1Affine, pub g2_gen: G2Affine, pub g2_tau: G2Affine, pub digest: [u8; 32] }  // canonical-LE serde
impl Srs { pub fn verifier(&self) -> SrsVerifier; }

// srs::kzg (the univariate core Mercury builds on in S08)
pub fn kzg_commit(srs: &Srs, coeffs: &[Fr]) -> Result<G1Affine, SrsError>;              // deg ≥ SRS size → Err
pub fn kzg_open(srs: &Srs, coeffs: &[Fr], z: Fr) -> Result<(Fr, G1Affine), SrsError>;   // (f(z), [q(x)] with q = (f−f(z))/(X−z))
pub fn kzg_verify(srs: &Srs, cm: &G1Affine, z: Fr, v: Fr, w: &G1Affine) -> bool;        // one pairing_check, G1-only rewrite
```

## Core algorithm

- **MSM.** Use windowed Pippenger: bucket accumulation per window with mixed adds (`add_affine`), bucket reduction by running sum, window combination by doublings. Window width follows a size heuristic: w = 3 for n < 32, otherwise ⌊(log₂ n × 69)/100⌋ + 2. That is the arkworks rule (integer ln n + 2), so gate 9 compares like with like. Recode digits signed into [−2^(w−1), 2^(w−1)], halving each window to 2^(w−1) `G1Projective` buckets. Affine negation is one `Fq` negation, so the sign costs nothing. Rayon parallelizes across windows, plus per-thread input chunks when windows are fewer than threads. Precomputed base tables stay off by default: 2^24 affine bases already cost about a gigabyte. Add them only if gate 9 needs them, and record that in the handoff. **Small-scalar fast path**: u16/u32-bounded scalars are the dominant case, since S03 trace columns are U8/U16/U32-backed. They need only ⌈32/w⌉ windows and no Montgomery decomposition of scalars. This path is separate code, not the general one fed small numbers.
- **ptau ingestion.** Parse the snarkjs container per the provided format doc. Extract the first 2^power tauG1 points and the first two tauG2 points, converting from the file's point representation to `G1Affine`/`G2Affine`. S05 `from_bytes` validation semantics apply to every point: on-curve plus subgroup, or a hard error. The required capability is power = 24, i.e. 2^24 G1 powers: the master trace-height ceiling 2^22 plus Mercury quotient headroom. **The snarkjs `.ptau` format from the perpetual-powers-of-tau / Hermez ceremony is THE frozen ingestion format** — no other ceremony format in v1.
- **`validate()`.** Check structural τ-consistency with one RLC pairing check. Draw random c_i. OS randomness is fine here: this is local validation, not a protocol transcript. Check e(Σ cᵢ·[xⁱ], [x]₂) = e(Σ cᵢ·[x^(i+1)], [1]₂) over i < n−1, which costs two MSMs and one `pairing_check`. Also check that g1[0] is the G1 generator.
- **`digest()`.** Run Poseidon2 (S02 permutation) over the canonical serialization of all points plus the power. Document the exact absorb schedule in `docs/spec/srs.md` (new). The digest is absorbed in statement binding and frozen forever after this stage. The archive format is pinned too: an 8-byte magic, a u32 version, the power, the G1 count, the two G2 points, the digest, then the G1 points in canonical LE order. `load` reads the whole file eagerly: no mmap, no lazy loading, since it re-hashes every point anyway.
- **`SrsVerifier`.** `SrsVerifier { g1_gen: G1Affine, g2_gen: G2Affine, g2_tau: G2Affine, digest: [u8; 32] }` is frozen in S07 via `Srs::verifier()` and is the ONLY SRS material any verifier path may require. The full `&Srs` stays prover-side.
- **KZG.** Commit is one MSM over the coefficients. Open is Horner synthetic division for q, then one MSM. Verify is rewritten G1-only as e(cm − v·[1] + z·w, [1]₂) · e(−w, [x]₂) = 1 via `pairing_check` — the deferrable shape.

`MsmError` and `SrsError` are plain enums, one per crate, with a variant per failure class in Must-be-exact 1 and 3 name.

## Must-be-exact

1. `msm` handles empty input (identity), length mismatch (Err), scalars = 0, bases = ∞ interspersed, a single element, and all-identical scalars. No panics.
2. `msm_small_u32(b, s)` ≡ `msm(b, lift(s))` for all inputs, and is measurably faster on u16/u32-range data (shown in the bench table).
3. `from_ptau` rejects truncated files, wrong magic or section structure, any point failing S05 validation, and a requested power exceeding the file's. It errors, never panics.
4. `validate()` passes on the real ceremony file and fails on any single corrupted point.
5. `digest()` is deterministic across runs and machines, changes if any point changes, and is spec'd normatively in `docs/spec/srs.md`.
6. `save`/`load` round-trips bit-exactly, stores the digest, and `load` re-verifies the digest against the stored points.
7. KZG obeys `kzg_verify(commit(f), z, f(z), open-proof) = true` for deg(f) up to SRS size − 2; degree overflow is an Err at commit time.
8. Fixtures come from the committed dev-tool: it generates MSM vectors and KZG vectors from arkworks-bn254, you commit them hash-pinned, and tests only read files.
9. `msm` always runs the general path and never auto-dispatches on small scalars. `msm_small_u32` is the only entry to the small path.

## Acceptance

1. **MSM differential fixtures.** Commit arkworks vectors at sizes 1, 2, 100, 2^10 and 2^16 with random Fr scalars, including the cases from Must-be-exact 1; the owned `msm` matches them all.
2. **Live differential test.** Check at least 100 random MSMs of mixed sizes ≤ 2^12 against arkworks `VariableBaseMSM` in one test run.
3. **Small-path equivalence.** Check `msm_small_u32` ≡ `msm` on random u16-range and u32-range scalar sets at sizes up to 2^14, plus all-zero and single-bit scalar sets.
4. **ptau ingestion.** The real ceremony file loads at power 24; g1[0] is the generator, g1 length is 2^24, both G2 points are subgroup-valid, and `validate()` passes.
5. **Ingestion negative controls.** A dev-tool-produced corrupted copy (one flipped point byte) fails `validate()`, a truncated copy fails `from_ptau`, and each error class of Must-be-exact 3 is exercised.
6. **Digest + archive.** The digest is stable across two ingestion runs, save → load → digest is identical, and a tampered archive fails `load`'s digest re-verification.
7. **KZG round-trip + differential.** Commit, open and verify are Ok for random f at degrees {1, 100, 2^10, 2^16}, and commitments match arkworks KZG on the same SRS prefix (committed fixtures).
8. **KZG tamper twins.** (a) Witness tamper: open honestly for an f' differing from the committed f in ONE coefficient, then verify against commit(f) → false. (b) Verify with v+1 → false. (c) Verify with a perturbed proof point → false. (d) Verify at z+1 → false.
9. **PERFORMANCE GATE** Time the owned `msm` at 2^22 random Fr scalars over real SRS bases on the dev machine. Its wall-clock lands within 2× of arkworks-bn254, run on the same machine and data, both timed in one harness run. Record both sides' numbers, the machine spec and the window config in the handoff. Fail ⇒ stage not done.
10. **Small-path bench.** In the same harness at 2^22 with u32-bounded scalars, the small path beats the general path. Both numbers go in the handoff.
11. **Negative control.** One corrupted fixture byte fails the corresponding test. Run this once and note it in the handoff.

## Handoff

Write `docs/handoff/S07-msm-srs-kzg.md`. Record the frozen APIs as implemented, including `SrsVerifier` and `Srs::verifier()`, the only SRS material any verifier may require. Point at `docs/spec/srs.md` for the digest schedule, archive format and frozen ptau ingestion statement. List fixture paths and the full Acceptance 9/10 bench table. Give the ceremony file's provenance as source URL plus file hash.