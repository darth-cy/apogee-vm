//! Mercury: a multilinear polynomial commitment scheme over a KZG SRS.
//!
//! Eagen and Gabizon, ePrint 2025/385 §6, finished with the batched KZG opening
//! of Boneh, Drake, Fisch and Gabizon, ePrint 2020/081 §4. The normative
//! document is `docs/spec/mercury.md`; this crate is that specification in
//! code, and nothing else.
//!
//! A commitment is a plain univariate KZG commitment to the polynomial whose
//! **coefficients are the multilinear's evaluation table**, in
//! `crates/poly`'s frozen little-endian index order. An opening at
//! `u = (u1, u2)` costs `O(n)` field operations and `2n + O(sqrt n)` scalar
//! multiplications, and is a fixed 8 `G1` points and 6 `Fr` values however
//! large `n` is.
//!
//! # The variable-order convention
//!
//! This is the integration bug this crate exists to not have, so it is stated
//! three ways and tested end to end.
//!
//! `n = 2^(2t)` and `b = 2^t`. The evaluation at index `i + j*b` is the
//! coefficient of `X^(i + j*b)`, with `i` the **least** significant digit —
//! `i` is the low `t` bits of the index, `j` the high `t`. `u` splits the same
//! way: **`u1` is the first `t` coordinates** `u_0 .. u_(t-1)`, the ones that
//! pair with `i`, and `u2` is the last `t`. Variable `k` is bit `k` of the
//! index, exactly as in [`poly::MultilinearPoly::evaluate`], and
//! [`open`] returns the same value that method does.
//!
//! # Batching, and deferred pairings
//!
//! [`batch_open`] opens `k` same-size columns at **one** point as a single
//! Mercury instance: the commitments and the claimed values are absorbed, a
//! challenge `rho` is squeezed, and `cm* = sum rho^i cm_i` and
//! `f* = sum rho^i f_i` go through one ordinary opening.
//! `docs/spec/mercury.md` §11 is normative and carries the lemma.
//!
//! [`verify_deferred`] and [`batch_verify_deferred`] run the identical
//! verification and, instead of executing the two pairings, emit their terms as
//! [`AccumulatorEntry`] items. [`discharge`] spends a concatenated list of them
//! with one MSM per side and one two-pairing check.
//! `docs/spec/accumulator.md` is normative for that.
//!
//! # What this crate does not do
//!
//! No hiding, no zero knowledge: Mercury is not a hiding commitment and
//! nothing here pretends otherwise.

use rayon::prelude::*;

use constants::{transcript_tags as tags, FR_TWO_ADICITY, G1_INFINITY_SENTINEL};
use curve::msm::{msm, msm_small_u32};
use curve::G1Affine;
use field::Fr;
use poly::{eq_table, MultilinearPoly, PolyBacking};
use srs::{Srs, SrsVerifier};
use transcript::{Tag, Transcript};

mod accumulator;
mod bdfg;
mod fft;
mod uni;

pub use accumulator::{
    accumulator_digest, accumulator_from_words, accumulator_words, discharge, AccumulatorEntry,
    PairingSide, ENTRIES_PER_CHECK, ENTRY_WORDS,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way this crate refuses. One flat enum, one variant per failure class.
///
/// Nothing here is a panic: a malformed instance, a malformed proof and a
/// failed check are all data errors a caller can act on. Panics in this crate
/// are reserved for broken internal invariants, and each one names the
/// invariant it broke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcsError {
    /// The multilinear does not have `2t` variables for an integer `t >= 1`:
    /// an odd variable count, or the single-evaluation polynomial. Mercury is
    /// defined for `n = 2^(2t)` and this crate never pads to reach it.
    UnsupportedNumVars { num_vars: usize },
    /// The opening point's length is not the polynomial's variable count.
    PointLengthMismatch { point: usize, num_vars: usize },
    /// The SRS holds fewer than `n` powers, so `f` cannot be committed.
    SrsTooSmall { needed: usize, available: usize },
    /// A point supplied to [`verify`] is off the curve or outside the order-`r`
    /// subgroup. The string names which one.
    InvalidPoint { field: &'static str },
    /// The transcript produced `{z, 1/z, alpha}` with fewer than three distinct
    /// members, which leaves the BDFG20 batch undefined. Probability about
    /// `2^-252`; `docs/spec/mercury.md` §7.
    DegenerateChallenge,
    /// A batch with no columns. There is no `cm*` and no `v*` to open, and no
    /// statement to make. `docs/spec/mercury.md` §11.
    EmptyBatch,
    /// A batch's commitment list and the list paired with it differ in length:
    /// the columns in [`batch_open`], the claimed values in [`batch_verify`].
    BatchLengthMismatch { commitments: usize, paired: usize },
    /// A batch's columns do not all have the same number of variables. Mercury
    /// batches one instance size at a time and never pads to reach it.
    MixedColumnSizes { expected: usize, found: usize },
    /// An accumulator's per-check counts do not partition it, or a count word is
    /// not a length. `length` is how long the thing being read is and `at` is
    /// how far the counts got — in **entries** when the counts were handed in
    /// beside an entry list, in **words** when they were read off a word array,
    /// which is why neither field names a unit. `docs/spec/accumulator.md` §3.
    MalformedAccumulator { length: usize, at: usize },
    /// The pairing check failed. There is one, so there is one variant.
    VerificationFailed,
}

// ---------------------------------------------------------------------------
// Commitment and proof
// ---------------------------------------------------------------------------

/// A Mercury commitment: the KZG commitment to `f`'s evaluation table read as
/// coefficients, and nothing more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MercuryCommitment(pub G1Affine);

/// A Mercury opening proof: 8 `G1` points and 6 `Fr` values, always.
///
/// The field order below is the serialization order and the transcript order.
/// Nothing in it is optional and nothing in it depends on `n`, so
/// [`MercuryProof::to_bytes`] is [`PROOF_BYTES`] long for every instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MercuryProof {
    /// `[h(x)]_1`, the restriction `h(X) = sum_i eq(i, u1) f_i(X)`.
    pub h: G1Affine,
    /// `[q(x)]_1`, the quotient of `f` by `X^b - alpha`.
    pub q: G1Affine,
    /// `[g(x)]_1`, the remainder: `g(X) = sum_i f_i(alpha) X^i`.
    pub g: G1Affine,
    /// `[S(x)]_1`, the symmetrized inner-product witness.
    pub s: G1Affine,
    /// `[D(x)]_1` for `D(X) = X^(b-1) g(1/X)`, the degree check on `g`.
    pub d: G1Affine,
    /// `[H(x)]_1`, the KZG opening of the fold identity at `z`.
    pub pi_z: G1Affine,
    /// BDFG20's `W`: the batch quotient `[(F/Z_T)(x)]_1`.
    pub w: G1Affine,
    /// BDFG20's `W'`: the linearization quotient at `z'`.
    pub w_prime: G1Affine,
    /// `g(z)`.
    pub g_z: Fr,
    /// `g(1/z)`.
    pub g_inv_z: Fr,
    /// `h(z)`.
    pub h_z: Fr,
    /// `h(1/z)`.
    pub h_inv_z: Fr,
    /// `S(z)`.
    pub s_z: Fr,
    /// `S(1/z)`.
    pub s_inv_z: Fr,
}

/// The serialized length of every proof: 8 uncompressed `G1` points then 6
/// canonical `Fr` values.
pub const PROOF_BYTES: usize = 8 * 64 + 6 * 32;

impl MercuryProof {
    /// The eight points, in field order.
    fn points(&self) -> [G1Affine; 8] {
        [
            self.h,
            self.q,
            self.g,
            self.s,
            self.d,
            self.pi_z,
            self.w,
            self.w_prime,
        ]
    }

    /// The six values, in field order.
    fn evals(&self) -> [Fr; 6] {
        [
            self.g_z,
            self.g_inv_z,
            self.h_z,
            self.h_inv_z,
            self.s_z,
            self.s_inv_z,
        ]
    }

    /// Canonical little-endian, per master rule 3: the eight points in
    /// `crates/curve`'s 64-byte uncompressed form, then the six values in
    /// `Fr`'s 32-byte form, concatenated in field order.
    pub fn to_bytes(&self) -> [u8; PROOF_BYTES] {
        let mut out = [0u8; PROOF_BYTES];
        for (slot, p) in out.chunks_exact_mut(64).zip(self.points()) {
            slot.copy_from_slice(&p.to_bytes());
        }
        for (slot, x) in out[8 * 64..].chunks_exact_mut(32).zip(self.evals()) {
            slot.copy_from_slice(&x.to_bytes());
        }
        out
    }

    /// Decode, validating everything: every point through
    /// `G1Affine::from_bytes` — canonical coordinates, on the curve, in the
    /// subgroup — and every value through `Fr::from_bytes`, which rejects
    /// anything at or above the modulus. `None` rather than a panic.
    pub fn from_bytes(bytes: &[u8; PROOF_BYTES]) -> Option<MercuryProof> {
        let mut points = [G1Affine::IDENTITY; 8];
        for (slot, raw) in points.iter_mut().zip(bytes.chunks_exact(64)) {
            *slot = G1Affine::from_bytes(raw.try_into().expect("64 bytes"))?;
        }
        let mut evals = [Fr::ZERO; 6];
        for (slot, raw) in evals.iter_mut().zip(bytes[8 * 64..].chunks_exact(32)) {
            *slot = Fr::from_bytes(raw.try_into().expect("32 bytes"))?;
        }
        Some(MercuryProof {
            h: points[0],
            q: points[1],
            g: points[2],
            s: points[3],
            d: points[4],
            pi_z: points[5],
            w: points[6],
            w_prime: points[7],
            g_z: evals[0],
            g_inv_z: evals[1],
            h_z: evals[2],
            h_inv_z: evals[3],
            s_z: evals[4],
            s_inv_z: evals[5],
        })
    }
}

// ---------------------------------------------------------------------------
// Typed G1 absorption — the S02 typed layer, extended
// ---------------------------------------------------------------------------

/// The four `Fr` limbs an affine `G1` point absorbs as.
///
/// `x` low, `x` high, `y` low, `y` high, where "low" is the bottom 128 bits of
/// the coordinate's canonical little-endian encoding and "high" the remaining
/// 126. Both halves are below `2^128 < p`, so both are canonical `Fr` without
/// reduction. The point at infinity absorbs four copies of
/// `constants::G1_INFINITY_SENTINEL`, which is `2^128` and therefore cannot be
/// any real point's limb. `docs/spec/mercury.md` §4 is normative.
fn g1_limbs(p: &G1Affine) -> [Fr; 4] {
    if p.infinity {
        return [infinity_sentinel(); 4];
    }
    let half = |bytes: &[u8]| {
        let mut limb = [0u8; 32];
        limb[..16].copy_from_slice(bytes);
        Fr::from_bytes(&limb).expect("a 128-bit limb is below 2^128 < p")
    };
    let x = p.x.to_bytes();
    let y = p.y.to_bytes();
    [
        half(&x[..16]),
        half(&x[16..]),
        half(&y[..16]),
        half(&y[16..]),
    ]
}

/// `constants::G1_INFINITY_SENTINEL`, decoded.
///
/// `2^128`: the limb a point at infinity absorbs in each of its four lanes, and
/// the one value no real limb can take. Read here rather than in each caller so
/// the absorber and the accumulator's decoder cannot disagree about it.
fn infinity_sentinel() -> Fr {
    Fr::from_hex(G1_INFINITY_SENTINEL)
        .expect("the frozen infinity sentinel is a canonical hex literal")
}

/// Absorb one affine `G1` point under `tag`, as one typed message of four `Fr`
/// limbs. Exactly `append_g1_list(tr, tag, &[*p])`.
pub fn append_g1(tr: &mut Transcript, tag: Tag, p: &G1Affine) {
    append_g1_list(tr, tag, core::slice::from_ref(p));
}

/// Absorb a list of affine `G1` points under `tag`, as **one** typed
/// length-delimited message of `4 * ps.len()` `Fr` limbs.
///
/// One message, not one per point: the list's length is bound by the typed
/// framing's length field, so a list of `k` points cannot be confused with any
/// other list or with `k` separate messages. S09's commitment-list absorption
/// is this function.
pub fn append_g1_list(tr: &mut Transcript, tag: Tag, ps: &[G1Affine]) {
    let mut limbs = Vec::with_capacity(4 * ps.len());
    for p in ps {
        limbs.extend_from_slice(&g1_limbs(p));
    }
    tr.append_scalars(tag, &limbs);
}

// ---------------------------------------------------------------------------
// commit
// ---------------------------------------------------------------------------

/// `[f(x)]_1`, where `f`'s coefficients are the multilinear's evaluation table.
///
/// Dispatches on the backing (S03's frozen `backing()`): a `U1`, `U8`, `U16` or
/// `U32` column is **widened to `u32` and never lifted to `Fr`**, so a narrow
/// trace column commits through the small-scalar MSM path; only an `Fr` backing
/// takes the general one. The two paths agree on every value and differ only in
/// cost.
pub fn commit(srs: &Srs, f: &MultilinearPoly) -> Result<MercuryCommitment, PcsError> {
    let n = check_num_vars(f.num_vars())?;
    let powers = srs.g1();
    if powers.len() < n {
        return Err(PcsError::SrsTooSmall {
            needed: n,
            available: powers.len(),
        });
    }
    let bases = &powers[..n];

    let point = match f.backing() {
        PolyBacking::U1(limbs, count) => {
            let bits: Vec<u32> = (0..*count)
                .map(|i| ((limbs[i / 64] >> (i % 64)) & 1) as u32)
                .collect();
            msm_small_u32(bases, &bits)
        }
        PolyBacking::U8(v) => {
            msm_small_u32(bases, &v.iter().map(|x| *x as u32).collect::<Vec<_>>())
        }
        PolyBacking::U16(v) => {
            msm_small_u32(bases, &v.iter().map(|x| *x as u32).collect::<Vec<_>>())
        }
        PolyBacking::U32(v) => msm_small_u32(bases, v),
        PolyBacking::Fr(v) => msm(bases, v),
    }
    .expect("one power per coefficient");

    Ok(MercuryCommitment(point.to_affine()))
}

// ---------------------------------------------------------------------------
// open
// ---------------------------------------------------------------------------

/// Open `cm` at `u`, returning the claimed value and the proof.
///
/// `cm` is absorbed as passed and never recomputed: an `open` whose commitment
/// does not match `f` produces a proof that fails, which is what makes a
/// witness-tamper twin a rejection rather than a silent success.
///
/// The transcript is left in the state [`verify`] leaves it in, including the
/// pairing-merge challenge the prover has no use for. A caller that keeps
/// writing to the same transcript therefore stays in step with the verifier.
pub fn open(
    srs: &Srs,
    f: &MultilinearPoly,
    cm: &MercuryCommitment,
    u: &[Fr],
    tr: &mut Transcript,
) -> Result<(Fr, MercuryProof), PcsError> {
    let num_vars = f.num_vars();
    let n = check_num_vars(num_vars)?;
    if u.len() != num_vars {
        return Err(PcsError::PointLengthMismatch {
            point: u.len(),
            num_vars,
        });
    }
    let powers = srs.g1();
    if powers.len() < n {
        return Err(PcsError::SrsTooSmall {
            needed: n,
            available: powers.len(),
        });
    }
    let t = num_vars / 2;
    let b = 1usize << t;
    let commit_to = |c: &[Fr]| -> G1Affine {
        msm(&powers[..c.len()], c)
            .expect("one power per coefficient")
            .to_affine()
    };

    // f's evaluation table, read as coefficients. Row `j` is
    // `coeffs[j*b .. (j+1)*b]`, holding `f_{i,j}` for every `i`: the layout
    // that makes both the restriction and the fold one pass over rows.
    let coeffs: Vec<Fr> = (0..n).into_par_iter().map(|i| f.get(i)).collect();
    let eq1 = eq_table(&u[..t]);
    let eq2 = eq_table(&u[t..]);

    // Step 1 -- the restriction h, and the value it claims.
    let h_coeffs: Vec<Fr> = coeffs
        .par_chunks_exact(b)
        .map(|row| dot(&eq1, row))
        .collect();
    let v = dot(&eq2, &h_coeffs);
    let h_point = commit_to(&h_coeffs);

    tr.append_scalar(tags::MERCURY_INSTANCE, Fr::from_u64(n as u64));
    append_g1(tr, tags::COMMITMENT, &cm.0);
    let mut claim: Vec<Fr> = u.to_vec();
    claim.push(v);
    tr.append_scalars(tags::EVALUATION_CLAIM, &claim);
    append_g1(tr, tags::PCS_OPENING, &h_point);
    let alpha = tr.challenge_scalar(tags::MERCURY_ALPHA);

    // Step 2 -- the fold. `b` Horner divisions by `X - alpha`, interleaved so
    // that one pass down the rows advances all of them: `acc` holds every
    // column's carry, row `j` of the quotient is `acc` at that moment, and what
    // `acc` ends as is `f_i(alpha)` for every `i`.
    let mut acc: Vec<Fr> = coeffs[(b - 1) * b..].to_vec();
    let mut q_coeffs = vec![Fr::ZERO; (b - 1) * b];
    for j in (0..b - 1).rev() {
        q_coeffs[j * b..(j + 1) * b].copy_from_slice(&acc);
        acc.par_iter_mut()
            .zip(&coeffs[j * b..(j + 1) * b])
            .for_each(|(a, c)| *a = *c + *a * alpha);
    }
    let g_coeffs = acc;
    let q_point = commit_to(&q_coeffs);
    let g_point = commit_to(&g_coeffs);

    append_g1_list(tr, tags::PCS_OPENING, &[q_point, g_point]);
    let gamma = tr.challenge_scalar(tags::MERCURY_GAMMA);

    // Step 3 -- the symmetrized inner-product witness S, and the degree check D.
    let h_alpha = uni::eval(&h_coeffs, alpha);
    let s_coeffs = symmetric_witness(&g_coeffs, &h_coeffs, &eq1, &eq2, gamma, h_alpha, v);
    let d_coeffs: Vec<Fr> = g_coeffs.iter().rev().copied().collect();
    let s_point = commit_to(&s_coeffs);
    let d_point = commit_to(&d_coeffs);

    append_g1_list(tr, tags::PCS_OPENING, &[s_point, d_point]);
    let z = challenge_z(tr);
    if degenerate(alpha, z) {
        return Err(PcsError::DegenerateChallenge);
    }
    let z_inv = z.inverse().expect("a nonzero challenge is invertible");

    // Step 4 -- the six values, then the fold's KZG opening at z.
    let g_z = uni::eval(&g_coeffs, z);
    let g_inv_z = uni::eval(&g_coeffs, z_inv);
    let h_z = uni::eval(&h_coeffs, z);
    let h_inv_z = uni::eval(&h_coeffs, z_inv);
    let s_z = uni::eval(&s_coeffs, z);
    let s_inv_z = uni::eval(&s_coeffs, z_inv);
    let evals = [g_z, g_inv_z, h_z, h_inv_z, s_z, s_inv_z];
    tr.append_scalars(tags::PCS_OPENING, &evals);

    let z_pow_b = uni::pow_usize(z, b);
    let mut numerator = coeffs;
    numerator
        .par_iter_mut()
        .zip(&q_coeffs)
        .for_each(|(f, q)| *f -= (z_pow_b - alpha) * *q);
    numerator[0] -= g_z;
    let (h_quotient, remainder) = uni::div_by_linear(&numerator, z);
    assert_eq!(
        remainder,
        Fr::ZERO,
        "open: f(z) - (z^b - alpha) q(z) - g(z) must vanish by the fold identity"
    );
    let pi_z = commit_to(&h_quotient);
    append_g1(tr, tags::PCS_OPENING, &pi_z);

    // Step 4(e) -- the BDFG20 batch. The claims are built the verifier's way,
    // from the six values just sent, so the two sides cannot disagree on them;
    // the assertion is that the verifier's route to h(alpha) really does land
    // on the h(alpha) that step 3 built S around.
    let claims = bdfg::Claims {
        g_z,
        g_inv_z,
        h_z,
        h_inv_z,
        s_z,
        s_inv_z,
        h_alpha: derive_h_alpha(&u[..t], &u[t..], z, z_inv, gamma, v, &evals),
        d_z: uni::pow_usize(z, b - 1) * g_inv_z,
    };
    assert_eq!(
        claims.h_alpha, h_alpha,
        "open: the symmetrized identity must re-derive h(alpha) from the six values"
    );

    let t_set = bdfg::point_set(alpha, z, z_inv);
    let items = bdfg::items(alpha, z, z_inv, &claims);
    let polys = [
        g_coeffs.as_slice(),
        h_coeffs.as_slice(),
        s_coeffs.as_slice(),
        d_coeffs.as_slice(),
    ];

    let delta = tr.challenge_scalar(tags::BDFG_BATCH);
    let w_poly = bdfg::quotient(&polys, &items, &t_set, delta);
    let w = commit_to(&w_poly);
    append_g1(tr, tags::PCS_OPENING, &w);

    let z_prime = tr.challenge_scalar(tags::BDFG_POINT);
    let l_poly = bdfg::linearization(&polys, &items, &t_set, &w_poly, delta, z_prime);
    let (w_prime_poly, remainder) = uni::div_by_linear(&l_poly, z_prime);
    assert_eq!(
        remainder,
        Fr::ZERO,
        "open: the BDFG20 linearization must vanish at z'"
    );
    let w_prime = commit_to(&w_prime_poly);
    append_g1(tr, tags::PCS_OPENING, &w_prime);

    // The prover has no use for the merge challenge and draws it anyway, so a
    // transcript shared with later messages advances identically on both sides.
    let _ = tr.challenge_scalar(tags::PAIRING_MERGE);

    Ok((
        v,
        MercuryProof {
            h: h_point,
            q: q_point,
            g: g_point,
            s: s_point,
            d: d_point,
            pi_z,
            w,
            w_prime,
            g_z,
            g_inv_z,
            h_z,
            h_inv_z,
            s_z,
            s_inv_z,
        },
    ))
}

// ---------------------------------------------------------------------------
// The verification core
// ---------------------------------------------------------------------------

/// Every field-side check of one Mercury verification, and the terms of its two
/// pairing relations.
///
/// This is the one verification path. It validates the points, replays
/// `docs/spec/mercury.md` §5's schedule, derives `h(alpha)` and `D(z)`, builds
/// the BDFG20 batch and squeezes the merge challenge — everything [`verify`]
/// used to do except the pairings themselves, which it hands back as the twelve
/// [`AccumulatorEntry`] items of `docs/spec/accumulator.md` §2. Its callers
/// either execute them or return them, and that branch is the only thing that
/// separates a native verification from a deferred one.
///
/// The entry order is frozen: the statement's commitment, the eight proof
/// points in their field order, `[1]_1`, then the two `G2X` terms.
fn accumulate(
    vsrs: &SrsVerifier,
    cm: &MercuryCommitment,
    u: &[Fr],
    v: Fr,
    proof: &MercuryProof,
    tr: &mut Transcript,
) -> Result<Vec<AccumulatorEntry>, PcsError> {
    check_num_vars(u.len())?;
    let t = u.len() / 2;
    let b = 1usize << t;

    // Every point is validated before it is used, including the commitment the
    // statement names: an off-curve or out-of-subgroup point reaching the
    // pairing is a way to make a check mean something other than it says.
    const NAMES: [&str; 8] = ["h", "q", "g", "s", "d", "pi_z", "w", "w_prime"];
    for (point, name) in proof.points().iter().zip(NAMES) {
        if !point.is_on_curve() || !point.is_in_subgroup() {
            return Err(PcsError::InvalidPoint { field: name });
        }
    }
    if !cm.0.is_on_curve() || !cm.0.is_in_subgroup() {
        return Err(PcsError::InvalidPoint { field: "cm" });
    }

    // The transcript schedule, mirroring `open` step for step.
    tr.append_scalar(tags::MERCURY_INSTANCE, Fr::from_u64(1u64 << u.len()));
    append_g1(tr, tags::COMMITMENT, &cm.0);
    let mut claim: Vec<Fr> = u.to_vec();
    claim.push(v);
    tr.append_scalars(tags::EVALUATION_CLAIM, &claim);
    append_g1(tr, tags::PCS_OPENING, &proof.h);
    let alpha = tr.challenge_scalar(tags::MERCURY_ALPHA);
    append_g1_list(tr, tags::PCS_OPENING, &[proof.q, proof.g]);
    let gamma = tr.challenge_scalar(tags::MERCURY_GAMMA);
    append_g1_list(tr, tags::PCS_OPENING, &[proof.s, proof.d]);
    let z = challenge_z(tr);
    if degenerate(alpha, z) {
        return Err(PcsError::DegenerateChallenge);
    }
    let z_inv = z.inverse().expect("a nonzero challenge is invertible");
    tr.append_scalars(tags::PCS_OPENING, &proof.evals());
    append_g1(tr, tags::PCS_OPENING, &proof.pi_z);
    let delta = tr.challenge_scalar(tags::BDFG_BATCH);
    append_g1(tr, tags::PCS_OPENING, &proof.w);
    let z_prime = tr.challenge_scalar(tags::BDFG_POINT);
    append_g1(tr, tags::PCS_OPENING, &proof.w_prime);
    let rho = tr.challenge_scalar(tags::PAIRING_MERGE);

    // The two values the verifier derives rather than receives.
    let claims = bdfg::Claims {
        g_z: proof.g_z,
        g_inv_z: proof.g_inv_z,
        h_z: proof.h_z,
        h_inv_z: proof.h_inv_z,
        s_z: proof.s_z,
        s_inv_z: proof.s_inv_z,
        h_alpha: derive_h_alpha(&u[..t], &u[t..], z, z_inv, gamma, v, &proof.evals()),
        d_z: uni::pow_usize(z, b - 1) * proof.g_inv_z,
    };

    // The BDFG20 batch at `z'`, from the one definition both sides read: `c[i]`
    // is `delta^i Z_{T \ S_i}(z')` and `constant` is `sum_i c[i] r_i(z')`.
    let t_set = bdfg::point_set(alpha, z, z_inv);
    let items = bdfg::items(alpha, z, z_inv, &claims);
    let mut c = [Fr::ZERO; 4];
    let mut constant = Fr::ZERO;
    for (i, item) in items.iter().enumerate() {
        c[i] = uni::pow_usize(delta, i) * uni::eval(&item.z_complement, z_prime);
        constant += c[i] * uni::eval(&item.r, z_prime);
    }
    let z_t = uni::eval(&uni::vanishing(&t_set), z_prime);
    let z_pow_b = uni::pow_usize(z, b);

    // Check A is the fold identity at `z`; check B is the BDFG20 batch; `rho`
    // merges them, which is why every check-B term carries it and no check-A
    // term does. `docs/spec/mercury.md` §8.2 and §8.3.
    let one = |scalar: Fr, point: G1Affine| AccumulatorEntry {
        side: PairingSide::G2One,
        scalar,
        point,
    };
    Ok(vec![
        one(Fr::ONE, cm.0),
        one(rho * c[1], proof.h),
        one(-(z_pow_b - alpha), proof.q),
        one(rho * c[0], proof.g),
        one(rho * c[2], proof.s),
        one(rho * c[3], proof.d),
        one(z, proof.pi_z),
        one(-(rho * z_t), proof.w),
        one(rho * z_prime, proof.w_prime),
        one(-(proof.g_z + rho * constant), vsrs.g1_gen),
        AccumulatorEntry {
            side: PairingSide::G2X,
            scalar: Fr::ONE,
            point: proof.pi_z,
        },
        AccumulatorEntry {
            side: PairingSide::G2X,
            scalar: rho,
            point: proof.w_prime,
        },
    ])
}

// ---------------------------------------------------------------------------
// The batch preamble
// ---------------------------------------------------------------------------

/// The batch preamble: absorb, squeeze `rho`, and derive `cm*` and `v*`.
///
/// One length-delimited message of `4k` limbs for the commitments **as
/// passed**, then one message of `u` followed by all `k` claimed values, then
/// the challenge. Nothing may be chosen after `rho` is drawn, which is what the
/// order of those three steps buys. `docs/spec/mercury.md` §11.
///
/// Callers validate `k`, the list lengths and `u` before reaching here, so this
/// only absorbs and combines.
fn batch_preamble(
    cms: &[MercuryCommitment],
    u: &[Fr],
    vs: &[Fr],
    tr: &mut Transcript,
) -> (Fr, MercuryCommitment, Fr) {
    let points: Vec<G1Affine> = cms.iter().map(|cm| cm.0).collect();
    append_g1_list(tr, tags::COMMITMENT, &points);
    let mut claim: Vec<Fr> = u.to_vec();
    claim.extend_from_slice(vs);
    tr.append_scalars(tags::EVALUATION_CLAIM, &claim);
    let rho = tr.challenge_scalar(tags::MERCURY_BATCH);

    let weights = powers(rho, cms.len());
    let cm_star = msm(&points, &weights)
        .expect("one weight per commitment")
        .to_affine();
    let v_star = dot(&weights, vs);
    (rho, MercuryCommitment(cm_star), v_star)
}

/// `batch_verify` and `batch_verify_deferred`, up to their one difference.
fn batch_accumulate(
    vsrs: &SrsVerifier,
    cms: &[MercuryCommitment],
    u: &[Fr],
    vs: &[Fr],
    proof: &MercuryProof,
    tr: &mut Transcript,
) -> Result<Vec<AccumulatorEntry>, PcsError> {
    if cms.is_empty() {
        return Err(PcsError::EmptyBatch);
    }
    if cms.len() != vs.len() {
        return Err(PcsError::BatchLengthMismatch {
            commitments: cms.len(),
            paired: vs.len(),
        });
    }
    check_num_vars(u.len())?;
    // `cm*` is a sum of these, so an off-curve summand would smuggle a point
    // the curve equation never saw into a sum that passes it.
    for cm in cms {
        if !cm.0.is_on_curve() || !cm.0.is_in_subgroup() {
            return Err(PcsError::InvalidPoint { field: "cm" });
        }
    }

    let (_, cm_star, v_star) = batch_preamble(cms, u, vs, tr);
    accumulate(vsrs, &cm_star, u, v_star, proof, tr)
}

// ---------------------------------------------------------------------------
// The four verifier entry points
// ---------------------------------------------------------------------------

/// Check that `cm` opens to `v` at `u`.
///
/// Takes the three-point [`SrsVerifier`] and nothing else from the SRS: this
/// path never commits to anything and never touches a power of `x` beyond
/// `[1]_1`, `[1]_2` and `[x]_2`.
pub fn verify(
    vsrs: &SrsVerifier,
    cm: &MercuryCommitment,
    u: &[Fr],
    v: Fr,
    proof: &MercuryProof,
    tr: &mut Transcript,
) -> Result<(), PcsError> {
    let entries = accumulate(vsrs, cm, u, v, proof, tr)?;
    accumulator::check_pairings(vsrs, &entries, &[entries.len()], &[Fr::ONE])
}

/// [`verify`], stopping one step short: the pairing terms, not the pairings.
///
/// Every field-side check still runs, and every point is still validated — only
/// the two group relations are left unspent. The returned list is exactly one
/// deferred check, [`ENTRIES_PER_CHECK`] entries long, and is discharged by
/// [`discharge`] alongside however many others it is concatenated with.
pub fn verify_deferred(
    vsrs: &SrsVerifier,
    cm: &MercuryCommitment,
    u: &[Fr],
    v: Fr,
    proof: &MercuryProof,
    tr: &mut Transcript,
) -> Result<Vec<AccumulatorEntry>, PcsError> {
    accumulate(vsrs, cm, u, v, proof, tr)
}

/// Check that `k` commitments open to `vs` at the single point `u`.
///
/// The commitments are absorbed **as passed** and `cm*` is derived from them by
/// KZG's homomorphism, so a list in a different order, or one commitment short,
/// is a different statement and fails. `docs/spec/mercury.md` §11.
pub fn batch_verify(
    vsrs: &SrsVerifier,
    cms: &[MercuryCommitment],
    u: &[Fr],
    vs: &[Fr],
    proof: &MercuryProof,
    tr: &mut Transcript,
) -> Result<(), PcsError> {
    let entries = batch_accumulate(vsrs, cms, u, vs, proof, tr)?;
    accumulator::check_pairings(vsrs, &entries, &[entries.len()], &[Fr::ONE])
}

/// [`batch_verify`], stopping one step short. See [`verify_deferred`].
pub fn batch_verify_deferred(
    vsrs: &SrsVerifier,
    cms: &[MercuryCommitment],
    u: &[Fr],
    vs: &[Fr],
    proof: &MercuryProof,
    tr: &mut Transcript,
) -> Result<Vec<AccumulatorEntry>, PcsError> {
    batch_accumulate(vsrs, cms, u, vs, proof, tr)
}

// ---------------------------------------------------------------------------
// batch_open
// ---------------------------------------------------------------------------

/// Open `k` same-size columns at one point `u`, as one Mercury instance.
///
/// Returns each column's value at `u` — the same value
/// `MultilinearPoly::evaluate(u)` gives — and **one** ordinary proof, of
/// `cm* = sum rho^i cm_i` at `u`. The commitments are absorbed as passed and
/// never recomputed, exactly as [`open`] treats the single one.
///
/// `f* = sum rho^i f_i` is materialised into one column before the opening
/// rather than recombined lazily inside it: `open` makes several passes over
/// its polynomial, and a lazy combination would multiply `k` into every one of
/// them. The combination is indexed and exact, so the result does not depend on
/// the thread count.
pub fn batch_open(
    srs: &Srs,
    cols: &[MultilinearPoly],
    cms: &[MercuryCommitment],
    u: &[Fr],
    tr: &mut Transcript,
) -> Result<(Vec<Fr>, MercuryProof), PcsError> {
    if cols.is_empty() {
        return Err(PcsError::EmptyBatch);
    }
    if cols.len() != cms.len() {
        return Err(PcsError::BatchLengthMismatch {
            commitments: cms.len(),
            paired: cols.len(),
        });
    }
    let num_vars = cols[0].num_vars();
    for col in cols {
        if col.num_vars() != num_vars {
            return Err(PcsError::MixedColumnSizes {
                expected: num_vars,
                found: col.num_vars(),
            });
        }
    }
    let n = check_num_vars(num_vars)?;
    if u.len() != num_vars {
        return Err(PcsError::PointLengthMismatch {
            point: u.len(),
            num_vars,
        });
    }
    let available = srs.g1().len();
    if available < n {
        return Err(PcsError::SrsTooSmall {
            needed: n,
            available,
        });
    }

    let vs: Vec<Fr> = cols.iter().map(|col| col.evaluate(u)).collect();
    let (rho, cm_star, v_star) = batch_preamble(cms, u, &vs, tr);

    let weights = powers(rho, cols.len());
    let combined: Vec<Fr> = (0..n)
        .into_par_iter()
        .map(|i| {
            let mut acc = Fr::ZERO;
            for (col, weight) in cols.iter().zip(&weights) {
                acc += *weight * col.get(i);
            }
            acc
        })
        .collect();
    let f_star = MultilinearPoly::new(PolyBacking::Fr(combined));

    let (v, proof) = open(srs, &f_star, &cm_star, u, tr)?;
    assert_eq!(
        v, v_star,
        "batch_open: the combined column's value must be the combination of the columns' values"
    );
    Ok((vs, proof))
}

// ---------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------

/// The largest instance Mercury can express.
///
/// The opening's transform needs a `2b`-th root of unity, so `t + 1` may not
/// exceed `Fr`'s two-adicity and `num_vars = 2t` may not exceed 54. That bound
/// is also what keeps `1 << num_vars` in range: [`verify`] takes `u` straight
/// from a caller, so `u.len()` is adversarial input and must not be allowed to
/// shift a `usize` off its end — with `overflow-checks` on that is a panic out
/// of a verifier, and with them off it is a silently wrong `n`.
const MAX_NUM_VARS: usize = 2 * (FR_TWO_ADICITY as usize - 1);
const _: () = assert!(MAX_NUM_VARS < usize::BITS as usize);

/// `n = 2^num_vars`, or the reason it is not a Mercury instance.
///
/// `n = 2^(2t)` with `1 <= t <= FR_TWO_ADICITY - 1`. Odd counts are rejected
/// rather than padded, and so is the single-evaluation polynomial, whose
/// `b = 1` leaves `S` and the degree check with no room to exist.
fn check_num_vars(num_vars: usize) -> Result<usize, PcsError> {
    if !(2..=MAX_NUM_VARS).contains(&num_vars) || !num_vars.is_multiple_of(2) {
        return Err(PcsError::UnsupportedNumVars { num_vars });
    }
    Ok(1usize << num_vars)
}

/// `sum_i a[i] * b[i]`, over equal-length slices.
fn dot(a: &[Fr], b: &[Fr]) -> Fr {
    debug_assert_eq!(a.len(), b.len());
    let mut acc = Fr::ZERO;
    for (x, y) in a.iter().zip(b) {
        acc += *x * *y;
    }
    acc
}

/// `[1, x, x^2, ..., x^(k-1)]`, the weights of a geometric batch.
///
/// Index `i` carries `x^i`, so the first element of a batched list carries `1`.
fn powers(x: Fr, k: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(k);
    let mut acc = Fr::ONE;
    for _ in 0..k {
        out.push(acc);
        acc *= x;
    }
    out
}

/// Draw `z` under `MERCURY_Z`, taking the first squeeze that is not `reject`
/// and squeezing again under the same tag while it is.
///
/// `docs/spec/mercury.md` §7 pins `reject = 0`, so that `1/z` exists, and
/// [`challenge_z`] is that rule. The rejected value is a parameter because the
/// loop is otherwise unreachable and so untestable: a transcript squeezes zero
/// with probability about `2^-254`, and no test can wait for that. A test names
/// a value the sponge really does produce instead, and watches the next squeeze
/// be taken.
fn challenge_z_rejecting(tr: &mut Transcript, reject: Fr) -> Fr {
    loop {
        let z = tr.challenge_scalar(tags::MERCURY_Z);
        if z != reject {
            return z;
        }
    }
}

/// Draw `z`, resampling under the same tag while it is zero so that `1/z`
/// exists. `docs/spec/mercury.md` §7.
fn challenge_z(tr: &mut Transcript) -> Fr {
    challenge_z_rejecting(tr, Fr::ZERO)
}

/// Whether `{z, 1/z, alpha}` has fewer than three distinct members, which would
/// leave `Z_T` with a repeated root and the interpolation of `h` undefined.
///
/// `z != 0` is already guaranteed by [`challenge_z`] and is repeated here so
/// the predicate stands alone. `docs/spec/mercury.md` §7.
fn degenerate(alpha: Fr, z: Fr) -> bool {
    z == Fr::ZERO || z.square() == Fr::ONE || z == alpha || z * alpha == Fr::ONE
}

/// `P_u(X) = prod_k (u_k X^(2^k) + 1 - u_k)`, the `O(t)` product formula.
///
/// Equal to `sum_i eq(i, u) X^i`, whose coefficient vector is `eq_table(u)`:
/// the prover uses the table, the verifier uses this, and
/// `crates/pcs/tests/identities.rs` holds them to each other.
fn tensor_eval(u: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::ONE;
    let mut power = x;
    for uk in u {
        acc *= *uk * power + (Fr::ONE - *uk);
        power = power.square();
    }
    acc
}

/// `h(alpha)`, from the symmetrized identity evaluated at `z`.
///
/// `2 h(alpha) = g_z P_u1(1/z) + g_1/z P_u1(z)
///             + gamma (h_z P_u2(1/z) + h_1/z P_u2(z) - 2v) - z S(z) - S(1/z)/z`.
///
/// The prover computes it this way too, so that the value it builds the batch
/// around is the value the verifier will use.
///
/// `evals` is the six sent values in the proof's field order:
/// `g_z, g_1/z, h_z, h_1/z, s_z, s_1/z`.
fn derive_h_alpha(u1: &[Fr], u2: &[Fr], z: Fr, z_inv: Fr, gamma: Fr, v: Fr, evals: &[Fr; 6]) -> Fr {
    let [g_z, g_inv_z, h_z, h_inv_z, s_z, s_inv_z] = *evals;
    let two_inv = Fr::from_u64(2)
        .inverse()
        .expect("2 is invertible in a field of odd characteristic");
    let inner = g_z * tensor_eval(u1, z_inv)
        + g_inv_z * tensor_eval(u1, z)
        + gamma * (h_z * tensor_eval(u2, z_inv) + h_inv_z * tensor_eval(u2, z) - v - v)
        - z * s_z
        - z_inv * s_inv_z;
    inner * two_inv
}

/// `S(X)`, the witness for both inner products at once.
///
/// Multiplying the symmetrized identity by `X^(b-1)` turns it into a polynomial
/// identity of degree `2b - 2`:
///
/// ```text
///   T(X) = g(X) rev(P_u1)(X) + rev(g)(X) P_u1(X)
///        + gamma ( h(X) rev(P_u2)(X) + rev(h)(X) P_u2(X) )
///        = 2(h(alpha) + gamma v) X^(b-1) + X^b S(X) + X^(b-2) S(1/X)
/// ```
///
/// where `rev` reverses a length-`b` coefficient vector. The reversal is not a
/// second product: `rev_(2b-1)(A * rev_b(B)) = rev_b(A) * B`, so with
/// `R = g * rev(P_u1) + gamma * h * rev(P_u2)` — one pointwise combination in
/// the evaluation domain, one inverse transform — `T = R + rev(R)`. The
/// symmetry is then structural rather than something to hope for, and `S` is
/// the top half of `T`.
fn symmetric_witness(
    g: &[Fr],
    h: &[Fr],
    eq1: &[Fr],
    eq2: &[Fr],
    gamma: Fr,
    h_alpha: Fr,
    v: Fr,
) -> Vec<Fr> {
    let b = g.len();
    // The four operands are what bound the transform: `for_product(b)` is a
    // size-`2b` domain and there is no larger one anywhere in this crate.
    assert!(
        h.len() == b && eq1.len() == b && eq2.len() == b,
        "symmetric_witness: g, h and both eq tables must all hold b coefficients"
    );
    let domain = fft::Domain::for_product(b);
    let padded = |c: &[Fr], reverse: bool| -> Vec<Fr> {
        let mut out = vec![Fr::ZERO; 2 * b];
        if reverse {
            for (slot, x) in out[..b].iter_mut().zip(c.iter().rev()) {
                *slot = *x;
            }
        } else {
            out[..b].copy_from_slice(c);
        }
        domain.fft(&mut out);
        out
    };

    let g_hat = padded(g, false);
    let p1_hat = padded(eq1, true);
    let h_hat = padded(h, false);
    let p2_hat = padded(eq2, true);

    let mut r: Vec<Fr> = (0..2 * b)
        .map(|k| g_hat[k] * p1_hat[k] + gamma * h_hat[k] * p2_hat[k])
        .collect();
    domain.ifft(&mut r);
    assert_eq!(
        r[2 * b - 1],
        Fr::ZERO,
        "symmetric_witness: the product of two degree-<b polynomials has degree < 2b-1"
    );
    assert_eq!(
        r[b - 1],
        h_alpha + gamma * v,
        "symmetric_witness: the constant coefficient must be ghat(u1) + gamma*hhat(u2)"
    );

    // T[k] = R[k] + R[2b-2-k]; S is T[b..2b-1].
    (b..2 * b - 1).map(|k| r[k] + r[2 * b - 2 - k]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve::G1Projective;

    /// The instance rule: `2t` variables for `1 <= t <= FR_TWO_ADICITY - 1`,
    /// and nothing else.
    ///
    /// The upper bound is not decoration. `verify` takes `u` straight from a
    /// caller, so without it `1usize << u.len()` shifts off the end of a
    /// `usize` — a panic out of a verifier where `overflow-checks` are on, and
    /// a silently wrong `n` where they are not.
    #[test]
    fn only_even_variable_counts_in_range_are_instances() {
        for num_vars in 0..=256usize {
            let got = check_num_vars(num_vars);
            let legal = (2..=MAX_NUM_VARS).contains(&num_vars) && num_vars % 2 == 0;
            if legal {
                assert_eq!(got, Ok(1usize << num_vars), "num_vars {num_vars}");
            } else {
                assert_eq!(
                    got,
                    Err(PcsError::UnsupportedNumVars { num_vars }),
                    "num_vars {num_vars}"
                );
            }
        }
        assert_eq!(MAX_NUM_VARS, 54);
        assert!(check_num_vars(MAX_NUM_VARS).is_ok());
        assert!(check_num_vars(MAX_NUM_VARS + 2).is_err());
        // The bound really is what keeps the shift in range.
        assert!(MAX_NUM_VARS < usize::BITS as usize);
    }

    /// Acceptance 5, and `docs/spec/mercury.md` §7's `z in F*` rule: a rejected
    /// squeeze is discarded and the **next** squeeze under the same tag is
    /// used.
    ///
    /// The rule rejects zero, which a sponge produces with probability about
    /// `2^-254`, so the loop is undrivable as written. Naming the rejected
    /// value instead makes it drivable with a value the sponge really does
    /// produce, and what is then checked is the whole rule: the first draw is
    /// discarded, the second is returned, and the transcript is left where two
    /// squeezes under `MERCURY_Z` leave it — not one, and not a squeeze under
    /// some other tag.
    #[test]
    fn a_rejected_z_draw_takes_the_next_squeeze() {
        // What the sponge really produces under this tag, in order.
        let mut tr = Transcript::new();
        let draws: Vec<Fr> = (0..3)
            .map(|_| tr.challenge_scalar(tags::MERCURY_Z))
            .collect();
        assert!(draws.iter().all(|z| *z != Fr::ZERO), "and none is zero");
        assert_ne!(draws[0], draws[1]);

        // The production rule rejects zero, so it takes the first draw.
        let mut tr = Transcript::new();
        assert_eq!(challenge_z(&mut tr), draws[0]);
        assert_eq!(tr.challenge_scalar(tags::MERCURY_Z), draws[1]);

        // Rejecting the first draw takes the second, and leaves the transcript
        // two squeezes in rather than one.
        let mut tr = Transcript::new();
        assert_eq!(challenge_z_rejecting(&mut tr, draws[0]), draws[1]);
        assert_eq!(tr.challenge_scalar(tags::MERCURY_Z), draws[2]);
        assert_eq!(
            tr.event_log(),
            &[transcript::TranscriptEvent::Challenge {
                tag: tags::MERCURY_Z
            }; 3],
            "the resample is a squeeze under the same tag, not a different one"
        );

        // And the production rule is exactly this helper at zero.
        let mut plain = Transcript::new();
        let mut named = Transcript::new();
        assert_eq!(
            challenge_z(&mut plain),
            challenge_z_rejecting(&mut named, Fr::ZERO)
        );
        assert_eq!(plain.snapshot(), named.snapshot());
    }

    /// `docs/spec/mercury.md` §7. The transcript reaches this with probability
    /// about `2^-252`, so it is the one predicate no end-to-end test can drive:
    /// it gets its negative control here.
    #[test]
    fn the_degenerate_challenge_set_is_exactly_the_four_cases() {
        let alpha = Fr::from_u64(11);
        assert!(degenerate(alpha, Fr::ZERO), "z = 0 has no inverse");
        assert!(degenerate(alpha, Fr::ONE), "z = 1/z");
        assert!(degenerate(alpha, Fr::MINUS_ONE), "z = 1/z");
        assert!(degenerate(alpha, alpha), "z = alpha");
        assert!(
            degenerate(alpha, alpha.inverse().expect("nonzero")),
            "1/z = alpha"
        );
        for z in [2u64, 3, 5, 7, 12, 1 << 40] {
            assert!(!degenerate(alpha, Fr::from_u64(z)), "z = {z} is fine");
        }
        // alpha = 0 is not degenerate on its own: Z_{T \ S} is then just X.
        assert!(!degenerate(Fr::ZERO, Fr::from_u64(3)));
    }

    /// Every limb of a real point is below `2^128`, which is what makes the
    /// infinity sentinel collision-free by construction rather than by an
    /// appeal to the curve equation.
    #[test]
    fn every_limb_is_below_the_sentinel() {
        let sentinel = Fr::from_hex(G1_INFINITY_SENTINEL).expect("canonical");
        let mut point = G1Projective::GENERATOR;
        for _ in 0..64 {
            let affine = point.to_affine();
            for limb in g1_limbs(&affine) {
                let bytes = limb.to_bytes();
                assert!(
                    bytes[16..].iter().all(|b| *b == 0),
                    "a limb must fit in 128 bits"
                );
                assert_ne!(limb, sentinel, "no real limb is the sentinel");
            }
            point = point.add(&G1Projective::GENERATOR);
        }
        assert_eq!(g1_limbs(&G1Affine::IDENTITY), [sentinel; 4]);
        // The sentinel is exactly 2^128: one at byte 16, zero everywhere else.
        let bytes = sentinel.to_bytes();
        assert_eq!(bytes[16], 1);
        assert!(bytes.iter().enumerate().all(|(i, b)| i == 16 || *b == 0));
    }

    /// The `P_u` product formula is the coefficient vector `eq_table` builds.
    #[test]
    fn the_tensor_product_formula_matches_the_eq_table() {
        for t in 0..8usize {
            let u: Vec<Fr> = (0..t).map(|k| Fr::from_u64(3 * k as u64 + 1)).collect();
            let table = eq_table(&u);
            for x in [2u64, 5, 9, 1 << 20] {
                let x = Fr::from_u64(x);
                let mut expected = Fr::ZERO;
                let mut power = Fr::ONE;
                for c in &table {
                    expected += *c * power;
                    power *= x;
                }
                assert_eq!(tensor_eval(&u, x), expected, "t = {t}");
            }
        }
    }
}
