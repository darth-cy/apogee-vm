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

use constants::{transcript_tags as tags, G1_INFINITY_SENTINEL};
use curve::msm::{msm, msm_small_u32};
use curve::G1Affine;
use field::Fr;
use pcs_verify::{
    bdfg, challenge_z, check_batch, check_num_vars, degenerate, derive_h_alpha, dot, powers, uni,
    ENTRY_POINTS,
};
use poly::{eq_table, MultilinearPoly, PolyBacking};
use srs::{Srs, SrsVerifier};
use transcript::{Tag, Transcript};

mod accumulator;
mod fft;

// The instance size `pcs_verify::check_num_vars` returns is a `u64`, so that the
// rule is the same on the recursion guest's 32-bit target; this crate allocates
// it, and every size it can be fits a host `usize`.
const _: () = assert!(pcs_verify::MAX_NUM_VARS < usize::BITS as usize);

pub use accumulator::{accumulator_from_words, accumulator_words, discharge, AccumulatorEntry};
pub use pcs_verify::{accumulator_digest, PairingSide, PcsError, ENTRIES_PER_CHECK, ENTRY_WORDS};

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
    let points: Vec<[u8; 64]> = ps.iter().map(G1Affine::to_bytes).collect();
    transcript::append_g1_points(tr, tag, &points);
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
    let n = check_num_vars(f.num_vars())? as usize;
    let powers = srs.g1();
    if powers.len() < n {
        return Err(PcsError::SrsTooSmall {
            needed: n,
            available: powers.len(),
        });
    }
    Ok(MercuryCommitment(column_msm(&powers[..n], f).to_affine()))
}

/// A **stack**'s commitment (`docs/spec/recursion.md` §1.3): the multilinear
/// whose evaluations `[j·2^n, (j+1)·2^n)` are `cols[j]` and whose every slot
/// past the last column is zero, read as coefficients like any other. One MSM
/// a column over the powers its slot starts at, summed — the stack is never
/// materialized, and a narrow column keeps [`commit`]'s small-scalar path.
/// Zero slots above the last column move nothing, so a stack's commitment does
/// not depend on how many slots it is declared to have.
pub fn commit_stack(srs: &Srs, cols: &[&MultilinearPoly]) -> Result<MercuryCommitment, PcsError> {
    let width = cols.first().ok_or(PcsError::EmptyBatch)?.num_vars();
    let n = 1usize << width;
    let powers = srs.g1();
    if powers.len() < n * cols.len() {
        return Err(PcsError::SrsTooSmall {
            needed: n * cols.len(),
            available: powers.len(),
        });
    }
    let mut acc = curve::G1Projective::IDENTITY;
    for (j, col) in cols.iter().enumerate() {
        if col.num_vars() != width {
            return Err(PcsError::MixedColumnSizes {
                expected: width,
                found: col.num_vars(),
            });
        }
        acc = acc.add(&column_msm(&powers[j * n..(j + 1) * n], col));
    }
    Ok(MercuryCommitment(acc.to_affine()))
}

/// `Σ_i f_i·bases_i` over `f`'s evaluation table, dispatching on its backing.
fn column_msm(bases: &[G1Affine], f: &MultilinearPoly) -> curve::G1Projective {
    match f.backing() {
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
    .expect("one power per coefficient")
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
    let n = check_num_vars(num_vars)? as usize;
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

/// Every check of one Mercury verification but the pairings, and the terms of
/// its two pairing relations.
///
/// This is the one verification path. It validates the points, then hands the
/// field side — `docs/spec/mercury.md` §5's schedule, `h(alpha)`, `D(z)`, the
/// BDFG20 batch and the merge challenge — to [`pcs_verify::scalars`], which
/// the recursion guest runs too, and pairs each scalar with its point as
/// [`ENTRY_POINTS`] says. That is the twelve [`AccumulatorEntry`] items of
/// `docs/spec/accumulator.md` §2. Its callers either execute them or return
/// them, and that branch is the only thing that separates a native
/// verification from a deferred one.
fn accumulate(
    vsrs: &SrsVerifier,
    cm: &MercuryCommitment,
    u: &[Fr],
    v: Fr,
    proof: &MercuryProof,
    tr: &mut Transcript,
) -> Result<Vec<AccumulatorEntry>, PcsError> {
    check_num_vars(u.len())?;

    // Every point is validated before it is used, including the commitment the
    // statement names: an off-curve or out-of-subgroup point reaching the
    // pairing is a way to make a check mean something other than it says.
    const NAMES: [&str; 8] = ["h", "q", "g", "s", "d", "pi_z", "w", "w_prime"];
    let points = proof.points();
    for (point, name) in points.iter().zip(NAMES) {
        if !point.is_on_curve() || !point.is_in_subgroup() {
            return Err(PcsError::InvalidPoint { field: name });
        }
    }
    if !cm.0.is_on_curve() || !cm.0.is_in_subgroup() {
        return Err(PcsError::InvalidPoint { field: "cm" });
    }

    let scalars = pcs_verify::scalars(
        &cm.0.to_bytes(),
        u,
        v,
        &points.map(|p| p.to_bytes()),
        &proof.evals(),
        tr,
    )?;
    let [h, q, g, s, d, pi_z, w, w_prime] = points;
    let at = [cm.0, h, q, g, s, d, pi_z, w, w_prime, vsrs.g1_gen];
    Ok(ENTRY_POINTS
        .iter()
        .zip(scalars)
        .map(|((side, point), scalar)| AccumulatorEntry {
            side: *side,
            scalar,
            point: at[*point],
        })
        .collect())
}

// ---------------------------------------------------------------------------
// The batch preamble
// ---------------------------------------------------------------------------

/// The batch preamble: [`pcs_verify::batch_preamble`]'s absorptions and `rho`,
/// then `cm* = sum rho^i cm_i` by an MSM.
///
/// One length-delimited message of `4k` limbs for the commitments **as
/// passed**, then one message of `u` followed by all `k` claimed values, then
/// the challenge. Nothing may be chosen after `rho` is drawn, which is what the
/// order of those three steps buys. `docs/spec/mercury.md` §11.
///
/// Callers run [`check_batch`] before reaching here, so this only absorbs and
/// combines. Returns the weights `rho^i`, `cm*` and `v*`.
fn batch_preamble(
    cms: &[MercuryCommitment],
    u: &[Fr],
    vs: &[Fr],
    tr: &mut Transcript,
) -> (Vec<Fr>, MercuryCommitment, Fr) {
    let points: Vec<G1Affine> = cms.iter().map(|cm| cm.0).collect();
    let encoded: Vec<[u8; 64]> = points.iter().map(G1Affine::to_bytes).collect();
    let (weights, v_star) = pcs_verify::batch_preamble(&encoded, u, vs, tr);
    let cm_star = msm(&points, &weights)
        .expect("one weight per commitment")
        .to_affine();
    (weights, MercuryCommitment(cm_star), v_star)
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
    check_batch(cms.len(), vs.len(), u.len())?;
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
    let stacks: Vec<Vec<&MultilinearPoly>> = cols.iter().map(|c| vec![c]).collect();
    batch_open_stacked(srs, &stacks, cms, u, &[], tr)
}

/// Open **stacks** at `u ‖ r` as one Mercury instance
/// (`docs/spec/recursion.md` §1.3). `stacks[i]` is stack `i`'s columns in slot
/// order — every one `u.len()`-variate, at most `2^r.len()` of them — and its
/// value is `Σ_j eq(r, j)·col_j(u)`, what the stack evaluates to at `u ‖ r`.
/// [`batch_open`] is this at `r = []`, every stack one column: the base
/// format, byte for byte.
pub fn batch_open_stacked(
    srs: &Srs,
    stacks: &[Vec<&MultilinearPoly>],
    cms: &[MercuryCommitment],
    u: &[Fr],
    r: &[Fr],
    tr: &mut Transcript,
) -> Result<(Vec<Fr>, MercuryProof), PcsError> {
    if stacks.is_empty() || stacks.iter().any(Vec::is_empty) {
        return Err(PcsError::EmptyBatch);
    }
    if stacks.len() != cms.len() {
        return Err(PcsError::BatchLengthMismatch {
            commitments: cms.len(),
            paired: stacks.len(),
        });
    }
    // The refusals in `batch_open`'s order: the columns' sizes, the instance's,
    // then the point's.
    let width = stacks[0][0].num_vars();
    for col in stacks.iter().flatten() {
        if col.num_vars() != width {
            return Err(PcsError::MixedColumnSizes {
                expected: width,
                found: col.num_vars(),
            });
        }
    }
    let n = check_num_vars(width + r.len())? as usize;
    if u.len() != width {
        return Err(PcsError::PointLengthMismatch {
            point: u.len(),
            num_vars: width,
        });
    }
    let slots = 1usize << r.len();
    if let Some(stack) = stacks.iter().find(|s| s.len() > slots) {
        return Err(PcsError::BatchLengthMismatch {
            commitments: slots,
            paired: stack.len(),
        });
    }
    let point: Vec<Fr> = u.iter().chain(r).copied().collect();
    let available = srs.g1().len();
    if available < n {
        return Err(PcsError::SrsTooSmall {
            needed: n,
            available,
        });
    }

    let eq_r = eq_table(r);
    let vs: Vec<Fr> = stacks
        .iter()
        .map(|stack| {
            stack
                .iter()
                .zip(&eq_r)
                .fold(Fr::ZERO, |acc, (col, e)| acc + *e * col.evaluate(u))
        })
        .collect();
    let (weights, cm_star, v_star) = batch_preamble(cms, &point, &vs, tr);
    let column = 1usize << width;
    let combined: Vec<Fr> = (0..n)
        .into_par_iter()
        .map(|i| {
            let (slot, row) = (i / column, i % column);
            let mut acc = Fr::ZERO;
            for (stack, weight) in stacks.iter().zip(&weights) {
                if let Some(col) = stack.get(slot) {
                    acc += *weight * col.get(row);
                }
            }
            acc
        })
        .collect();
    let f_star = MultilinearPoly::new(PolyBacking::Fr(combined));

    let (v, proof) = open(srs, &f_star, &cm_star, &point, tr)?;
    assert_eq!(
        v, v_star,
        "batch_open: the combined column's value must be the combination of the columns' values"
    );
    Ok((vs, proof))
}

// ---------------------------------------------------------------------------
// The prover's witness
// ---------------------------------------------------------------------------

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

    /// Every limb of a real point is below `2^128`, which is what makes the
    /// infinity sentinel collision-free by construction rather than by an
    /// appeal to the curve equation.
    #[test]
    fn every_limb_is_below_the_sentinel() {
        let sentinel = Fr::from_hex(G1_INFINITY_SENTINEL).expect("canonical");
        let mut point = G1Projective::GENERATOR;
        for _ in 0..64 {
            let affine = point.to_affine();
            for limb in transcript::g1_limbs(&affine.to_bytes()) {
                let bytes = limb.to_bytes();
                assert!(
                    bytes[16..].iter().all(|b| *b == 0),
                    "a limb must fit in 128 bits"
                );
                assert_ne!(limb, sentinel, "no real limb is the sentinel");
            }
            point = point.add(&G1Projective::GENERATOR);
        }
        assert_eq!(
            transcript::g1_limbs(&G1Affine::IDENTITY.to_bytes()),
            [sentinel; 4]
        );
        // The sentinel is exactly 2^128: one at byte 16, zero everywhere else.
        let bytes = sentinel.to_bytes();
        assert_eq!(bytes[16], 1);
        assert!(bytes.iter().enumerate().all(|(i, b)| i == 16 || *b == 0));
    }
}
