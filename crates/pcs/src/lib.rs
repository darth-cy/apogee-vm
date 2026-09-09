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
//! # What this crate does not do
//!
//! No hiding, no zero knowledge: Mercury is not a hiding commitment and
//! nothing here pretends otherwise. No batching across polynomials — that is
//! S09's business, which reuses [`append_g1_list`] and the BDFG20 pins in
//! `docs/spec/mercury.md` §6.

use rayon::prelude::*;

use constants::{transcript_tags as tags, FR_TWO_ADICITY, G1_INFINITY_SENTINEL};
use curve::msm::{msm, msm_small_u32};
use curve::pairing::pairing_check;
use curve::{G1Affine, G1Projective};
use field::Fr;
use poly::{eq_table, MultilinearPoly, PolyBacking};
use srs::{Srs, SrsVerifier};
use transcript::{Tag, Transcript};

mod bdfg;
mod fft;
mod uni;

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
        let sentinel = Fr::from_hex(G1_INFINITY_SENTINEL)
            .expect("the frozen infinity sentinel is a canonical hex literal");
        return [sentinel; 4];
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
// verify
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

    // Check A, the fold identity at z, rewritten so both G2 arguments are SRS
    // constants: e(cm - (z^b - alpha) q - [g_z]_1 + z*pi_z, [1]_2) = e(pi_z, [x]_2).
    let z_pow_b = uni::pow_usize(z, b);
    let a1 = G1Projective::from(cm.0)
        .add(&G1Projective::from(proof.q).mul(&-(z_pow_b - alpha)))
        .add(&G1Projective::from(vsrs.g1_gen).mul(&-proof.g_z))
        .add(&G1Projective::from(proof.pi_z).mul(&z));
    let b1 = G1Projective::from(proof.pi_z);

    // Check B, the BDFG20 batch: e(F + z' W', [1]_2) = e(W', [x]_2).
    let b2 = G1Projective::from(proof.w_prime);
    let a2 = bdfg::batch_term(
        &[proof.g, proof.h, proof.s, proof.d],
        &bdfg::items(alpha, z, z_inv, &claims),
        &bdfg::point_set(alpha, z, z_inv),
        &vsrs.g1_gen,
        &proof.w,
        delta,
        z_prime,
    )
    .add(&b2.mul(&z_prime));

    // One RLC, one `pairing_check`. If either relation fails, the merged one
    // holds for at most a single `rho`, and `rho` was drawn after every proof
    // element was absorbed.
    let left = a1.add(&a2.mul(&rho)).to_affine();
    let right = b1.add(&b2.mul(&rho)).to_affine();
    if pairing_check(&[(left, vsrs.g2_gen), (-right, vsrs.g2_tau)]) {
        Ok(())
    } else {
        Err(PcsError::VerificationFailed)
    }
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

/// Draw `z`, resampling under the same tag while it is zero so that `1/z`
/// exists. `docs/spec/mercury.md` §7.
fn challenge_z(tr: &mut Transcript) -> Fr {
    loop {
        let z = tr.challenge_scalar(tags::MERCURY_Z);
        if z != Fr::ZERO {
            return z;
        }
    }
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
