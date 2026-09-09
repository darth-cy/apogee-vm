//! The BDFG20 batched KZG opening that finishes a Mercury proof.
//!
//! ePrint 2020/081 §4, in the "cleaned up" form of its §4.1. Four polynomials
//! are opened over the three-point set `T = {z, 1/z, alpha}`:
//!
//! | i | polynomial | `S_i`            | `Z_{T \ S_i}`          |
//! | - | ---------- | ---------------- | ---------------------- |
//! | 0 | `g`        | `{z, 1/z}`       | `X - alpha`            |
//! | 1 | `h`        | `{z, 1/z, alpha}`| `1`                    |
//! | 2 | `S`        | `{z, 1/z}`       | `X - alpha`            |
//! | 3 | `D`        | `{z}`            | `(X - 1/z)(X - alpha)` |
//!
//! **That order is frozen**: it fixes which power of the batch challenge each
//! polynomial carries. `docs/spec/mercury.md` §6 is normative.
//!
//! [`items`] is the one definition of the batch, called by the prover and by
//! the verifier. Everything either side needs beyond it — the quotient, the
//! linearization, the verifier's `G1` accumulation — is derived from what
//! `items` returns, so the two cannot drift.

use curve::{G1Affine, G1Projective};
use field::Fr;

use crate::uni;

/// The eight values a Mercury opening batches: the six the prover sends, and
/// the two the verifier derives before the batch is built.
#[derive(Clone, Copy, Debug)]
pub struct Claims {
    pub g_z: Fr,
    pub g_inv_z: Fr,
    pub h_z: Fr,
    pub h_inv_z: Fr,
    pub s_z: Fr,
    pub s_inv_z: Fr,
    /// `h(alpha)`, from the symmetrized inner-product identity at `z`.
    pub h_alpha: Fr,
    /// `D(z) = z^(b-1) * g(1/z)`, from the degree check.
    pub d_z: Fr,
}

/// One polynomial's place in the batch.
pub struct Item {
    /// `Z_{T \ S_i}`, the vanishing polynomial of the points this polynomial is
    /// *not* opened at.
    pub z_complement: Vec<Fr>,
    /// `r_i`, the interpolation of the claimed values over `S_i`.
    pub r: Vec<Fr>,
}

/// `T = {z, 1/z, alpha}`, in the frozen order.
pub fn point_set(alpha: Fr, z: Fr, z_inv: Fr) -> [Fr; 3] {
    [z, z_inv, alpha]
}

/// The batch, in the frozen order `g, h, S, D`.
///
/// The caller must have rejected a degenerate challenge set first: `z`, `1/z`
/// and `alpha` pairwise distinct. [`uni::interpolate`] panics otherwise, which
/// is the right response to a broken invariant but not to adversarial input.
pub fn items(alpha: Fr, z: Fr, z_inv: Fr, c: &Claims) -> [Item; 4] {
    let without_alpha = uni::vanishing(&[alpha]);
    [
        Item {
            z_complement: without_alpha.clone(),
            r: uni::interpolate(&[(z, c.g_z), (z_inv, c.g_inv_z)]),
        },
        Item {
            z_complement: vec![Fr::ONE],
            r: uni::interpolate(&[(z, c.h_z), (z_inv, c.h_inv_z), (alpha, c.h_alpha)]),
        },
        Item {
            z_complement: without_alpha,
            r: uni::interpolate(&[(z, c.s_z), (z_inv, c.s_inv_z)]),
        },
        Item {
            z_complement: uni::vanishing(&[z_inv, alpha]),
            r: vec![c.d_z],
        },
    ]
}

/// `F / Z_T` where `F = sum_i delta^i * Z_{T \ S_i} * (f_i - r_i)`.
///
/// The division is exact whenever each `r_i` really interpolates `f_i` over
/// `S_i`, because `Z_{T \ S_i} * Z_{S_i} = Z_T`. A nonzero remainder means the
/// caller handed in claims that do not match the polynomials, so it panics
/// naming the invariant rather than committing to a wrong quotient.
pub fn quotient(polys: &[&[Fr]; 4], items: &[Item; 4], t_set: &[Fr; 3], delta: Fr) -> Vec<Fr> {
    let mut f: Vec<Fr> = Vec::new();
    let mut power = Fr::ONE;
    for (poly, item) in polys.iter().zip(items) {
        let mut shifted = poly.to_vec();
        uni::add_scaled(&mut shifted, &item.r, -Fr::ONE);
        uni::add_scaled(&mut f, &uni::mul(&item.z_complement, &shifted), power);
        power *= delta;
    }

    let mut quotient = f;
    for root in t_set {
        let (q, rem) = uni::div_by_linear(&quotient, *root);
        assert_eq!(
            rem,
            Fr::ZERO,
            "bdfg::quotient: F is not divisible by Z_T, so a claimed value does not match its polynomial"
        );
        quotient = q;
    }
    quotient
}

/// `L = sum_i delta^i * Z_{T \ S_i}(z') * (f_i - r_i(z')) - Z_T(z') * W`, whose
/// root at `z'` is what the second BDFG20 proof element opens.
pub fn linearization(
    polys: &[&[Fr]; 4],
    items: &[Item; 4],
    t_set: &[Fr; 3],
    w_poly: &[Fr],
    delta: Fr,
    z_prime: Fr,
) -> Vec<Fr> {
    let mut l: Vec<Fr> = Vec::new();
    let mut constant = Fr::ZERO;
    uni::add_scaled(&mut l, w_poly, -uni::eval(&uni::vanishing(t_set), z_prime));
    for (i, (poly, item)) in polys.iter().zip(items).enumerate() {
        let c = uni::pow_usize(delta, i) * uni::eval(&item.z_complement, z_prime);
        uni::add_scaled(&mut l, poly, c);
        constant += c * uni::eval(&item.r, z_prime);
    }
    // Every `r_i(z')` is a scalar, so the whole batch shifts one coefficient.
    if l.is_empty() {
        l.push(Fr::ZERO);
    }
    l[0] -= constant;
    l
}

/// BDFG20 §4.1's `F`, the verifier's `G1` accumulation:
///
/// ```text
///   F = sum_i delta^i Z_{T \ S_i}(z') cm_i
///     - [ sum_i delta^i Z_{T \ S_i}(z') r_i(z') ]_1
///     - Z_T(z') W
/// ```
///
/// The batch then holds exactly when `e(F + z' W', [1]_2) = e(W', [x]_2)`,
/// which the caller assembles beside Mercury's own pairing relation so that
/// both rewrites read in one place.
pub fn batch_term(
    commitments: &[G1Affine; 4],
    items: &[Item; 4],
    t_set: &[Fr; 3],
    g1_gen: &G1Affine,
    w: &G1Affine,
    delta: Fr,
    z_prime: Fr,
) -> G1Projective {
    let mut acc = G1Projective::IDENTITY;
    let mut constant = Fr::ZERO;
    for (i, (cm, item)) in commitments.iter().zip(items).enumerate() {
        let c = uni::pow_usize(delta, i) * uni::eval(&item.z_complement, z_prime);
        acc = acc.add(&G1Projective::from(*cm).mul(&c));
        constant += c * uni::eval(&item.r, z_prime);
    }
    let z_t = uni::eval(&uni::vanishing(t_set), z_prime);
    acc.add(&G1Projective::from(*g1_gen).mul(&-constant))
        .add(&G1Projective::from(*w).mul(&-z_t))
}
