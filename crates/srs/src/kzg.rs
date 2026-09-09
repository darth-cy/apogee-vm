//! Univariate KZG over the ceremony powers: the core Mercury is built on.
//!
//! Coefficients are little-endian in the degree — `coeffs[i]` multiplies
//! `X^i` — matching the SRS, whose `g1[i]` is `[x^i]_1`. A commitment is then
//! one MSM of the coefficients against the powers, and nothing here needs an
//! FFT or a domain.

use curve::msm::msm;
use curve::pairing::pairing_check;
use curve::{G1Affine, G1Projective};
use field::Fr;

use crate::{Srs, SrsError};

/// `[f(x)]_1 = sum_i coeffs[i] * [x^i]_1`.
///
/// The empty polynomial is the zero polynomial and commits to the identity.
/// A polynomial with more coefficients than the SRS has powers is an error,
/// never a silent truncation.
pub fn kzg_commit(srs: &Srs, coeffs: &[Fr]) -> Result<G1Affine, SrsError> {
    let powers = srs.g1();
    if coeffs.len() > powers.len() {
        return Err(SrsError::DegreeTooLarge {
            degree: coeffs.len() - 1,
            max: srs.max_degree(),
        });
    }
    Ok(msm(&powers[..coeffs.len()], coeffs)
        .expect("one power per coefficient")
        .to_affine())
}

/// `(f(z), [q(x)]_1)` with `q(X) = (f(X) - f(z)) / (X - z)`.
///
/// One pass of synthetic division gives the quotient and the remainder
/// together: running Horner from the top coefficient down, the value carried
/// into step `i` *is* the quotient's coefficient of `X^i`, and what falls out
/// at the bottom is `f(z)`. The division is exact by construction — `X - z`
/// divides `f(X) - f(z)` — so there is no remainder to check.
pub fn kzg_open(srs: &Srs, coeffs: &[Fr], z: Fr) -> Result<(Fr, G1Affine), SrsError> {
    if coeffs.len() > srs.g1().len() {
        return Err(SrsError::DegreeTooLarge {
            degree: coeffs.len() - 1,
            max: srs.max_degree(),
        });
    }
    if coeffs.is_empty() {
        return Ok((Fr::ZERO, G1Affine::IDENTITY));
    }

    let mut quotient = vec![Fr::ZERO; coeffs.len() - 1];
    let mut acc = coeffs[coeffs.len() - 1];
    for i in (0..coeffs.len() - 1).rev() {
        quotient[i] = acc;
        acc = coeffs[i] + acc * z;
    }

    Ok((acc, kzg_commit(srs, &quotient)?))
}

/// Whether `w` proves `f(z) = v` for the polynomial `cm` commits to.
///
/// The textbook check is `e(cm - v*[1]_1, [1]_2) = e(w, [x]_2 - z*[1]_2)`.
/// Moving the `z` term to G1 rewrites it as one `pairing_check`:
///
/// ```text
///   e(cm - v*[1]_1 + z*w, [1]_2) * e(-w, [x]_2) == 1
/// ```
///
/// The rewrite matters beyond saving a G2 scalar multiplication: both G2
/// arguments are now SRS constants, so an aggregator can batch these across
/// proofs and defer them, which is what the accumulator riding public I/O
/// carries.
///
/// This reads only the three points [`crate::SrsVerifier`] holds. It takes the
/// whole `Srs` because S07 pins the signature that way, not because it needs
/// one.
pub fn kzg_verify(srs: &Srs, cm: &G1Affine, z: Fr, v: Fr, w: &G1Affine) -> bool {
    let g1_gen = srs.g1()[0];
    let lhs = G1Projective::from(*cm)
        .add(&G1Projective::from(g1_gen).mul(&-v))
        .add(&G1Projective::from(*w).mul(&z));

    pairing_check(&[(lhs.to_affine(), srs.g2_gen()), (-*w, srs.g2_tau())])
}
