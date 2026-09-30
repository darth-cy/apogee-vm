//! BN128 precompile using Arkworks BLS12-381 implementation.
use super::{FQ2_LEN, FQ_LEN, G1_LEN, G2_LEN, SCALAR_LEN};
use crate::PrecompileHalt;
use std::vec::Vec;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Reads a single `Fq` field element from the input slice.
///
/// Takes a byte slice and attempts to interpret the first 32 bytes as an
/// elliptic curve field element. Returns an error if the bytes do not form
/// a valid field element.
///
/// # Panics
///
/// Panics if the input is not at least 32 bytes long.
#[inline]
fn read_fq(input_be: &[u8; FQ_LEN]) -> Result<Fq, PrecompileHalt> {
    let mut input_le = [0u8; FQ_LEN];
    input_le.copy_from_slice(input_be);

    // Reverse in-place to convert from big-endian to little-endian.
    input_le.reverse();

    Fq::deserialize_uncompressed(&input_le[..])
        .map_err(|_| PrecompileHalt::Bn254FieldPointNotAMember)
}
/// Reads a Fq2 (quadratic extension field element) from the input slice.
///
/// Parses two consecutive Fq field elements as the real and imaginary parts
/// of an Fq2 element.
/// The second component is parsed before the first, ie if a we represent an
/// element in Fq2 as (x,y) -- `y` is parsed before `x`
///
/// # Panics
///
/// Panics if the input is not at least 64 bytes long.
#[inline]
fn read_fq2(input: &[u8]) -> Result<Fq2, PrecompileHalt> {
    let input: &[u8; FQ2_LEN] = input[..FQ2_LEN]
        .try_into()
        .expect("input must be at least FQ2_LEN bytes");
    let (y, x) = input.split_at(FQ_LEN);
    let y = read_fq(y.try_into().expect("split must yield FQ_LEN bytes"))?;
    let x = read_fq(x.try_into().expect("split must yield FQ_LEN bytes"))?;

    Ok(Fq2::new(x, y))
}

/// Creates a new `G1` point from the given `x` and `y` coordinates.
///
/// Constructs a point on the G1 curve from its affine coordinates.
///
/// Note: The point at infinity which is represented as (0,0) is
/// handled specifically because `AffineG1` is not capable of
/// representing such a point.
/// In particular, when we convert from `AffineG1` to `G1`, the point
/// will be (0,0,1) instead of (0,1,0)
#[inline]
fn new_g1_point(px: Fq, py: Fq) -> Result<G1Affine, PrecompileHalt> {
    if px.is_zero() && py.is_zero() {
        Ok(G1Affine::zero())
    } else {
        // We cannot use `G1Affine::new` because that triggers an assert if the point is not on the curve.
        let point = G1Affine::new_unchecked(px, py);
        if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(PrecompileHalt::Bn254AffineGFailedToCreate);
        }
        Ok(point)
    }
}

/// Creates a new `G2` point from the given Fq2 coordinates.
///
/// G2 points in BN254 are defined over a quadratic extension field Fq2.
/// This function takes two Fq2 elements representing the x and y coordinates
/// and creates a G2 point.
///
/// Note: The point at infinity which is represented as (0,0) is
/// handled specifically because `AffineG2` is not capable of
/// representing such a point.
/// In particular, when we convert from `AffineG2` to `G2`, the point
/// will be (0,0,1) instead of (0,1,0)
#[inline]
fn new_g2_point(x: Fq2, y: Fq2) -> Result<G2Affine, PrecompileHalt> {
    let point = if x.is_zero() && y.is_zero() {
        G2Affine::zero()
    } else {
        // We cannot use `G1Affine::new` because that triggers an assert if the point is not on the curve.
        let point = G2Affine::new_unchecked(x, y);
        if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(PrecompileHalt::Bn254AffineGFailedToCreate);
        }
        point
    };

    Ok(point)
}

/// Reads a G1 point from the input slice.
///
/// Parses a G1 point from a byte slice by reading two consecutive field elements
/// representing the x and y coordinates.
///
/// # Panics
///
/// Panics if the input is not at least 64 bytes long.
#[inline]
pub(super) fn read_g1_point(input: &[u8]) -> Result<G1Affine, PrecompileHalt> {
    let input: &[u8; G1_LEN] = input[..G1_LEN]
        .try_into()
        .expect("input must be at least G1_LEN bytes");
    let (px, py) = input.split_at(FQ_LEN);
    let px = read_fq(px.try_into().expect("split must yield FQ_LEN bytes"))?;
    let py = read_fq(py.try_into().expect("split must yield FQ_LEN bytes"))?;
    new_g1_point(px, py)
}

/// Encodes a G1 point into a byte array.
///
/// Converts a G1 point in Jacobian coordinates to affine coordinates and
/// serializes the x and y coordinates as big-endian byte arrays.
///
/// Note: If the point is the point at infinity, this function returns
/// all zeroes.
#[inline]
pub(super) fn encode_g1_point(point: G1Affine) -> [u8; G1_LEN] {
    let mut output = [0u8; G1_LEN];
    let Some((x, y)) = point.xy() else {
        return output;
    };

    let mut x_bytes = [0u8; FQ_LEN];
    x.serialize_uncompressed(&mut x_bytes[..])
        .expect("Failed to serialize x coordinate");

    let mut y_bytes = [0u8; FQ_LEN];
    y.serialize_uncompressed(&mut y_bytes[..])
        .expect("Failed to serialize x coordinate");

    // Convert to big endian by reversing the bytes.
    x_bytes.reverse();
    y_bytes.reverse();

    // Place x in the first half, y in the second half.
    output[0..FQ_LEN].copy_from_slice(&x_bytes);
    output[FQ_LEN..(FQ_LEN * 2)].copy_from_slice(&y_bytes);

    output
}

/// Reads a G2 point from the input slice.
///
/// Parses a G2 point from a byte slice by reading four consecutive Fq field elements
/// representing the two Fq2 coordinates (x and y) of the G2 point.
///
/// # Panics
///
/// Panics if the input is not at least 128 bytes long.
#[inline]
pub(super) fn read_g2_point(input: &[u8]) -> Result<G2Affine, PrecompileHalt> {
    let input: &[u8; G2_LEN] = input[..G2_LEN]
        .try_into()
        .expect("input must be at least G2_LEN bytes");
    let (ba, bb) = input.split_at(FQ2_LEN);
    let ba = read_fq2(ba)?;
    let bb = read_fq2(bb)?;
    new_g2_point(ba, bb)
}

/// Reads a scalar from the input slice
///
/// Note: The scalar does not need to be canonical.
///
/// # Panics
///
/// If `input.len()` is not equal to [`SCALAR_LEN`].
#[inline]
pub(super) fn read_scalar(input: &[u8]) -> Fr {
    let input: &[u8; SCALAR_LEN] = input.try_into().expect("input must be SCALAR_LEN bytes");
    Fr::from_be_bytes_mod_order(input)
}

/// Performs point addition on two G1 points.
#[inline]
pub(crate) fn g1_point_add(p1_bytes: &[u8], p2_bytes: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
    let p1 = read_g1_point(p1_bytes)?;
    let p2 = read_g1_point(p2_bytes)?;

    let p1_jacobian: G1Projective = p1.into();

    let p3 = p1_jacobian + p2;
    let output = encode_g1_point(p3.into_affine());

    Ok(output)
}

/// Performs a G1 scalar multiplication.
#[inline]
pub(crate) fn g1_point_mul(
    point_bytes: &[u8],
    fr_bytes: &[u8],
) -> Result<[u8; 64], PrecompileHalt> {
    let p = read_g1_point(point_bytes)?;
    let fr = read_scalar(fr_bytes);

    let big_int = fr.into_bigint();
    let result = p.mul_bigint(big_int);

    let output = encode_g1_point(result.into_affine());

    Ok(output)
}

/// pairing_check performs a pairing check on a list of G1 and G2 point pairs and
/// returns true if the result is equal to the identity element.
///
/// Note: If the input is empty, this function returns true.
/// This is different to EIP2537 which disallows the empty input.
#[inline]
pub(crate) fn pairing_check(pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
    let mut g1_points = Vec::with_capacity(pairs.len());
    let mut g2_points = Vec::with_capacity(pairs.len());

    for (g1_bytes, g2_bytes) in pairs {
        let g1 = read_g1_point(g1_bytes)?;
        let g2 = read_g2_point(g2_bytes)?;

        // Skip pairs where either point is at infinity
        if !g1.is_zero() && !g2.is_zero() {
            g1_points.push(g1);
            g2_points.push(g2);
        }
    }

    if g1_points.is_empty() {
        return Ok(true);
    }

    let pairing_result = Bn254::multi_pairing(&g1_points, &g2_points);
    Ok(pairing_result.0.is_one())
}

// ---------------------------------------------------------------------------
// apogee-vm: the `EC_ADD` delegation
// ---------------------------------------------------------------------------

/// `p1 + p2`, with the **group law** delegated and the parsing upstream's.
///
/// `read_g1_point` and `encode_g1_point` are the same functions
/// [`g1_point_add`] calls, which is the whole point of putting this here: a
/// malformed point, a coordinate at or above the modulus and the `(0, 0)`
/// encoding of infinity are all refused by exactly the code that refuses them
/// on the host. Nothing about the precompile's contract moves.
#[cfg(target_arch = "riscv32")]
pub(crate) fn g1_point_add_delegated(
    p1_bytes: &[u8],
    p2_bytes: &[u8],
) -> Result<[u8; 64], PrecompileHalt> {
    let p1 = read_g1_point(p1_bytes)?;
    let p2 = read_g1_point(p2_bytes)?;
    let sum = guest_sdk::ec_add(
        &guest_sdk::recursion::BN254_GROUPS,
        &apogee::lift(&p1),
        &apogee::lift(&p2),
    );
    Ok(encode_g1_point(match sum {
        Some(r) => apogee::jacobian(&r).into_affine(),
        // `-ENOSYS`: an executor with no `EC_ADD` circuit, which is every
        // executor but this VM's. Upstream's own group law is the fallback.
        None => (G1Projective::from(p1) + p2).into_affine(),
    }))
}

/// `scalar · point`, likewise. The ladder is `guest_sdk::ec_mul`.
#[cfg(target_arch = "riscv32")]
pub(crate) fn g1_point_mul_delegated(
    point_bytes: &[u8],
    fr_bytes: &[u8],
) -> Result<[u8; 64], PrecompileHalt> {
    let p = read_g1_point(point_bytes)?;
    let fr = read_scalar(fr_bytes);
    let big = fr.into_bigint();
    let product = guest_sdk::ec_mul(
        &guest_sdk::recursion::BN254_GROUPS,
        &apogee::lift(&p),
        &apogee::scalar_limbs(&big),
    );
    Ok(encode_g1_point(match product {
        Some(r) => apogee::jacobian(&r).into_affine(),
        None => p.mul_bigint(big).into_affine(),
    }))
}

/// The conversion between arkworks' representation and the delegation's, and
/// nothing else: the ABI — the selector triple, the three invocations in group
/// order and the double-and-add ladder — is `guest_sdk`'s.
#[cfg(target_arch = "riscv32")]
mod apogee {
    use super::{Fq, G1Affine, G1Projective};
    use ark_ec::AffineRepr;
    use ark_ff::{BigInteger256, PrimeField};

    /// A field element's eight little-endian 32-bit limbs. arkworks holds
    /// `x·R`; `into_bigint` is the conversion out of Montgomery form, so what
    /// this returns is the canonical integer the frame requires — below `q` by
    /// the type's own invariant, so the delegation's `< m` operand bound costs
    /// this path nothing.
    fn limbs(f: &Fq) -> [u32; 8] {
        split(&f.into_bigint())
    }

    /// Four 64-bit limbs as eight 32-bit ones, little-endian throughout.
    fn split(n: &BigInteger256) -> [u32; 8] {
        let w = n.0;
        core::array::from_fn(|k| (w[k / 2] >> (32 * (k % 2))) as u32)
    }

    /// A reduced scalar's eight limbs, for `guest_sdk::ec_mul`.
    pub(super) fn scalar_limbs(n: &BigInteger256) -> [u32; 8] {
        split(n)
    }

    /// [`limbs`]' inverse. Every lane the delegation writes is below `q`, so the
    /// reduction `from_le_bytes_mod_order` performs is the identity.
    fn field(v: &[u32; 8]) -> Fq {
        let mut bytes = [0u8; 32];
        for (k, limb) in v.iter().enumerate() {
            bytes[4 * k..4 * k + 4].copy_from_slice(&limb.to_le_bytes());
        }
        Fq::from_le_bytes_mod_order(&bytes)
    }

    /// An affine point lifted to `Z = 1`; the affine infinity to `(0 : 1 : 0)`.
    ///
    /// The special case is required and not defensive: arkworks encodes an
    /// affine infinity as `(0, 0)` with a flag, and `(0 : 0 : 1)` is neither the
    /// projective identity nor a curve point, so no complete formula rescues it.
    pub(super) fn lift(p: &G1Affine) -> guest_sdk::ProjectivePoint {
        match p.xy() {
            Some((x, y)) => {
                let mut one = [0u32; 8];
                one[0] = 1;
                [limbs(&x), limbs(&y), one]
            }
            None => guest_sdk::ec_identity(),
        }
    }

    /// A homogeneous point as arkworks' **Jacobian** one: `(X·Z, Y·Z², Z)`,
    /// since arkworks reads `x = X/Z²` and `y = Y/Z³` where the delegation
    /// reads `x = X/Z` and `y = Y/Z`.
    pub(super) fn jacobian(p: &guest_sdk::ProjectivePoint) -> G1Projective {
        let (x, y, z) = (field(&p[0]), field(&p[1]), field(&p[2]));
        let zz = z * z;
        G1Projective::new_unchecked(x * z, y * zz, z)
    }
}
