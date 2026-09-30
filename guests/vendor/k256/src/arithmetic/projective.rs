//! Projective points

#![allow(clippy::op_ref)]

use super::{AffinePoint, FieldElement, Scalar, CURVE_EQUATION_B_SINGLE};
use crate::{CompressedPoint, EncodedPoint, PublicKey, Secp256k1};
use core::{
    iter::Sum,
    ops::{Add, AddAssign, Neg, Sub, SubAssign},
};
use elliptic_curve::ops::BatchInvert;
use elliptic_curve::{
    group::{
        ff::Field,
        prime::{PrimeCurve, PrimeCurveAffine, PrimeGroup},
        Curve, Group, GroupEncoding,
    },
    rand_core::RngCore,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    BatchNormalize, Error, Result,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[rustfmt::skip]
const ENDOMORPHISM_BETA: FieldElement = FieldElement::from_bytes_unchecked(&[
    0x7a, 0xe9, 0x6a, 0x2b, 0x65, 0x7c, 0x07, 0x10,
    0x6e, 0x64, 0x47, 0x9e, 0xac, 0x34, 0x34, 0xe9,
    0x9c, 0xf0, 0x49, 0x75, 0x12, 0xf5, 0x89, 0x95,
    0xc1, 0x39, 0x6c, 0x28, 0x71, 0x95, 0x01, 0xee,
]);

/// A point on the secp256k1 curve in projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct ProjectivePoint {
    x: FieldElement,
    y: FieldElement,
    pub(super) z: FieldElement,
}

impl ProjectivePoint {
    /// Additive identity of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    /// Base point of secp256k1.
    pub const GENERATOR: Self = Self {
        x: AffinePoint::GENERATOR.x,
        y: AffinePoint::GENERATOR.y,
        z: FieldElement::ONE,
    };

    /// Returns the additive identity of SECP256k1, also known as the "neutral element" or
    /// "point at infinity".
    #[deprecated(since = "0.10.2", note = "use `ProjectivePoint::IDENTITY` instead")]
    pub const fn identity() -> ProjectivePoint {
        Self::IDENTITY
    }

    /// Returns the base point of SECP256k1.
    #[deprecated(since = "0.10.2", note = "use `ProjectivePoint::GENERATOR` instead")]
    pub fn generator() -> ProjectivePoint {
        Self::GENERATOR
    }

    /// Returns the affine representation of this point.
    pub fn to_affine(&self) -> AffinePoint {
        self.z
            .invert()
            .map(|zinv| self.to_affine_internal(zinv))
            .unwrap_or_else(|| AffinePoint::IDENTITY)
    }

    pub(super) fn to_affine_internal(self, zinv: FieldElement) -> AffinePoint {
        let x = self.x * &zinv;
        let y = self.y * &zinv;
        AffinePoint::new(x.normalize(), y.normalize())
    }

    /// Returns `-self`.
    fn neg(&self) -> ProjectivePoint {
        ProjectivePoint {
            x: self.x,
            y: self.y.negate(1).normalize_weak(),
            z: self.z,
        }
    }

    /// Returns `self + other`.
    ///
    /// apogee-vm: on the guest target this is the `EC_ADD` delegation, whose
    /// circuit implements this very algorithm over this very representation,
    /// so the delegated path and [`Self::add_inner`] agree limb for limb and
    /// not merely as points. The result is fully normalized, which upstream's
    /// weakly normalized one also is a representative of.
    fn add(&self, other: &ProjectivePoint) -> ProjectivePoint {
        #[cfg(target_arch = "riscv32")]
        let out = apogee::add(self, other);
        #[cfg(not(target_arch = "riscv32"))]
        let out = self.add_inner(other);
        out
    }

    /// Returns `self + other`, in software.
    fn add_inner(&self, other: &ProjectivePoint) -> ProjectivePoint {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060 Algorithm 7).

        let xx = self.x * &other.x;
        let yy = self.y * &other.y;
        let zz = self.z * &other.z;

        let n_xx_yy = (xx + &yy).negate(2);
        let n_yy_zz = (yy + &zz).negate(2);
        let n_xx_zz = (xx + &zz).negate(2);
        let xy_pairs = ((self.x + &self.y) * &(other.x + &other.y)) + &n_xx_yy;
        let yz_pairs = ((self.y + &self.z) * &(other.y + &other.z)) + &n_yy_zz;
        let xz_pairs = ((self.x + &self.z) * &(other.x + &other.z)) + &n_xx_zz;

        let bzz = zz.mul_single(CURVE_EQUATION_B_SINGLE);
        let bzz3 = (bzz.double() + &bzz).normalize_weak();

        let yy_m_bzz3 = yy + &bzz3.negate(1);
        let yy_p_bzz3 = yy + &bzz3;

        let byz = &yz_pairs
            .mul_single(CURVE_EQUATION_B_SINGLE)
            .normalize_weak();
        let byz3 = (byz.double() + byz).normalize_weak();

        let xx3 = xx.double() + &xx;
        let bxx9 = (xx3.double() + &xx3)
            .normalize_weak()
            .mul_single(CURVE_EQUATION_B_SINGLE)
            .normalize_weak();

        let new_x = ((xy_pairs * &yy_m_bzz3) + &(byz3 * &xz_pairs).negate(1)).normalize_weak(); // m1
        let new_y = ((yy_p_bzz3 * &yy_m_bzz3) + &(bxx9 * &xz_pairs)).normalize_weak();
        let new_z = ((yz_pairs * &yy_p_bzz3) + &(xx3 * &xy_pairs)).normalize_weak();

        ProjectivePoint {
            x: new_x,
            y: new_y,
            z: new_z,
        }
    }

    /// Returns `self + other`.
    /// apogee-vm: on the guest target the affine operand is lifted to `Z = 1`
    /// and the addition is the `EC_ADD` delegation — Algorithm 7 rather than
    /// Algorithm 8, which is the same function of the same point and three
    /// invocations either way. **The identity correction below is kept**: an
    /// affine identity is `(0, 0)` here, which as `(0 : 0 : 1)` is not the
    /// projective identity and not on the curve, so no complete formula
    /// rescues it and the conditional assignment is what does.
    fn add_mixed(&self, other: &AffinePoint) -> ProjectivePoint {
        #[cfg(target_arch = "riscv32")]
        let out = apogee::add_mixed(self, other);
        #[cfg(not(target_arch = "riscv32"))]
        let out = self.add_mixed_inner(other);
        out
    }

    /// Returns `self + other`, in software.
    fn add_mixed_inner(&self, other: &AffinePoint) -> ProjectivePoint {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060 Algorithm 8).

        let xx = self.x * &other.x;
        let yy = self.y * &other.y;
        let xy_pairs = ((self.x + &self.y) * &(other.x + &other.y)) + &(xx + &yy).negate(2);
        let yz_pairs = (other.y * &self.z) + &self.y;
        let xz_pairs = (other.x * &self.z) + &self.x;

        let bzz = &self.z.mul_single(CURVE_EQUATION_B_SINGLE);
        let bzz3 = (bzz.double() + bzz).normalize_weak();

        let yy_m_bzz3 = yy + &bzz3.negate(1);
        let yy_p_bzz3 = yy + &bzz3;

        let byz = &yz_pairs
            .mul_single(CURVE_EQUATION_B_SINGLE)
            .normalize_weak();
        let byz3 = (byz.double() + byz).normalize_weak();

        let xx3 = xx.double() + &xx;
        let bxx9 = &(xx3.double() + &xx3)
            .normalize_weak()
            .mul_single(CURVE_EQUATION_B_SINGLE)
            .normalize_weak();

        let mut ret = ProjectivePoint {
            x: ((xy_pairs * &yy_m_bzz3) + &(byz3 * &xz_pairs).negate(1)).normalize_weak(),
            y: ((yy_p_bzz3 * &yy_m_bzz3) + &(bxx9 * &xz_pairs)).normalize_weak(),
            z: ((yz_pairs * &yy_p_bzz3) + &(xx3 * &xy_pairs)).normalize_weak(),
        };
        ret.conditional_assign(self, other.is_identity());
        ret
    }

    /// Doubles this point.
    #[inline]
    /// apogee-vm: on the guest target this is `self + self` through the
    /// `EC_ADD` delegation. Algorithm 7 is **complete**, so it doubles
    /// correctly and needs no separate formula; Algorithm 9 below is the
    /// cheaper one to run in software and is what the fallback keeps.
    pub fn double(&self) -> ProjectivePoint {
        #[cfg(target_arch = "riscv32")]
        let out = apogee::double(self);
        #[cfg(not(target_arch = "riscv32"))]
        let out = self.double_inner();
        out
    }

    /// Returns `self + self`, in software.
    fn double_inner(&self) -> ProjectivePoint {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060 Algorithm 9).

        let yy = self.y.square();
        let zz = self.z.square();
        let xy2 = (self.x * &self.y).double();

        let bzz = &zz.mul_single(CURVE_EQUATION_B_SINGLE);
        let bzz3 = (bzz.double() + bzz).normalize_weak();
        let bzz9 = (bzz3.double() + &bzz3).normalize_weak();

        let yy_m_bzz9 = yy + &bzz9.negate(1);
        let yy_p_bzz3 = yy + &bzz3;

        let yy_zz = yy * &zz;
        let yy_zz8 = yy_zz.double().double().double();
        let t = (yy_zz8.double() + &yy_zz8)
            .normalize_weak()
            .mul_single(CURVE_EQUATION_B_SINGLE);

        ProjectivePoint {
            x: xy2 * &yy_m_bzz9,
            y: ((yy_m_bzz9 * &yy_p_bzz3) + &t).normalize_weak(),
            z: ((yy * &self.y) * &self.z)
                .double()
                .double()
                .double()
                .normalize_weak(),
        }
    }

    /// Returns `self - other`.
    fn sub(&self, other: &ProjectivePoint) -> ProjectivePoint {
        self.add(&other.neg())
    }

    /// Returns `self - other`.
    fn sub_mixed(&self, other: &AffinePoint) -> ProjectivePoint {
        self.add_mixed(&other.neg())
    }

    /// Calculates SECP256k1 endomorphism: `self * lambda`.
    pub fn endomorphism(&self) -> Self {
        Self {
            x: self.x * &ENDOMORPHISM_BETA,
            y: self.y,
            z: self.z,
        }
    }

    /// Check whether `self` is equal to an affine point.
    ///
    /// This is a lot faster than first converting `self` to an `AffinePoint` and then doing the
    /// comparison. It is a little bit faster than converting `other` to a `ProjectivePoint` first.
    pub fn eq_affine(&self, other: &AffinePoint) -> Choice {
        // For understanding of this algorithm see Projective equality comment. It's the same except
        // that we know z = 1 for rhs and we have to check identity as a separate case.
        let both_identity = self.is_identity() & other.is_identity();
        let rhs_identity = other.is_identity();
        let rhs_x = &other.x * &self.z;
        let x_eq = rhs_x.negate(1).add(&self.x).normalizes_to_zero();

        let rhs_y = &other.y * &self.z;
        let y_eq = rhs_y.negate(1).add(&self.y).normalizes_to_zero();

        both_identity | (!rhs_identity & x_eq & y_eq)
    }
}

impl From<AffinePoint> for ProjectivePoint {
    fn from(p: AffinePoint) -> Self {
        let projective = ProjectivePoint {
            x: p.x,
            y: p.y,
            z: FieldElement::ONE,
        };
        Self::conditional_select(&projective, &Self::IDENTITY, p.is_identity())
    }
}

impl<const N: usize> BatchNormalize<[ProjectivePoint; N]> for ProjectivePoint {
    type Output = [Self::AffineRepr; N];

    #[inline]
    fn batch_normalize(points: &[Self; N]) -> [Self::AffineRepr; N] {
        let mut zs = [FieldElement::ONE; N];
        let mut affine_points = [AffinePoint::IDENTITY; N];
        batch_normalize_generic(points, &mut zs, &mut affine_points);
        affine_points
    }
}

#[cfg(feature = "alloc")]
impl BatchNormalize<[ProjectivePoint]> for ProjectivePoint {
    type Output = Vec<Self::AffineRepr>;

    #[inline]
    fn batch_normalize(points: &[Self]) -> Vec<Self::AffineRepr> {
        let mut zs = vec![FieldElement::ONE; points.len()];
        let mut affine_points = vec![AffinePoint::IDENTITY; points.len()];
        batch_normalize_generic(points, zs.as_mut_slice(), &mut affine_points);
        affine_points
    }
}

fn batch_normalize_generic<P, Z, O>(points: &P, zs: &mut Z, out: &mut O)
where
    FieldElement: BatchInvert<Z>,
    P: AsRef<[ProjectivePoint]> + ?Sized,
    Z: AsMut<[FieldElement]> + ?Sized,
    O: AsMut<[AffinePoint]> + ?Sized,
{
    let points = points.as_ref();
    let out = out.as_mut();

    for i in 0..points.len() {
        // Even a single zero value will fail inversion for the entire batch.
        // Put a dummy value (above `FieldElement::ONE`) so inversion succeeds
        // and treat that case specially later-on.
        zs.as_mut()[i].conditional_assign(&points[i].z, !points[i].z.ct_eq(&FieldElement::ZERO));
    }

    // This is safe to unwrap since we assured that all elements are non-zero
    let zs_inverses = <FieldElement as BatchInvert<Z>>::batch_invert(zs).unwrap();

    for i in 0..out.len() {
        // If the `z` coordinate is non-zero, we can use it to invert;
        // otherwise it defaults to the `IDENTITY` value.
        out[i] = AffinePoint::conditional_select(
            &points[i].to_affine_internal(zs_inverses.as_ref()[i]),
            &AffinePoint::IDENTITY,
            points[i].z.ct_eq(&FieldElement::ZERO),
        );
    }
}

impl From<&AffinePoint> for ProjectivePoint {
    fn from(p: &AffinePoint) -> Self {
        Self::from(*p)
    }
}

impl From<ProjectivePoint> for AffinePoint {
    fn from(p: ProjectivePoint) -> AffinePoint {
        p.to_affine()
    }
}

impl From<&ProjectivePoint> for AffinePoint {
    fn from(p: &ProjectivePoint) -> AffinePoint {
        p.to_affine()
    }
}

impl FromEncodedPoint<Secp256k1> for ProjectivePoint {
    fn from_encoded_point(p: &EncodedPoint) -> CtOption<Self> {
        AffinePoint::from_encoded_point(p).map(ProjectivePoint::from)
    }
}

impl ToEncodedPoint<Secp256k1> for ProjectivePoint {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        self.to_affine().to_encoded_point(compress)
    }
}

impl ConditionallySelectable for ProjectivePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ProjectivePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl ConstantTimeEq for ProjectivePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        // If both points are not equal to inifinity then they are in the form:
        //
        // lhs: (x₁z₁, y₁z₁, z₁), rhs: (x₂z₂, y₂z₂, z₂) where z₁ ≠ 0 and z₂ ≠ 0.
        // we want to know if x₁ == x₂ and y₁ == y₂
        // So we multiply the x and y by the opposing z to get:
        // lhs: (x₁z₁z₂, y₁z₁z₂) rhs: (x₂z₁z₂, y₂z₁z₂)
        // and check lhs == rhs which implies x₁ == x₂ and y₁ == y₂.
        //
        // If one point is infinity it is always in the form (0, y, 0). Note that the above
        // algorithm still works here. If They are both infinity then they'll both evaluate to (0,0).
        // If for example the first point is infinity then the above will evaluate to (z₂ * 0, z₂ *
        // y₂) = (0, z₂y₂) for the first point and (0 * x₂z₂, 0 * y₂z₂) = (0, 0) for the second.
        //
        // Since z₂y₂ will never be 0 they will not be equal in this case either.
        let lhs_x = self.x * &other.z;
        let rhs_x = other.x * &self.z;
        let x_eq = rhs_x.negate(1).add(&lhs_x).normalizes_to_zero();

        let lhs_y = self.y * &other.z;
        let rhs_y = other.y * &self.z;
        let y_eq = rhs_y.negate(1).add(&lhs_y).normalizes_to_zero();
        x_eq & y_eq
    }
}

impl PartialEq for ProjectivePoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl PartialEq<AffinePoint> for ProjectivePoint {
    fn eq(&self, other: &AffinePoint) -> bool {
        self.eq_affine(other).into()
    }
}

impl PartialEq<ProjectivePoint> for AffinePoint {
    fn eq(&self, other: &ProjectivePoint) -> bool {
        other.eq_affine(self).into()
    }
}

impl Eq for ProjectivePoint {}

impl Group for ProjectivePoint {
    type Scalar = Scalar;

    fn random(mut rng: impl RngCore) -> Self {
        Self::GENERATOR * Scalar::random(&mut rng)
    }

    fn identity() -> Self {
        Self::IDENTITY
    }

    fn generator() -> Self {
        Self::GENERATOR
    }

    fn is_identity(&self) -> Choice {
        self.z.normalizes_to_zero()
    }

    #[must_use]
    fn double(&self) -> Self {
        Self::double(self)
    }
}

impl GroupEncoding for ProjectivePoint {
    type Repr = CompressedPoint;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <AffinePoint as GroupEncoding>::from_bytes(bytes).map(Into::into)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // No unchecked conversion possible for compressed points
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.to_affine().to_bytes()
    }
}

impl PrimeGroup for ProjectivePoint {}

impl Curve for ProjectivePoint {
    type AffineRepr = AffinePoint;

    fn to_affine(&self) -> AffinePoint {
        ProjectivePoint::to_affine(self)
    }

    #[cfg(feature = "alloc")]
    #[inline]
    fn batch_normalize(projective: &[Self], affine: &mut [Self::AffineRepr]) {
        assert_eq!(projective.len(), affine.len());
        let mut zs = vec![FieldElement::ONE; projective.len()];
        batch_normalize_generic(projective, zs.as_mut_slice(), affine);
    }
}

impl PrimeCurve for ProjectivePoint {
    type Affine = AffinePoint;
}

impl Default for ProjectivePoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl DefaultIsZeroes for ProjectivePoint {}

impl Add<&ProjectivePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::add(self, other)
    }
}

impl Add<ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::add(&self, &other)
    }
}

impl Add<&ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::add(&self, other)
    }
}

impl AddAssign<ProjectivePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: ProjectivePoint) {
        *self = ProjectivePoint::add(self, &rhs);
    }
}

impl AddAssign<&ProjectivePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: &ProjectivePoint) {
        *self = ProjectivePoint::add(self, rhs);
    }
}

impl Add<AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: AffinePoint) -> ProjectivePoint {
        ProjectivePoint::add_mixed(&self, &other)
    }
}

impl Add<&AffinePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::add_mixed(self, other)
    }
}

impl Add<&AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::add_mixed(&self, other)
    }
}

impl AddAssign<AffinePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: AffinePoint) {
        *self = ProjectivePoint::add_mixed(self, &rhs);
    }
}

impl AddAssign<&AffinePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: &AffinePoint) {
        *self = ProjectivePoint::add_mixed(self, rhs);
    }
}

impl Sum for ProjectivePoint {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(ProjectivePoint::IDENTITY, |a, b| a + b)
    }
}

impl<'a> Sum<&'a ProjectivePoint> for ProjectivePoint {
    fn sum<I: Iterator<Item = &'a ProjectivePoint>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

impl Sub<ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::sub(&self, &other)
    }
}

impl Sub<&ProjectivePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::sub(self, other)
    }
}

impl Sub<&ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::sub(&self, other)
    }
}

impl SubAssign<ProjectivePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: ProjectivePoint) {
        *self = ProjectivePoint::sub(self, &rhs);
    }
}

impl SubAssign<&ProjectivePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: &ProjectivePoint) {
        *self = ProjectivePoint::sub(self, rhs);
    }
}

impl Sub<AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: AffinePoint) -> ProjectivePoint {
        ProjectivePoint::sub_mixed(&self, &other)
    }
}

impl Sub<&AffinePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::sub_mixed(self, other)
    }
}

impl Sub<&AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::sub_mixed(&self, other)
    }
}

impl SubAssign<AffinePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: AffinePoint) {
        *self = ProjectivePoint::sub_mixed(self, &rhs);
    }
}

impl SubAssign<&AffinePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: &AffinePoint) {
        *self = ProjectivePoint::sub_mixed(self, rhs);
    }
}

impl Neg for ProjectivePoint {
    type Output = ProjectivePoint;

    fn neg(self) -> ProjectivePoint {
        ProjectivePoint::neg(&self)
    }
}

impl<'a> Neg for &'a ProjectivePoint {
    type Output = ProjectivePoint;

    fn neg(self) -> ProjectivePoint {
        ProjectivePoint::neg(self)
    }
}

impl From<PublicKey> for ProjectivePoint {
    fn from(public_key: PublicKey) -> ProjectivePoint {
        AffinePoint::from(public_key).into()
    }
}

impl From<&PublicKey> for ProjectivePoint {
    fn from(public_key: &PublicKey) -> ProjectivePoint {
        AffinePoint::from(public_key).into()
    }
}

impl TryFrom<ProjectivePoint> for PublicKey {
    type Error = Error;

    fn try_from(point: ProjectivePoint) -> Result<PublicKey> {
        AffinePoint::from(point).try_into()
    }
}

impl TryFrom<&ProjectivePoint> for PublicKey {
    type Error = Error;

    fn try_from(point: &ProjectivePoint) -> Result<PublicKey> {
        AffinePoint::from(point).try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::{AffinePoint, ProjectivePoint};
    use crate::{
        test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS},
        Scalar,
    };
    use elliptic_curve::group::{ff::PrimeField, prime::PrimeCurveAffine};
    use elliptic_curve::ops::MulByGenerator;
    use elliptic_curve::Field;
    use elliptic_curve::{group, BatchNormalize};
    use rand_core::OsRng;

    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;

    #[test]
    fn affine_to_projective() {
        let basepoint_affine = AffinePoint::GENERATOR;
        let basepoint_projective = ProjectivePoint::GENERATOR;

        assert_eq!(
            ProjectivePoint::from(basepoint_affine),
            basepoint_projective,
        );
        assert_eq!(basepoint_projective.to_affine(), basepoint_affine);
        assert!(!bool::from(basepoint_projective.to_affine().is_identity()));

        assert!(bool::from(
            ProjectivePoint::IDENTITY.to_affine().is_identity()
        ));
    }

    #[test]
    fn batch_normalize_array() {
        let k: Scalar = Scalar::random(&mut OsRng);
        let l: Scalar = Scalar::random(&mut OsRng);
        let g = ProjectivePoint::mul_by_generator(&k);
        let h = ProjectivePoint::mul_by_generator(&l);

        let mut res = [AffinePoint::IDENTITY; 2];
        let expected = [g.to_affine(), h.to_affine()];
        assert_eq!(
            <ProjectivePoint as BatchNormalize<_>>::batch_normalize(&[g, h]),
            expected
        );

        <ProjectivePoint as group::Curve>::batch_normalize(&[g, h], &mut res);
        assert_eq!(res, expected);

        let expected = [g.to_affine(), AffinePoint::IDENTITY];
        assert_eq!(
            <ProjectivePoint as BatchNormalize<_>>::batch_normalize(&[
                g,
                ProjectivePoint::IDENTITY
            ]),
            expected
        );

        <ProjectivePoint as group::Curve>::batch_normalize(
            &[g, ProjectivePoint::IDENTITY],
            &mut res,
        );
        assert_eq!(res, expected);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn batch_normalize_slice() {
        let k: Scalar = Scalar::random(&mut OsRng);
        let l: Scalar = Scalar::random(&mut OsRng);
        let g = ProjectivePoint::mul_by_generator(&k);
        let h = ProjectivePoint::mul_by_generator(&l);

        let expected = vec![g.to_affine(), h.to_affine()];
        let scalars = vec![g, h];
        let mut res: Vec<_> =
            <ProjectivePoint as BatchNormalize<_>>::batch_normalize(scalars.as_slice());
        assert_eq!(res, expected);

        <ProjectivePoint as group::Curve>::batch_normalize(&[g, h], res.as_mut());
        assert_eq!(res.to_vec(), expected);

        let expected = vec![g.to_affine(), AffinePoint::IDENTITY];
        let scalars = vec![g, ProjectivePoint::IDENTITY];
        res = <ProjectivePoint as BatchNormalize<_>>::batch_normalize(scalars.as_slice());

        assert_eq!(res, expected);

        <ProjectivePoint as group::Curve>::batch_normalize(
            &[g, ProjectivePoint::IDENTITY],
            res.as_mut(),
        );
        assert_eq!(res.to_vec(), expected);
    }

    #[test]
    fn projective_identity_addition() {
        let identity = ProjectivePoint::IDENTITY;
        let generator = ProjectivePoint::GENERATOR;

        assert_eq!(identity + &generator, generator);
        assert_eq!(generator + &identity, generator);
    }

    #[test]
    fn projective_mixed_addition() {
        let identity = ProjectivePoint::IDENTITY;
        let basepoint_affine = AffinePoint::GENERATOR;
        let basepoint_projective = ProjectivePoint::GENERATOR;

        assert_eq!(identity + &basepoint_affine, basepoint_projective);
        assert_eq!(
            basepoint_projective + &basepoint_affine,
            basepoint_projective + &basepoint_projective
        );
    }

    #[test]
    fn test_vector_repeated_add() {
        let generator = ProjectivePoint::GENERATOR;
        let mut p = generator;

        for i in 0..ADD_TEST_VECTORS.len() {
            let affine = p.to_affine();

            let (expected_x, expected_y) = ADD_TEST_VECTORS[i];
            assert_eq!(affine.x.to_bytes(), expected_x.into());
            assert_eq!(affine.y.to_bytes(), expected_y.into());

            p += &generator;
        }
    }

    #[test]
    fn test_vector_repeated_add_mixed() {
        let generator = AffinePoint::GENERATOR;
        let mut p = ProjectivePoint::GENERATOR;

        for i in 0..ADD_TEST_VECTORS.len() {
            let affine = p.to_affine();

            let (expected_x, expected_y) = ADD_TEST_VECTORS[i];
            assert_eq!(affine.x.to_bytes(), expected_x.into());
            assert_eq!(affine.y.to_bytes(), expected_y.into());

            p += &generator;
        }
    }

    #[test]
    fn test_vector_add_mixed_identity() {
        let generator = ProjectivePoint::GENERATOR;
        let p0 = generator + ProjectivePoint::IDENTITY;
        let p1 = generator + AffinePoint::IDENTITY;
        assert_eq!(p0, p1);
    }

    #[test]
    fn test_vector_double_generator() {
        let generator = ProjectivePoint::GENERATOR;
        let mut p = generator;

        for i in 0..2 {
            let affine = p.to_affine();

            let (expected_x, expected_y) = ADD_TEST_VECTORS[i];
            assert_eq!(affine.x.to_bytes(), expected_x.into());
            assert_eq!(affine.y.to_bytes(), expected_y.into());

            p = p.double();
        }
    }

    #[test]
    fn projective_add_vs_double() {
        let generator = ProjectivePoint::GENERATOR;

        let r1 = generator + &generator;
        let r2 = generator.double();
        assert_eq!(r1, r2);

        let r1 = (generator + &generator) + &(generator + &generator);
        let r2 = generator.double().double();
        assert_eq!(r1, r2);
    }

    #[test]
    fn projective_add_and_sub() {
        let basepoint_affine = AffinePoint::GENERATOR;
        let basepoint_projective = ProjectivePoint::GENERATOR;

        assert_eq!(
            (basepoint_projective + &basepoint_projective) - &basepoint_projective,
            basepoint_projective
        );
        assert_eq!(
            (basepoint_projective + &basepoint_affine) - &basepoint_affine,
            basepoint_projective
        );
    }

    #[test]
    fn projective_double_and_sub() {
        let generator = ProjectivePoint::GENERATOR;
        assert_eq!(generator.double() - &generator, generator);
    }

    #[test]
    fn test_vector_scalar_mult() {
        let generator = ProjectivePoint::GENERATOR;

        for (k, coords) in ADD_TEST_VECTORS
            .iter()
            .enumerate()
            .map(|(k, coords)| (Scalar::from(k as u32 + 1), *coords))
            .chain(
                MUL_TEST_VECTORS
                    .iter()
                    .cloned()
                    .map(|(k, x, y)| (Scalar::from_repr(k.into()).unwrap(), (x, y))),
            )
        {
            let res = (generator * &k).to_affine();
            assert_eq!(res.x.to_bytes(), coords.0.into());
            assert_eq!(res.y.to_bytes(), coords.1.into());
        }
    }

    #[test]
    fn projective_equality() {
        use core::ops::Neg;
        assert_ne!(ProjectivePoint::GENERATOR, ProjectivePoint::IDENTITY);
        assert_ne!(ProjectivePoint::IDENTITY, ProjectivePoint::GENERATOR);
        assert_eq!(ProjectivePoint::IDENTITY, ProjectivePoint::IDENTITY);
        assert_eq!(ProjectivePoint::IDENTITY.neg(), ProjectivePoint::IDENTITY);
        assert_eq!(ProjectivePoint::GENERATOR, ProjectivePoint::GENERATOR);
        assert_ne!(ProjectivePoint::GENERATOR, ProjectivePoint::GENERATOR.neg());

        assert_ne!(ProjectivePoint::GENERATOR, AffinePoint::IDENTITY);
        assert_ne!(ProjectivePoint::IDENTITY, AffinePoint::GENERATOR);
        assert_eq!(ProjectivePoint::IDENTITY, AffinePoint::IDENTITY);
        assert_eq!(ProjectivePoint::IDENTITY.neg(), AffinePoint::IDENTITY);
        assert_eq!(ProjectivePoint::GENERATOR, AffinePoint::GENERATOR);
        assert_ne!(ProjectivePoint::GENERATOR.neg(), AffinePoint::GENERATOR);
        assert_eq!(
            ProjectivePoint::GENERATOR.neg(),
            AffinePoint::GENERATOR.neg()
        );
    }
}

#[cfg(target_arch = "riscv32")]
mod apogee {
    use super::{AffinePoint, ConditionallySelectable, FieldElement, ProjectivePoint};
    use super::{PrimeCurveAffine, CURVE_EQUATION_B_SINGLE};
    use guest_sdk::recursion::{ec_add_complete, EcAddFrame, SECP256K1_GROUPS};

    /// The curve constant the delegation's circuit holds as a literal is
    /// `b3 = 3b`, and `constants::ec_add::CURVE_B3[0]` is 21. This is the other
    /// half of that equality, asserted here because it is the one thing in this
    /// patch that a curve parameter changing upstream would make silently
    /// wrong: the frame carries no `b`, so a disagreement is a wrong point and
    /// not a refusal.
    const _: () = assert!(CURVE_EQUATION_B_SINGLE == 7);

    /// A field element's eight little-endian 32-bit limbs, **below `p`**.
    ///
    /// `to_bytes` fully normalizes before encoding, so the operand bound the
    /// circuit enforces — and the executor refuses by name — holds by this
    /// function's construction rather than by a caller's promise. That is the
    /// difference from `field_10x26`'s `operand`, which has a fast path worth
    /// taking because it runs once per multiply; this runs six times per
    /// addition against twelve multiplies removed.
    fn limbs(x: FieldElement) -> [u32; 8] {
        let b = x.to_bytes();
        core::array::from_fn(|k| {
            let at = 32 - 4 * (k + 1);
            u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
        })
    }

    /// [`limbs`]' inverse on a value below `p`, which every lane the delegation
    /// writes is. `from_bytes_unchecked` records it as normalized, and it is.
    fn field(v: &[u32; 8]) -> FieldElement {
        let mut b = [0u8; 32];
        for (k, limb) in v.iter().enumerate() {
            let at = 32 - 4 * (k + 1);
            b[at..at + 4].copy_from_slice(&limb.to_be_bytes());
        }
        FieldElement::from_bytes_unchecked(&b)
    }

    /// A projective point's three coordinates as frame lanes.
    fn lanes(p: &ProjectivePoint) -> [[u32; 8]; 3] {
        [limbs(p.x), limbs(p.y), limbs(p.z)]
    }

    /// `a + b` through the delegation, or through this file's own Algorithm 7.
    ///
    /// `false` from the shim is exactly `-ENOSYS` — an executor with no
    /// `EC_ADD` circuit, which is every executor but this VM's — and then the
    /// answer comes from `add_inner`. The two are the same algorithm over the
    /// same representation, so unlike the field patch they agree on the
    /// representative and not only on the value.
    pub(super) fn add(a: &ProjectivePoint, b: &ProjectivePoint) -> ProjectivePoint {
        let mut frame = EcAddFrame::of(&SECP256K1_GROUPS, &lanes(a), &lanes(b));
        match ec_add_complete(&mut frame, &SECP256K1_GROUPS) {
            true => point(&frame.result()),
            false => a.add_inner(b),
        }
    }

    /// `a + b` for an affine `b`, lifted to `Z = 1`.
    ///
    /// The identity correction is the caller's, not this function's: an affine
    /// identity lifts to a point that is neither the projective identity nor on
    /// the curve, and no complete formula fixes that.
    pub(super) fn add_mixed(a: &ProjectivePoint, b: &AffinePoint) -> ProjectivePoint {
        let q = [limbs(b.x), limbs(b.y), limbs(FieldElement::ONE)];
        let mut frame = EcAddFrame::of(&SECP256K1_GROUPS, &lanes(a), &q);
        if !ec_add_complete(&mut frame, &SECP256K1_GROUPS) {
            return a.add_mixed_inner(b);
        }
        let mut ret = point(&frame.result());
        ret.conditional_assign(a, b.is_identity());
        ret
    }

    /// `a + a` through the delegation, or through this file's Algorithm 9.
    ///
    /// Algorithm 7 is complete and doubles correctly, so the delegated path is
    /// the same call [`add`] makes. The **fallback** is Algorithm 9 and not
    /// `add_inner(a, a)`, because in software the dedicated doubling is the
    /// cheaper of the two and an executor taking the fallback is one paying
    /// software prices for everything.
    pub(super) fn double(a: &ProjectivePoint) -> ProjectivePoint {
        let p = lanes(a);
        let mut frame = EcAddFrame::of(&SECP256K1_GROUPS, &p, &p);
        match ec_add_complete(&mut frame, &SECP256K1_GROUPS) {
            true => point(&frame.result()),
            false => a.double_inner(),
        }
    }

    /// The frame's three result lanes as a projective point.
    fn point(v: &[[u32; 8]; 3]) -> ProjectivePoint {
        ProjectivePoint {
            x: field(&v[0]),
            y: field(&v[1]),
            z: field(&v[2]),
        }
    }
}
