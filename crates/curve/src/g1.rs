//! G1: `E/Fq: y^2 = x^3 + 3`, in affine and Jacobian coordinates.
//!
//! `#E(Fq) = r`, an odd prime, so the cofactor is 1 and there is no 2-torsion:
//! no on-curve point has `y = 0`. Both facts are used below and re-derived in
//! `tests/constants_check.rs`.

use core::ops::Neg;

use constants::FQ_R;
use field::Fr;

use crate::fq::{batch_inverse, Fq};

/// The curve constant `b = 3`, in Montgomery form.
/// Checked against `constants::G1_B` in `tests/constants_check.rs`.
const B: Fq = Fq([
    0x7a17_caa9_50ad_28d7,
    0x1f6a_c17a_e155_21b9,
    0x334b_ea4e_696b_d284,
    0x2a1f_6744_ce17_9d8e,
]);

/// The generator's `y = 2`, in Montgomery form. Its `x = 1` is `Fq::ONE`,
/// whose limbs are `R`. Both are checked against `constants::G1_GENERATOR_*`.
const GENERATOR_Y: Fq = Fq([
    0xa6ba_871b_8b1e_1b3a,
    0x14f1_d651_eb8e_167b,
    0xccdd_46de_f0f2_8c58,
    0x1c14_ef83_340f_be5e,
]);

/// A point in affine coordinates, or the point at infinity.
///
/// When `infinity` is true the coordinates carry no meaning: every operation
/// ignores them, [`G1Affine::to_bytes`] emits zeros, and equality holds against
/// any other infinity. That is why `PartialEq` is written out rather than
/// derived.
#[derive(Clone, Copy, Debug, Eq)]
pub struct G1Affine {
    pub x: Fq,
    pub y: Fq,
    pub infinity: bool,
}

/// A point in Jacobian coordinates: `(X : Y : Z)` stands for the affine point
/// `(X/Z^2, Y/Z^3)`, and `Z = 0` is the point at infinity.
#[derive(Clone, Copy, Debug)]
pub struct G1Projective {
    x: Fq,
    y: Fq,
    z: Fq,
}

impl G1Affine {
    /// The point at infinity, with both coordinates zeroed.
    pub const IDENTITY: G1Affine = G1Affine {
        x: Fq::ZERO,
        y: Fq::ZERO,
        infinity: true,
    };

    /// The standard generator `(1, 2)`.
    pub const GENERATOR: G1Affine = G1Affine {
        x: Fq(FQ_R),
        y: GENERATOR_Y,
        infinity: false,
    };

    /// `y^2 == x^3 + 3`. The point at infinity is on every curve.
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }
        self.y.square() == self.x.square() * self.x + B
    }

    /// Whether the point is in the order-`r` subgroup.
    ///
    /// **G1's cofactor is 1**: `#E(Fq) = r` exactly, so every on-curve point
    /// already has order dividing `r` and this is `is_on_curve` under another
    /// name. It exists so that call sites read the same for both groups, and
    /// so that the one group where the check is real — [`G2Affine`] — is not
    /// the only one that has it.
    ///
    /// [`G2Affine`]: crate::G2Affine
    pub fn is_in_subgroup(&self) -> bool {
        self.is_on_curve()
    }

    /// Uncompressed canonical encoding: `x || y`, each a 32-byte
    /// little-endian `Fq`. Infinity is 64 zero bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        if self.infinity {
            return out;
        }
        out[..32].copy_from_slice(&self.x.to_bytes());
        out[32..].copy_from_slice(&self.y.to_bytes());
        out
    }

    /// Decode an uncompressed point, validating everything.
    ///
    /// `None` — never a panic — for a coordinate that is not canonical
    /// (`>= q`), for an off-curve point, and for an on-curve point outside the
    /// order-`r` subgroup. All-zero bytes decode to infinity, which is
    /// unambiguous because `(0, 0)` is off-curve: `0^2 != 0^3 + 3`.
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<G1Affine> {
        if *bytes == [0u8; 64] {
            return Some(G1Affine::IDENTITY);
        }
        let mut half = [0u8; 32];
        half.copy_from_slice(&bytes[..32]);
        let x = Fq::from_bytes(&half)?;
        half.copy_from_slice(&bytes[32..]);
        let y = Fq::from_bytes(&half)?;

        let point = G1Affine {
            x,
            y,
            infinity: false,
        };
        if !point.is_on_curve() || !point.is_in_subgroup() {
            return None;
        }
        Some(point)
    }
}

impl G1Projective {
    /// The point at infinity, `(1 : 1 : 0)`.
    pub const IDENTITY: G1Projective = G1Projective {
        x: Fq::ONE,
        y: Fq::ONE,
        z: Fq::ZERO,
    };

    /// The standard generator, `Z = 1`.
    pub const GENERATOR: G1Projective = G1Projective {
        x: G1Affine::GENERATOR.x,
        y: G1Affine::GENERATOR.y,
        z: Fq::ONE,
    };

    /// `Z == 0`.
    pub fn is_identity(&self) -> bool {
        self.z == Fq::ZERO
    }

    /// `add-2007-bl`, the generic Jacobian addition for `a = 0`.
    ///
    /// `H == 0` means the two points share an affine `x`, and then `r == 0`
    /// separates `P == Q` from `P == -Q`; both are dispatched explicitly
    /// because the formula produces `(0 : 0 : 0)` for either.
    pub fn add(&self, other: &G1Projective) -> G1Projective {
        if self.is_identity() {
            return *other;
        }
        if other.is_identity() {
            return *self;
        }

        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x * z2z2;
        let u2 = other.x * z1z1;
        let s1 = self.y * z2z2 * other.z;
        let s2 = other.y * z1z1 * self.z;
        let h = u2 - u1;
        let r = {
            let d = s2 - s1;
            d + d
        };

        if h == Fq::ZERO {
            if r == Fq::ZERO {
                return self.double();
            }
            return G1Projective::IDENTITY;
        }

        let i = {
            let two_h = h + h;
            two_h.square()
        };
        let j = h * i;
        let v = u1 * i;
        let x3 = r.square() - j - v - v;
        let s1j = s1 * j;
        let y3 = r * (v - x3) - (s1j + s1j);
        let z3 = ((self.z + other.z).square() - z1z1 - z2z2) * h;
        G1Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `madd-2007-bl`, the mixed addition that takes `Z2 = 1` as given.
    ///
    /// The hot path of the MSM a later stage builds on. Same two `H == 0`
    /// branches as [`G1Projective::add`].
    pub fn add_affine(&self, other: &G1Affine) -> G1Projective {
        if other.infinity {
            return *self;
        }
        if self.is_identity() {
            return G1Projective::from(*other);
        }

        let z1z1 = self.z.square();
        let u2 = other.x * z1z1;
        let s2 = other.y * z1z1 * self.z;
        let h = u2 - self.x;
        let r = {
            let d = s2 - self.y;
            d + d
        };

        if h == Fq::ZERO {
            if r == Fq::ZERO {
                return self.double();
            }
            return G1Projective::IDENTITY;
        }

        let hh = h.square();
        let i = {
            let two_hh = hh + hh;
            two_hh + two_hh
        };
        let j = h * i;
        let v = self.x * i;
        let x3 = r.square() - j - v - v;
        let y1j = self.y * j;
        let y3 = r * (v - x3) - (y1j + y1j);
        let z3 = (self.z + h).square() - z1z1 - hh;
        G1Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `dbl-2009-l`, the Jacobian doubling for `a = 0`.
    pub fn double(&self) -> G1Projective {
        if self.is_identity() {
            return G1Projective::IDENTITY;
        }

        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        // 2*((X+B)^2 - A - C) = 4*X*Y^2.
        let d = {
            let t = (self.x + b).square() - a - c;
            t + t
        };
        let e = a + a + a;
        let f = e.square();
        let x3 = f - d - d;
        let eight_c = {
            let c2 = c + c;
            let c4 = c2 + c2;
            c4 + c4
        };
        let y3 = e * (d - x3) - eight_c;
        let z3 = {
            let t = self.y * self.z;
            t + t
        };
        G1Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `scalar * self`, by a fixed 4-bit window over sixteen precomputed
    /// multiples. Not constant time, and nothing here needs it to be.
    pub fn mul(&self, scalar: &Fr) -> G1Projective {
        self.mul_le_bytes(&scalar.to_bytes())
    }

    /// The window ladder over a 256-bit little-endian scalar.
    ///
    /// Takes bytes rather than an `Fr` so that a caller can multiply by an
    /// integer that is not a field element — the only one being `r` itself,
    /// which `Fr` cannot represent and which [`crate::G2Affine::is_in_subgroup`]
    /// needs.
    fn mul_le_bytes(&self, scalar: &[u8; 32]) -> G1Projective {
        let mut table = [G1Projective::IDENTITY; 16];
        table[1] = *self;
        for i in 2..16 {
            // `add` dispatches i = 2 into `double`, which is what P + P needs.
            table[i] = table[i - 1].add(self);
        }

        let mut acc = G1Projective::IDENTITY;
        for byte in scalar.iter().rev() {
            for nibble in [byte >> 4, byte & 0x0f] {
                acc = acc.double().double().double().double();
                acc = acc.add(&table[nibble as usize]);
            }
        }
        acc
    }

    /// Normalize to affine, at the cost of one inversion.
    pub fn to_affine(&self) -> G1Affine {
        match self.z.inverse() {
            None => G1Affine::IDENTITY,
            Some(z_inv) => {
                let z_inv2 = z_inv.square();
                G1Affine {
                    x: self.x * z_inv2,
                    y: self.y * z_inv2 * z_inv,
                    infinity: false,
                }
            }
        }
    }

    /// Normalize a whole slice with one inversion in total.
    ///
    /// Identity entries pass straight through: `batch_inverse` leaves their
    /// `z = 0` alone, and a zero inverse is exactly the flag this reads.
    pub fn batch_to_affine(points: &[G1Projective]) -> Vec<G1Affine> {
        let mut z_invs: Vec<Fq> = points.iter().map(|p| p.z).collect();
        batch_inverse(&mut z_invs);
        points
            .iter()
            .zip(z_invs)
            .map(|(p, z_inv)| {
                if z_inv == Fq::ZERO {
                    G1Affine::IDENTITY
                } else {
                    let z_inv2 = z_inv.square();
                    G1Affine {
                        x: p.x * z_inv2,
                        y: p.y * z_inv2 * z_inv,
                        infinity: false,
                    }
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Conversions, negation, equality
// ---------------------------------------------------------------------------

impl From<G1Affine> for G1Projective {
    fn from(p: G1Affine) -> G1Projective {
        if p.infinity {
            G1Projective::IDENTITY
        } else {
            G1Projective {
                x: p.x,
                y: p.y,
                z: Fq::ONE,
            }
        }
    }
}

impl From<G1Projective> for G1Affine {
    fn from(p: G1Projective) -> G1Affine {
        p.to_affine()
    }
}

impl Neg for G1Affine {
    type Output = G1Affine;
    fn neg(self) -> G1Affine {
        if self.infinity {
            self
        } else {
            G1Affine {
                x: self.x,
                y: -self.y,
                infinity: false,
            }
        }
    }
}

impl Neg for &G1Affine {
    type Output = G1Affine;
    fn neg(self) -> G1Affine {
        -*self
    }
}

impl Neg for G1Projective {
    type Output = G1Projective;
    fn neg(self) -> G1Projective {
        // Z is untouched, so the identity stays the identity.
        G1Projective {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }
}

impl Neg for &G1Projective {
    type Output = G1Projective;
    fn neg(self) -> G1Projective {
        -*self
    }
}

impl PartialEq for G1Affine {
    fn eq(&self, other: &G1Affine) -> bool {
        match (self.infinity, other.infinity) {
            (true, true) => true,
            (false, false) => self.x == other.x && self.y == other.y,
            _ => false,
        }
    }
}

/// Projective equality without normalizing: `(X1 : Y1 : Z1) == (X2 : Y2 : Z2)`
/// iff `X1 Z2^2 == X2 Z1^2` and `Y1 Z2^3 == Y2 Z1^3`.
impl PartialEq for G1Projective {
    fn eq(&self, other: &G1Projective) -> bool {
        match (self.is_identity(), other.is_identity()) {
            (true, true) => true,
            (false, false) => {
                let z1z1 = self.z.square();
                let z2z2 = other.z.square();
                self.x * z2z2 == other.x * z1z1
                    && self.y * z2z2 * other.z == other.y * z1z1 * self.z
            }
            _ => false,
        }
    }
}

impl Eq for G1Projective {}
