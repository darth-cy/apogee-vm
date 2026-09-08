//! G2: `E'/Fq2: y^2 = x^3 + 3/(9+u)`, the D-type sextic twist.
//!
//! A literal mirror of `g1.rs` with `Fq2` coordinates — same `dbl-2009-l`,
//! `add-2007-bl` and `madd-2007-bl`, same two `H == 0` branches. The one real
//! difference is the cofactor: `#E'(Fq2) = r * (2q - r)`, so an on-curve point
//! is *not* automatically in the order-`r` subgroup and
//! [`G2Affine::is_in_subgroup`] has to do arithmetic.
//!
//! `2q - r` is odd, so `#E'(Fq2)` is odd and the twist has no 2-torsion
//! either: no on-curve point has `y = 0`. Both facts are re-derived in
//! `tests/constants_check.rs`.

use core::ops::Neg;

use constants::FR_MODULUS;
use field::Fr;

use crate::fq::Fq;
use crate::fq2::Fq2;

/// The curve constant `b' = 3/(9+u)`, in Montgomery form.
/// Checked against `constants::G2_B_C0`/`_C1` in `tests/constants_check.rs`.
const B: Fq2 = Fq2 {
    c0: Fq([
        0x3bf9_38e3_77b8_02a8,
        0x020b_1b27_3633_535d,
        0x26b7_edf0_4975_5260,
        0x2514_c632_4384_a86d,
    ]),
    c1: Fq([
        0x38e7_eccc_d1dc_ff67,
        0x65f0_b37d_93ce_0d3e,
        0xd749_d0dd_22ac_00aa,
        0x0141_b9ce_4a68_8d4d,
    ]),
};

/// The standard generator's coordinates, in Montgomery form. Checked against
/// `constants::G2_GENERATOR_*`, which are EIP-197's values.
const GENERATOR_X: Fq2 = Fq2 {
    c0: Fq([
        0x8e83_b5d1_02bc_2026,
        0xdceb_1935_497b_0172,
        0xfbb8_2647_9781_1adf,
        0x1957_3841_af96_503b,
    ]),
    c1: Fq([
        0xafb4_737d_a84c_6140,
        0x6043_dd5a_5802_d8c4,
        0x09e9_50fc_52a0_2f86,
        0x14fe_f083_3aea_7b6b,
    ]),
};

const GENERATOR_Y: Fq2 = Fq2 {
    c0: Fq([
        0x619d_fa9d_886b_e9f6,
        0xfe7f_d297_f59e_9b78,
        0xff9e_1a62_231b_7dfe,
        0x28fd_7eeb_ae9e_4206,
    ]),
    c1: Fq([
        0x6409_5b56_c718_56ee,
        0xdc57_f922_327d_3cbb,
        0x55f9_35be_3335_1076,
        0x0da4_a0e6_93fd_6482,
    ]),
};

/// `r`, the subgroup order, as the little-endian bytes the window ladder reads.
///
/// `r` is the modulus of `Fr` and therefore not an `Fr` value — which is
/// exactly why the ladder takes bytes.
fn subgroup_order_le_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 8].copy_from_slice(&FR_MODULUS[i].to_le_bytes());
    }
    out
}

/// A point in affine coordinates, or the point at infinity.
///
/// When `infinity` is true the coordinates carry no meaning, exactly as in
/// [`crate::G1Affine`].
#[derive(Clone, Copy, Debug, Eq)]
pub struct G2Affine {
    pub x: Fq2,
    pub y: Fq2,
    pub infinity: bool,
}

/// A point in Jacobian coordinates over Fq2. `Z = 0` is the point at infinity.
#[derive(Clone, Copy, Debug)]
pub struct G2Projective {
    x: Fq2,
    y: Fq2,
    z: Fq2,
}

impl G2Affine {
    /// The point at infinity, with both coordinates zeroed.
    pub const IDENTITY: G2Affine = G2Affine {
        x: Fq2::ZERO,
        y: Fq2::ZERO,
        infinity: true,
    };

    /// The standard generator, EIP-197's G2.
    pub const GENERATOR: G2Affine = G2Affine {
        x: GENERATOR_X,
        y: GENERATOR_Y,
        infinity: false,
    };

    /// `y^2 == x^3 + 3/(9+u)`. The point at infinity is on every curve.
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }
        self.y.square() == self.x.square() * self.x + B
    }

    /// Whether the point is in the order-`r` subgroup: on the curve **and**
    /// `r * self == O`.
    ///
    /// A real check, unlike G1's: the twist's cofactor `2q - r` is not 1, so
    /// on-curve does not imply in-subgroup. This is the direct test named by
    /// S05's core algorithm — one 256-bit window ladder, no endomorphism
    /// shortcut.
    ///
    /// The `is_on_curve` conjunct is what makes this a *complete* validity
    /// predicate, so a caller may use it alone. Without it, a point off `E'`
    /// would be judged only by the ladder, and the a = 0 Jacobian formulas
    /// compute in the group of whatever curve the point does lie on — so an
    /// input whose implied curve has order divisible by `r` could be accepted.
    /// No test in this crate discriminates the conjunct, because constructing
    /// such a witness means finding a curve over Fq2 whose order `r` divides;
    /// it is defence in depth, and deliberate. `from_bytes` checks the curve
    /// equation separately, so the two are independent.
    pub fn is_in_subgroup(&self) -> bool {
        self.is_on_curve()
            && G2Projective::from(*self)
                .mul_le_bytes(&subgroup_order_le_bytes())
                .is_identity()
    }

    /// `self + other`, through the mixed-addition path.
    pub fn add(&self, other: &G2Affine) -> G2Affine {
        G2Projective::from(*self).add_affine(other).to_affine()
    }

    /// `2 * self`.
    pub fn double(&self) -> G2Affine {
        G2Projective::from(*self).double().to_affine()
    }

    /// `scalar * self`.
    pub fn mul(&self, scalar: &Fr) -> G2Affine {
        G2Projective::from(*self).mul(scalar).to_affine()
    }

    /// Uncompressed canonical encoding: `x.c0 || x.c1 || y.c0 || y.c1`, each a
    /// 32-byte little-endian `Fq`. Infinity is 128 zero bytes.
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        if self.infinity {
            return out;
        }
        out[..64].copy_from_slice(&self.x.to_bytes());
        out[64..].copy_from_slice(&self.y.to_bytes());
        out
    }

    /// Decode an uncompressed point, validating everything.
    ///
    /// `None` — never a panic — for a coordinate half that is not canonical
    /// (`>= q`), for an off-curve point, and for an on-curve point outside the
    /// order-`r` subgroup. All-zero bytes decode to infinity, which is
    /// unambiguous because `(0, 0)` is off-curve: `0 != 3/(9+u)`.
    pub fn from_bytes(bytes: &[u8; 128]) -> Option<G2Affine> {
        if *bytes == [0u8; 128] {
            return Some(G2Affine::IDENTITY);
        }
        let mut half = [0u8; 64];
        half.copy_from_slice(&bytes[..64]);
        let x = Fq2::from_bytes(&half)?;
        half.copy_from_slice(&bytes[64..]);
        let y = Fq2::from_bytes(&half)?;

        let point = G2Affine {
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

impl G2Projective {
    /// The point at infinity, `(1 : 1 : 0)`.
    pub const IDENTITY: G2Projective = G2Projective {
        x: Fq2::ONE,
        y: Fq2::ONE,
        z: Fq2::ZERO,
    };

    /// The standard generator, `Z = 1`.
    pub const GENERATOR: G2Projective = G2Projective {
        x: GENERATOR_X,
        y: GENERATOR_Y,
        z: Fq2::ONE,
    };

    /// `Z == 0`.
    pub fn is_identity(&self) -> bool {
        self.z == Fq2::ZERO
    }

    /// `add-2007-bl` over Fq2. See [`crate::G1Projective::add`].
    pub fn add(&self, other: &G2Projective) -> G2Projective {
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

        if h == Fq2::ZERO {
            if r == Fq2::ZERO {
                return self.double();
            }
            return G2Projective::IDENTITY;
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
        G2Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `madd-2007-bl` over Fq2. See [`crate::G1Projective::add_affine`].
    pub fn add_affine(&self, other: &G2Affine) -> G2Projective {
        if other.infinity {
            return *self;
        }
        if self.is_identity() {
            return G2Projective::from(*other);
        }

        let z1z1 = self.z.square();
        let u2 = other.x * z1z1;
        let s2 = other.y * z1z1 * self.z;
        let h = u2 - self.x;
        let r = {
            let d = s2 - self.y;
            d + d
        };

        if h == Fq2::ZERO {
            if r == Fq2::ZERO {
                return self.double();
            }
            return G2Projective::IDENTITY;
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
        G2Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `dbl-2009-l` over Fq2. See [`crate::G1Projective::double`].
    pub fn double(&self) -> G2Projective {
        if self.is_identity() {
            return G2Projective::IDENTITY;
        }

        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
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
        G2Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `scalar * self`, by a fixed 4-bit window over sixteen precomputed
    /// multiples.
    pub fn mul(&self, scalar: &Fr) -> G2Projective {
        self.mul_le_bytes(&scalar.to_bytes())
    }

    /// The window ladder over a 256-bit little-endian scalar. See
    /// [`crate::G1Projective`]; taking bytes is what lets
    /// [`G2Affine::is_in_subgroup`] multiply by `r`.
    fn mul_le_bytes(&self, scalar: &[u8; 32]) -> G2Projective {
        let mut table = [G2Projective::IDENTITY; 16];
        table[1] = *self;
        for i in 2..16 {
            table[i] = table[i - 1].add(self);
        }

        let mut acc = G2Projective::IDENTITY;
        for byte in scalar.iter().rev() {
            for nibble in [byte >> 4, byte & 0x0f] {
                acc = acc.double().double().double().double();
                acc = acc.add(&table[nibble as usize]);
            }
        }
        acc
    }

    /// Normalize to affine, at the cost of one Fq2 inversion.
    pub fn to_affine(&self) -> G2Affine {
        match self.z.inverse() {
            None => G2Affine::IDENTITY,
            Some(z_inv) => {
                let z_inv2 = z_inv.square();
                G2Affine {
                    x: self.x * z_inv2,
                    y: self.y * z_inv2 * z_inv,
                    infinity: false,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Conversions, negation, equality
// ---------------------------------------------------------------------------

impl From<G2Affine> for G2Projective {
    fn from(p: G2Affine) -> G2Projective {
        if p.infinity {
            G2Projective::IDENTITY
        } else {
            G2Projective {
                x: p.x,
                y: p.y,
                z: Fq2::ONE,
            }
        }
    }
}

impl From<G2Projective> for G2Affine {
    fn from(p: G2Projective) -> G2Affine {
        p.to_affine()
    }
}

impl Neg for G2Affine {
    type Output = G2Affine;
    fn neg(self) -> G2Affine {
        if self.infinity {
            self
        } else {
            G2Affine {
                x: self.x,
                y: -self.y,
                infinity: false,
            }
        }
    }
}

impl Neg for &G2Affine {
    type Output = G2Affine;
    fn neg(self) -> G2Affine {
        -*self
    }
}

impl Neg for G2Projective {
    type Output = G2Projective;
    fn neg(self) -> G2Projective {
        G2Projective {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }
}

impl Neg for &G2Projective {
    type Output = G2Projective;
    fn neg(self) -> G2Projective {
        -*self
    }
}

impl PartialEq for G2Affine {
    fn eq(&self, other: &G2Affine) -> bool {
        match (self.infinity, other.infinity) {
            (true, true) => true,
            (false, false) => self.x == other.x && self.y == other.y,
            _ => false,
        }
    }
}

impl PartialEq for G2Projective {
    fn eq(&self, other: &G2Projective) -> bool {
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

impl Eq for G2Projective {}
