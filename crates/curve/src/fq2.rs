//! `Fq2 = Fq[u]/(u^2 + 1)`, tower level one: where G2 coordinates live.
//!
//! `u^2 = -1`, i.e. the nonresidue is `constants::FQ2_NONRESIDUE = q - 1`.
//! Multiplying an `Fq` by it is negation, so the constant appears in
//! `tests/constants_check.rs` as the thing negation is checked against rather
//! than as a factor in a product.
//!
//! [`Fq2::mul_by_nonresidue`] is the *other* nonresidue: `xi = 9 + u`, the one
//! that builds Fq6 over Fq2. That is the universal meaning of the name at this
//! tower level (bls12_381's `Fp2::mul_by_nonresidue`, gnark's
//! `E2.MulByNonResidue`), and the reading `self * (-1)` would be a second
//! spelling of `Neg`. S05's Must-be-exact 1 reserves `xi` for the pairing
//! stage; the multiplication by it is frozen here.

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use constants::FQ_R;

use crate::fq::Fq;

/// `xi = 9 + u`, in Montgomery form.
///
/// `c1` is `Fq::ONE`, whose Montgomery limbs are `R`. Both halves are checked
/// against `constants::FQ6_NONRESIDUE_C0`/`_C1` in `tests/constants_check.rs`.
const XI: Fq2 = Fq2 {
    c0: Fq([
        0xf606_47ce_410d_7ff7,
        0x2f3d_6f4d_d31b_d011,
        0x2943_337e_3940_c6d1,
        0x1d95_98e8_a7e3_9857,
    ]),
    c1: Fq(FQ_R),
};

/// An element `c0 + c1 * u` of the BN254 quadratic extension.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fq2 {
    pub c0: Fq,
    pub c1: Fq,
}

impl Fq2 {
    /// The additive identity.
    pub const ZERO: Fq2 = Fq2 {
        c0: Fq::ZERO,
        c1: Fq::ZERO,
    };

    /// The multiplicative identity.
    pub const ONE: Fq2 = Fq2 {
        c0: Fq::ONE,
        c1: Fq::ZERO,
    };

    /// `c0 + c1 * u`.
    pub fn new(c0: Fq, c1: Fq) -> Fq2 {
        Fq2 { c0, c1 }
    }

    /// The embedding of `Fq` in `Fq2`.
    pub fn from_fq(c0: Fq) -> Fq2 {
        Fq2 { c0, c1: Fq::ZERO }
    }

    /// `self * self`.
    ///
    /// `(c0 + c1 u)^2 = (c0^2 - c1^2) + 2 c0 c1 u`, and `c0^2 - c1^2` factors
    /// as `(c0 + c1)(c0 - c1)`, which is one multiplication instead of two
    /// squarings.
    pub fn square(&self) -> Fq2 {
        let cross = self.c0 * self.c1;
        Fq2 {
            c0: (self.c0 + self.c1) * (self.c0 - self.c1),
            c1: cross + cross,
        }
    }

    /// `c0 - c1 * u`, the nontrivial Frobenius.
    pub fn conjugate(&self) -> Fq2 {
        Fq2 {
            c0: self.c0,
            c1: -self.c1,
        }
    }

    /// The field norm `self * conjugate(self) = c0^2 + c1^2`, an `Fq`.
    ///
    /// Zero only for zero: `c0^2 = -c1^2` with `c1 != 0` would make `-1` a
    /// square, and it is not.
    pub fn norm(&self) -> Fq {
        self.c0.square() + self.c1.square()
    }

    /// Multiplicative inverse. `None` for zero.
    ///
    /// `1/(c0 + c1 u) = (c0 - c1 u)/norm`.
    pub fn inverse(&self) -> Option<Fq2> {
        let norm_inv = self.norm().inverse()?;
        Some(Fq2 {
            c0: self.c0 * norm_inv,
            c1: -(self.c1 * norm_inv),
        })
    }

    /// `self * xi`, with `xi = 9 + u` the Fq6 nonresidue.
    pub fn mul_by_nonresidue(&self) -> Fq2 {
        *self * XI
    }

    /// A square root of `self`, or `None` if `self` is not a square.
    ///
    /// The closed form for `q = 3 mod 4`. Writing `x = x0 + x1 u` and matching
    /// coefficients in `x^2 = a`:
    ///
    /// ```text
    ///   x0^2 - x1^2 = a0        2 x0 x1 = a1
    /// ```
    ///
    /// Eliminating `x1 = a1/(2 x0)` gives `4 x0^4 - 4 a0 x0^2 - a1^2 = 0`, so
    /// `x0^2 = (a0 +- lambda)/2` with `lambda^2 = a0^2 + a1^2 = norm(a)`.
    ///
    /// Three facts make the two branches below exhaustive and panic-free:
    ///
    /// 1. `a` is a square in Fq2 iff `norm(a)` is a square in Fq. `norm(a) =
    ///    a^(1+q)`, so `norm(a)^((q-1)/2) = a^((q^2-1)/2)`, and the two Euler
    ///    criteria are the same statement. So a `None` from `lambda` is a
    ///    genuine non-square and the only `None` this function returns.
    /// 2. With `a1 != 0` the two candidates multiply to `(a0^2 - lambda^2)/4 =
    ///    -a1^2/4`, a nonresidue (`-1` is one, `a1^2/4` is a nonzero square).
    ///    A nonresidue product means exactly one factor is a square — so the
    ///    second branch always succeeds when the first fails — and neither
    ///    factor is zero, so `x0 != 0` and `1/(2 x0)` exists.
    /// 3. With `a1 == 0` the element is an `Fq`, and exactly one of `a0` and
    ///    `-a0` is a square, again because `-1` is a nonresidue. The root is
    ///    real in the first case and purely imaginary in the second.
    ///
    /// Which of the two roots comes back is unspecified, exactly as for
    /// [`Fq::sqrt`].
    pub fn sqrt(&self) -> Option<Fq2> {
        if self.c1 == Fq::ZERO {
            // Fact 3.
            if let Some(root) = self.c0.sqrt() {
                return Some(Fq2::from_fq(root));
            }
            let root = (-self.c0)
                .sqrt()
                .expect("-1 is a nonresidue, so one of a0 and -a0 is a square");
            return Some(Fq2 {
                c0: Fq::ZERO,
                c1: root,
            });
        }

        // Fact 1: the only rejection.
        let lambda = self.norm().sqrt()?;

        let two_inv = Fq::from_u64(2)
            .inverse()
            .expect("2 is nonzero in a field of odd characteristic");

        // Fact 2.
        let x0 = match ((self.c0 + lambda) * two_inv).sqrt() {
            Some(x0) => x0,
            None => ((self.c0 - lambda) * two_inv)
                .sqrt()
                .expect("(a0+lambda)/2 and (a0-lambda)/2 multiply to a nonresidue"),
        };
        let x1 = self.c1
            * (x0 + x0)
                .inverse()
                .expect("x0 is nonzero when a1 is nonzero");
        Some(Fq2 { c0: x0, c1: x1 })
    }

    /// Canonical encoding: `c0 || c1`, each a 32-byte little-endian `Fq`.
    ///
    /// This is the coordinate layout inside a serialized G2 point.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.c0.to_bytes());
        out[32..].copy_from_slice(&self.c1.to_bytes());
        out
    }

    /// Decode `c0 || c1`. `None` if either half is `>= q`.
    pub fn from_bytes(b: &[u8; 64]) -> Option<Fq2> {
        let mut half = [0u8; 32];
        half.copy_from_slice(&b[..32]);
        let c0 = Fq::from_bytes(&half)?;
        half.copy_from_slice(&b[32..]);
        let c1 = Fq::from_bytes(&half)?;
        Some(Fq2 { c0, c1 })
    }
}

// ---------------------------------------------------------------------------
// Operators. Same six-impl shape as `Fq`, with the arithmetic written out
// once per operator rather than passed in as a limb function.
// ---------------------------------------------------------------------------

fn add_fq2(a: &Fq2, b: &Fq2) -> Fq2 {
    Fq2 {
        c0: a.c0 + b.c0,
        c1: a.c1 + b.c1,
    }
}

fn sub_fq2(a: &Fq2, b: &Fq2) -> Fq2 {
    Fq2 {
        c0: a.c0 - b.c0,
        c1: a.c1 - b.c1,
    }
}

/// `(a0 + a1 u)(b0 + b1 u) = (a0 b0 - a1 b1) + (a0 b1 + a1 b0) u`, using
/// `u^2 = -1`. Schoolbook: four multiplications, no Karatsuba bookkeeping.
fn mul_fq2(a: &Fq2, b: &Fq2) -> Fq2 {
    Fq2 {
        c0: a.c0 * b.c0 - a.c1 * b.c1,
        c1: a.c0 * b.c1 + a.c1 * b.c0,
    }
}

macro_rules! impl_binop {
    ($Op:ident, $op:ident, $OpAssign:ident, $op_assign:ident, $f:ident) => {
        impl $Op<Fq2> for Fq2 {
            type Output = Fq2;
            fn $op(self, rhs: Fq2) -> Fq2 {
                $f(&self, &rhs)
            }
        }
        impl $Op<&Fq2> for Fq2 {
            type Output = Fq2;
            fn $op(self, rhs: &Fq2) -> Fq2 {
                $f(&self, rhs)
            }
        }
        impl $Op<Fq2> for &Fq2 {
            type Output = Fq2;
            fn $op(self, rhs: Fq2) -> Fq2 {
                $f(self, &rhs)
            }
        }
        impl $Op<&Fq2> for &Fq2 {
            type Output = Fq2;
            fn $op(self, rhs: &Fq2) -> Fq2 {
                $f(self, rhs)
            }
        }
        impl $OpAssign<Fq2> for Fq2 {
            fn $op_assign(&mut self, rhs: Fq2) {
                *self = $f(self, &rhs);
            }
        }
        impl $OpAssign<&Fq2> for Fq2 {
            fn $op_assign(&mut self, rhs: &Fq2) {
                *self = $f(self, rhs);
            }
        }
    };
}

impl_binop!(Add, add, AddAssign, add_assign, add_fq2);
impl_binop!(Sub, sub, SubAssign, sub_assign, sub_fq2);
impl_binop!(Mul, mul, MulAssign, mul_assign, mul_fq2);

impl Neg for Fq2 {
    type Output = Fq2;
    fn neg(self) -> Fq2 {
        Fq2 {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

impl Neg for &Fq2 {
    type Output = Fq2;
    fn neg(self) -> Fq2 {
        Fq2 {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

/// Both coefficients in canonical big-endian hex, `c0` first.
impl fmt::Debug for Fq2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fq2({:?} + {:?} u)", self.c0, self.c1)
    }
}
