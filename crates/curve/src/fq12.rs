//! `Fq12 = Fq6[w]/(w^2 - v)`, the top of the tower and the pairing's target
//! group.
//!
//! An element is `c0 + c1 w` with each half an [`Fq6`]. Composing the two
//! levels below gives `w^2 = v`, `v^3 = xi`, so `w^6 = xi` and `w^12 =
//! xi^2`; the tower is the arkworks-bn254 / py_ecc one, which is what makes a
//! full pairing value comparable coefficient for coefficient against either.

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use constants::FQ12_FROBENIUS_C1;

use crate::fq2::fq2_from_hex;
use crate::fq6::Fq6;

/// An element `c0 + c1 w` of the BN254 degree-twelve extension.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fq12 {
    pub c0: Fq6,
    pub c1: Fq6,
}

impl Fq12 {
    /// The additive identity.
    pub const ZERO: Fq12 = Fq12 {
        c0: Fq6::ZERO,
        c1: Fq6::ZERO,
    };

    /// The multiplicative identity, and the value `pairing_check` compares to.
    pub const ONE: Fq12 = Fq12 {
        c0: Fq6::ONE,
        c1: Fq6::ZERO,
    };

    /// `c0 + c1 w`.
    pub fn new(c0: Fq6, c1: Fq6) -> Fq12 {
        Fq12 { c0, c1 }
    }

    /// `self * self`. The general multiplication; see [`Fq6::square`].
    pub fn square(&self) -> Fq12 {
        *self * *self
    }

    /// `c0 - c1 w`: the `q^6` Frobenius, and the nontrivial element of
    /// `Gal(Fq12/Fq6)`.
    ///
    /// On the cyclotomic subgroup the final exponentiation's easy part lands
    /// in — elements of order dividing `q^4 - q^2 + 1` — this is the inverse,
    /// which is how the negative `lambda` exponents in
    /// [`crate::pairing::final_exponentiation`] are taken. `tests/pairing.rs`
    /// pins that unitarity rather than assuming it.
    pub fn conjugate(&self) -> Fq12 {
        Fq12 {
            c0: self.c0,
            c1: -self.c1,
        }
    }

    /// `self^exp`, with `exp` a 256-bit little-endian limb array.
    ///
    /// The exponent is a plain integer, not reduced, exactly as for
    /// [`crate::Fq::pow`]. `x^0 == ONE` for every `x`, including zero.
    pub fn pow(&self, exp: &[u64; 4]) -> Fq12 {
        let mut acc = Fq12::ONE;
        for limb in exp.iter().rev() {
            for bit in (0..64).rev() {
                acc = acc.square();
                if (limb >> bit) & 1 == 1 {
                    acc *= self;
                }
            }
        }
        acc
    }

    /// Multiplicative inverse. `None` for zero.
    ///
    /// `1/(c0 + c1 w) = (c0 - c1 w)/(c0^2 - v c1^2)`, the quadratic-extension
    /// inverse with `w^2 = v`.
    ///
    /// The denominator vanishes only for zero. If `c1 != 0` and
    /// `c0^2 = v c1^2` then `(c0/c1)^2 = v`, making `v` a square in Fq6 — and
    /// `Fq6[w]/(w^2 - v)` is a field precisely because it is not.
    pub fn inverse(&self) -> Option<Fq12> {
        let d = self.c0.square() - self.c1.square().mul_by_nonresidue();
        let d_inv = d.inverse()?;
        Some(Fq12 {
            c0: self.c0 * d_inv,
            c1: -(self.c1 * d_inv),
        })
    }

    /// `self^(q^power)`, the `power`-fold Frobenius.
    ///
    /// `power` is taken modulo 12, which is exact: Fq12 has `q^12` elements.
    ///
    /// `(c1 w)^(q^i) = c1^(q^i) (w^(q^i))` and `w^(q^i) = xi^((q^i - 1)/6) w`,
    /// because `w^6 = xi`. That power of `xi` is
    /// [`constants::FQ12_FROBENIUS_C1`]; the `Fq6` halves carry their own
    /// tables one level down.
    pub fn frobenius_map(&self, power: usize) -> Fq12 {
        let i = power % 12;
        let twist = fq2_from_hex(FQ12_FROBENIUS_C1[i]);
        let c1 = self.c1.frobenius_map(i);
        Fq12 {
            c0: self.c0.frobenius_map(i),
            c1: Fq6 {
                c0: c1.c0 * twist,
                c1: c1.c1 * twist,
                c2: c1.c2 * twist,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Operators. The same six-impl shape as `Fq`, `Fq2` and `Fq6`.
// ---------------------------------------------------------------------------

fn add_fq12(a: &Fq12, b: &Fq12) -> Fq12 {
    Fq12 {
        c0: a.c0 + b.c0,
        c1: a.c1 + b.c1,
    }
}

fn sub_fq12(a: &Fq12, b: &Fq12) -> Fq12 {
    Fq12 {
        c0: a.c0 - b.c0,
        c1: a.c1 - b.c1,
    }
}

/// Schoolbook: four `Fq6` multiplications, with `w^2 = v` folding the one
/// overflowing term back down.
///
/// ```text
///   c0 = a0 b0 + v (a1 b1)
///   c1 = a0 b1 + a1 b0
/// ```
fn mul_fq12(a: &Fq12, b: &Fq12) -> Fq12 {
    Fq12 {
        c0: a.c0 * b.c0 + (a.c1 * b.c1).mul_by_nonresidue(),
        c1: a.c0 * b.c1 + a.c1 * b.c0,
    }
}

macro_rules! impl_binop {
    ($Op:ident, $op:ident, $OpAssign:ident, $op_assign:ident, $f:ident) => {
        impl $Op<Fq12> for Fq12 {
            type Output = Fq12;
            fn $op(self, rhs: Fq12) -> Fq12 {
                $f(&self, &rhs)
            }
        }
        impl $Op<&Fq12> for Fq12 {
            type Output = Fq12;
            fn $op(self, rhs: &Fq12) -> Fq12 {
                $f(&self, rhs)
            }
        }
        impl $Op<Fq12> for &Fq12 {
            type Output = Fq12;
            fn $op(self, rhs: Fq12) -> Fq12 {
                $f(self, &rhs)
            }
        }
        impl $Op<&Fq12> for &Fq12 {
            type Output = Fq12;
            fn $op(self, rhs: &Fq12) -> Fq12 {
                $f(self, rhs)
            }
        }
        impl $OpAssign<Fq12> for Fq12 {
            fn $op_assign(&mut self, rhs: Fq12) {
                *self = $f(self, &rhs);
            }
        }
        impl $OpAssign<&Fq12> for Fq12 {
            fn $op_assign(&mut self, rhs: &Fq12) {
                *self = $f(self, rhs);
            }
        }
    };
}

impl_binop!(Add, add, AddAssign, add_assign, add_fq12);
impl_binop!(Sub, sub, SubAssign, sub_assign, sub_fq12);
impl_binop!(Mul, mul, MulAssign, mul_assign, mul_fq12);

impl Neg for Fq12 {
    type Output = Fq12;
    fn neg(self) -> Fq12 {
        Fq12 {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

impl Neg for &Fq12 {
    type Output = Fq12;
    fn neg(self) -> Fq12 {
        Fq12 {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

/// The two halves, in `w`-degree order.
impl fmt::Debug for Fq12 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fq12({:?} + {:?} w)", self.c0, self.c1)
    }
}
