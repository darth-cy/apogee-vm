//! `Fq6 = Fq2[v]/(v^3 - xi)`, tower level two, with `xi = 9 + u`.
//!
//! An element is `c0 + c1 v + c2 v^2` with each coefficient an [`Fq2`]. The
//! only place `v^3` appears is as `xi`, so every product below reduces by
//! [`Fq2::mul_by_nonresidue`] and nothing else knows the modulus.
//!
//! There is deliberately **no `conjugate`**. Fq6 is a *cubic* extension of
//! Fq2, so it has no two-element Galois group over Fq2 and no canonical
//! conjugation: coefficientwise Fq2-conjugation is not even a ring
//! homomorphism, because it would have to send `xi = 9 + u` to `9 - u` while
//! fixing `v^3`. The one order-two automorphism Fq6 does have is `a^(q^3)`,
//! which is [`Fq6::frobenius_map`]`(3)` and needs no second name. Conjugation
//! enters the tower one level up, on [`crate::Fq12`], where it is the `q^6`
//! Frobenius and the map the final exponentiation is built from.

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use constants::{FQ6_FROBENIUS_C1, FQ6_FROBENIUS_C2};

use crate::fq2::{fq2_from_hex, Fq2};

/// An element `c0 + c1 v + c2 v^2` of the BN254 sextic extension.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fq6 {
    pub c0: Fq2,
    pub c1: Fq2,
    pub c2: Fq2,
}

impl Fq6 {
    /// The additive identity.
    pub const ZERO: Fq6 = Fq6 {
        c0: Fq2::ZERO,
        c1: Fq2::ZERO,
        c2: Fq2::ZERO,
    };

    /// The multiplicative identity.
    pub const ONE: Fq6 = Fq6 {
        c0: Fq2::ONE,
        c1: Fq2::ZERO,
        c2: Fq2::ZERO,
    };

    /// `c0 + c1 v + c2 v^2`.
    pub fn new(c0: Fq2, c1: Fq2, c2: Fq2) -> Fq6 {
        Fq6 { c0, c1, c2 }
    }

    /// The embedding of `Fq2` in `Fq6`.
    pub fn from_fq2(c0: Fq2) -> Fq6 {
        Fq6 {
            c0,
            c1: Fq2::ZERO,
            c2: Fq2::ZERO,
        }
    }

    /// `self * self`.
    ///
    /// The general multiplication, not a squaring formula. The pairing is a
    /// verification-side routine and never runs in the prover, so the two
    /// saved `Fq2` multiplications are not worth a second set of coefficient
    /// identities to audit.
    pub fn square(&self) -> Fq6 {
        *self * *self
    }

    /// `self * v`, the Fq12 nonresidue.
    ///
    /// `(c0 + c1 v + c2 v^2) v = c2 xi + c0 v + c1 v^2`, using `v^3 = xi`.
    pub fn mul_by_nonresidue(&self) -> Fq6 {
        Fq6 {
            c0: self.c2.mul_by_nonresidue(),
            c1: self.c0,
            c2: self.c1,
        }
    }

    /// `self^exp`, with `exp` a 256-bit little-endian limb array.
    ///
    /// The exponent is a plain integer, not reduced, exactly as for
    /// [`crate::Fq::pow`]. `x^0 == ONE` for every `x`, including zero.
    pub fn pow(&self, exp: &[u64; 4]) -> Fq6 {
        let mut acc = Fq6::ONE;
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
    /// The textbook cubic-extension inverse: the three cofactors
    ///
    /// ```text
    ///   t0 = c0^2 - xi c1 c2      t1 = xi c2^2 - c0 c1      t2 = c1^2 - c0 c2
    /// ```
    ///
    /// are the entries of the adjugate that `self` needs, and
    /// `d = c0 t0 + xi (c2 t1 + c1 t2)` is the norm of `self` down to `Fq2`.
    /// So `self * (t0 + t1 v + t2 v^2) = d`, which is checked directly in
    /// `tests/tower.rs` rather than left to the reader, and the inverse is
    /// that cofactor triple over `d`.
    ///
    /// `d` is zero only when `self` is: it is the `Fq2`-norm of a nonzero
    /// element of a field extension.
    pub fn inverse(&self) -> Option<Fq6> {
        let t0 = self.c0.square() - (self.c1 * self.c2).mul_by_nonresidue();
        let t1 = self.c2.square().mul_by_nonresidue() - self.c0 * self.c1;
        let t2 = self.c1.square() - self.c0 * self.c2;
        let d = self.c0 * t0 + (self.c2 * t1 + self.c1 * t2).mul_by_nonresidue();
        let d_inv = d.inverse()?;
        Some(Fq6 {
            c0: t0 * d_inv,
            c1: t1 * d_inv,
            c2: t2 * d_inv,
        })
    }

    /// `self^(q^power)`, the `power`-fold Frobenius.
    ///
    /// `power` is taken modulo 6, which is exact rather than a convenience:
    /// Fq6 has `q^6` elements, so `a^(q^6) = a` for every `a`.
    ///
    /// Coefficientwise, `(a_k v^k)^(q^i) = a_k^(q^i) (v^(q^i))^k` and
    /// `v^(q^i) = xi^((q^i - 1)/3) v` because `v^3 = xi`. Those two powers of
    /// `xi` are the tables in `constants`.
    pub fn frobenius_map(&self, power: usize) -> Fq6 {
        let i = power % 6;
        Fq6 {
            c0: fq2_frobenius(&self.c0, i),
            c1: fq2_frobenius(&self.c1, i) * fq2_from_hex(FQ6_FROBENIUS_C1[i]),
            c2: fq2_frobenius(&self.c2, i) * fq2_from_hex(FQ6_FROBENIUS_C2[i]),
        }
    }
}

/// `a^(q^power)` in Fq2: the identity for even `power`, conjugation for odd.
///
/// `Fq2` has `q^2` elements, so its Frobenius has order two.
fn fq2_frobenius(a: &Fq2, power: usize) -> Fq2 {
    if power.is_multiple_of(2) {
        *a
    } else {
        a.conjugate()
    }
}

// ---------------------------------------------------------------------------
// Operators. The same six-impl shape as `Fq` and `Fq2`.
// ---------------------------------------------------------------------------

fn add_fq6(a: &Fq6, b: &Fq6) -> Fq6 {
    Fq6 {
        c0: a.c0 + b.c0,
        c1: a.c1 + b.c1,
        c2: a.c2 + b.c2,
    }
}

fn sub_fq6(a: &Fq6, b: &Fq6) -> Fq6 {
    Fq6 {
        c0: a.c0 - b.c0,
        c1: a.c1 - b.c1,
        c2: a.c2 - b.c2,
    }
}

/// Schoolbook: nine `Fq2` multiplications, with `v^3 = xi` folding the three
/// overflowing terms back down.
///
/// ```text
///   c0 = a0 b0 + xi (a1 b2 + a2 b1)
///   c1 = a0 b1 + a1 b0 + xi (a2 b2)
///   c2 = a0 b2 + a1 b1 + a2 b0
/// ```
fn mul_fq6(a: &Fq6, b: &Fq6) -> Fq6 {
    Fq6 {
        c0: a.c0 * b.c0 + (a.c1 * b.c2 + a.c2 * b.c1).mul_by_nonresidue(),
        c1: a.c0 * b.c1 + a.c1 * b.c0 + (a.c2 * b.c2).mul_by_nonresidue(),
        c2: a.c0 * b.c2 + a.c1 * b.c1 + a.c2 * b.c0,
    }
}

macro_rules! impl_binop {
    ($Op:ident, $op:ident, $OpAssign:ident, $op_assign:ident, $f:ident) => {
        impl $Op<Fq6> for Fq6 {
            type Output = Fq6;
            fn $op(self, rhs: Fq6) -> Fq6 {
                $f(&self, &rhs)
            }
        }
        impl $Op<&Fq6> for Fq6 {
            type Output = Fq6;
            fn $op(self, rhs: &Fq6) -> Fq6 {
                $f(&self, rhs)
            }
        }
        impl $Op<Fq6> for &Fq6 {
            type Output = Fq6;
            fn $op(self, rhs: Fq6) -> Fq6 {
                $f(self, &rhs)
            }
        }
        impl $Op<&Fq6> for &Fq6 {
            type Output = Fq6;
            fn $op(self, rhs: &Fq6) -> Fq6 {
                $f(self, rhs)
            }
        }
        impl $OpAssign<Fq6> for Fq6 {
            fn $op_assign(&mut self, rhs: Fq6) {
                *self = $f(self, &rhs);
            }
        }
        impl $OpAssign<&Fq6> for Fq6 {
            fn $op_assign(&mut self, rhs: &Fq6) {
                *self = $f(self, rhs);
            }
        }
    };
}

impl_binop!(Add, add, AddAssign, add_assign, add_fq6);
impl_binop!(Sub, sub, SubAssign, sub_assign, sub_fq6);
impl_binop!(Mul, mul, MulAssign, mul_assign, mul_fq6);

impl Neg for Fq6 {
    type Output = Fq6;
    fn neg(self) -> Fq6 {
        Fq6 {
            c0: -self.c0,
            c1: -self.c1,
            c2: -self.c2,
        }
    }
}

impl Neg for &Fq6 {
    type Output = Fq6;
    fn neg(self) -> Fq6 {
        Fq6 {
            c0: -self.c0,
            c1: -self.c1,
            c2: -self.c2,
        }
    }
}

/// The three coefficients, in `v`-degree order.
impl fmt::Debug for Fq6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Fq6({:?} + {:?} v + {:?} v^2)",
            self.c0, self.c1, self.c2
        )
    }
}
