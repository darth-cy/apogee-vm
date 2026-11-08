#![no_std]
//! The A64-C5 field and its quadratic extension, specified in
//! `docs/spec/primitives.md` §1:
//!
//! - [`Fp`], the integers mod `p = 2^64 − 59`: the base field, every witness
//!   value and every gate literal;
//! - [`Fp2`], `F_p[x]/(x^2 − 2)`: the challenge field, every transcript
//!   challenge and every value a challenge reaches.
//!
//! `#![no_std]`, so guests and the no_std verifier core can link it.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// The A64-C5 prime, `2^64 − 59`.
pub const A64_C5: u64 = 0xFFFF_FFFF_FFFF_FFC5;

const P: u128 = A64_C5 as u128;

/// An element of the A64-C5 field, held as its canonical representative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp(u64);

impl Fp {
    pub const ZERO: Fp = Fp(0);
    pub const ONE: Fp = Fp(1);
    /// `p − 1`.
    pub const MINUS_ONE: Fp = Fp(A64_C5 - 1);

    /// `x mod p`. A `u64` is below `2p`, so `p` is subtracted at most once.
    #[inline]
    pub const fn from_u64(x: u64) -> Fp {
        Fp(if x >= A64_C5 { x - A64_C5 } else { x })
    }

    /// `x mod p` for any `x < 2^128`. Two folds by `2^64 ≡ 59` leave
    /// `x < 2^64 + 3481 < 2p`, so `p` is then subtracted at most once.
    #[inline]
    pub const fn from_u128(x: u128) -> Fp {
        let x = (x >> 64) * 59 + (x as u64 as u128);
        let x = (x >> 64) * 59 + (x as u64 as u128);
        Fp((if x >= P { x - P } else { x }) as u64)
    }

    /// `x`, if it is canonical.
    pub const fn from_canonical(x: u64) -> Option<Fp> {
        if x < A64_C5 {
            Some(Fp(x))
        } else {
            None
        }
    }

    /// The canonical representative, in `[0, p)`.
    #[inline]
    pub const fn to_u64(self) -> u64 {
        self.0
    }

    /// The wire form: the canonical representative, 8 bytes little-endian.
    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// The inverse of [`Fp::to_bytes`]: `None` at or above `p`, never reduced.
    pub fn from_bytes(bytes: &[u8; 8]) -> Option<Fp> {
        Fp::from_canonical(u64::from_le_bytes(*bytes))
    }

    /// `self^(p − 2)` by Fermat; `None` for zero.
    pub fn inverse(self) -> Option<Fp> {
        if self == Fp::ZERO {
            return None;
        }
        let (mut base, mut e, mut acc) = (self, A64_C5 - 2, Fp::ONE);
        while e > 0 {
            if e & 1 == 1 {
                acc *= base;
            }
            base *= base;
            e >>= 1;
        }
        Some(acc)
    }
}

impl Add for Fp {
    type Output = Fp;

    #[inline]
    fn add(self, rhs: Fp) -> Fp {
        let s = self.0 as u128 + rhs.0 as u128;
        Fp((if s >= P { s - P } else { s }) as u64)
    }
}

impl Sub for Fp {
    type Output = Fp;

    /// A borrow wraps by `2^64`; adding `p` back, modulo `2^64`, lands on
    /// `self − rhs + p`.
    #[inline]
    fn sub(self, rhs: Fp) -> Fp {
        let (d, borrow) = self.0.overflowing_sub(rhs.0);
        Fp(if borrow { d.wrapping_add(A64_C5) } else { d })
    }
}

impl Neg for Fp {
    type Output = Fp;

    #[inline]
    fn neg(self) -> Fp {
        Fp::ZERO - self
    }
}

impl Mul for Fp {
    type Output = Fp;

    #[inline]
    fn mul(self, rhs: Fp) -> Fp {
        Fp::from_u128(self.0 as u128 * rhs.0 as u128)
    }
}

/// An element `c0 + c1·x` of `F_{p^2} = F_p[x]/(x^2 − 2)`, a field because
/// `p ≡ 5 (mod 8)` makes 2 a non-square mod `p`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl Fp2 {
    pub const ZERO: Fp2 = Fp2 {
        c0: Fp::ZERO,
        c1: Fp::ZERO,
    };
    pub const ONE: Fp2 = Fp2 {
        c0: Fp::ONE,
        c1: Fp::ZERO,
    };

    /// The wire form: `c0` then `c1`, each as [`Fp::to_bytes`].
    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.c0.to_bytes());
        out[8..].copy_from_slice(&self.c1.to_bytes());
        out
    }

    /// The inverse of [`Fp2::to_bytes`]: `None` unless both halves are canonical.
    pub fn from_bytes(bytes: &[u8; 16]) -> Option<Fp2> {
        let half = |i: usize| Fp::from_bytes(bytes[i..i + 8].try_into().expect("8 bytes"));
        Some(Fp2 {
            c0: half(0)?,
            c1: half(8)?,
        })
    }

    /// `(c0 − c1·x) / (c0^2 − 2·c1^2)`: the norm lies in `F_p` and is zero only
    /// at zero, 2 being a non-square. `None` for zero.
    pub fn inverse(self) -> Option<Fp2> {
        let n = (self.c0 * self.c0 - (self.c1 * self.c1 + self.c1 * self.c1)).inverse()?;
        Some(Fp2 {
            c0: self.c0 * n,
            c1: -(self.c1 * n),
        })
    }
}

/// The embedding of `F_p` in `F_{p^2}`.
impl From<Fp> for Fp2 {
    #[inline]
    fn from(c0: Fp) -> Fp2 {
        Fp2 { c0, c1: Fp::ZERO }
    }
}

impl Add for Fp2 {
    type Output = Fp2;

    #[inline]
    fn add(self, rhs: Fp2) -> Fp2 {
        Fp2 {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}

impl Sub for Fp2 {
    type Output = Fp2;

    #[inline]
    fn sub(self, rhs: Fp2) -> Fp2 {
        Fp2 {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
        }
    }
}

impl Neg for Fp2 {
    type Output = Fp2;

    #[inline]
    fn neg(self) -> Fp2 {
        Fp2 {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

impl Mul for Fp2 {
    type Output = Fp2;

    /// `(a0 + a1·x)(b0 + b1·x) = (a0·b0 + 2·a1·b1) + (a0·b1 + a1·b0)·x`. With
    /// `a1·b1` reduced first, `a0·b0 + 2·(a1·b1 mod p) ≤ p^2 − 1 < 2^128`.
    #[inline]
    fn mul(self, rhs: Fp2) -> Fp2 {
        let wide = |a: Fp, b: Fp| a.0 as u128 * b.0 as u128;
        let t = Fp::from_u128(wide(self.c1, rhs.c1)).0 as u128;
        Fp2 {
            c0: Fp::from_u128(wide(self.c0, rhs.c0) + 2 * t),
            c1: Fp::from_u128(wide(self.c0, rhs.c1)) + Fp::from_u128(wide(self.c1, rhs.c0)),
        }
    }
}

// A base element on the right, as the embedding would give it: two base
// products where a full one takes four.
impl Add<Fp> for Fp2 {
    type Output = Fp2;

    #[inline]
    fn add(self, rhs: Fp) -> Fp2 {
        Fp2 {
            c0: self.c0 + rhs,
            c1: self.c1,
        }
    }
}

impl Sub<Fp> for Fp2 {
    type Output = Fp2;

    #[inline]
    fn sub(self, rhs: Fp) -> Fp2 {
        Fp2 {
            c0: self.c0 - rhs,
            c1: self.c1,
        }
    }
}

impl Mul<Fp> for Fp2 {
    type Output = Fp2;

    #[inline]
    fn mul(self, rhs: Fp) -> Fp2 {
        Fp2 {
            c0: self.c0 * rhs,
            c1: self.c1 * rhs,
        }
    }
}

// And on the left, as a formula writes a literal: `c·x`, `1 − x`.
impl Add<Fp2> for Fp {
    type Output = Fp2;

    #[inline]
    fn add(self, rhs: Fp2) -> Fp2 {
        rhs + self
    }
}

impl Sub<Fp2> for Fp {
    type Output = Fp2;

    #[inline]
    fn sub(self, rhs: Fp2) -> Fp2 {
        -rhs + self
    }
}

impl Mul<Fp2> for Fp {
    type Output = Fp2;

    #[inline]
    fn mul(self, rhs: Fp2) -> Fp2 {
        rhs * self
    }
}

macro_rules! assign {
    ($($T:ty, $R:ty;)*) => {$(
        impl AddAssign<$R> for $T {
            #[inline]
            fn add_assign(&mut self, rhs: $R) {
                *self = *self + rhs;
            }
        }
        impl SubAssign<$R> for $T {
            #[inline]
            fn sub_assign(&mut self, rhs: $R) {
                *self = *self - rhs;
            }
        }
        impl MulAssign<$R> for $T {
            #[inline]
            fn mul_assign(&mut self, rhs: $R) {
                *self = *self * rhs;
            }
        }
    )*};
}

assign! {
    Fp, Fp;
    Fp2, Fp2;
    Fp2, Fp;
}

// Serde routes through the wire form, so a non-canonical value is refused on
// the way in. `F_{p^2}` has no serde: no serde-encoded type carries one.
impl serde::Serialize for Fp {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_bytes().serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Fp {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Fp, D::Error> {
        let b = <[u8; 8] as serde::Deserialize>::deserialize(d)?;
        Fp::from_bytes(&b).ok_or_else(|| {
            <D::Error as serde::de::Error>::custom("non-canonical Fp encoding: value >= modulus")
        })
    }
}
