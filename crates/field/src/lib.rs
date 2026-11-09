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

    /// `x mod p` for any `x < 2^128`, folding the high word down by `2^64 ≡ 59`
    /// twice. The first fold leaves `x < 60·2^64`; the second adds at most 3481
    /// in 64 bits, so its carry, one more `2^64 ≡ 59`, lands on a sum below
    /// 3481, and `p` is then subtracted at most once.
    #[inline]
    pub const fn from_u128(x: u128) -> Fp {
        let x = (x >> 64) * 59 + (x as u64 as u128);
        let (r, carry) = (x as u64).overflowing_add((x >> 64) as u64 * 59);
        Fp::from_u64(r + 59 * carry as u64)
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

    /// The inverse, `None` for zero, by the extended Euclidean algorithm on
    /// `(p, self)`: about 39 division steps for a random element, where
    /// `self^(p − 2)` takes 63 squarings and some products in series. Row by
    /// row `t·self ≡ r (mod p)`, and `t` alternates in sign, so its magnitude is
    /// kept, growing to `p` and no further, and the step count's parity signs
    /// it. The loop ends on `r = 1`, whose `|t|` is at most `p/2`: the next
    /// row's is `p`, at least twice it.
    pub fn inverse(self) -> Option<Fp> {
        if self == Fp::ZERO {
            return None;
        }
        let (mut r0, mut r1) = (A64_C5, self.0);
        let (mut t0, mut t1, mut odd) = (0u64, 1u64, false);
        while r1 != 0 {
            let q = r0 / r1;
            (r0, r1) = (r1, r0 - q * r1);
            (t0, t1) = (t1, t0 + q * t1);
            odd = !odd;
        }
        Some(Fp(if odd { t0 } else { A64_C5 - t0 }))
    }
}

impl Add for Fp {
    type Output = Fp;

    /// `rhs + 59 < 2^64`, and `self + rhs + 59` carries out of 64 bits exactly
    /// when `self + rhs ≥ p`, leaving `self + rhs − p`: one 64-bit add decides,
    /// and two coordinates' adds vectorize.
    #[inline]
    fn add(self, rhs: Fp) -> Fp {
        let (t, carry) = self.0.overflowing_add(rhs.0 + 59);
        Fp(if carry { t } else { t - 59 })
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

    /// `(a0 + a1·x)(b0 + b1·x) = (a0·b0 + 2·a1·b1) + (a0·b1 + a1·b0)·x`, each
    /// coordinate summed in 128 bits by [`wide_add`] and reduced once: two
    /// reductions where reducing each product takes four. Karatsuba's three
    /// products would be slower: on a one-word field a product is one
    /// instruction pair, and the sums and differences Karatsuba trades the
    /// fourth for are modular operations of their own.
    #[inline]
    fn mul(self, rhs: Fp2) -> Fp2 {
        let wide = |a: Fp, b: Fp| a.0 as u128 * b.0 as u128;
        let t = wide(self.c1, rhs.c1);
        Fp2 {
            c0: Fp::from_u128(wide_add(wide_add(wide(self.c0, rhs.c0), t), t)),
            c1: Fp::from_u128(wide_add(wide(self.c0, rhs.c1), wide(self.c1, rhs.c0))),
        }
    }
}

/// A sum of `Fp2` products reduced once, when it is read: each coordinate's
/// 128-bit products are added as they come and the carries out of 128 bits
/// counted, a carry being `2^128 ≡ 3481`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fp2Sum {
    c0: (u128, u64),
    c1: (u128, u64),
}

impl Fp2Sum {
    /// `+= a·b`, by [`Fp2`]'s schoolbook products.
    #[inline]
    pub fn add_product(&mut self, a: Fp2, b: Fp2) {
        let wide = |x: Fp, y: Fp| x.0 as u128 * y.0 as u128;
        let t = wide(a.c1, b.c1);
        for y in [wide(a.c0, b.c0), t, t] {
            carry_add(&mut self.c0, y);
        }
        for y in [wide(a.c0, b.c1), wide(a.c1, b.c0)] {
            carry_add(&mut self.c1, y);
        }
    }

    /// The sum mod `p`. `3481` times the carries stays below `2^64` for fewer
    /// than `2^50` products.
    #[inline]
    pub fn reduce(self) -> Fp2 {
        let r = |(s, k): (u128, u64)| Fp::from_u128(s) + Fp::from_u64(3481 * k);
        Fp2 {
            c0: r(self.c0),
            c1: r(self.c1),
        }
    }
}

#[inline]
fn carry_add(acc: &mut (u128, u64), y: u128) {
    let (s, carry) = acc.0.overflowing_add(y);
    *acc = (s, acc.1 + carry as u64);
}

/// `x + y`, as a `u128` equal to it mod `p`: a carry out of 128 bits is
/// `2^128 ≡ 59^2 = 3481`, and adding 3481 back cannot carry again while one of
/// the two is a product of canonical elements, at most `(p − 1)^2`.
#[inline]
const fn wide_add(x: u128, y: u128) -> u128 {
    let (s, carry) = x.overflowing_add(y);
    s + 3481 * carry as u128
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
