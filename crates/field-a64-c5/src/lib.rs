#![no_std]
//! `Fp`, the A64-C5 field: the integers mod `p = 2^64 − 59`, specified in
//! `docs/spec/transcript.md` §1.1.
//!
//! `#![no_std]`, so guests and the no_std verifier core can link it.

use core::ops::{Add, Mul};

/// The A64-C5 prime, `2^64 − 59`.
pub const A64_C5: u64 = 0xFFFF_FFFF_FFFF_FFC5;

const P: u128 = A64_C5 as u128;

/// An element of the A64-C5 field, held as its canonical representative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp(u64);

impl Fp {
    pub const ZERO: Fp = Fp(0);
    pub const ONE: Fp = Fp(1);

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
}

impl Add for Fp {
    type Output = Fp;

    #[inline]
    fn add(self, rhs: Fp) -> Fp {
        let s = self.0 as u128 + rhs.0 as u128;
        Fp((if s >= P { s - P } else { s }) as u64)
    }
}

impl Mul for Fp {
    type Output = Fp;

    #[inline]
    fn mul(self, rhs: Fp) -> Fp {
        Fp::from_u128(self.0 as u128 * rhs.0 as u128)
    }
}
