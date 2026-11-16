//! A 256-bit unsigned integer, the width an ERC-20 balance has on L1: four
//! 64-bit limbs, least significant first.
//!
//! Addition, subtraction, comparison, shifts and the bitwise operators are a
//! few instructions a limb, and multiplication is the schoolbook product.
//! Division and [`U256::mul_div`] are the `MUL_DIV_U256` precompile
//! (`docs/spec/precompiles.md` §4): one call, where a long division is
//! hundreds of shift-and-subtract steps.
//!
//! The operators panic on an overflow, a zero divisor and a shift of 256 or
//! more, as Rust's integers do with overflow checks on; the `checked_*`,
//! `overflowing_*` and `wrapping_*` methods are the total forms.

use core::cmp::Ordering;
use core::ops::{
    Add, AddAssign, BitAnd, BitOr, BitXor, Div, DivAssign, Mul, MulAssign, Not, Rem, Shl, Shr, Sub,
    SubAssign,
};

/// A 256-bit unsigned integer: `self.0[0]` is its low 64 bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0; 4]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);
    pub const MAX: U256 = U256([u64::MAX; 4]);

    /// `v`, widened.
    pub const fn from_u128(v: u128) -> U256 {
        U256([v as u64, (v >> 64) as u64, 0, 0])
    }

    /// The value, if it is below `2^128`.
    pub const fn to_u128(self) -> Option<u128> {
        match self.0[2] | self.0[3] {
            0 => Some(self.0[0] as u128 | (self.0[1] as u128) << 64),
            _ => None,
        }
    }

    /// The value, if it is below `2^64`.
    pub const fn to_u64(self) -> Option<u64> {
        match self.0[1] | self.0[2] | self.0[3] {
            0 => Some(self.0[0]),
            _ => None,
        }
    }

    pub const fn is_zero(self) -> bool {
        self.0[0] | self.0[1] | self.0[2] | self.0[3] == 0
    }

    /// From 32 bytes, least significant first.
    pub fn from_le_bytes(bytes: [u8; 32]) -> U256 {
        U256(core::array::from_fn(|i| {
            let mut limb = [0u8; 8];
            limb.copy_from_slice(&bytes[8 * i..8 * i + 8]);
            u64::from_le_bytes(limb)
        }))
    }

    /// From 32 bytes, most significant first: an EVM word's encoding.
    pub fn from_be_bytes(mut bytes: [u8; 32]) -> U256 {
        bytes.reverse();
        U256::from_le_bytes(bytes)
    }

    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = self.to_le_bytes();
        out.reverse();
        out
    }

    /// The number of leading zero bits.
    pub fn leading_zeros(self) -> u32 {
        match self.0.iter().rposition(|&l| l != 0) {
            Some(i) => 64 * (3 - i as u32) + self.0[i].leading_zeros(),
            None => 256,
        }
    }

    pub fn overflowing_add(self, rhs: U256) -> (U256, bool) {
        let mut out = [0u64; 4];
        let mut carry = false;
        for (i, limb) in out.iter_mut().enumerate() {
            let (s, c1) = self.0[i].overflowing_add(rhs.0[i]);
            let (s, c2) = s.overflowing_add(carry as u64);
            *limb = s;
            carry = c1 | c2;
        }
        (U256(out), carry)
    }

    pub fn overflowing_sub(self, rhs: U256) -> (U256, bool) {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for (i, limb) in out.iter_mut().enumerate() {
            let (d, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (d, b2) = d.overflowing_sub(borrow as u64);
            *limb = d;
            borrow = b1 | b2;
        }
        (U256(out), borrow)
    }

    pub fn checked_add(self, rhs: U256) -> Option<U256> {
        match self.overflowing_add(rhs) {
            (v, false) => Some(v),
            _ => None,
        }
    }

    pub fn checked_sub(self, rhs: U256) -> Option<U256> {
        match self.overflowing_sub(rhs) {
            (v, false) => Some(v),
            _ => None,
        }
    }

    pub fn wrapping_add(self, rhs: U256) -> U256 {
        self.overflowing_add(rhs).0
    }

    pub fn wrapping_sub(self, rhs: U256) -> U256 {
        self.overflowing_sub(rhs).0
    }

    pub fn saturating_add(self, rhs: U256) -> U256 {
        self.checked_add(rhs).unwrap_or(U256::MAX)
    }

    pub fn saturating_sub(self, rhs: U256) -> U256 {
        self.checked_sub(rhs).unwrap_or(U256::ZERO)
    }

    /// The full 512-bit product as `(low, high)`.
    pub fn widening_mul(self, rhs: U256) -> (U256, U256) {
        let mut p = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = self.0[i] as u128 * rhs.0[j] as u128 + p[i + j] as u128 + carry;
                p[i + j] = t as u64;
                carry = t >> 64;
            }
            p[i + 4] = carry as u64;
        }
        (
            U256([p[0], p[1], p[2], p[3]]),
            U256([p[4], p[5], p[6], p[7]]),
        )
    }

    pub fn overflowing_mul(self, rhs: U256) -> (U256, bool) {
        let (low, high) = self.widening_mul(rhs);
        (low, !high.is_zero())
    }

    pub fn checked_mul(self, rhs: U256) -> Option<U256> {
        match self.overflowing_mul(rhs) {
            (v, false) => Some(v),
            _ => None,
        }
    }

    pub fn wrapping_mul(self, rhs: U256) -> U256 {
        self.overflowing_mul(rhs).0
    }

    /// `(floor(self·b/d), self·b mod d)` over the full 512-bit product, by
    /// the precompile; `None` when `d = 0` or the quotient is not below
    /// `2^256`, which the call does not answer. Uniswap's `FullMath.mulDiv`,
    /// with its remainder.
    pub fn mul_div_rem(self, b: U256, d: U256) -> Option<(U256, U256)> {
        if d.is_zero() {
            return None;
        }
        // Two operands below 2^128 have a product below 2^256, whose high
        // half, 0, is below any nonzero `d`.
        let narrow = |x: U256| x.0[2] | x.0[3] == 0;
        if !(narrow(self) && narrow(b)) && self.widening_mul(b).1 >= d {
            return None;
        }
        Some(super::mul_div_u256(self, b, d))
    }

    /// `floor(self·b/d)`; `None` as [`U256::mul_div_rem`].
    pub fn mul_div(self, b: U256, d: U256) -> Option<U256> {
        self.mul_div_rem(b, d).map(|(q, _)| q)
    }

    /// `(self / d, self % d)`, or `None` at `d = 0`.
    pub fn div_rem(self, d: U256) -> Option<(U256, U256)> {
        self.mul_div_rem(U256::ONE, d)
    }

    pub fn checked_div(self, d: U256) -> Option<U256> {
        self.div_rem(d).map(|(q, _)| q)
    }

    pub fn checked_rem(self, d: U256) -> Option<U256> {
        self.div_rem(d).map(|(_, r)| r)
    }

    /// `self << n`, or `None` at `n ≥ 256`; bits shifted out are lost.
    pub fn checked_shl(self, n: u32) -> Option<U256> {
        (n < 256).then(|| {
            let (limbs, bits) = ((n / 64) as usize, n % 64);
            U256(core::array::from_fn(|i| {
                let at = |k: usize| if k >= limbs { self.0[k - limbs] } else { 0 };
                match (i >= limbs, bits) {
                    (false, _) => 0,
                    (true, 0) => at(i),
                    (true, _) => {
                        at(i) << bits
                            | if i > limbs {
                                at(i - 1) >> (64 - bits)
                            } else {
                                0
                            }
                    }
                }
            }))
        })
    }

    /// `self >> n`, or `None` at `n ≥ 256`.
    pub fn checked_shr(self, n: u32) -> Option<U256> {
        (n < 256).then(|| {
            let (limbs, bits) = ((n / 64) as usize, n % 64);
            U256(core::array::from_fn(|i| {
                let at = |k: usize| if k < 4 { self.0[k] } else { 0 };
                match bits {
                    0 => at(i + limbs),
                    _ => at(i + limbs) >> bits | at(i + limbs + 1) << (64 - bits),
                }
            }))
        })
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &U256) -> Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &U256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<u64> for U256 {
    fn from(v: u64) -> U256 {
        U256([v, 0, 0, 0])
    }
}

impl From<u128> for U256 {
    fn from(v: u128) -> U256 {
        U256::from_u128(v)
    }
}

/// An operator over `checked`, panicking with Rust's own message on `None`.
macro_rules! checked_op {
    ($trait:ident, $method:ident, $assign:ident, $assign_method:ident, $checked:ident, $what:literal) => {
        impl $trait for U256 {
            type Output = U256;
            fn $method(self, rhs: U256) -> U256 {
                self.$checked(rhs).expect($what)
            }
        }
        impl $assign for U256 {
            fn $assign_method(&mut self, rhs: U256) {
                *self = $trait::$method(*self, rhs);
            }
        }
    };
}

checked_op!(
    Add,
    add,
    AddAssign,
    add_assign,
    checked_add,
    "attempt to add with overflow"
);
checked_op!(
    Sub,
    sub,
    SubAssign,
    sub_assign,
    checked_sub,
    "attempt to subtract with overflow"
);
checked_op!(
    Mul,
    mul,
    MulAssign,
    mul_assign,
    checked_mul,
    "attempt to multiply with overflow"
);
checked_op!(
    Div,
    div,
    DivAssign,
    div_assign,
    checked_div,
    "attempt to divide by zero"
);

impl Rem for U256 {
    type Output = U256;
    fn rem(self, rhs: U256) -> U256 {
        self.checked_rem(rhs)
            .expect("attempt to calculate the remainder with a divisor of zero")
    }
}

impl Shl<u32> for U256 {
    type Output = U256;
    fn shl(self, n: u32) -> U256 {
        self.checked_shl(n)
            .expect("attempt to shift left with overflow")
    }
}

impl Shr<u32> for U256 {
    type Output = U256;
    fn shr(self, n: u32) -> U256 {
        self.checked_shr(n)
            .expect("attempt to shift right with overflow")
    }
}

/// A limb-wise bitwise operator.
macro_rules! bitwise {
    ($trait:ident, $method:ident, $op:tt) => {
        impl $trait for U256 {
            type Output = U256;
            fn $method(self, rhs: U256) -> U256 {
                U256(core::array::from_fn(|i| self.0[i] $op rhs.0[i]))
            }
        }
    };
}

bitwise!(BitAnd, bitand, &);
bitwise!(BitOr, bitor, |);
bitwise!(BitXor, bitxor, ^);

impl Not for U256 {
    type Output = U256;
    fn not(self) -> U256 {
        U256(self.0.map(|l| !l))
    }
}
