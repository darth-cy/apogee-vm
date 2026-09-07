#![no_std]
//! `Fr`, the BN254 scalar field.
//!
//! Arithmetic runs in Montgomery form over four 64-bit limbs. Montgomery form
//! never escapes memory: [`Fr::to_bytes`] and [`Fr::from_bytes`] are the only
//! wire path, and they are canonical (non-Montgomery) 32-byte little-endian.
//!
//! Everything is portable stable Rust with `u128` intermediates — no carry
//! intrinsics, no assembly, no nightly — so this crate compiles unchanged for
//! `riscv32imac-unknown-none-elf`.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use constants::{FR_INV, FR_MODULUS, FR_MODULUS_MINUS_TWO, FR_R, FR_R2};

/// `-1` in Montgomery form, i.e. `(p - 1) * R mod p`, which equals `p - R`.
///
/// Checked against `ZERO - ONE` in `tests/edge_cases.rs`.
const MINUS_ONE_MONTGOMERY: [u64; 4] = [
    0x974b_c177_a000_0006,
    0xf137_71b2_da58_a367,
    0x51e1_a247_0908_122e,
    0x2259_d6b1_4729_c0fa,
];

/// An element of the BN254 scalar field.
///
/// The limbs are the Montgomery representation `x * R mod p`, little-endian,
/// always fully reduced to `[0, p)`. That canonical representation is what
/// makes the derived `PartialEq` correct.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fr([u64; 4]);

// ---------------------------------------------------------------------------
// Limb primitives. Every intermediate fits in `u128` by inspection:
// `(2^64 - 1) + (2^64 - 1)^2 + (2^64 - 1) = 2^128 - 1`.
// ---------------------------------------------------------------------------

/// `acc + a * b + carry`, split into (low limb, carry out).
#[inline(always)]
fn mac(acc: u64, a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (acc as u128) + (a as u128) * (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// `a + b + carry`, split into (low limb, carry out).
#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// `a - b - borrow`, split into (low limb, borrow out).
#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128)
        .wrapping_sub(b as u128)
        .wrapping_sub(borrow as u128);
    (t as u64, ((t >> 64) as u64) & 1)
}

/// Little-endian limbwise `a >= p`.
#[inline]
fn is_ge_modulus(a: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != FR_MODULUS[i] {
            return a[i] > FR_MODULUS[i];
        }
    }
    true
}

/// Subtract `p` once if `a >= p`.
#[inline]
fn reduce_once(a: &mut [u64; 4]) {
    if is_ge_modulus(a) {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, b) = sbb(a[i], FR_MODULUS[i], borrow);
            a[i] = d;
            borrow = b;
        }
        debug_assert_eq!(borrow, 0, "a >= p, so a - p cannot borrow");
    }
}

/// `(a + b) mod p` for reduced `a`, `b`.
fn add_limbs(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (s, c) = adc(a[i], b[i], carry);
        r[i] = s;
        carry = c;
    }
    // p < 2^254, so a + b < 2^255 and the sum always fits in four limbs.
    debug_assert_eq!(carry, 0, "operands must be reduced to [0, p)");
    reduce_once(&mut r);
    r
}

/// `(a - b) mod p` for reduced `a`, `b`.
fn sub_limbs(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, bw) = sbb(a[i], b[i], borrow);
        r[i] = d;
        borrow = bw;
    }
    if borrow == 1 {
        let mut carry = 0u64;
        for i in 0..4 {
            let (s, c) = adc(r[i], FR_MODULUS[i], carry);
            r[i] = s;
            carry = c;
        }
    }
    r
}

/// `-a mod p` for reduced `a`.
fn neg_limbs(a: &[u64; 4]) -> [u64; 4] {
    if *a == [0u64; 4] {
        [0u64; 4]
    } else {
        sub_limbs(&FR_MODULUS, a)
    }
}

/// Montgomery product `a * b * R^{-1} mod p` for reduced `a`, `b`.
///
/// CIOS (Koc-Acar-Kaliski) over `s = 4` limbs. With `a < p` the running
/// accumulator stays below `2p`, and `2p < 2^255`, so it never spills past the
/// fourth limb and one conditional subtraction reduces the result.
fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 6];
    for &b_i in b.iter() {
        // t += a * b_i
        let mut carry = 0u64;
        for j in 0..4 {
            let (s, c) = mac(t[j], a[j], b_i, carry);
            t[j] = s;
            carry = c;
        }
        let (s, c) = adc(t[4], carry, 0);
        t[4] = s;
        t[5] = c;

        // t = (t + m * p) / 2^64, with m chosen so the low limb cancels.
        let m = t[0].wrapping_mul(FR_INV);
        let (cancelled, mut carry) = mac(t[0], m, FR_MODULUS[0], 0);
        debug_assert_eq!(cancelled, 0, "m = t[0] * (-p^-1) must cancel limb 0");
        for j in 1..4 {
            let (s, c) = mac(t[j], m, FR_MODULUS[j], carry);
            t[j - 1] = s;
            carry = c;
        }
        let (s, c) = adc(t[4], carry, 0);
        t[3] = s;
        t[4] = t[5] + c;
    }
    debug_assert_eq!(t[4], 0, "CIOS accumulator stays below 2p < 2^255");

    let mut r = [t[0], t[1], t[2], t[3]];
    reduce_once(&mut r);
    r
}

/// Montgomery form to canonical: `a * R^{-1} mod p`.
#[inline]
fn from_montgomery(a: &[u64; 4]) -> [u64; 4] {
    mont_mul(a, &[1, 0, 0, 0])
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl Fr {
    /// The additive identity.
    pub const ZERO: Fr = Fr([0, 0, 0, 0]);

    /// The multiplicative identity.
    pub const ONE: Fr = Fr(FR_R);

    /// `p - 1`. Also the decoded-table padding sentinel from S11 on.
    pub const MINUS_ONE: Fr = Fr(MINUS_ONE_MONTGOMERY);

    /// Lift a `u64`. Always in range: `2^64 < p`.
    pub fn from_u64(x: u64) -> Fr {
        Fr(mont_mul(&[x, 0, 0, 0], &FR_R2))
    }

    /// `self * self`.
    pub fn square(&self) -> Fr {
        Fr(mont_mul(&self.0, &self.0))
    }

    /// `self^exp`, with `exp` a 256-bit little-endian limb array.
    ///
    /// The exponent is a plain integer, not a field element: it is not reduced
    /// and need not be below `p`. `x^0 == ONE` for every `x`, including zero.
    pub fn pow(&self, exp: &[u64; 4]) -> Fr {
        let mut acc = Fr::ONE;
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

    /// Multiplicative inverse by Fermat, `self^(p-2)`. `None` for zero.
    pub fn inverse(&self) -> Option<Fr> {
        if *self == Fr::ZERO {
            None
        } else {
            Some(self.pow(&FR_MODULUS_MINUS_TWO))
        }
    }

    /// Canonical (non-Montgomery) 32-byte little-endian encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        let c = from_montgomery(&self.0);
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[8 * i..8 * i + 8].copy_from_slice(&c[i].to_le_bytes());
        }
        out
    }

    /// Decode a source-literal hex constant: `0x` followed by exactly 64
    /// lowercase hex digits, read **big-endian**.
    ///
    /// This is the form frozen constant tables are written in — the order
    /// [`Debug`] prints, and the order upstream tables such as the Poseidon2
    /// round constants use, so a vendored table diffs against its source by
    /// eye. It is deliberately *not* the little-endian byte order of
    /// [`to_bytes`], which is the wire form; a hex literal in source is a
    /// number, not a byte string.
    ///
    /// `None` for anything else: a missing prefix, the wrong length, an
    /// uppercase or non-hex digit, or a value `>= p`. There is exactly one
    /// accepted spelling, so a constant that does not parse is a build-time
    /// failure at its `expect`, not a silently different field element.
    ///
    /// [`to_bytes`]: Fr::to_bytes
    pub fn from_hex(s: &str) -> Option<Fr> {
        let digits = s.strip_prefix("0x")?.as_bytes();
        if digits.len() != 64 {
            return None;
        }
        let mut le = [0u8; 32];
        for i in 0..32 {
            let hi = hex_digit(digits[2 * i])?;
            let lo = hex_digit(digits[2 * i + 1])?;
            // The text is big-endian, the bytes are little-endian.
            le[31 - i] = (hi << 4) | lo;
        }
        Fr::from_bytes(&le)
    }

    /// Decode a canonical 32-byte little-endian value.
    ///
    /// `None` if the value is `>= p`. Non-canonical input is never silently
    /// reduced.
    pub fn from_bytes(b: &[u8; 32]) -> Option<Fr> {
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(b.chunks_exact(8)) {
            let mut w = [0u8; 8];
            w.copy_from_slice(chunk);
            *limb = u64::from_le_bytes(w);
        }
        if is_ge_modulus(&limbs) {
            return None;
        }
        Some(Fr(mont_mul(&limbs, &FR_R2)))
    }
}

/// One lowercase hex digit's value, or `None`.
fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Invert every element in place with Montgomery's trick.
///
/// Zero entries stay zero; they are skipped, not treated as an error.
pub fn batch_inverse(xs: &mut [Fr]) {
    // prefix[i] = product of the nonzero entries strictly before i.
    let mut prefix: Vec<Fr> = Vec::with_capacity(xs.len());
    let mut running = Fr::ONE;
    for x in xs.iter() {
        prefix.push(running);
        if *x != Fr::ZERO {
            running *= x;
        }
    }

    // A product of nonzero field elements is nonzero, and the empty product is
    // ONE, so this inverse always exists.
    let mut inv = running
        .inverse()
        .expect("batch_inverse: product of nonzero entries is nonzero");

    for i in (0..xs.len()).rev() {
        if xs[i] == Fr::ZERO {
            continue;
        }
        // inv == 1 / (product of nonzero entries at indices <= i)
        let next_inv = inv * xs[i];
        xs[i] = inv * prefix[i];
        inv = next_inv;
    }
}

// ---------------------------------------------------------------------------
// Operators. The macro collapses six near-identical impls per operator.
// ---------------------------------------------------------------------------

macro_rules! impl_binop {
    ($Op:ident, $op:ident, $OpAssign:ident, $op_assign:ident, $limbs:ident) => {
        impl $Op<Fr> for Fr {
            type Output = Fr;
            fn $op(self, rhs: Fr) -> Fr {
                Fr($limbs(&self.0, &rhs.0))
            }
        }
        impl $Op<&Fr> for Fr {
            type Output = Fr;
            fn $op(self, rhs: &Fr) -> Fr {
                Fr($limbs(&self.0, &rhs.0))
            }
        }
        impl $Op<Fr> for &Fr {
            type Output = Fr;
            fn $op(self, rhs: Fr) -> Fr {
                Fr($limbs(&self.0, &rhs.0))
            }
        }
        impl $Op<&Fr> for &Fr {
            type Output = Fr;
            fn $op(self, rhs: &Fr) -> Fr {
                Fr($limbs(&self.0, &rhs.0))
            }
        }
        impl $OpAssign<Fr> for Fr {
            fn $op_assign(&mut self, rhs: Fr) {
                self.0 = $limbs(&self.0, &rhs.0);
            }
        }
        impl $OpAssign<&Fr> for Fr {
            fn $op_assign(&mut self, rhs: &Fr) {
                self.0 = $limbs(&self.0, &rhs.0);
            }
        }
    };
}

impl_binop!(Add, add, AddAssign, add_assign, add_limbs);
impl_binop!(Sub, sub, SubAssign, sub_assign, sub_limbs);
impl_binop!(Mul, mul, MulAssign, mul_assign, mont_mul);

impl Neg for Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        Fr(neg_limbs(&self.0))
    }
}

impl Neg for &Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        Fr(neg_limbs(&self.0))
    }
}

/// Prints the canonical value in big-endian hex, never the Montgomery limbs.
impl fmt::Debug for Fr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.to_bytes();
        write!(f, "Fr(0x")?;
        for byte in b.iter().rev() {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

// ---------------------------------------------------------------------------
// Serde. Routed through the canonical byte form, so the Montgomery
// representation never reaches an artifact.
// ---------------------------------------------------------------------------

impl serde::Serialize for Fr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_bytes().serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Fr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Fr, D::Error> {
        let b = <[u8; 32] as serde::Deserialize>::deserialize(d)?;
        Fr::from_bytes(&b).ok_or_else(|| {
            <D::Error as serde::de::Error>::custom("non-canonical Fr encoding: value >= modulus")
        })
    }
}
