//! `Fq`, the BN254 base field: where curve coordinates live.
//!
//! The limb primitives and the Montgomery core below are a deliberate, literal
//! duplicate of `crates/field`'s, with `FQ_*` constants in place of `FR_*`.
//! S05 says "reuse the approach, not the type", and the master prompt's rule 1
//! forbids a generic field: `Fq` is its own concrete struct, so the arithmetic
//! is its own concrete code. Two copies of a proven 150-line kernel are
//! cheaper to review than one abstraction over a field that will only ever
//! have two instances.
//!
//! `q < 2^254`, exactly as `p` is, so every bound the `Fr` kernel relies on
//! holds here unchanged: a sum of two reduced values fits in four limbs, and
//! the CIOS accumulator stays below `2q < 2^255`.

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use constants::{
    FQ_INV, FQ_MODULUS, FQ_MODULUS_MINUS_TWO, FQ_MODULUS_PLUS_ONE_DIV_FOUR, FQ_R, FQ_R2,
};

/// `-1` in Montgomery form, i.e. `(q - 1) * R mod q`, which equals `q - R`.
///
/// Checked against `ZERO - ONE` and against `constants::FQ2_NONRESIDUE` in
/// `tests/constants_check.rs`.
const MINUS_ONE_MONTGOMERY: [u64; 4] = [
    0x68c3_4889_12ed_efaa,
    0x8d08_7f68_72aa_bf4f,
    0x51e1_a247_0908_1231,
    0x2259_d6b1_4729_c0fa,
];

/// An element of the BN254 base field.
///
/// The limbs are the Montgomery representation `x * R mod q`, little-endian,
/// always fully reduced to `[0, q)`. That canonical representation is what
/// makes the derived `PartialEq` correct.
///
/// The limbs are `pub(crate)` rather than private so that `g1.rs` and `g2.rs`
/// can write the frozen `GENERATOR` constants, which need Montgomery limbs at
/// const-evaluation time. Nothing outside this crate can see the layout.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fq(pub(crate) [u64; 4]);

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

/// Little-endian limbwise `a >= q`.
#[inline]
fn is_ge_modulus(a: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != FQ_MODULUS[i] {
            return a[i] > FQ_MODULUS[i];
        }
    }
    true
}

/// Subtract `q` once if `a >= q`.
#[inline]
fn reduce_once(a: &mut [u64; 4]) {
    if is_ge_modulus(a) {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, b) = sbb(a[i], FQ_MODULUS[i], borrow);
            a[i] = d;
            borrow = b;
        }
        debug_assert_eq!(borrow, 0, "a >= q, so a - q cannot borrow");
    }
}

/// `(a + b) mod q` for reduced `a`, `b`.
fn add_limbs(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (s, c) = adc(a[i], b[i], carry);
        r[i] = s;
        carry = c;
    }
    // q < 2^254, so a + b < 2^255 and the sum always fits in four limbs.
    debug_assert_eq!(carry, 0, "operands must be reduced to [0, q)");
    reduce_once(&mut r);
    r
}

/// `(a - b) mod q` for reduced `a`, `b`.
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
            let (s, c) = adc(r[i], FQ_MODULUS[i], carry);
            r[i] = s;
            carry = c;
        }
    }
    r
}

/// `-a mod q` for reduced `a`.
fn neg_limbs(a: &[u64; 4]) -> [u64; 4] {
    if *a == [0u64; 4] {
        [0u64; 4]
    } else {
        sub_limbs(&FQ_MODULUS, a)
    }
}

/// Montgomery product `a * b * R^{-1} mod q` for reduced `a`, `b`.
///
/// CIOS (Koc-Acar-Kaliski) over `s = 4` limbs. With `a < q` the running
/// accumulator stays below `2q`, and `2q < 2^255`, so it never spills past the
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

        // t = (t + m * q) / 2^64, with m chosen so the low limb cancels.
        let m = t[0].wrapping_mul(FQ_INV);
        let (cancelled, mut carry) = mac(t[0], m, FQ_MODULUS[0], 0);
        debug_assert_eq!(cancelled, 0, "m = t[0] * (-q^-1) must cancel limb 0");
        for j in 1..4 {
            let (s, c) = mac(t[j], m, FQ_MODULUS[j], carry);
            t[j - 1] = s;
            carry = c;
        }
        let (s, c) = adc(t[4], carry, 0);
        t[3] = s;
        t[4] = t[5] + c;
    }
    debug_assert_eq!(t[4], 0, "CIOS accumulator stays below 2q < 2^255");

    let mut r = [t[0], t[1], t[2], t[3]];
    reduce_once(&mut r);
    r
}

/// Montgomery form to canonical: `a * R^{-1} mod q`.
#[inline]
fn from_montgomery(a: &[u64; 4]) -> [u64; 4] {
    mont_mul(a, &[1, 0, 0, 0])
}

// ---------------------------------------------------------------------------
// Public API. The names mirror `field::Fr`'s frozen surface exactly, plus
// `sqrt`, which `Fr` has no use for and `Fq2` needs.
// ---------------------------------------------------------------------------

impl Fq {
    /// The additive identity.
    pub const ZERO: Fq = Fq([0, 0, 0, 0]);

    /// The multiplicative identity.
    pub const ONE: Fq = Fq(FQ_R);

    /// `q - 1`. Also the Fq2 nonresidue: `u^2 = -1`.
    pub const MINUS_ONE: Fq = Fq(MINUS_ONE_MONTGOMERY);

    /// Lift a `u64`. Always in range: `2^64 < q`.
    pub fn from_u64(x: u64) -> Fq {
        Fq(mont_mul(&[x, 0, 0, 0], &FQ_R2))
    }

    /// `self * self`.
    pub fn square(&self) -> Fq {
        Fq(mont_mul(&self.0, &self.0))
    }

    /// `self^exp`, with `exp` a 256-bit little-endian limb array.
    ///
    /// The exponent is a plain integer, not a field element: it is not reduced
    /// and need not be below `q`. `x^0 == ONE` for every `x`, including zero.
    pub fn pow(&self, exp: &[u64; 4]) -> Fq {
        let mut acc = Fq::ONE;
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

    /// Multiplicative inverse by Fermat, `self^(q-2)`. `None` for zero.
    pub fn inverse(&self) -> Option<Fq> {
        if *self == Fq::ZERO {
            None
        } else {
            Some(self.pow(&FQ_MODULUS_MINUS_TWO))
        }
    }

    /// A square root of `self`, or `None` if `self` is not a square.
    ///
    /// `q = 3 mod 4`, so `self^((q+1)/4)` is a square root whenever one
    /// exists, and squaring the candidate is the whole test. `sqrt(0)` is
    /// `Some(0)`.
    ///
    /// **Which root is unspecified.** A nonzero square has two, `x` and `-x`,
    /// and nothing here normalises the sign; callers that care must compare up
    /// to negation. Nothing in the protocol depends on the choice — points are
    /// serialized uncompressed, so no decompression ever needs a root.
    pub fn sqrt(&self) -> Option<Fq> {
        let candidate = self.pow(&FQ_MODULUS_PLUS_ONE_DIV_FOUR);
        if candidate.square() == *self {
            Some(candidate)
        } else {
            None
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

    /// Decode a canonical 32-byte little-endian value.
    ///
    /// `None` if the value is `>= q`. Non-canonical input is never silently
    /// reduced.
    pub fn from_bytes(b: &[u8; 32]) -> Option<Fq> {
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(b.chunks_exact(8)) {
            let mut w = [0u8; 8];
            w.copy_from_slice(chunk);
            *limb = u64::from_le_bytes(w);
        }
        if is_ge_modulus(&limbs) {
            return None;
        }
        Some(Fq(mont_mul(&limbs, &FQ_R2)))
    }

    /// Decode a source-literal hex constant: `0x` followed by exactly 64
    /// lowercase hex digits, read **big-endian**.
    ///
    /// The one accepted spelling for a constant in source, defined by
    /// `field::Fr::from_hex` and repeated here for `Fq`. It is deliberately
    /// *not* the little-endian byte order of [`to_bytes`], which is the wire
    /// form; a hex literal in source is a number, not a byte string.
    ///
    /// `None` for a missing prefix, the wrong length, an uppercase or non-hex
    /// digit, or a value `>= q`.
    ///
    /// [`to_bytes`]: Fq::to_bytes
    pub fn from_hex(s: &str) -> Option<Fq> {
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
        Fq::from_bytes(&le)
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
/// Zero entries stay zero; they are skipped, not treated as an error. That is
/// what lets [`G1Projective::batch_to_affine`] hand the identity's `z = 0`
/// straight through.
///
/// [`G1Projective::batch_to_affine`]: crate::G1Projective::batch_to_affine
pub fn batch_inverse(xs: &mut [Fq]) {
    // prefix[i] = product of the nonzero entries strictly before i.
    let mut prefix: Vec<Fq> = Vec::with_capacity(xs.len());
    let mut running = Fq::ONE;
    for x in xs.iter() {
        prefix.push(running);
        if *x != Fq::ZERO {
            running *= x;
        }
    }

    // A product of nonzero field elements is nonzero, and the empty product is
    // ONE, so this inverse always exists.
    let mut inv = running
        .inverse()
        .expect("batch_inverse: product of nonzero entries is nonzero");

    for i in (0..xs.len()).rev() {
        if xs[i] == Fq::ZERO {
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
        impl $Op<Fq> for Fq {
            type Output = Fq;
            fn $op(self, rhs: Fq) -> Fq {
                Fq($limbs(&self.0, &rhs.0))
            }
        }
        impl $Op<&Fq> for Fq {
            type Output = Fq;
            fn $op(self, rhs: &Fq) -> Fq {
                Fq($limbs(&self.0, &rhs.0))
            }
        }
        impl $Op<Fq> for &Fq {
            type Output = Fq;
            fn $op(self, rhs: Fq) -> Fq {
                Fq($limbs(&self.0, &rhs.0))
            }
        }
        impl $Op<&Fq> for &Fq {
            type Output = Fq;
            fn $op(self, rhs: &Fq) -> Fq {
                Fq($limbs(&self.0, &rhs.0))
            }
        }
        impl $OpAssign<Fq> for Fq {
            fn $op_assign(&mut self, rhs: Fq) {
                self.0 = $limbs(&self.0, &rhs.0);
            }
        }
        impl $OpAssign<&Fq> for Fq {
            fn $op_assign(&mut self, rhs: &Fq) {
                self.0 = $limbs(&self.0, &rhs.0);
            }
        }
    };
}

impl_binop!(Add, add, AddAssign, add_assign, add_limbs);
impl_binop!(Sub, sub, SubAssign, sub_assign, sub_limbs);
impl_binop!(Mul, mul, MulAssign, mul_assign, mont_mul);

impl Neg for Fq {
    type Output = Fq;
    fn neg(self) -> Fq {
        Fq(neg_limbs(&self.0))
    }
}

impl Neg for &Fq {
    type Output = Fq;
    fn neg(self) -> Fq {
        Fq(neg_limbs(&self.0))
    }
}

/// Prints the canonical value in big-endian hex, never the Montgomery limbs.
impl fmt::Debug for Fq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.to_bytes();
        write!(f, "Fq(0x")?;
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

impl serde::Serialize for Fq {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_bytes().serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Fq {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Fq, D::Error> {
        let b = <[u8; 32] as serde::Deserialize>::deserialize(d)?;
        Fq::from_bytes(&b).ok_or_else(|| {
            <D::Error as serde::de::Error>::custom("non-canonical Fq encoding: value >= modulus")
        })
    }
}
