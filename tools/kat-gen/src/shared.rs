//! The hex codec and the exponents the three curve-family generators share.
//!
//! One token per value, in the wire form `crates/curve` emits: 64 hex
//! characters of canonical little-endian `Fq`, concatenated in coefficient
//! order all the way up the tower. A value that does not exist is the token
//! `none`, so every line kind has a fixed arity.
//!
//! ```text
//!   Fq     64      Fq6    384   c0 || c1 || c2
//!   Fq2   128      Fq12   768   c0 || c1
//!   G1    128      G2     256
//! ```

use ark_bn254::{Fq, Fq12, Fq2, Fq6, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use test_support::to_hex;

pub fn hex_fq(x: &Fq) -> String {
    let bytes = x.into_bigint().to_bytes_le();
    assert_eq!(bytes.len(), 32, "Fq must serialize to 32 bytes");
    to_hex(&bytes)
}

pub fn hex_fq2(x: &Fq2) -> String {
    format!("{}{}", hex_fq(&x.c0), hex_fq(&x.c1))
}

pub fn hex_fq6(x: &Fq6) -> String {
    format!("{}{}{}", hex_fq2(&x.c0), hex_fq2(&x.c1), hex_fq2(&x.c2))
}

pub fn hex_fq12(x: &Fq12) -> String {
    format!("{}{}", hex_fq6(&x.c0), hex_fq6(&x.c1))
}

pub fn hex_fr(x: &Fr) -> String {
    let bytes = x.into_bigint().to_bytes_le();
    assert_eq!(bytes.len(), 32, "Fr must serialize to 32 bytes");
    to_hex(&bytes)
}

pub fn hex_g1(p: &G1Affine) -> String {
    if p.is_zero() {
        return to_hex(&[0u8; 64]);
    }
    format!("{}{}", hex_fq(&p.x), hex_fq(&p.y))
}

pub fn hex_g2(p: &G2Affine) -> String {
    if p.is_zero() {
        return to_hex(&[0u8; 128]);
    }
    format!("{}{}", hex_fq2(&p.x), hex_fq2(&p.y))
}

pub fn hex_exp(e: &[u64; 4]) -> String {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        bytes[8 * i..8 * i + 8].copy_from_slice(&e[i].to_le_bytes());
    }
    to_hex(&bytes)
}

pub fn opt_fq(x: Option<Fq>) -> String {
    x.map(|v| hex_fq(&v)).unwrap_or_else(|| "none".to_string())
}

pub fn opt_fq2(x: Option<Fq2>) -> String {
    x.map(|v| hex_fq2(&v)).unwrap_or_else(|| "none".to_string())
}

pub fn opt_fq6(x: Option<Fq6>) -> String {
    x.map(|v| hex_fq6(&v)).unwrap_or_else(|| "none".to_string())
}

pub fn opt_fq12(x: Option<Fq12>) -> String {
    x.map(|v| hex_fq12(&v))
        .unwrap_or_else(|| "none".to_string())
}

/// The exponents every `pow` fixture runs on top of its random ones: the empty
/// ladder, the identity, one squaring, a limb boundary, and an all-ones
/// 256-bit ladder.
pub const FIXED_EXPONENTS: [[u64; 4]; 5] = [
    [0, 0, 0, 0],
    [1, 0, 0, 0],
    [2, 0, 0, 0],
    [0, 1, 0, 0],
    [u64::MAX; 4],
];

/// `(q^12 - 1)/r`, the exact final exponent, as little-endian 64-bit limbs.
///
/// 2,790 bits. This is the *definition* of the final exponentiation, computed
/// as an integer here so that no fixture depends on how any library chooses to
/// evaluate it — arkworks' own routine returns a fixed power of it. The
/// division is exact, which is asserted rather than assumed.
pub fn full_final_exponent() -> Vec<u64> {
    let q: BigUint = Fq::MODULUS.into();
    let r: BigUint = Fr::MODULUS.into();
    let numerator = q.pow(12) - BigUint::from(1u32);
    let exponent = &numerator / &r;
    assert_eq!(&exponent * &r, numerator, "r divides q^12 - 1");
    exponent.to_u64_digits()
}
