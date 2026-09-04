//! The frozen constants are re-derived here rather than trusted. A wrong
//! Montgomery constant is silent: every operation stays self-consistent while
//! the field is the wrong one.

mod common;

use std::str::FromStr;

use common::{ark_to_bytes, to_hex};
use constants::{FR_INV, FR_MODULUS, FR_MODULUS_MINUS_TWO, FR_R, FR_R2, PROTOCOL_VERSION};
use field::Fr;

/// The master prompt's frozen Fr modulus, in decimal.
const FR_MODULUS_DECIMAL: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

fn limbs_to_bytes(limbs: &[u64; 4]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        b[8 * i..8 * i + 8].copy_from_slice(&limbs[i].to_le_bytes());
    }
    b
}

#[test]
fn modulus_is_the_bn254_scalar_field() {
    assert_eq!(
        FR_MODULUS,
        <ark_bn254::Fr as ark_ff::PrimeField>::MODULUS.0,
        "FR_MODULUS must be Fr, not Fq"
    );

    // The decimal in the master prompt is pinned from both sides: p - 1 is the
    // largest element, and p itself is not an element at all.
    let p_minus_one_decimal =
        "21888242871839275222246405745257275088548364400416034343698204186575808495616";
    let p_minus_one = ark_bn254::Fr::from_str(p_minus_one_decimal).expect("p-1 is an element");
    assert_eq!(p_minus_one, -ark_bn254::Fr::from(1u64));
    assert_eq!(Fr::MINUS_ONE.to_bytes(), ark_to_bytes(&p_minus_one));
    assert_eq!(
        ark_bn254::Fr::from_str(FR_MODULUS_DECIMAL).map(|x| x == ark_bn254::Fr::from(0u64)),
        Ok(true),
        "the decimal modulus must reduce to zero"
    );

    // ...and the hex form of the limbs is the master prompt's hex form.
    assert_eq!(
        to_hex(&limbs_to_bytes(&FR_MODULUS)),
        "010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",
        "FR_MODULUS limbs, little-endian bytes"
    );
}

#[test]
fn modulus_minus_two_is_p_minus_two() {
    let mut want = FR_MODULUS;
    // p ends in ...0001, so subtracting 2 only touches the low limb.
    want[0] = want[0].wrapping_sub(2);
    assert!(FR_MODULUS[0] >= 2, "no borrow out of the low limb");
    assert_eq!(FR_MODULUS_MINUS_TWO, want);
}

#[test]
fn montgomery_radix_constants_are_right() {
    // R = 2^256 mod p and R^2 = 2^512 mod p, as canonical little-endian limbs.
    let two = ark_bn254::Fr::from(2u64);
    let r = ark_ff::Field::pow(&two, [256u64, 0, 0, 0]);
    let r2 = ark_ff::Field::pow(&two, [512u64, 0, 0, 0]);
    assert_eq!(limbs_to_bytes(&FR_R), ark_to_bytes(&r), "FR_R");
    assert_eq!(limbs_to_bytes(&FR_R2), ark_to_bytes(&r2), "FR_R2");
    assert_eq!(r * r, r2, "R^2 is the square of R");

    // R is simultaneously the Montgomery representation of ONE.
    assert_eq!(Fr::ONE.to_bytes()[0], 1);
}

#[test]
fn montgomery_inverse_constant_is_right() {
    // FR_INV = -p^{-1} mod 2^64, so p * FR_INV == -1 mod 2^64.
    assert_eq!(FR_MODULUS[0].wrapping_mul(FR_INV), u64::MAX);
    // ...which is equivalent to (p * FR_INV) + 1 == 0 mod 2^64.
    assert_eq!(FR_MODULUS[0].wrapping_mul(FR_INV).wrapping_add(1), 0);
    assert_eq!(FR_MODULUS[0] & 1, 1, "Montgomery needs an odd modulus");
}

#[test]
fn protocol_version_is_the_placeholder() {
    assert_eq!(PROTOCOL_VERSION, 0);
}
