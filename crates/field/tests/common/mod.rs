//! Test support specific to this crate: sampling an `Fr`, and the arkworks
//! bridge. The RNG behind the sampler, hex, and SHA-256 are shared with the
//! other test suites and live in `tools/test-support`. Test-only; never
//! compiled into the library.
#![allow(dead_code)]

use field::Fr;
use test_support::Rng;

// ---------------------------------------------------------------------------
// Sampling an Fr
//
// Rejection, not reduction: a test that compares against arkworks has to feed
// both sides the same value, and `from_bytes` refuses anything `>= p`.
// ---------------------------------------------------------------------------

/// Canonical bytes of a uniformly sampled element, by rejection.
pub fn next_canonical(rng: &mut Rng) -> [u8; 32] {
    loop {
        let mut b = rng.next_le32();
        b[31] &= 0x3f; // p < 2^254, so clearing two bits keeps rejection rare
        if Fr::from_bytes(&b).is_some() {
            return b;
        }
    }
}

pub fn next_fr(rng: &mut Rng) -> Fr {
    Fr::from_bytes(&next_canonical(rng)).expect("rejection sampling returns canonical bytes")
}

// ---------------------------------------------------------------------------
// arkworks bridge
// ---------------------------------------------------------------------------

pub fn to_ark(x: &Fr) -> ark_bn254::Fr {
    ark_ff::PrimeField::from_le_bytes_mod_order(&x.to_bytes())
}

pub fn ark_to_bytes(x: &ark_bn254::Fr) -> [u8; 32] {
    let v = ark_ff::BigInteger::to_bytes_le(&ark_ff::PrimeField::into_bigint(*x));
    let mut b = [0u8; 32];
    assert_eq!(v.len(), 32, "ark Fr must serialize to 32 bytes");
    b.copy_from_slice(&v);
    b
}
