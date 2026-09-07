//! Test support specific to this crate: a seeded RNG and the arkworks bridge.
//! Hex and SHA-256 are shared with the other test suites and live in
//! `tools/test-support`. Test-only; never compiled into the library.
#![allow(dead_code)]

use field::Fr;

// ---------------------------------------------------------------------------
// Deterministic RNG
// ---------------------------------------------------------------------------

/// splitmix64. Owned so tests stay reproducible independent of any RNG crate.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A 256-bit little-endian integer, unreduced. Used as a `pow` exponent.
    pub fn next_exp(&mut self) -> [u64; 4] {
        [
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
        ]
    }

    /// Canonical bytes of a uniformly sampled element, by rejection.
    pub fn next_canonical(&mut self) -> [u8; 32] {
        loop {
            let mut b = [0u8; 32];
            for i in 0..4 {
                b[8 * i..8 * i + 8].copy_from_slice(&self.next_u64().to_le_bytes());
            }
            b[31] &= 0x3f; // p < 2^254, so clearing two bits keeps rejection rare
            if Fr::from_bytes(&b).is_some() {
                return b;
            }
        }
    }

    pub fn next_fr(&mut self) -> Fr {
        Fr::from_bytes(&self.next_canonical()).expect("rejection sampling returns canonical bytes")
    }
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
