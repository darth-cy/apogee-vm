//! The reference fields the `poly` group answers with: arkworks' Montgomery
//! field over the A64-C5 prime `p = 2^64 − 59`, derived here from the decimal
//! modulus with `ark-ff`'s own `MontConfig`, and its quadratic extension
//! `F_p[x]/(x^2 − 2)` from `ark-ff`'s own `Fp2Config`, so they share no code
//! and no constant with `crates/field-a64-c5`.

// `MontConfig`'s expansion names arkworks' own `asm` feature, which this crate
// does not have.
#![allow(unexpected_cfgs)]

use ark_ff::{Fp2Config, Fp64, MontBackend, MontConfig, MontFp};

/// 2 is a primitive root mod `p`, hence a non-square.
#[derive(MontConfig)]
#[modulus = "18446744073709551557"]
#[generator = "2"]
pub struct A64C5Config;

/// `Fp`, as arkworks computes in it.
pub type ArkFp = Fp64<MontBackend<A64C5Config, 1>>;

pub struct Fp2Cfg;

impl Fp2Config for Fp2Cfg {
    type Fp = ArkFp;
    const NONRESIDUE: ArkFp = MontFp!("2");
    /// `x^p = x · 2^((p − 1)/2) = −x`, 2 being a non-square.
    const FROBENIUS_COEFF_FP2_C1: &[ArkFp] = &[MontFp!("1"), MontFp!("-1")];
}

/// `Fp2`, as arkworks computes in it: `c0 + c1·x` with `x^2 = 2`.
pub type ArkFp2 = ark_ff::Fp2<Fp2Cfg>;
