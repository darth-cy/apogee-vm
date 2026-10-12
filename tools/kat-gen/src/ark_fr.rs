//! The reference field the `field` and `poly` groups answer with: arkworks'
//! Montgomery field over `Fr`'s modulus, derived here from the decimal modulus
//! with `ark-ff`'s own `MontConfig`, so it shares no code and no constant with
//! `crates/field`.

// `MontConfig`'s expansion names arkworks' own `asm` feature, which this crate
// does not have.
#![allow(unexpected_cfgs)]

use ark_ff::fields::{Fp256, MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[generator = "5"]
pub struct ArkFrConfig;

/// `Fr`, as arkworks computes in it.
pub type ArkFr = Fp256<MontBackend<ArkFrConfig, 4>>;
