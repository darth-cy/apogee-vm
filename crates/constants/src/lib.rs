#![no_std]
//! Frozen constants and tags for the whole workspace. Zero logic, forever.
//!
//! This crate holds constant items and doc comments and nothing else: no
//! functions, no traits, no macros, no tests. Guest-side code links it, so it
//! is `#![no_std]` and stays that way.
//!
//! Changing any value here is a protocol-version change.

/// Protocol version absorbed into every transcript before anything else.
///
/// Placeholder: bumped whenever a frozen protocol invariant changes.
pub const PROTOCOL_VERSION: u32 = 0;

/// BN254 scalar field modulus `p`, little-endian 64-bit limbs.
///
/// `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`
/// `  = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`
///
/// This is Fr, the *scalar* field. The base field Fq is a different modulus.
pub const FR_MODULUS: [u64; 4] = [
    0x43e1_f593_f000_0001,
    0x2833_e848_79b9_7091,
    0xb850_45b6_8181_585d,
    0x3064_4e72_e131_a029,
];

/// `p - 2`, little-endian 64-bit limbs: the Fermat exponent for inversion.
pub const FR_MODULUS_MINUS_TWO: [u64; 4] = [
    0x43e1_f593_efff_ffff,
    0x2833_e848_79b9_7091,
    0xb850_45b6_8181_585d,
    0x3064_4e72_e131_a029,
];

/// Montgomery radix `R = 2^256 mod p`, little-endian 64-bit limbs.
///
/// `R` is also the Montgomery representation of `1`.
pub const FR_R: [u64; 4] = [
    0xac96_341c_4fff_fffb,
    0x36fc_7695_9f60_cd29,
    0x666e_a36f_7879_462e,
    0x0e0a_77c1_9a07_df2f,
];

/// `R^2 mod p`, little-endian 64-bit limbs: converts a canonical value into
/// Montgomery form via one Montgomery multiplication.
pub const FR_R2: [u64; 4] = [
    0x1bb8_e645_ae21_6da7,
    0x53fe_3ab1_e35c_59e3,
    0x8c49_833d_53bb_8085,
    0x0216_d0b1_7f4e_44a5,
];

/// `-p^{-1} mod 2^64`, the per-limb Montgomery reduction multiplier.
pub const FR_INV: u64 = 0xc2e1_f593_efff_ffff;

/// Domain-separation tags for the Poseidon2 duplex transcript.
///
/// Empty until the transcript stage defines the tag alphabet. Every future tag
/// lives here, never at its use site.
pub mod transcript_tags {}
