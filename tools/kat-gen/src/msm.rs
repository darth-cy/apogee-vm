//! MSM fixtures for `crates/curve`, generated against arkworks-bn254.
//!
//! One file, `crates/curve/tests/vectors/msm_kats.txt`. Every expected value
//! is `ark_ec::VariableBaseMSM::msm`'s; nothing here is `curve::msm`'s own
//! answer read back.
//!
//! # Encoding
//!
//! ```text
//!   msm <pattern> <n> <seed> <expected>
//! ```
//!
//! `expected` is a G1 point in the wire form `crates/curve` emits: 128 hex
//! characters of `x || y`, each coordinate canonical little-endian, all-zero
//! for the point at infinity.
//!
//! Inputs are **not** written out. A 2^16-point case would be 12 MB of hex,
//! which is a worse fixture than a seed and a rule: `<seed>` names a
//! `test_support::Rng` stream and `<pattern>` names how the case reads it.
//! Both sides expand the same seed independently — arkworks here, `curve` in
//! `crates/curve/tests/msm.rs` — so a drift in either expansion changes the
//! expected value and fails, and CI's regenerate-and-diff sees it.
//!
//! The patterns exist to cover S07 must-be-exact 1, which asks for empty
//! input, zero scalars, interspersed points at infinity, a single element and
//! all-identical scalars:
//!
//! | pattern | bases | scalars |
//! | --- | --- | --- |
//! | `random` | `k_i * G`, fresh `k_i` | fresh each |
//! | `zeros` | `k_i * G` | every one zero |
//! | `identical` | `k_i * G` | one draw, repeated |
//! | `infinity` | every third base is the identity | fresh each |
//!
//! The stream is read in the same order for every pattern — all `n` bases,
//! then all `n` scalars — so two patterns at one size share their bases.

use std::fmt::Write as _;

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField, Zero};
use test_support::Rng;

use crate::shared::hex_g1;

const SEED: u64 = 20260918;

/// `(pattern, n)`, in the order the file lists them. The sizes are S07
/// acceptance 1's — 1, 2, 100, 2^10, 2^16 — plus the degenerate empty case,
/// and the other patterns run at two sizes each: one below the window
/// heuristic's 32-point threshold and one above it.
const CASES: [(&str, usize); 13] = [
    ("random", 0),
    ("random", 1),
    ("random", 2),
    ("random", 100),
    ("random", 1024),
    ("random", 65536),
    ("zeros", 7),
    ("zeros", 1024),
    ("identical", 7),
    ("identical", 1024),
    ("infinity", 7),
    ("infinity", 1024),
    ("infinity", 1),
];

pub fn generate() {
    let mut out = String::new();
    out.push_str(
        "# MSM known-answer vectors, from ark-bn254's VariableBaseMSM.\n\
         #\n\
         # msm <pattern> <n> <seed> <expected>\n\
         #\n\
         # <expected> is 128 hex characters: x || y, each coordinate canonical\n\
         # 32-byte little-endian, all-zero for infinity.\n\
         #\n\
         # Inputs are the deterministic expansion of <seed> through\n\
         # test_support::Rng, documented in tools/kat-gen/src/msm.rs and\n\
         # reimplemented independently in crates/curve/tests/msm.rs: n bases\n\
         # first, then n scalars, each a 32-byte little-endian draw with the\n\
         # top two bits cleared and values >= p rejected.\n\
         #\n\
         # patterns: random | zeros | identical | infinity\n",
    );

    let mut expected = Vec::new();
    for (index, (pattern, n)) in CASES.iter().enumerate() {
        // A per-case seed, so one case's size does not shift the next case's
        // stream and a reader can regenerate any single line.
        let seed = SEED + index as u64;
        let (bases, scalars) = case(pattern, *n, seed);
        let answer = G1Projective::msm(&bases, &scalars).expect("equal lengths");
        let token = hex_g1(&answer.into_affine());
        writeln!(out, "msm {pattern} {n} {seed} {token}").expect("writing to a string");
        expected.push(token);
    }

    // Two cases that agree by accident would hide a collapsed generator.
    // `zeros` at both sizes is the identity twice over, and legitimately so.
    let distinct: Vec<String> = expected
        .iter()
        .enumerate()
        .filter(|(i, _)| CASES[*i].0 != "zeros" && CASES[*i].1 != 0)
        .map(|(_, t)| t.clone())
        .collect();
    crate::assert_distinct(&distinct, "msm answers");

    crate::write_vectors("crates/curve/tests/vectors/msm_kats.txt", &out);
}

/// Expand one case. The mirror of this lives in `crates/curve/tests/msm.rs`.
fn case(pattern: &str, n: usize, seed: u64) -> (Vec<G1Affine>, Vec<Fr>) {
    let mut rng = Rng::new(seed);

    let bases: Vec<G1Affine> = (0..n)
        .map(|i| {
            let k = next_fr(&mut rng);
            if pattern == "infinity" && i % 3 == 0 {
                G1Affine::zero()
            } else {
                (G1Projective::generator() * k).into_affine()
            }
        })
        .collect();

    let scalars: Vec<Fr> = match pattern {
        "zeros" => {
            // The stream is still read, so every pattern at one size sees the
            // same bases and the same scalar draws.
            (0..n)
                .map(|_| next_fr(&mut rng))
                .map(|_| Fr::zero())
                .collect()
        }
        "identical" => {
            let all: Vec<Fr> = (0..n).map(|_| next_fr(&mut rng)).collect();
            let one = all.first().copied().unwrap_or_else(Fr::zero);
            vec![one; n]
        }
        _ => (0..n).map(|_| next_fr(&mut rng)).collect(),
    };

    (bases, scalars)
}

/// One canonical `Fr`: 32 little-endian bytes with the top two bits cleared,
/// rejecting anything still at or above `p`.
///
/// Clearing two bits puts the draw below `2^254`, and `p` is just under that,
/// so rejection is rare but not impossible — and it is a rejection, never a
/// reduction, because both sides have to agree on the bytes as well as the
/// value.
fn next_fr(rng: &mut Rng) -> Fr {
    loop {
        let mut b = rng.next_le32();
        b[31] &= 0x3f;
        let x = Fr::from_le_bytes_mod_order(&b);
        if x.into_bigint().to_bytes_le() == b {
            return x;
        }
    }
}
