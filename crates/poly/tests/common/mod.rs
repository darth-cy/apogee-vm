//! Test support specific to this crate: the vector-file reader, the corpus
//! rebuild rule of `evaluate_diff.txt`, bit packing, and the arkworks bridge.
//! The RNG, hex and SHA-256 are shared and live in `tools/test-support`.
//! Test-only; never compiled into the library.
#![allow(dead_code)]
// `MontConfig`'s expansion names arkworks' own `asm` feature, which this crate
// does not have.
#![allow(unexpected_cfgs)]

use field::{Fp, Fp2};
use poly::{MultilinearPoly, PolyBacking};
use test_support::{hex_to_bytes, sha256, to_hex, Rng};

// ---------------------------------------------------------------------------
// Vector files
// ---------------------------------------------------------------------------

/// One non-comment, non-blank line, split on whitespace.
pub struct Line {
    pub no: usize,
    pub fields: Vec<String>,
}

pub fn read_vectors(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("committed vector file {path} must be readable: {e}"))
}

pub fn data_lines(text: &str) -> Vec<Line> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|(i, l)| Line {
            no: i + 1,
            fields: l.split_whitespace().map(|s| s.to_string()).collect(),
        })
        .collect()
}

/// Parse a committed `Fp2` element, the 16 bytes `Fp2::to_bytes` writes,
/// refusing anything the wire form rejects.
pub fn field_element(s: &str) -> Result<Fp2, String> {
    let bytes: [u8; 16] = hex_to_bytes(s)?
        .try_into()
        .map_err(|b: Vec<u8>| format!("vector value {s} is {} bytes, not 16", b.len()))?;
    Fp2::from_bytes(&bytes).ok_or_else(|| format!("vector value {s} is not canonical"))
}

/// `expect` a token that is meant to be a decimal index, loudly.
pub fn index(line: &Line, field: usize) -> Result<usize, String> {
    line.fields
        .get(field)
        .ok_or_else(|| format!("line {}: missing field {field}", line.no))?
        .parse::<usize>()
        .map_err(|_| format!("line {}: field {field} is not an index", line.no))
}

// ---------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------

/// One `u64` draw, reduced mod p.
///
/// This is the generator's arkworks `from_le_bytes_mod_order` on the draw's
/// eight little-endian bytes, rebuilt through `Fp::from_u64`, which reduces.
/// The two are checked against each other in `differential.rs`, so the corpus
/// rebuild rule is verified rather than assumed.
pub fn next_fp(rng: &mut Rng) -> Fp {
    Fp::from_u64(rng.next_u64())
}

/// Two base draws as one `Fp2` element, `c0` first: the generator's draw of a
/// challenge or a point coordinate.
pub fn next_fp2(rng: &mut Rng) -> Fp2 {
    let c0 = next_fp(rng);
    let c1 = next_fp(rng);
    Fp2 { c0, c1 }
}

/// The `U1` bitset for `bits`, with the tail of the final limb zeroed.
pub fn pack_bits(bits: &[bool]) -> PolyBacking {
    let mut limbs = vec![0u64; bits.len().div_ceil(64)];
    for (i, b) in bits.iter().enumerate() {
        if *b {
            limbs[i / 64] |= 1u64 << (i % 64);
        }
    }
    PolyBacking::U1(limbs, bits.len())
}

/// One table of `entries` values in `backing`'s native width, by the draw rule
/// documented in the header of `evaluate_diff.txt`.
pub fn corpus_backing(rng: &mut Rng, backing: &str, entries: usize) -> PolyBacking {
    match backing {
        "u1" => {
            let bits: Vec<bool> = (0..entries).map(|_| rng.next_u64() & 1 == 1).collect();
            pack_bits(&bits)
        }
        "u8" => PolyBacking::U8((0..entries).map(|_| rng.next_u64() as u8).collect()),
        "u16" => PolyBacking::U16((0..entries).map(|_| rng.next_u64() as u16).collect()),
        "u32" => PolyBacking::U32((0..entries).map(|_| rng.next_u64() as u32).collect()),
        "fp" => PolyBacking::Fp((0..entries).map(|_| next_fp(rng)).collect()),
        other => panic!("unknown backing {other}"),
    }
}

/// SHA-256 over the table lifted into `Fp2`, 16 bytes per entry as
/// `Fp2::to_bytes` writes them. The generator computes the same digest from
/// arkworks values, so this pins both the draw rule and the lift.
pub fn table_digest(p: &MultilinearPoly) -> String {
    let mut bytes = Vec::with_capacity(16 * p.len());
    for i in 0..p.len() {
        bytes.extend_from_slice(&p.get(i).to_bytes());
    }
    to_hex(&sha256(&bytes))
}

/// The cube vertex `y` as a point, for feeding `eq_eval`.
pub fn vertex(y: usize, num_vars: usize) -> Vec<Fp2> {
    (0..num_vars)
        .map(|j| {
            if (y >> j) & 1 == 1 {
                Fp2::ONE
            } else {
                Fp2::ZERO
            }
        })
        .collect()
}

/// Flip the last hex digit of the first line starting with `prefix`. The
/// negative controls use it to tamper with one committed value at a time.
pub fn corrupt(text: &str, prefix: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut done = false;
    for line in text.lines() {
        if !done && line.starts_with(prefix) {
            let mut chars: Vec<char> = line.chars().collect();
            let last = chars.len() - 1;
            chars[last] = if chars[last] == '0' { '1' } else { '0' };
            out.push(chars.into_iter().collect());
            done = true;
        } else {
            out.push(line.to_string());
        }
    }
    assert!(done, "no line starts with `{prefix}`");
    out.join("\n")
}

// ---------------------------------------------------------------------------
// arkworks bridge
// ---------------------------------------------------------------------------

use ark_ff::{BigInt, Fp2Config, Fp64, MontBackend, MontConfig, MontFp, PrimeField};

/// arkworks' Montgomery field over the A64-C5 prime, derived from the decimal
/// modulus with `ark-ff`'s own `MontConfig`. 2 is a primitive root mod p,
/// hence a non-square.
#[derive(MontConfig)]
#[modulus = "18446744073709551557"]
#[generator = "2"]
pub struct A64C5Config;

pub type ArkFp = Fp64<MontBackend<A64C5Config, 1>>;

/// arkworks' `F_p[x]/(x^2 − 2)`, from `ark-ff`'s own `Fp2Config`.
pub struct Fp2Cfg;

impl Fp2Config for Fp2Cfg {
    type Fp = ArkFp;
    const NONRESIDUE: ArkFp = MontFp!("2");
    /// `x^p = x · 2^((p − 1)/2) = −x`, 2 being a non-square.
    const FROBENIUS_COEFF_FP2_C1: &[ArkFp] = &[MontFp!("1"), MontFp!("-1")];
}

/// The reference field `ark-poly`'s polynomials are taken over.
pub type ArkFp2 = ark_ff::Fp2<Fp2Cfg>;

/// Strict: an `Fp` that is not canonical is a bug to catch, not a value for
/// arkworks to reduce out of sight.
pub fn to_ark_fp(x: &Fp) -> ArkFp {
    ArkFp::from_bigint(BigInt([x.to_u64()])).expect("an Fp holds its canonical representative")
}

pub fn to_ark(x: &Fp2) -> ArkFp2 {
    ArkFp2::new(to_ark_fp(&x.c0), to_ark_fp(&x.c1))
}

/// The same table as an `ark-poly` polynomial, so the two can be compared at
/// any point. Reads through `get`, which is where our lift lives.
pub fn to_ark_mle(p: &MultilinearPoly) -> ark_poly::DenseMultilinearExtension<ArkFp2> {
    ark_poly::DenseMultilinearExtension::from_evaluations_vec(
        p.num_vars(),
        (0..p.len()).map(|i| to_ark(&p.get(i))).collect(),
    )
}
