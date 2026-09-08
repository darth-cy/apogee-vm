//! Test support specific to this crate: the vector-file reader, the corpus
//! rebuild rule of `evaluate_diff.txt`, bit packing, and the arkworks bridge.
//! The RNG, hex and SHA-256 are shared and live in `tools/test-support`.
//! Test-only; never compiled into the library.
#![allow(dead_code)]

use field::Fr;
use poly::{MultilinearPoly, PolyBacking};
use test_support::{hex_to_32, sha256, to_hex, Rng};

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

pub fn assert_sha256(path: &str, text: &str, expected: &str) {
    let got = to_hex(&sha256(text.as_bytes()));
    assert_eq!(
        got, expected,
        "{path} changed. Regenerate it with `cargo run -p kat-gen`, review the \
         diff, then update the pinned digest deliberately."
    );
}

/// Parse a committed field element, refusing anything the wire form rejects.
pub fn field_element(s: &str) -> Result<Fr, String> {
    let bytes = hex_to_32(s)?;
    Fr::from_bytes(&bytes).ok_or_else(|| format!("vector value {s} is not canonical"))
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

/// Four `u64` draws read as one 256-bit little-endian integer mod p.
///
/// This is the generator's `Fr::from_le_bytes_mod_order(&rng.next_le32())`,
/// rebuilt through `Fr::from_u64` because `crates/field` deliberately has no
/// reducing constructor — `from_bytes` rejects rather than reduces. The two
/// are checked against each other in `differential.rs`, so the corpus rebuild
/// rule is verified rather than assumed.
pub fn next_fr(rng: &mut Rng) -> Fr {
    let two64 = Fr::from_u64(1 << 63) + Fr::from_u64(1 << 63);
    let mut acc = Fr::ZERO;
    for limb in rng.next_exp().iter().rev() {
        acc = acc * two64 + Fr::from_u64(*limb);
    }
    acc
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
        "fr" => PolyBacking::Fr((0..entries).map(|_| next_fr(rng)).collect()),
        other => panic!("unknown backing {other}"),
    }
}

/// SHA-256 over the lifted table, 32 canonical little-endian bytes per entry.
/// The generator computes the same digest from arkworks values, so this pins
/// both the draw rule and the lift.
pub fn table_digest(p: &MultilinearPoly) -> String {
    let mut bytes = Vec::with_capacity(32 * p.len());
    for i in 0..p.len() {
        bytes.extend_from_slice(&p.get(i).to_bytes());
    }
    to_hex(&sha256(&bytes))
}

/// The cube vertex `y` as a point, for feeding `eq_eval`.
pub fn vertex(y: usize, num_vars: usize) -> Vec<Fr> {
    (0..num_vars)
        .map(|j| if (y >> j) & 1 == 1 { Fr::ONE } else { Fr::ZERO })
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

pub fn to_ark(x: &Fr) -> ark_bn254::Fr {
    ark_ff::PrimeField::from_le_bytes_mod_order(&x.to_bytes())
}

/// The same table as an `ark-poly` polynomial, so the two can be compared at
/// any point. Reads through `get`, which is where our lift lives.
pub fn to_ark_mle(p: &MultilinearPoly) -> ark_poly::DenseMultilinearExtension<ark_bn254::Fr> {
    ark_poly::DenseMultilinearExtension::from_evaluations_vec(
        p.num_vars(),
        (0..p.len()).map(|i| to_ark(&p.get(i))).collect(),
    )
}
