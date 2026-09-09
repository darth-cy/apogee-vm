//! Locating the ceremony files, and scratch copies of them.
//!
//! `assets/ptau/` is gitignored: the power-24 file is 19 GB and the smaller
//! ones are ceremony output, not fixtures this repository owns. Every test
//! that needs one asks for it and returns quietly when it is absent, so a
//! clone without the assets still runs a green suite.

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

/// The ceremony file for `power`, if it has been downloaded.
pub fn ptau(power: u32) -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../assets/ptau")
        .join(format!("powersOfTau28_hez_final_{power:02}.ptau"));
    path.exists().then_some(path)
}

/// Say so, on stdout, so `cargo test -- --nocapture` shows what did not run.
pub fn skipped(what: &str, power: u32) {
    println!("skipped {what}: assets/ptau/powersOfTau28_hez_final_{power:02}.ptau is absent");
}

/// A scratch file path unique to this process and `name`.
pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("apogee-srs-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("creating a scratch directory");
    dir.join(name)
}

/// Copy `power`'s ceremony file, hand the bytes to `edit`, and write the
/// result to a scratch path. This is how every ingestion negative control
/// makes its broken twin: from the real file, one edit at a time.
pub fn damaged(power: u32, name: &str, edit: impl FnOnce(&mut Vec<u8>)) -> Option<PathBuf> {
    let mut bytes = fs::read(ptau(power)?).expect("reading the ceremony file");
    edit(&mut bytes);
    let path = scratch(name);
    fs::write(&path, &bytes).expect("writing a scratch file");
    Some(path)
}

/// Offset of the first byte of section `id`'s payload, by walking the table.
pub fn section_at(bytes: &[u8], id: u32) -> u64 {
    let sections = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let mut pos = 12usize;
    for _ in 0..sections {
        let this = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
        let size = u64::from_le_bytes(bytes[pos + 4..pos + 12].try_into().unwrap());
        pos += 12;
        if this == id {
            return pos as u64;
        }
        pos += size as usize;
    }
    panic!("no section {id}");
}

// ---------------------------------------------------------------------------
// The fixture codec and the sampler the vector files encode
// ---------------------------------------------------------------------------

use curve::{G1Affine, G2Affine};
use field::Fr;
use test_support::{hex_to_bytes, Rng};

/// One canonical `Fr`: 32 little-endian bytes, top two bits cleared, values at
/// or above `p` rejected rather than reduced. The mirror of this rule lives in
/// `tools/kat-gen/src/srs.rs`, written against arkworks.
pub fn next_fr(rng: &mut Rng) -> Fr {
    loop {
        let mut b = rng.next_le32();
        b[31] &= 0x3f;
        if let Some(x) = Fr::from_bytes(&b) {
            return x;
        }
    }
}

pub fn fr_from_hex(s: &str) -> Fr {
    let b = hex_to_bytes(s).expect("a fixture Fr is hex");
    Fr::from_bytes(&b.try_into().expect("32 bytes")).expect("a fixture Fr is canonical")
}

pub fn g1_from_hex(s: &str) -> G1Affine {
    let b = hex_to_bytes(s).expect("a fixture G1 point is hex");
    G1Affine::from_bytes(&b.try_into().expect("64 bytes")).expect("a fixture G1 point is valid")
}

pub fn g2_from_hex(s: &str) -> G2Affine {
    let b = hex_to_bytes(s).expect("a fixture G2 point is hex");
    G2Affine::from_bytes(&b.try_into().expect("128 bytes")).expect("a fixture G2 point is valid")
}
