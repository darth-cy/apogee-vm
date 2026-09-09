//! Shared test scaffolding: the toy SRS, the ceremony files, and the seeded
//! sampler the fixtures encode.
//!
//! # Why there is a toy SRS
//!
//! `crates/srs` ingests a 19 GB gitignored ceremony file, so every test there
//! returns quietly on a machine without `assets/`. That is acceptable for a
//! crate whose subject *is* the ceremony file; it would not be acceptable here,
//! where it would leave the whole of Mercury untested in CI.
//!
//! So the small and medium instances run over an SRS this module builds from a
//! **known** `tau`: `[tau^i]_1` for `i < 2^power`, with `[1]_2` and `[tau]_2`.
//! It is a real, structurally valid SRS — `Srs::validate` accepts it — and it
//! is completely insecure, because `tau` is written down four lines below. It
//! exists to exercise the protocol, never to stand in for a ceremony.
//!
//! It is built by writing the archive of `docs/spec/srs.md` §5 and loading it
//! through `Srs::load`, which is the only way to get an `Srs` from points and
//! keeps every point going through `crates/curve`'s validating decoder. No
//! constructor was added to `crates/srs` for the sake of a test.

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

use curve::{G1Projective, G2Affine};
use field::Fr;
use poly::{MultilinearPoly, PolyBacking};
use rayon::prelude::*;
use srs::Srs;
use test_support::Rng;

/// The toy SRS secret. Written down on purpose; see the module docs.
pub const TOY_TAU: &str = "0x0000000000000000000000000000000000000000000000000000000000abcdef";

/// `docs/spec/srs.md` §5, transcribed. Duplicated from `crates/srs` on purpose:
/// a test that reads the layout out of the crate cannot notice it changing.
const ARCHIVE_MAGIC: &[u8; 8] = b"APOGESRS";
const ARCHIVE_VERSION: u32 = 1;

/// An SRS of `2^power` powers of [`TOY_TAU`].
pub fn toy_srs(power: u32) -> Srs {
    let tau = Fr::from_hex(TOY_TAU).expect("the toy tau is a canonical literal");
    let count = 1usize << power;

    let mut scalars = Vec::with_capacity(count);
    let mut acc = Fr::ONE;
    for _ in 0..count {
        scalars.push(acc);
        acc *= tau;
    }
    let projective: Vec<G1Projective> = scalars
        .par_iter()
        .map(|s| G1Projective::GENERATOR.mul(s))
        .collect();
    let g1 = G1Projective::batch_to_affine(&projective);
    let g2_tau = G2Affine::GENERATOR.mul(&tau);

    let mut bytes = Vec::with_capacity(280 + count * 64);
    bytes.extend_from_slice(ARCHIVE_MAGIC);
    bytes.extend_from_slice(&ARCHIVE_VERSION.to_le_bytes());
    bytes.extend_from_slice(&power.to_le_bytes());
    bytes.extend_from_slice(&(count as u64).to_le_bytes());
    bytes.extend_from_slice(&G2Affine::GENERATOR.to_bytes());
    bytes.extend_from_slice(&g2_tau.to_bytes());
    for p in &g1 {
        bytes.extend_from_slice(&p.to_bytes());
    }

    // The file name carries the thread as well as the process: `cargo test`
    // runs test functions in parallel and two of them asking for the same
    // power would otherwise race on one path.
    let thread = format!("{:?}", std::thread::current().id());
    let thread: String = thread
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let path = scratch(&format!("toy-{power}-{thread}.srs"));
    fs::write(&path, &bytes).expect("writing the toy archive");
    let srs = Srs::load(&path).expect("the toy archive loads");
    fs::remove_file(&path).ok();
    srs
}

/// A scratch file path unique to this process and `name`.
pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("apogee-pcs-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("creating a scratch directory");
    dir.join(name)
}

/// The PSE ceremony file for `power`, if it has been downloaded. The menu
/// sizes above 2^18 are only reachable on a machine that has it.
pub fn ptau(power: u32) -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../assets/ptau")
        .join(format!("ppot_0080_{power:02}.ptau"));
    path.exists().then_some(path)
}

/// Say so, on stdout, so `cargo test -- --nocapture` shows what did not run.
pub fn skipped(what: &str, power: u32) {
    println!("skipped {what}: assets/ptau/ppot_0080_{power:02}.ptau is absent");
}

// ---------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------

/// One canonical `Fr`: 32 little-endian bytes with the top two bits cleared,
/// values at or above `p` rejected rather than reduced. The same rule
/// `crates/srs`'s and `crates/curve`'s suites use.
pub fn next_fr(rng: &mut Rng) -> Fr {
    loop {
        let mut b = rng.next_le32();
        b[31] &= 0x3f;
        if let Some(x) = Fr::from_bytes(&b) {
            return x;
        }
    }
}

/// A random `Fr`-backed multilinear on `num_vars` variables.
pub fn random_poly(rng: &mut Rng, num_vars: usize) -> MultilinearPoly {
    let values: Vec<Fr> = (0..1usize << num_vars).map(|_| next_fr(rng)).collect();
    MultilinearPoly::new(PolyBacking::Fr(values))
}

/// A random opening point of `num_vars` coordinates.
pub fn random_point(rng: &mut Rng, num_vars: usize) -> Vec<Fr> {
    (0..num_vars).map(|_| next_fr(rng)).collect()
}

// ---------------------------------------------------------------------------
// The fixture codec
// ---------------------------------------------------------------------------

/// Non-comment, non-blank lines, split on whitespace.
pub fn records(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().map(str::to_string).collect())
        .collect()
}
