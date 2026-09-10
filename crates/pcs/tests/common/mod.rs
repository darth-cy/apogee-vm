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

// ---------------------------------------------------------------------------
// The verifier's arithmetic, written a second time
// ---------------------------------------------------------------------------
//
// Everything below rebuilds what `crates/pcs` derives, from the definitions in
// `docs/spec/mercury.md` and `docs/spec/accumulator.md` rather than from the
// crate. Two files read it: `accumulator.rs`, which replays the schedule to
// recover the challenges, and `edge_cases.rs`, which reads forced ones out of a
// fixture. Naive on purpose — schoolbook multiplication, Lagrange written out,
// `eq` from its product form — so that agreeing with the crate means something.

use constants::transcript_tags as tags;
use curve::G1Affine;
use pcs::{
    append_g1, append_g1_list, AccumulatorEntry, MercuryCommitment, MercuryProof, PairingSide,
};
use transcript::Transcript;

/// The six challenges of one Mercury opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenges {
    pub alpha: Fr,
    pub gamma: Fr,
    pub z: Fr,
    pub delta: Fr,
    pub z_prime: Fr,
    pub rho: Fr,
}

pub fn eval(c: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::ZERO;
    let mut power = Fr::ONE;
    for a in c {
        acc += *a * power;
        power *= x;
    }
    acc
}

pub fn mul(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::ZERO; a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            out[i + j] += *x * *y;
        }
    }
    out
}

pub fn vanishing(roots: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::ONE];
    for r in roots {
        out = mul(&out, &[-*r, Fr::ONE]);
    }
    out
}

/// Lagrange through `points`, evaluated at `x`.
pub fn interpolate_at(points: &[(Fr, Fr)], x: Fr) -> Fr {
    let mut acc = Fr::ZERO;
    for (i, (xi, yi)) in points.iter().enumerate() {
        let mut term = *yi;
        for (j, (xj, _)) in points.iter().enumerate() {
            if i != j {
                term *= (x - *xj) * (*xi - *xj).inverse().expect("distinct abscissae");
            }
        }
        acc += term;
    }
    acc
}

pub fn pow(x: Fr, e: usize) -> Fr {
    let mut acc = Fr::ONE;
    for _ in 0..e {
        acc *= x;
    }
    acc
}

/// The verifier's `O(t)` route to `P_u(x)`.
pub fn product_formula(u: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::ONE;
    let mut power = x;
    for uk in u {
        acc *= *uk * power + (Fr::ONE - *uk);
        power = power.square();
    }
    acc
}

/// `docs/spec/mercury.md` §7's two derived values: `h(alpha)` and `D(z)`.
pub fn derived(u: &[Fr], v: Fr, p: &MercuryProof, c: &Challenges) -> (Fr, Fr) {
    let t = u.len() / 2;
    let b = 1usize << t;
    let (u1, u2) = (&u[..t], &u[t..]);
    let z_inv = c.z.inverse().expect("z is nonzero");
    let two_inv = Fr::from_u64(2).inverse().expect("2 is invertible");

    let h_alpha = (p.g_z * product_formula(u1, z_inv)
        + p.g_inv_z * product_formula(u1, c.z)
        + c.gamma
            * (p.h_z * product_formula(u2, z_inv) + p.h_inv_z * product_formula(u2, c.z) - v - v)
        - c.z * p.s_z
        - z_inv * p.s_inv_z)
        * two_inv;
    (h_alpha, pow(c.z, b - 1) * p.g_inv_z)
}

/// The twelve accumulator entries of `docs/spec/accumulator.md` §2, rebuilt
/// from the specification for a given challenge set.
pub fn deferred_entries(
    g1_gen: &G1Affine,
    cm: &MercuryCommitment,
    u: &[Fr],
    v: Fr,
    p: &MercuryProof,
    c: &Challenges,
) -> Vec<AccumulatorEntry> {
    let t = u.len() / 2;
    let b = 1usize << t;
    let z_inv = c.z.inverse().expect("z is nonzero");
    let (h_alpha, d_z) = derived(u, v, p, c);

    // The BDFG20 batch of §6, in its frozen order g, h, S, D.
    let complements = [
        vanishing(&[c.alpha]),
        vec![Fr::ONE],
        vanishing(&[c.alpha]),
        vanishing(&[z_inv, c.alpha]),
    ];
    let r_at = [
        interpolate_at(&[(c.z, p.g_z), (z_inv, p.g_inv_z)], c.z_prime),
        interpolate_at(
            &[(c.z, p.h_z), (z_inv, p.h_inv_z), (c.alpha, h_alpha)],
            c.z_prime,
        ),
        interpolate_at(&[(c.z, p.s_z), (z_inv, p.s_inv_z)], c.z_prime),
        d_z,
    ];
    let mut coefficients = [Fr::ZERO; 4];
    let mut constant = Fr::ZERO;
    for i in 0..4 {
        coefficients[i] = pow(c.delta, i) * eval(&complements[i], c.z_prime);
        constant += coefficients[i] * r_at[i];
    }
    let z_t = eval(&vanishing(&[c.z, z_inv, c.alpha]), c.z_prime);
    let z_pow_b = pow(c.z, b);
    let rho = c.rho;

    let one = |scalar: Fr, point: G1Affine| AccumulatorEntry {
        side: PairingSide::G2One,
        scalar,
        point,
    };
    vec![
        one(Fr::ONE, cm.0),
        one(rho * coefficients[1], p.h),
        one(-(z_pow_b - c.alpha), p.q),
        one(rho * coefficients[0], p.g),
        one(rho * coefficients[2], p.s),
        one(rho * coefficients[3], p.d),
        one(c.z, p.pi_z),
        one(-(rho * z_t), p.w),
        one(rho * c.z_prime, p.w_prime),
        one(-(p.g_z + rho * constant), *g1_gen),
        AccumulatorEntry {
            side: PairingSide::G2X,
            scalar: Fr::ONE,
            point: p.pi_z,
        },
        AccumulatorEntry {
            side: PairingSide::G2X,
            scalar: rho,
            point: p.w_prime,
        },
    ]
}

/// `docs/spec/mercury.md` §5's schedule, transcribed a second time, run to
/// recover every challenge it draws.
///
/// `prefix` is whatever the transcript absorbed before the opening: nothing for
/// a single verification, §11's preamble for a batch.
pub fn replay_schedule(
    cm: &MercuryCommitment,
    u: &[Fr],
    v: Fr,
    p: &MercuryProof,
    prefix: &dyn Fn(&mut Transcript),
) -> Challenges {
    let mut tr = Transcript::new();
    prefix(&mut tr);
    tr.append_scalar(tags::MERCURY_INSTANCE, Fr::from_u64(1u64 << u.len()));
    append_g1(&mut tr, tags::COMMITMENT, &cm.0);
    let mut claim = u.to_vec();
    claim.push(v);
    tr.append_scalars(tags::EVALUATION_CLAIM, &claim);
    append_g1(&mut tr, tags::PCS_OPENING, &p.h);
    let alpha = tr.challenge_scalar(tags::MERCURY_ALPHA);
    append_g1_list(&mut tr, tags::PCS_OPENING, &[p.q, p.g]);
    let gamma = tr.challenge_scalar(tags::MERCURY_GAMMA);
    append_g1_list(&mut tr, tags::PCS_OPENING, &[p.s, p.d]);
    let z = loop {
        let z = tr.challenge_scalar(tags::MERCURY_Z);
        if z != Fr::ZERO {
            break z;
        }
    };
    tr.append_scalars(
        tags::PCS_OPENING,
        &[p.g_z, p.g_inv_z, p.h_z, p.h_inv_z, p.s_z, p.s_inv_z],
    );
    append_g1(&mut tr, tags::PCS_OPENING, &p.pi_z);
    let delta = tr.challenge_scalar(tags::BDFG_BATCH);
    append_g1(&mut tr, tags::PCS_OPENING, &p.w);
    let z_prime = tr.challenge_scalar(tags::BDFG_POINT);
    append_g1(&mut tr, tags::PCS_OPENING, &p.w_prime);
    let rho = tr.challenge_scalar(tags::PAIRING_MERGE);
    Challenges {
        alpha,
        gamma,
        z,
        delta,
        z_prime,
        rho,
    }
}

/// The `Fr` a 32-byte hex token names.
pub fn parse_fr(token: &str) -> Result<Fr, String> {
    let raw = test_support::hex_to_bytes(token).map_err(|e| e.to_string())?;
    let raw: [u8; 32] = raw.try_into().map_err(|_| "an Fr token is 32 bytes")?;
    Fr::from_bytes(&raw).ok_or_else(|| "an Fr token must be canonical".to_string())
}

/// The `G1Affine` a 64-byte hex token names, validated.
pub fn parse_g1(token: &str) -> Result<G1Affine, String> {
    let raw = test_support::hex_to_bytes(token).map_err(|e| e.to_string())?;
    let raw: [u8; 64] = raw.try_into().map_err(|_| "a G1 token is 64 bytes")?;
    G1Affine::from_bytes(&raw).ok_or_else(|| "a G1 token must be a valid point".to_string())
}

/// The `MercuryProof` a 704-byte hex token names, validated.
pub fn parse_proof(token: &str) -> Result<MercuryProof, String> {
    let raw = test_support::hex_to_bytes(token).map_err(|e| e.to_string())?;
    let raw: [u8; pcs::PROOF_BYTES] = raw.try_into().map_err(|_| "a proof token is 704 bytes")?;
    MercuryProof::from_bytes(&raw).ok_or_else(|| "a proof token must decode".to_string())
}
