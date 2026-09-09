//! Ceremony and KZG fixtures for `crates/srs`, generated against
//! arkworks-bn254 over the real powers-of-tau file.
//!
//! Two files, both written to `crates/srs/tests/vectors/`:
//!
//! * `ptau_kats.txt` — ceremony points at pinned indices, read out of the
//!   `.ptau` container by **this** module's own parser. That is the point of
//!   it: `crates/srs` decodes the same file its own way, and the two readers
//!   have to agree point for point.
//! * `kzg_kats.txt` — commitment, evaluation and witness for random
//!   polynomials over the first `2^CEREMONY_POWER` ceremony powers, all three
//!   computed with arkworks arithmetic.
//!
//! # The ceremony file
//!
//! `assets/ptau/ppot_0080_24.ptau`, which is gitignored — it is
//! 19 GB. When it is absent this group prints why and writes nothing, so a
//! regenerate-and-diff on a machine without the assets is still clean.
//!
//! Both files record `[x]_1` in a `# ceremony` header line. A different
//! power-24 ceremony has a different `tau`, so its points and its commitments
//! all differ; the header is what turns that into one clear message instead of
//! a wall of mismatches.
//!
//! # Encoding
//!
//! ```text
//!   point g1 <index> <128 hex>          x || y
//!   point g2 <index> <256 hex>          x.c0 || x.c1 || y.c0 || y.c1
//!   kzg <degree> <seed> <z> <cm> <v> <w>
//! ```
//!
//! Coefficients are `degree + 1` draws from `<seed>`, then `z` is the next
//! draw — the same draw-mask-reject rule `msm_kats.txt` uses, reimplemented in
//! `crates/srs/tests/kzg.rs`.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, BigInteger, PrimeField, Zero};
use test_support::Rng;

use crate::shared::{hex_fr, hex_g1, hex_g2};

const SEED: u64 = 20260940;

/// How many powers the KZG fixtures run over: `2^17`, so the acceptance's
/// degree-2^16 case has its `2^16 + 1` coefficients with room to spare. Only
/// this prefix is read, which is 8 MB of a 19 GB file.
const CEREMONY_POWER: u32 = 17;

/// Degrees from S07 acceptance 7.
const DEGREES: [usize; 4] = [1, 100, 1024, 65536];

/// Where the pinned points are taken from: the first few powers, one in the
/// middle, and both ends of the prefix.
const PINNED: [usize; 8] = [0, 1, 2, 3, 1000, 65535, 65536, (1 << CEREMONY_POWER) - 1];

pub fn generate() {
    let path = ceremony_path();
    if !path.exists() {
        println!("skipped srs vectors: {} is absent", path.display());
        return;
    }

    let ceremony = read_ptau(&path, 1usize << CEREMONY_POWER);
    let identity = hex_g1(&ceremony.g1[1]);

    // -- points ------------------------------------------------------------
    let mut out = String::new();
    writeln!(
        out,
        "# Ceremony points, read out of the .ptau container by kat-gen's own\n\
         # parser (tools/kat-gen/src/srs.rs), independently of crates/srs.\n\
         #\n\
         #   point g1 <index> <128 hex>   x || y\n\
         #   point g2 <index> <256 hex>   x.c0 || x.c1 || y.c0 || y.c1\n\
         #\n\
         # Every coordinate is canonical 32-byte little-endian, which is *not*\n\
         # how the container stores them: .ptau points are little-endian\n\
         # Montgomery.\n\
         #\n\
         # ceremony {identity}"
    )
    .expect("writing to a string");
    for index in PINNED {
        writeln!(out, "point g1 {index} {}", hex_g1(&ceremony.g1[index]))
            .expect("writing to a string");
    }
    for (index, p) in ceremony.g2.iter().enumerate() {
        writeln!(out, "point g2 {index} {}", hex_g2(p)).expect("writing to a string");
    }
    crate::write_vectors("crates/srs/tests/vectors/ptau_kats.txt", &out);

    // -- KZG ---------------------------------------------------------------
    let mut out = String::new();
    writeln!(
        out,
        "# KZG known-answer vectors over the first 2^{CEREMONY_POWER} ceremony\n\
         # powers, all computed with arkworks arithmetic.\n\
         #\n\
         #   kzg <degree> <seed> <z> <cm> <v> <w>\n\
         #\n\
         # Coefficients are <degree> + 1 draws from <seed>, then <z> is the\n\
         # next draw: a 32-byte little-endian draw with the top two bits\n\
         # cleared, rejecting values >= p. cm and w are G1 points in the\n\
         # 128-hex wire form; z and v are canonical Fr.\n\
         #\n\
         # ceremony {identity}"
    )
    .expect("writing to a string");

    let mut seen = Vec::new();
    for (i, degree) in DEGREES.iter().enumerate() {
        let seed = SEED + i as u64;
        let mut rng = Rng::new(seed);
        let coeffs: Vec<Fr> = (0..degree + 1).map(|_| next_fr(&mut rng)).collect();
        let z = next_fr(&mut rng);

        let cm = G1Projective::msm(&ceremony.g1[..coeffs.len()], &coeffs)
            .expect("one power per coefficient")
            .into_affine();

        // Synthetic division, arkworks side: q(X) = (f(X) - f(z)) / (X - z).
        let mut quotient = vec![Fr::zero(); coeffs.len() - 1];
        let mut acc = coeffs[coeffs.len() - 1];
        for j in (0..coeffs.len() - 1).rev() {
            quotient[j] = acc;
            acc = coeffs[j] + acc * z;
        }
        let value = acc;
        let witness = G1Projective::msm(&ceremony.g1[..quotient.len()], &quotient)
            .expect("one power per coefficient")
            .into_affine();

        // The quotient is only right if it reproduces f, so check that here
        // rather than trusting the recurrence.
        assert_eq!(value, horner(&coeffs, z), "synthetic division remainder");

        writeln!(
            out,
            "kzg {degree} {seed} {} {} {} {}",
            hex_fr(&z),
            hex_g1(&cm),
            hex_fr(&value),
            hex_g1(&witness)
        )
        .expect("writing to a string");
        seen.push(hex_g1(&cm));
    }
    crate::assert_distinct(&seen, "KZG commitments");
    crate::write_vectors("crates/srs/tests/vectors/kzg_kats.txt", &out);
}

fn ceremony_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/ptau/ppot_0080_24.ptau")
}

/// `f(z)` by Horner, as a second opinion on the synthetic division.
fn horner(coeffs: &[Fr], z: Fr) -> Fr {
    coeffs.iter().rev().fold(Fr::zero(), |acc, c| acc * z + c)
}

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

// ---------------------------------------------------------------------------
// An independent .ptau reader
//
// Deliberately not `crates/srs`': this is the oracle that says our parser
// reads the container correctly, so it has to read it separately. It is also
// deliberately unforgiving — a generator that limps past a malformed file
// writes a fixture nobody can trust.
// ---------------------------------------------------------------------------

struct Ceremony {
    g1: Vec<G1Affine>,
    g2: [G2Affine; 2],
}

fn read_ptau(path: &PathBuf, count: usize) -> Ceremony {
    let file = File::open(path).expect("opening the ceremony file");
    let mut input = BufReader::with_capacity(1 << 20, file);

    let mut prologue = [0u8; 12];
    input
        .read_exact(&mut prologue)
        .expect("reading the prologue");
    assert_eq!(&prologue[..4], b"ptau", "not a .ptau container");
    assert_eq!(u32::from_le_bytes(prologue[4..8].try_into().unwrap()), 1);
    let sections = u32::from_le_bytes(prologue[8..12].try_into().unwrap());

    let mut table = Vec::new();
    let mut pos = 12u64;
    for _ in 0..sections {
        input.seek(SeekFrom::Start(pos)).expect("seeking");
        let mut head = [0u8; 12];
        input
            .read_exact(&mut head)
            .expect("reading a section header");
        pos += 12;
        let size = u64::from_le_bytes(head[4..12].try_into().unwrap());
        table.push((u32::from_le_bytes(head[..4].try_into().unwrap()), pos, size));
        pos += size;
    }
    let at = |id: u32| -> u64 {
        table
            .iter()
            .find(|(s, _, _)| *s == id)
            .unwrap_or_else(|| panic!("no section {id}"))
            .1
    };

    input.seek(SeekFrom::Start(at(1))).expect("seeking");
    let mut header = [0u8; 44];
    input.read_exact(&mut header).expect("reading the header");
    assert_eq!(u32::from_le_bytes(header[..4].try_into().unwrap()), 32);
    let power = u32::from_le_bytes(header[36..40].try_into().unwrap());
    assert!(
        1usize << power >= count,
        "the ceremony file holds 2^{power} powers, fewer than the {count} wanted"
    );

    input.seek(SeekFrom::Start(at(2))).expect("seeking");
    let mut raw = vec![0u8; count * 64];
    input.read_exact(&mut raw).expect("reading tauG1");
    let g1: Vec<G1Affine> = raw.chunks_exact(64).map(g1_from_lem).collect();
    assert_eq!(g1[0], G1Affine::generator(), "tauG1[0] is the generator");

    input.seek(SeekFrom::Start(at(3))).expect("seeking");
    let mut raw = [0u8; 256];
    input.read_exact(&mut raw).expect("reading tauG2");
    let g2 = [g2_from_lem(&raw[..128]), g2_from_lem(&raw[128..])];
    assert_eq!(g2[0], G2Affine::generator(), "tauG2[0] is the generator");

    Ceremony { g1, g2 }
}

/// One `.ptau` coordinate. The container stores `coord * R mod q` in 32
/// little-endian bytes, which is exactly arkworks' own internal layout, so
/// `new_unchecked` reads it with no conversion at all — a decode by a
/// different route than `crates/srs`', which multiplies by `R^-1`.
fn fq_from_lem(bytes: &[u8]) -> Fq {
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    Fq::new_unchecked(BigInt::new(limbs))
}

fn g1_from_lem(bytes: &[u8]) -> G1Affine {
    let (x, y) = (fq_from_lem(&bytes[..32]), fq_from_lem(&bytes[32..]));
    if x.is_zero() && y.is_zero() {
        return G1Affine::zero();
    }
    let p = G1Affine::new_unchecked(x, y);
    assert!(p.is_on_curve(), "a ceremony G1 point is off the curve");
    assert!(
        p.is_in_correct_subgroup_assuming_on_curve(),
        "a ceremony G1 point is out of the subgroup"
    );
    p
}

fn g2_from_lem(bytes: &[u8]) -> G2Affine {
    let c = |i: usize| fq_from_lem(&bytes[32 * i..32 * i + 32]);
    let (x, y) = (Fq2::new(c(0), c(1)), Fq2::new(c(2), c(3)));
    if x.is_zero() && y.is_zero() {
        return G2Affine::zero();
    }
    let p = G2Affine::new_unchecked(x, y);
    assert!(p.is_on_curve(), "a ceremony G2 point is off the curve");
    assert!(
        p.is_in_correct_subgroup_assuming_on_curve(),
        "a ceremony G2 point is out of the subgroup"
    );
    p
}
