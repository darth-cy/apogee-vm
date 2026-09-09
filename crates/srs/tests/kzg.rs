//! `srs::kzg`: the committed arkworks differential, the round trip at every
//! acceptance degree, the degree bound, and the four tamper twins.
//!
//! The SRS is the first `2^17` powers of the real ceremony file, which is
//! gitignored; every test here returns quietly when it is absent.

mod common;

use std::fs;
use std::path::PathBuf;

use curve::{Fq, G1Affine};
use field::Fr;
use srs::kzg::{kzg_commit, kzg_open, kzg_verify};
use srs::{Srs, SrsError};
use test_support::{sha256, to_hex, Rng};

/// The committed corpus, pinned. Refresh deliberately:
/// `cargo run -p kat-gen -- srs`, then paste the digest it prints.
const KAT_SHA256: &str = "346361caa5f0ec12bc3215afff9dbcc53b9bb750314c3469c6955f53ca9ea6a8";

/// The power the fixtures were generated at: `2^16 + 1` coefficients need
/// more than `2^16` powers.
const POWER: u32 = 17;

fn vectors() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/kzg_kats.txt");
    let text = fs::read_to_string(path).expect("reading kzg_kats.txt");
    assert_eq!(
        to_hex(&sha256(text.as_bytes())),
        KAT_SHA256,
        "kzg_kats.txt does not match its pin; regenerate it deliberately"
    );
    text
}

fn ceremony() -> Option<Srs> {
    let path = common::ptau(24)?;
    Some(Srs::from_ptau(&path, POWER).expect("the fixture prefix ingests"))
}

fn coefficients(seed: u64, degree: usize) -> (Vec<Fr>, Fr) {
    let mut rng = Rng::new(seed);
    let coeffs: Vec<Fr> = (0..degree + 1).map(|_| common::next_fr(&mut rng)).collect();
    let z = common::next_fr(&mut rng);
    (coeffs, z)
}

// ---------------------------------------------------------------------------
// Acceptance 7 — the committed differential and the round trip
// ---------------------------------------------------------------------------

#[test]
fn committed_vectors_match() {
    let text = vectors();
    let Some(srs) = ceremony() else {
        common::skipped("the KZG differential", 24);
        return;
    };
    assert_eq!(
        to_hex(&srs.g1()[1].to_bytes()),
        text.lines()
            .find_map(|l| l.strip_prefix("# ceremony "))
            .expect("the corpus records its ceremony")
            .trim(),
        "this is a different power-24 ceremony than the fixtures were built \
         from; regenerate them with `cargo run -p kat-gen -- srs`"
    );

    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 7, "malformed line: {line}");
        assert_eq!(f[0], "kzg");
        let degree: usize = f[1].parse().unwrap();
        let (coeffs, z) = coefficients(f[2].parse().unwrap(), degree);
        assert_eq!(
            common::fr_from_hex(f[3]),
            z,
            "the z draw at degree {degree}"
        );

        let cm = kzg_commit(&srs, &coeffs).expect("degree fits");
        assert_eq!(
            cm,
            common::g1_from_hex(f[4]),
            "commitment at degree {degree}"
        );

        let (v, w) = kzg_open(&srs, &coeffs, z).expect("degree fits");
        assert_eq!(v, common::fr_from_hex(f[5]), "value at degree {degree}");
        assert_eq!(w, common::g1_from_hex(f[6]), "witness at degree {degree}");

        assert!(kzg_verify(&srs, &cm, z, v, &w), "degree {degree}");
        checked += 1;
    }
    assert_eq!(checked, 4, "every committed case ran");
}

/// Acceptance 11's negative control on this corpus.
#[test]
fn a_corrupted_vector_fails() {
    let text = vectors();
    let Some(srs) = ceremony() else {
        common::skipped("the KZG negative control", 24);
        return;
    };
    let line = text
        .lines()
        .find(|l| l.starts_with("kzg 100 "))
        .expect("the degree-100 case");
    let f: Vec<&str> = line.split_whitespace().collect();
    let (coeffs, _) = coefficients(f[2].parse().unwrap(), 100);

    let mut corrupted: Vec<u8> = f[4].bytes().collect();
    corrupted[0] ^= b'0' ^ b'1';
    let corrupted = String::from_utf8(corrupted).unwrap();
    assert_ne!(corrupted, f[4]);
    assert_ne!(
        to_hex(&kzg_commit(&srs, &coeffs).unwrap().to_bytes()),
        corrupted
    );
}

/// Commit, open and verify agree at every acceptance degree, plus the two
/// degenerate ones at the bottom.
#[test]
fn round_trip_at_every_degree() {
    let Some(srs) = ceremony() else {
        common::skipped("the KZG round trip", 24);
        return;
    };
    let mut rng = Rng::new(20260950);
    for degree in [0usize, 1, 2, 100, 1024, 65536] {
        let coeffs: Vec<Fr> = (0..degree + 1).map(|_| common::next_fr(&mut rng)).collect();
        let z = common::next_fr(&mut rng);

        let cm = kzg_commit(&srs, &coeffs).expect("degree fits");
        let (v, w) = kzg_open(&srs, &coeffs, z).expect("degree fits");
        assert_eq!(v, horner(&coeffs, z), "f(z) at degree {degree}");
        assert!(kzg_verify(&srs, &cm, z, v, &w), "degree {degree}");
    }
}

/// The zero polynomial: no coefficients, no commitment, no witness, and an
/// opening that still verifies. Every one of those is the identity, and
/// `pairing_check` skips pairs at infinity — so this is the one case where the
/// verifier equation is satisfied by an empty product.
#[test]
fn the_zero_polynomial_round_trips() {
    let Some(srs) = ceremony() else {
        common::skipped("the zero polynomial", 24);
        return;
    };
    let z = common::next_fr(&mut Rng::new(20260951));
    assert_eq!(kzg_commit(&srs, &[]).unwrap(), G1Affine::IDENTITY);
    assert_eq!(
        kzg_open(&srs, &[], z).unwrap(),
        (Fr::ZERO, G1Affine::IDENTITY)
    );
    assert!(kzg_verify(
        &srs,
        &G1Affine::IDENTITY,
        z,
        Fr::ZERO,
        &G1Affine::IDENTITY
    ));
}

/// Must-be-exact 7: a polynomial the SRS cannot hold is an error at commit
/// time, not a truncated commitment.
#[test]
fn degree_overflow_is_an_error() {
    let Some(srs) = ceremony() else {
        common::skipped("the degree bound", 24);
        return;
    };
    let powers = srs.g1().len();
    let z = Fr::ONE;

    // Exactly the SRS size is the last polynomial that fits.
    let fits = vec![Fr::ONE; powers];
    assert!(kzg_commit(&srs, &fits).is_ok());
    assert!(kzg_open(&srs, &fits, z).is_ok());

    let one_too_many = vec![Fr::ONE; powers + 1];
    let expected = SrsError::DegreeTooLarge {
        degree: powers,
        max: powers - 1,
    };
    assert_eq!(kzg_commit(&srs, &one_too_many), Err(expected.clone()));
    assert_eq!(kzg_open(&srs, &one_too_many, z), Err(expected));
    assert_eq!(srs.max_degree(), powers - 1);
}

// ---------------------------------------------------------------------------
// Acceptance 8 — the tamper twins
// ---------------------------------------------------------------------------

#[test]
fn tamper_twins_all_fail() {
    let Some(srs) = ceremony() else {
        common::skipped("the KZG tamper twins", 24);
        return;
    };
    let mut rng = Rng::new(20260952);
    let coeffs: Vec<Fr> = (0..257).map(|_| common::next_fr(&mut rng)).collect();
    let z = common::next_fr(&mut rng);

    let cm = kzg_commit(&srs, &coeffs).expect("degree fits");
    let (v, w) = kzg_open(&srs, &coeffs, z).expect("degree fits");
    assert!(
        kzg_verify(&srs, &cm, z, v, &w),
        "the honest opening verifies"
    );

    // (a) Open honestly for an f' that differs from f in one coefficient, then
    //     verify against commit(f). This is the tamper that matters: the proof
    //     is internally consistent and about the wrong polynomial.
    let mut other = coeffs.clone();
    other[17] += Fr::ONE;
    let (v2, w2) = kzg_open(&srs, &other, z).expect("degree fits");
    assert!(!kzg_verify(&srs, &cm, z, v2, &w2), "(a) witness tamper");
    // The same proof against its own commitment is fine, so (a) is not just a
    // broken proof.
    let cm2 = kzg_commit(&srs, &other).expect("degree fits");
    assert!(kzg_verify(&srs, &cm2, z, v2, &w2));

    // (b) The claimed value, off by one.
    assert!(!kzg_verify(&srs, &cm, z, v + Fr::ONE, &w), "(b) v + 1");

    // (c) A perturbed proof point: still on the curve, still in the subgroup,
    //     and not the witness.
    let perturbed = perturb(&w);
    assert_ne!(perturbed, w);
    assert!(perturbed.is_in_subgroup());
    assert!(!kzg_verify(&srs, &cm, z, v, &perturbed), "(c) proof tamper");

    // (d) The wrong point of evaluation.
    assert!(!kzg_verify(&srs, &cm, z + Fr::ONE, v, &w), "(d) z + 1");

    // And the two degenerate substitutions, which a naive rewrite can let
    // through: an infinite witness, and an infinite commitment.
    assert!(!kzg_verify(&srs, &cm, z, v, &G1Affine::IDENTITY));
    assert!(!kzg_verify(&srs, &G1Affine::IDENTITY, z, v, &w));
}

/// `-P`, which is a different subgroup point whenever `P` is not infinity —
/// no on-curve G1 point has `y = 0`, since the group order is odd.
fn perturb(p: &G1Affine) -> G1Affine {
    assert!(!p.infinity, "perturbing infinity says nothing");
    assert_ne!(p.y, Fq::ZERO);
    -*p
}

fn horner(coeffs: &[Fr], z: Fr) -> Fr {
    coeffs.iter().rev().fold(Fr::ZERO, |acc, c| acc * z + c)
}
