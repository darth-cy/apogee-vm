//! `Srs::save` / `Srs::load`: the round trip, the pinned byte layout, and what
//! a tampered archive does.
//!
//! There is no digest — S07's SRS hashing was dropped, and this crate's module
//! docs say what that costs. What `load` still refuses is anything that is not
//! a well-formed archive of valid points.

mod common;

use std::fs;

use curve::{G1Affine, G1Projective, G2Affine};
use field::Fr;
use srs::kzg::{kzg_commit, kzg_verify};
use srs::{Srs, SrsError};

/// `docs/spec/srs.md` §5. Duplicated here on purpose: a test that reads the
/// constant out of the crate cannot notice the constant changing.
const MAGIC: &[u8; 8] = b"APOGESRS";
const HEADER: usize = 8 + 4 + 4 + 8 + 128 + 128;

/// Powers worth round-tripping: one below the reader's 65,536-point chunk,
/// and one that is exactly two chunks, so the chunk boundary is crossed.
const POWERS: [u32; 3] = [0, 12, 17];

fn ceremony(power: u32) -> Option<Srs> {
    let path = common::ptau(24)?;
    Some(Srs::from_ptau(&path, power).expect("a ceremony prefix ingests"))
}

// ---------------------------------------------------------------------------
// Acceptance 6 — the round trip
// ---------------------------------------------------------------------------

#[test]
fn save_load_round_trips() {
    for power in POWERS {
        let Some(srs) = ceremony(power) else {
            common::skipped("the archive round trip", 24);
            return;
        };
        let path = common::scratch(&format!("round-trip-{power}.srs"));
        srs.save(&path).expect("saving");

        let back = Srs::load(&path).expect("loading");
        assert_eq!(back, srs, "power {power}");
        assert_eq!(back.g1().len(), 1 << power);
        assert_eq!(back.verifier(), srs.verifier());
    }
}

/// Bit-exact, not merely equal: saving what was loaded reproduces the file.
#[test]
fn the_archive_is_byte_stable() {
    let Some(srs) = ceremony(12) else {
        common::skipped("archive byte stability", 24);
        return;
    };
    let first = common::scratch("stable-1.srs");
    let second = common::scratch("stable-2.srs");

    srs.save(&first).expect("saving");
    Srs::load(&first)
        .expect("loading")
        .save(&second)
        .expect("saving again");

    assert_eq!(
        fs::read(&first).unwrap(),
        fs::read(&second).unwrap(),
        "save . load . save is save"
    );
    // And the size is exactly what the format says it is.
    assert_eq!(
        fs::metadata(&first).unwrap().len() as usize,
        HEADER + 4096 * 64
    );
}

/// The header is a frozen layout, so read it as bytes rather than trusting
/// that `load` and `save` agree with each other.
#[test]
fn the_header_layout_is_pinned() {
    let Some(srs) = ceremony(12) else {
        common::skipped("the header layout", 24);
        return;
    };
    let path = common::scratch("layout.srs");
    srs.save(&path).expect("saving");
    let bytes = fs::read(&path).unwrap();

    assert_eq!(&bytes[..8], MAGIC);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 12);
    assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), 4096);
    assert_eq!(&bytes[24..152], &srs.g2_gen().to_bytes());
    assert_eq!(&bytes[152..280], &srs.g2_tau().to_bytes());
    assert_eq!(&bytes[280..344], &G1Affine::GENERATOR.to_bytes());
    assert_eq!(&bytes[344..408], &srs.g1()[1].to_bytes());
}

// ---------------------------------------------------------------------------
// Acceptance 6 — a tampered archive
// ---------------------------------------------------------------------------

/// Build the power-12 archive, hand the bytes to `edit`, and try to load it.
///
/// Both scratch paths are derived from `name`: the suite runs its tests in
/// parallel, and two of them call this.
fn tampered(name: &str, edit: impl FnOnce(&mut Vec<u8>)) -> Option<Result<Srs, SrsError>> {
    let srs = ceremony(12)?;
    let good = common::scratch(&format!("{name}.source"));
    srs.save(&good).expect("saving");

    let mut bytes = fs::read(&good).unwrap();
    edit(&mut bytes);
    let path = common::scratch(name);
    fs::write(&path, &bytes).expect("writing");
    Some(Srs::load(&path))
}

#[test]
fn a_tampered_archive_is_rejected() {
    let Some(_) = ceremony(0) else {
        common::skipped("the archive tamper controls", 24);
        return;
    };

    // A flipped bit in a coordinate leaves the point off the curve.
    assert_eq!(
        tampered("bad-point.srs", |b| b[HEADER + 5 * 64] ^= 1).unwrap(),
        Err(SrsError::InvalidPoint { index: 5 })
    );

    // A non-canonical coordinate is the other half of the same rejection.
    assert_eq!(
        tampered("noncanonical.srs", |b| {
            b[HEADER + 7 * 64..HEADER + 7 * 64 + 32].fill(0xff)
        })
        .unwrap(),
        Err(SrsError::InvalidPoint { index: 7 })
    );

    // A tampered G2 point, which the header carries rather than the block.
    assert_eq!(
        tampered("bad-g2.srs", |b| b[24] ^= 1).unwrap(),
        Err(SrsError::InvalidPoint { index: 4096 })
    );

    assert_eq!(
        tampered("bad-magic.srs", |b| b[0] = b'X').unwrap(),
        Err(SrsError::BadMagic)
    );
    assert_eq!(
        tampered("bad-version.srs", |b| b[8] = 9).unwrap(),
        Err(SrsError::BadVersion(9))
    );

    // The count has to be `2^power`, so a claimed count that is not is
    // refused before a single point is read.
    assert_eq!(
        tampered("bad-count.srs", |b| b[16] = 5).unwrap(),
        Err(SrsError::BadSection("archive G1 count is not 2^power"))
    );

    // A short file, and a long one: the length is a function of the count.
    assert_eq!(
        tampered("short.srs", |b| {
            b.truncate(b.len() - 1);
        })
        .unwrap(),
        Err(SrsError::Truncated)
    );
    assert_eq!(
        tampered("long.srs", |b| b.push(0)).unwrap(),
        Err(SrsError::Truncated)
    );
    assert_eq!(
        tampered("headless.srs", |b| {
            b.truncate(HEADER - 1);
        })
        .unwrap(),
        Err(SrsError::Truncated)
    );

    // And an implausible power, which would otherwise shift past 64.
    assert_eq!(
        tampered("bad-power.srs", |b| b[12] = 200).unwrap(),
        Err(SrsError::BadSection("archive G1 count is not 2^power"))
    );
}

/// A loaded archive still has to pass the structural check, and a swapped
/// point still fails it — `load` validating each point is not the same as
/// `validate` relating them.
#[test]
fn a_loaded_archive_still_validates() {
    let Some(srs) = ceremony(12) else {
        common::skipped("archive validation", 24);
        return;
    };
    let path = common::scratch("validated.srs");
    srs.save(&path).expect("saving");
    Srs::load(&path)
        .expect("loading")
        .validate()
        .expect("a faithful archive validates");

    let swapped = tampered("swapped.srs", |b| {
        let source = b[HEADER + 6 * 64..HEADER + 7 * 64].to_vec();
        b[HEADER + 5 * 64..HEADER + 6 * 64].copy_from_slice(&source);
    })
    .unwrap()
    .expect("a real point in the wrong place still decodes");
    assert_eq!(swapped.validate(), Err(SrsError::TauMismatch));
}

/// A degenerate SRS — `tau = 0`, so the powers and `[x]_2` are the point at
/// infinity — has to be rejected, and rejected *here*, because the pairing
/// check cannot do it.
///
/// `curve::pairing::pairing_check` contributes the identity for a pair at
/// infinity rather than failing on it. With `g2_tau` at infinity the first
/// pair vanishes and with the tail of `g1` at infinity the second does too, so
/// the check passes on an empty product. `kzg_verify` over such an SRS then
/// accepts any commitment opened to any value at any point, since every
/// pairing it forms is skipped as well — which this test also demonstrates,
/// so the rejection is shown to be load-bearing rather than tidy.
#[test]
fn a_degenerate_srs_is_rejected() {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&2u64.to_le_bytes());
    bytes.extend_from_slice(&G2Affine::GENERATOR.to_bytes());
    bytes.extend_from_slice(&[0u8; 128]); // g2_tau = infinity
    bytes.extend_from_slice(&G1Affine::GENERATOR.to_bytes());
    bytes.extend_from_slice(&[0u8; 64]); // g1[1] = infinity

    let path = common::scratch("degenerate.srs");
    fs::write(&path, &bytes).expect("writing");

    // It decodes: infinity is a valid point, and S05 says so.
    let srs = Srs::load(&path).expect("infinity points decode");
    assert!(srs.g2_tau().infinity);
    assert_eq!(srs.validate(), Err(SrsError::TauMismatch));

    // And this is what accepting it would have cost. f(X) = 7 + 11X commits to
    // 7*G alone, because [x^1] is infinity; the true f(3) is 40.
    let coeffs = [Fr::from_u64(7), Fr::from_u64(11)];
    let cm = kzg_commit(&srs, &coeffs).expect("degree fits");
    let z = Fr::from_u64(3);
    let lie = Fr::from_u64(99_999);
    let w = G1Projective::GENERATOR
        .mul(&((lie - Fr::from_u64(7)) * z.inverse().expect("3 is invertible")))
        .to_affine();
    assert!(
        kzg_verify(&srs, &cm, z, lie, &w),
        "the forgery this SRS enables"
    );
}

/// A missing archive is an error, not a panic.
#[test]
fn a_missing_archive_is_an_error() {
    let path = common::scratch("absent.srs");
    let _ = fs::remove_file(&path);
    assert!(matches!(Srs::load(&path), Err(SrsError::Io(_))));
}
