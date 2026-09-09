//! `.ptau` ingestion: the real ceremony file, the point-for-point differential
//! against kat-gen's independent reader, and every rejection class S07
//! must-be-exact 3 names.
//!
//! Every test here needs `assets/ptau/`, which is gitignored, and returns
//! quietly when the file it wants is absent. What that costs is stated in the
//! S07 handoff note: CI runs none of this.

mod common;

use std::fs;
use std::path::PathBuf;

use curve::{G1Affine, G2Affine};
use srs::{Srs, SrsError};
use test_support::{hex_to_bytes, sha256, to_hex};

/// The committed corpus, pinned. Refresh deliberately:
/// `cargo run -p kat-gen -- srs`, then paste the digest it prints.
const KAT_SHA256: &str = "a5b27c13b27c19047f05dc4fe0e9f2be0169a43849f7ad0da82d9f86a96d8d6f";

/// The power the point fixtures were generated at.
const FIXTURE_POWER: u32 = 17;

fn vectors() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/ptau_kats.txt");
    let text = fs::read_to_string(path).expect("reading ptau_kats.txt");
    assert_eq!(
        to_hex(&sha256(text.as_bytes())),
        KAT_SHA256,
        "ptau_kats.txt does not match its pin; regenerate it deliberately"
    );
    text
}

// ---------------------------------------------------------------------------
// Acceptance 4 — the real ceremony file at power 24
// ---------------------------------------------------------------------------

/// The required capability: 2^24 G1 powers, the generators where they belong,
/// both G2 points subgroup-valid, and the structural check passing.
///
/// This reads 1 GiB of a 19 GB file and then runs two 2^24-point MSMs and a
/// pairing, so it is the slowest test in the workspace by a wide margin. It is
/// also the one that says the stage's headline capability works.
#[test]
fn the_ceremony_file_ingests_at_power_24() {
    let Some(path) = common::ptau(24) else {
        common::skipped("power-24 ingestion", 24);
        return;
    };

    let srs = Srs::from_ptau(&path, 24).expect("the ceremony file ingests at power 24");
    assert_eq!(srs.g1().len(), 1 << 24);
    assert_eq!(srs.max_degree(), (1 << 24) - 1);
    assert_eq!(srs.g1()[0], G1Affine::GENERATOR);
    assert_eq!(srs.g2_gen(), G2Affine::GENERATOR);

    // `from_bytes` already refused anything outside the subgroup on the way
    // in; asserting it here is what makes that a claim of this test rather
    // than an implementation detail.
    assert!(srs.g2_gen().is_in_subgroup());
    assert!(srs.g2_tau().is_in_subgroup());
    assert_ne!(srs.g2_tau(), G2Affine::GENERATOR, "tau is not 1");

    srs.validate().expect("the real ceremony validates");

    let v = srs.verifier();
    assert_eq!(v.g1_gen, srs.g1()[0]);
    assert_eq!(v.g2_gen, srs.g2_gen());
    assert_eq!(v.g2_tau, srs.g2_tau());
}

/// The same file at the smaller powers a prefix is taken at, which is how
/// every other test and the bench use it. A prefix of a ceremony is a ceremony.
#[test]
fn prefixes_of_the_ceremony_validate() {
    let Some(path) = common::ptau(24) else {
        common::skipped("ceremony prefixes", 24);
        return;
    };
    for power in [0u32, 1, 2, 8, 12] {
        let srs = Srs::from_ptau(&path, power).expect("a prefix ingests");
        assert_eq!(srs.g1().len(), 1 << power);
        assert_eq!(srs.g1()[0], G1Affine::GENERATOR);
        srs.validate().expect("a prefix validates");
    }
}

// ---------------------------------------------------------------------------
// The point-for-point differential
// ---------------------------------------------------------------------------

/// Our decoder against kat-gen's, which reads the same container by a
/// different route: arkworks reads the stored limbs as its own Montgomery
/// representation directly, while `crates/srs` multiplies by `R^-1` through
/// the field. Agreement on real ceremony points is what says the little-endian
/// Montgomery reading is right.
#[test]
fn decoded_points_match_the_independent_reader() {
    let text = vectors();
    let Some(path) = common::ptau(24) else {
        common::skipped("the point differential", 24);
        return;
    };

    let srs = Srs::from_ptau(&path, FIXTURE_POWER).expect("the fixture prefix ingests");
    assert_eq!(
        to_hex(&srs.g1()[1].to_bytes()),
        ceremony_identity(&text),
        "this is a different power-24 ceremony than the fixtures were built \
         from; regenerate them with `cargo run -p kat-gen -- srs`"
    );

    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 4, "malformed line: {line}");
        assert_eq!(f[0], "point");
        let index: usize = f[2].parse().unwrap();
        let got = match f[1] {
            "g1" => to_hex(&srs.g1()[index].to_bytes()),
            "g2" => to_hex(&[srs.g2_gen(), srs.g2_tau()][index].to_bytes()),
            other => panic!("unknown group {other}"),
        };
        assert_eq!(got, f[3], "{} point {index}", f[1]);
        checked += 1;
    }
    assert_eq!(checked, 10, "every pinned point ran");
}

/// Acceptance 11's negative control on this corpus: one corrupted expected
/// point has to fail.
#[test]
fn a_corrupted_point_vector_fails() {
    let text = vectors();
    let Some(path) = common::ptau(24) else {
        common::skipped("the point negative control", 24);
        return;
    };
    let srs = Srs::from_ptau(&path, 2).expect("two powers ingest");

    let line = text
        .lines()
        .find(|l| l.starts_with("point g1 1 "))
        .expect("the [x]_1 line");
    let expected = line.split_whitespace().nth(3).unwrap();
    let mut corrupted: Vec<u8> = expected.bytes().collect();
    corrupted[0] ^= b'0' ^ b'1';
    assert_ne!(
        to_hex(&srs.g1()[1].to_bytes()),
        String::from_utf8(corrupted).unwrap()
    );
}

fn ceremony_identity(text: &str) -> &str {
    text.lines()
        .find_map(|l| l.strip_prefix("# ceremony "))
        .expect("the corpus records which ceremony it came from")
        .trim()
}

// ---------------------------------------------------------------------------
// Acceptance 5 — the rejection classes
//
// Each control is the real power-12 ceremony file with exactly one edit, so
// what is being tested is the edit and never the scaffolding.
// ---------------------------------------------------------------------------

const CONTROL_POWER: u32 = 12;

/// Byte offset of the `.ptau` header's `power` field, and of section 2's
/// first point, worked out from the file itself rather than assumed.
fn header_at(bytes: &[u8]) -> usize {
    common::section_at(bytes, 1) as usize
}

fn tau_g1_at(bytes: &[u8]) -> usize {
    common::section_at(bytes, 2) as usize
}

#[test]
fn a_truncated_file_is_rejected() {
    let Some(path) = common::damaged(CONTROL_POWER, "truncated.ptau", |b| {
        b.truncate(b.len() - 100);
    }) else {
        common::skipped("the truncation control", CONTROL_POWER);
        return;
    };
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER),
        Err(SrsError::Truncated)
    );

    // And a file too short to hold even a prologue.
    let path = common::damaged(CONTROL_POWER, "stub.ptau", |b| b.truncate(6)).unwrap();
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER),
        Err(SrsError::Truncated)
    );
}

#[test]
fn wrong_magic_is_rejected() {
    let Some(path) = common::damaged(CONTROL_POWER, "magic.ptau", |b| b[0] = b'q') else {
        common::skipped("the magic control", CONTROL_POWER);
        return;
    };
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER),
        Err(SrsError::BadMagic)
    );
}

#[test]
fn an_unknown_version_is_rejected() {
    let Some(path) = common::damaged(CONTROL_POWER, "version.ptau", |b| b[4] = 2) else {
        common::skipped("the version control", CONTROL_POWER);
        return;
    };
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER),
        Err(SrsError::BadVersion(2))
    );
}

#[test]
fn a_missing_section_is_rejected() {
    // Rename section 2, so tauG1 is gone but the table still walks.
    let Some(path) = common::damaged(CONTROL_POWER, "missing.ptau", |b| {
        let id = common::section_at(b, 2) as usize - 12;
        b[id] = 99;
    }) else {
        common::skipped("the missing-section control", CONTROL_POWER);
        return;
    };
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER),
        Err(SrsError::BadSection("tauG1"))
    );
}

#[test]
fn a_duplicated_section_is_rejected() {
    // Relabel tauG2 as a second tauG1.
    let Some(path) = common::damaged(CONTROL_POWER, "duplicate.ptau", |b| {
        let id = common::section_at(b, 3) as usize - 12;
        b[id] = 2;
    }) else {
        common::skipped("the duplicate-section control", CONTROL_POWER);
        return;
    };
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER),
        Err(SrsError::BadSection("tauG1"))
    );
}

#[test]
fn a_section_size_that_disagrees_with_the_power_is_rejected() {
    // Drop the declared power by one. Every section is now the wrong size for
    // it, and tauG1 is the first one checked.
    let Some(path) = common::damaged(CONTROL_POWER, "power.ptau", |b| {
        let at = header_at(b) + 36;
        b[at] = (CONTROL_POWER - 1) as u8;
    }) else {
        common::skipped("the section-size control", CONTROL_POWER);
        return;
    };
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER - 1),
        Err(SrsError::BadSection("tauG1 size disagrees with the power"))
    );
}

#[test]
fn another_curve_is_rejected() {
    let Some(path) = common::damaged(CONTROL_POWER, "modulus.ptau", |b| {
        let at = header_at(b) + 4;
        b[at] ^= 1;
    }) else {
        common::skipped("the modulus control", CONTROL_POWER);
        return;
    };
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER),
        Err(SrsError::WrongCurve)
    );

    // A different field-element width is the same class of wrongness.
    let path = common::damaged(CONTROL_POWER, "n8.ptau", |b| {
        let at = header_at(b);
        b[at] = 48;
    })
    .unwrap();
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER),
        Err(SrsError::WrongCurve)
    );
}

#[test]
fn asking_for_more_powers_than_the_file_holds_is_rejected() {
    let Some(path) = common::ptau(CONTROL_POWER) else {
        common::skipped("the power control", CONTROL_POWER);
        return;
    };
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER + 1),
        Err(SrsError::PowerTooLarge {
            requested: CONTROL_POWER + 1,
            available: CONTROL_POWER,
        })
    );
    assert_eq!(
        Srs::from_ptau(&path, 31),
        Err(SrsError::PowerTooLarge {
            requested: 31,
            available: CONTROL_POWER,
        })
    );
}

#[test]
fn a_corrupted_point_is_rejected() {
    // Flip one bit of power 5's x coordinate. The result is off the curve.
    let Some(path) = common::damaged(CONTROL_POWER, "point.ptau", |b| {
        let at = tau_g1_at(b) + 5 * 64;
        b[at] ^= 1;
    }) else {
        common::skipped("the corrupted-point control", CONTROL_POWER);
        return;
    };
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER),
        Err(SrsError::InvalidPoint { index: 5 })
    );

    // A non-canonical coordinate — every byte set, so the value is above q —
    // is the other half of the same rejection.
    let path = common::damaged(CONTROL_POWER, "noncanonical.ptau", |b| {
        let at = tau_g1_at(b) + 6 * 64;
        b[at..at + 32].fill(0xff);
    })
    .unwrap();
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER),
        Err(SrsError::InvalidPoint { index: 6 })
    );

    // And a corrupted G2 point, which is read by a different decoder.
    let path = common::damaged(CONTROL_POWER, "g2point.ptau", |b| {
        let at = common::section_at(b, 3) as usize + 128;
        b[at] ^= 1;
    })
    .unwrap();
    assert_eq!(
        Srs::from_ptau(&path, CONTROL_POWER),
        Err(SrsError::InvalidPoint {
            index: (1 << CONTROL_POWER) + 1
        })
    );
}

// ---------------------------------------------------------------------------
// Acceptance 4/5 — `validate` accepts the real thing and rejects a plausible
// forgery
// ---------------------------------------------------------------------------

/// A point that is perfectly valid and in the wrong place. `from_ptau` cannot
/// see it — it is a real subgroup point — and `validate` has to.
#[test]
fn a_valid_point_in_the_wrong_place_fails_validate() {
    let Some(path) = common::damaged(CONTROL_POWER, "swapped.ptau", |b| {
        let at = tau_g1_at(b);
        let source = b[at + 6 * 64..at + 7 * 64].to_vec();
        b[at + 5 * 64..at + 6 * 64].copy_from_slice(&source);
    }) else {
        common::skipped("the swapped-point control", CONTROL_POWER);
        return;
    };
    let srs = Srs::from_ptau(&path, CONTROL_POWER).expect("every point still decodes");
    assert_eq!(srs.validate(), Err(SrsError::TauMismatch));
}

/// The generator checks are separate from the pairing check, and each has to
/// be able to fail on its own.
#[test]
fn a_wrong_generator_fails_validate() {
    let Some(path) = common::damaged(CONTROL_POWER, "gen.ptau", |b| {
        let at = tau_g1_at(b);
        let source = b[at + 64..at + 128].to_vec();
        b[at..at + 64].copy_from_slice(&source);
    }) else {
        common::skipped("the generator control", CONTROL_POWER);
        return;
    };
    let srs = Srs::from_ptau(&path, CONTROL_POWER).expect("every point still decodes");
    assert_eq!(srs.validate(), Err(SrsError::NotGenerator));

    // The same for `[1]_2`, which pins tau under the pairing check.
    let path = common::damaged(CONTROL_POWER, "g2gen.ptau", |b| {
        let at = common::section_at(b, 3) as usize;
        let source = b[at + 128..at + 256].to_vec();
        b[at..at + 128].copy_from_slice(&source);
    })
    .unwrap();
    let srs = Srs::from_ptau(&path, CONTROL_POWER).expect("every point still decodes");
    assert_eq!(srs.validate(), Err(SrsError::NotGenerator));
}

/// A missing file is an error, not a panic — the one `Io` path a caller meets.
#[test]
fn a_missing_file_is_an_error() {
    let path = common::scratch("does-not-exist.ptau");
    let _ = fs::remove_file(&path);
    assert!(matches!(Srs::from_ptau(&path, 1), Err(SrsError::Io(_))));
}

/// The fixtures are hex, and a fixture the reader silently mangles is worse
/// than no fixture. This is the codec, not the SRS.
#[test]
fn the_fixture_codec_round_trips() {
    let text = vectors();
    for line in text.lines().filter(|l| l.starts_with("point ")) {
        let token = line.split_whitespace().nth(3).unwrap();
        let bytes = hex_to_bytes(token).expect("a fixture point is hex");
        assert_eq!(to_hex(&bytes), token);
        assert!(bytes.len() == 64 || bytes.len() == 128);
    }
}
