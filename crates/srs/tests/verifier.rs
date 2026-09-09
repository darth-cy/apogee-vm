//! `SrsVerifier`: the only SRS material a verifier path may require, and its
//! canonical-LE wire form.

mod common;

use curve::{G1Affine, G2Affine};
use srs::{Srs, SrsVerifier};

fn ceremony() -> Option<Srs> {
    let path = common::ptau(24)?;
    Some(Srs::from_ptau(&path, 4).expect("a ceremony prefix ingests"))
}

/// 320 bytes: `g1_gen || g2_gen || g2_tau`, each point in the encoding
/// `curve` writes, and nothing else. Pinned as bytes so the layout cannot
/// drift under a serde change.
#[test]
fn the_wire_form_is_the_three_points() {
    let Some(srs) = ceremony() else {
        common::skipped("the verifier wire form", 24);
        return;
    };
    let v = srs.verifier();
    let mut buf = [0u8; 512];
    let bytes = postcard::to_slice(&v, &mut buf).expect("serializing");

    assert_eq!(bytes.len(), 320, "no framing, no length prefix, no padding");
    assert_eq!(&bytes[..64], &G1Affine::GENERATOR.to_bytes());
    assert_eq!(&bytes[64..192], &G2Affine::GENERATOR.to_bytes());
    assert_eq!(&bytes[192..], &srs.g2_tau().to_bytes());

    let back: SrsVerifier = postcard::from_bytes(bytes).expect("deserializing");
    assert_eq!(back, v);
}

/// Deserialisation goes back through the validating `from_bytes`, so a wire
/// form carrying a point that is not on the curve is refused rather than
/// reconstructed.
#[test]
fn an_invalid_point_is_refused_on_the_wire() {
    let Some(srs) = ceremony() else {
        common::skipped("the verifier rejection classes", 24);
        return;
    };
    let mut buf = [0u8; 512];
    let good = postcard::to_slice(&srs.verifier(), &mut buf)
        .expect("serializing")
        .to_vec();

    for at in [0usize, 64, 192] {
        let mut bytes = good.clone();
        bytes[at] ^= 1;
        assert!(
            postcard::from_bytes::<SrsVerifier>(&bytes).is_err(),
            "a corrupted point at byte {at} decoded"
        );
    }

    // A non-canonical coordinate is the other rejection class.
    let mut bytes = good.clone();
    bytes[..32].fill(0xff);
    assert!(postcard::from_bytes::<SrsVerifier>(&bytes).is_err());

    // And a truncated wire form is not a shorter verifier.
    assert!(postcard::from_bytes::<SrsVerifier>(&good[..319]).is_err());
}

/// The verifier carries what the KZG check reads and nothing more: no powers,
/// so nothing on a verifier path can commit.
#[test]
fn the_verifier_is_three_points() {
    let Some(srs) = ceremony() else {
        common::skipped("the verifier contents", 24);
        return;
    };
    let v = srs.verifier();
    assert_eq!(v.g1_gen, G1Affine::GENERATOR);
    assert_eq!(v.g2_gen, G2Affine::GENERATOR);
    assert_eq!(v.g2_tau, srs.g2_tau());
    assert_eq!(
        std::mem::size_of_val(&v),
        std::mem::size_of::<SrsVerifier>()
    );
}
