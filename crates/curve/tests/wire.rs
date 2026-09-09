//! The wire format: canonicity, round-trips, and every class of input
//! `from_bytes` has to refuse.
//!
//! The committed fixtures pin the bytes of particular values. This file pins
//! the *rules*: one canonical spelling per element, all-zero and nothing else
//! is infinity, and `from_bytes` returns `None` rather than panicking on
//! anything else.

mod common;

use common::{next_fq, next_fq2, next_fr};
use constants::FQ_MODULUS;
use curve::{Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use test_support::Rng;

const SEED: u64 = 0x0500_b17e_0000_0001;

fn modulus_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        b[8 * i..8 * i + 8].copy_from_slice(&FQ_MODULUS[i].to_le_bytes());
    }
    b
}

// ---------------------------------------------------------------------------
// Fq
// ---------------------------------------------------------------------------

#[test]
fn fq_wire_form_round_trips_and_rejects_non_canonical() {
    let mut rng = Rng::new(SEED);
    for _ in 0..500 {
        let x = next_fq(&mut rng);
        assert_eq!(Fq::from_bytes(&x.to_bytes()), Some(x));
    }
    for x in [Fq::ZERO, Fq::ONE, Fq::MINUS_ONE, Fq::from_u64(u64::MAX)] {
        assert_eq!(Fq::from_bytes(&x.to_bytes()), Some(x));
    }

    // The largest element encodes; the modulus and everything above it does
    // not, and is never silently reduced.
    let q = modulus_bytes();
    assert_eq!(Fq::from_bytes(&q), None, "q itself is not an element");
    let mut q_plus_one = q;
    q_plus_one[0] += 1;
    assert_eq!(Fq::from_bytes(&q_plus_one), None);
    assert_eq!(Fq::from_bytes(&[0xff; 32]), None, "2^256 - 1");
    let mut top_bit = [0u8; 32];
    top_bit[31] = 0x80;
    assert_eq!(Fq::from_bytes(&top_bit), None, "2^255");

    // One byte below the modulus is q - 1, which must be accepted: the
    // boundary is exact, not approximate.
    let mut q_minus_one = q;
    q_minus_one[0] -= 1;
    assert_eq!(Fq::from_bytes(&q_minus_one), Some(Fq::MINUS_ONE));
}

#[test]
fn fq_from_hex_has_exactly_one_accepted_spelling() {
    // Big-endian text, little-endian bytes: the two orders are deliberately
    // different, and `2` is the smallest value that shows it.
    let two = Fq::from_hex("0x0000000000000000000000000000000000000000000000000000000000000002")
        .expect("the one accepted spelling");
    assert_eq!(two, Fq::from_u64(2));
    assert_eq!(two.to_bytes()[0], 2, "the wire form is little-endian");
    assert_eq!(two.to_bytes()[31], 0);

    let ok = "0x0000000000000000000000000000000000000000000000000000000000000002";
    assert!(Fq::from_hex(&ok[2..]).is_none(), "missing the 0x prefix");
    assert!(Fq::from_hex("0x02").is_none(), "too short");
    assert!(
        Fq::from_hex(&format!("{ok}0")).is_none(),
        "too long by one digit"
    );
    assert!(
        Fq::from_hex("0x000000000000000000000000000000000000000000000000000000000000000A")
            .is_none(),
        "uppercase is a different spelling"
    );
    assert!(
        Fq::from_hex("0x00000000000000000000000000000000000000000000000000000000000000 2")
            .is_none(),
        "a non-hex digit"
    );

    // ...and a value >= q does not parse, whatever its spelling.
    let q_hex = "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
    assert!(Fq::from_hex(q_hex).is_none(), "q is not an element");
}

#[test]
fn fq_serde_round_trips_through_a_real_wire_format() {
    let mut rng = Rng::new(SEED ^ 1);
    let mut buf = [0u8; 64];
    for x in (0..100)
        .map(|_| next_fq(&mut rng))
        .chain([Fq::ZERO, Fq::ONE, Fq::MINUS_ONE])
    {
        let encoded = postcard::to_slice(&x, &mut buf).expect("postcard encodes an Fq");
        assert_eq!(
            encoded.len(),
            32,
            "no framing beyond the 32 canonical bytes"
        );
        assert_eq!(encoded, &x.to_bytes()[..], "serde uses the wire form");
        let decoded: Fq = postcard::from_bytes(encoded).expect("and decodes it");
        assert_eq!(decoded, x);
    }

    // A non-canonical encoding is an error, not a reduction.
    assert!(
        postcard::from_bytes::<Fq>(&modulus_bytes()).is_err(),
        "deserializing q must fail"
    );
}

#[test]
fn fq_debug_prints_the_canonical_value_big_endian() {
    assert_eq!(
        format!("{:?}", Fq::ONE),
        "Fq(0x0000000000000000000000000000000000000000000000000000000000000001)"
    );
    assert_eq!(
        format!("{:?}", Fq::from_u64(2)),
        "Fq(0x0000000000000000000000000000000000000000000000000000000000000002)"
    );
    assert_eq!(
        format!("{:?}", Fq2::new(Fq::ONE, Fq::ZERO)),
        format!("Fq2({:?} + {:?} u)", Fq::ONE, Fq::ZERO)
    );
}

#[test]
fn fq2_wire_form_is_c0_then_c1() {
    let mut rng = Rng::new(SEED ^ 2);
    for _ in 0..200 {
        let x = next_fq2(&mut rng);
        let bytes = x.to_bytes();
        assert_eq!(bytes[..32], x.c0.to_bytes(), "c0 comes first");
        assert_eq!(bytes[32..], x.c1.to_bytes(), "c1 second");
        assert_eq!(Fq2::from_bytes(&bytes), Some(x));
    }

    // Either half being non-canonical rejects the pair.
    let q = modulus_bytes();
    let mut bad = [0u8; 64];
    bad[..32].copy_from_slice(&q);
    assert_eq!(Fq2::from_bytes(&bad), None, "c0 >= q");
    let mut bad = [0u8; 64];
    bad[32..].copy_from_slice(&q);
    assert_eq!(Fq2::from_bytes(&bad), None, "c1 >= q");
}

// ---------------------------------------------------------------------------
// Points
// ---------------------------------------------------------------------------

#[test]
fn g1_points_round_trip() {
    let mut rng = Rng::new(SEED ^ 3);
    for _ in 0..200 {
        let p = G1Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine();
        let bytes = p.to_bytes();
        assert_eq!(bytes[..32], p.x.to_bytes(), "x || y");
        assert_eq!(bytes[32..], p.y.to_bytes());
        assert_eq!(G1Affine::from_bytes(&bytes), Some(p));
    }
    for p in [
        G1Affine::GENERATOR,
        G1Affine::IDENTITY,
        -G1Affine::GENERATOR,
    ] {
        assert_eq!(G1Affine::from_bytes(&p.to_bytes()), Some(p));
    }
    assert_eq!(G1Affine::IDENTITY.to_bytes(), [0u8; 64]);
}

#[test]
fn g2_points_round_trip() {
    let mut rng = Rng::new(SEED ^ 4);
    for _ in 0..50 {
        let p = G2Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine();
        let bytes = p.to_bytes();
        assert_eq!(bytes[..64], p.x.to_bytes(), "x.c0 || x.c1 || y.c0 || y.c1");
        assert_eq!(bytes[64..], p.y.to_bytes());
        assert_eq!(G2Affine::from_bytes(&bytes), Some(p));
    }
    for p in [
        G2Affine::GENERATOR,
        G2Affine::IDENTITY,
        -G2Affine::GENERATOR,
    ] {
        assert_eq!(G2Affine::from_bytes(&p.to_bytes()), Some(p));
    }
    assert_eq!(G2Affine::IDENTITY.to_bytes(), [0u8; 128]);
}

/// All-zero is infinity, and *only* all-zero is: a single nonzero byte in an
/// otherwise-zero encoding is a coordinate pair, and every such pair is off
/// the curve. This is the "nonzero bytes violating the infinity pattern"
/// rejection class, checked at every byte position rather than sampled.
#[test]
fn only_all_zero_decodes_as_infinity() {
    for i in 0..64 {
        let mut bytes = [0u8; 64];
        bytes[i] = 1;
        assert_eq!(
            G1Affine::from_bytes(&bytes),
            None,
            "G1: byte {i} set must not decode"
        );
    }
    for i in 0..128 {
        let mut bytes = [0u8; 128];
        bytes[i] = 1;
        assert_eq!(
            G2Affine::from_bytes(&bytes),
            None,
            "G2: byte {i} set must not decode"
        );
    }

    // The reason it is unambiguous: (0, 0) is off both curves.
    assert!(!G1Affine {
        x: Fq::ZERO,
        y: Fq::ZERO,
        infinity: false,
    }
    .is_on_curve());
    assert!(!G2Affine {
        x: Fq2::ZERO,
        y: Fq2::ZERO,
        infinity: false,
    }
    .is_on_curve());
}

#[test]
fn from_bytes_rejects_off_curve_and_non_canonical_points() {
    let mut rng = Rng::new(SEED ^ 5);
    let q = modulus_bytes();

    for _ in 0..50 {
        let p = G1Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine();

        // y + 1 leaves the curve: y and -y are the only roots for this x.
        let mut bytes = p.to_bytes();
        bytes[32..].copy_from_slice(&(p.y + Fq::ONE).to_bytes());
        assert_eq!(G1Affine::from_bytes(&bytes), None, "off-curve y");

        // A non-canonical coordinate, in either position.
        let mut bytes = p.to_bytes();
        bytes[..32].copy_from_slice(&q);
        assert_eq!(G1Affine::from_bytes(&bytes), None, "x >= q");
        let mut bytes = p.to_bytes();
        bytes[32..].copy_from_slice(&q);
        assert_eq!(G1Affine::from_bytes(&bytes), None, "y >= q");
        let mut bytes = p.to_bytes();
        bytes[..32].copy_from_slice(&[0xff; 32]);
        assert_eq!(G1Affine::from_bytes(&bytes), None, "x is 2^256 - 1");
    }

    for _ in 0..10 {
        let p = G2Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine();

        let mut bytes = p.to_bytes();
        bytes[64..].copy_from_slice(&(p.y + Fq2::ONE).to_bytes());
        assert_eq!(G2Affine::from_bytes(&bytes), None, "off-curve y");

        for offset in [0, 32, 64, 96] {
            let mut bytes = p.to_bytes();
            bytes[offset..offset + 32].copy_from_slice(&q);
            assert_eq!(
                G2Affine::from_bytes(&bytes),
                None,
                "a non-canonical half at offset {offset}"
            );
        }
    }
}

/// The G2 rejection class G1 cannot have. Built here rather than read from a
/// fixture, so the API-level rule is checked independently of the corpus:
/// a random `x` with the cofactor left un-cleared is on the curve and outside
/// the order-`r` subgroup.
#[test]
fn from_bytes_rejects_on_curve_points_outside_the_g2_subgroup() {
    let mut rng = Rng::new(SEED ^ 6);
    let mut found = 0;
    while found < 8 {
        let x = next_fq2(&mut rng);
        let Some(y) = (x.square() * x + curve_b2()).sqrt() else {
            continue;
        };
        let point = G2Affine {
            x,
            y,
            infinity: false,
        };
        assert!(point.is_on_curve(), "built from the curve equation");
        assert!(
            !point.is_in_subgroup(),
            "an un-cleared random point is almost never in the subgroup"
        );
        assert_eq!(
            G2Affine::from_bytes(&point.to_bytes()),
            None,
            "from_bytes must apply the subgroup check"
        );
        found += 1;
    }
}

/// `3/(9+u)`, derived rather than copied: the crate keeps it private.
fn curve_b2() -> Fq2 {
    let xi = Fq2::new(Fq::from_u64(9), Fq::ONE);
    Fq2::from_fq(Fq::from_u64(3)) * xi.inverse().expect("xi is nonzero")
}
