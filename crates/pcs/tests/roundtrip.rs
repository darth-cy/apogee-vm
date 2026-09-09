//! Acceptance 1 and 2: the protocol round trip, the differential against S07's
//! KZG commitment, and the menu heights.

mod common;

use pcs::{commit, open, verify, MercuryProof, PROOF_BYTES};
use srs::kzg::kzg_commit;
use test_support::Rng;
use transcript::Transcript;

/// Acceptance 1: commit, open and verify at `n = 2^16` over a random `f` and a
/// random `u`, the opened value is `MultilinearPoly::evaluate(u)`, and the
/// commitment is exactly S07's KZG commitment of the evaluation table read as
/// coefficients.
#[test]
fn the_round_trip_holds_at_two_to_the_sixteen() {
    let srs = common::toy_srs(16);
    let mut rng = Rng::new(0x5008_0001);
    let f = common::random_poly(&mut rng, 16);
    let u = common::random_point(&mut rng, 16);

    let cm = commit(&srs, &f).expect("commit");

    let coeffs: Vec<_> = (0..f.len()).map(|i| f.get(i)).collect();
    assert_eq!(
        cm.0,
        kzg_commit(&srs, &coeffs).expect("the KZG commitment of the same coefficients"),
        "a Mercury commitment IS the plain KZG commitment of the evaluation table"
    );

    let mut prover = Transcript::new();
    let (v, proof) = open(&srs, &f, &cm, &u, &mut prover).expect("open");
    assert_eq!(
        v,
        f.evaluate(&u),
        "the opened value is the multilinear evaluation, which pins the variable order"
    );

    let mut verifier = Transcript::new();
    verify(&srs.verifier(), &cm, &u, v, &proof, &mut verifier).expect("verify");
    assert_eq!(
        prover.snapshot(),
        verifier.snapshot(),
        "the two transcripts must end in the same state"
    );

    let bytes = proof.to_bytes();
    assert_eq!(bytes.len(), PROOF_BYTES);
    assert_eq!(
        MercuryProof::from_bytes(&bytes).expect("a proof decodes"),
        proof
    );
}

/// Acceptance 2 in CI: every even height the toy SRS can reach cheaply,
/// including the two smallest menu heights.
#[test]
fn every_small_even_height_round_trips() {
    let srs = common::toy_srs(18);
    for num_vars in [2usize, 4, 6, 8, 10, 16, 18] {
        let mut rng = Rng::new(0x5008_0000 + num_vars as u64);
        let f = common::random_poly(&mut rng, num_vars);
        let u = common::random_point(&mut rng, num_vars);
        let cm = commit(&srs, &f).expect("commit");

        let mut prover = Transcript::new();
        let (v, proof) = open(&srs, &f, &cm, &u, &mut prover).expect("open");
        assert_eq!(v, f.evaluate(&u), "n = 2^{num_vars}");

        let mut verifier = Transcript::new();
        verify(&srs.verifier(), &cm, &u, v, &proof, &mut verifier)
            .unwrap_or_else(|e| panic!("verify at n = 2^{num_vars}: {e:?}"));
        assert_eq!(proof.to_bytes().len(), PROOF_BYTES, "the shape is fixed");
    }
}

/// Acceptance 2 in full: the master's height menu, over the real ceremony.
/// Needs `assets/ptau/ppot_0080_24.ptau`; returns quietly without it.
#[test]
fn every_menu_height_round_trips_over_the_ceremony() {
    let Some(path) = common::ptau(24) else {
        common::skipped("the menu-height round trip", 24);
        return;
    };
    for num_vars in [16usize, 18, 20, 22] {
        let srs = srs::Srs::from_ptau(&path, num_vars as u32).expect("a ceremony prefix ingests");
        let mut rng = Rng::new(0x5008_0100 + num_vars as u64);
        let f = common::random_poly(&mut rng, num_vars);
        let u = common::random_point(&mut rng, num_vars);
        let cm = commit(&srs, &f).expect("commit");

        let mut prover = Transcript::new();
        let (v, proof) = open(&srs, &f, &cm, &u, &mut prover).expect("open");
        assert_eq!(v, f.evaluate(&u), "n = 2^{num_vars}");

        let mut verifier = Transcript::new();
        verify(&srs.verifier(), &cm, &u, v, &proof, &mut verifier)
            .unwrap_or_else(|e| panic!("verify at n = 2^{num_vars}: {e:?}"));
    }
}
