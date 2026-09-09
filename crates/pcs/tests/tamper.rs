//! Acceptance 4, 5 and 6: every twin of an honest proof is rejected.
//!
//! Three kinds of tampering, and they fail for three different reasons.
//! A **witness** twin is an honest proof of a different polynomial, so it fails
//! the fold identity at `z`. A **proof** twin changes an element the transcript
//! absorbs, so every challenge downstream of it moves and the pairing check
//! misses. A **statement** twin changes what the verifier is asked to believe,
//! which moves `alpha` itself.

mod common;

use curve::{G1Affine, G1Projective};
use field::Fr;
use pcs::{commit, open, verify, MercuryCommitment, MercuryProof, PcsError};
use poly::{MultilinearPoly, PolyBacking};
use srs::Srs;
use test_support::Rng;
use transcript::Transcript;

const NUM_VARS: usize = 8;

/// One honest instance: the SRS, the polynomial, the commitment, the point, the
/// value and the proof.
struct Instance {
    srs: Srs,
    values: Vec<Fr>,
    cm: MercuryCommitment,
    u: Vec<Fr>,
    v: Fr,
    proof: MercuryProof,
}

fn honest(seed: u64) -> Instance {
    let srs = common::toy_srs(NUM_VARS as u32);
    let mut rng = Rng::new(seed);
    let values: Vec<Fr> = (0..1usize << NUM_VARS)
        .map(|_| common::next_fr(&mut rng))
        .collect();
    let f = MultilinearPoly::new(PolyBacking::Fr(values.clone()));
    let u = common::random_point(&mut rng, NUM_VARS);
    let cm = commit(&srs, &f).expect("commit");
    let mut tr = Transcript::new();
    let (v, proof) = open(&srs, &f, &cm, &u, &mut tr).expect("open");
    Instance {
        srs,
        values,
        cm,
        u,
        v,
        proof,
    }
}

impl Instance {
    fn check(
        &self,
        cm: &MercuryCommitment,
        u: &[Fr],
        v: Fr,
        proof: &MercuryProof,
    ) -> Result<(), PcsError> {
        let mut tr = Transcript::new();
        verify(&self.srs.verifier(), cm, u, v, proof, &mut tr)
    }
}

/// The control: the untampered instance verifies, so every rejection below is
/// about the tampering and not about the harness.
#[test]
fn the_honest_instance_verifies() {
    let it = honest(0x5008_0400);
    it.check(&it.cm, &it.u, it.v, &it.proof).expect("verify");
}

/// Acceptance 4: flip one evaluation of `f`, open honestly, and check the proof
/// against the **original** commitment.
///
/// The prover is not cheating — it runs the protocol correctly on the witness
/// it holds. What breaks is the fold identity `f(z) = (z^b - alpha) q(z) + g_z`,
/// which is the only place the commitment enters the pairing check.
#[test]
fn a_flipped_evaluation_fails_against_the_original_commitment() {
    let it = honest(0x5008_0401);
    for index in [0usize, 1, 17, (1 << NUM_VARS) - 1] {
        let mut flipped = it.values.clone();
        flipped[index] += Fr::ONE;
        let f = MultilinearPoly::new(PolyBacking::Fr(flipped));

        let mut tr = Transcript::new();
        let (v, proof) = open(&it.srs, &f, &it.cm, &it.u, &mut tr).expect("open");
        assert_ne!(v, it.v, "flipping an evaluation moves the claimed value");
        assert_eq!(
            it.check(&it.cm, &it.u, v, &proof),
            Err(PcsError::VerificationFailed),
            "index {index}"
        );
        // And with the honest value substituted, so the rejection cannot be
        // put down to `v` alone.
        assert_eq!(
            it.check(&it.cm, &it.u, it.v, &proof),
            Err(PcsError::VerificationFailed),
            "index {index}"
        );
    }
}

/// Acceptance 5: perturb each of the 14 proof fields on its own.
///
/// A `G1` field is moved by adding the generator, which lands on a different
/// valid point of the subgroup; an `Fr` field by adding one. Every one of the
/// 14 must be rejected, and the loop asserts it covered all 14.
#[test]
fn every_proof_field_is_load_bearing() {
    let it = honest(0x5008_0402);
    let shift = |p: G1Affine| {
        G1Projective::from(p)
            .add(&G1Projective::GENERATOR)
            .to_affine()
    };

    let mut count = 0;
    for which in 0..14 {
        let mut p = it.proof;
        match which {
            0 => p.h = shift(p.h),
            1 => p.q = shift(p.q),
            2 => p.g = shift(p.g),
            3 => p.s = shift(p.s),
            4 => p.d = shift(p.d),
            5 => p.pi_z = shift(p.pi_z),
            6 => p.w = shift(p.w),
            7 => p.w_prime = shift(p.w_prime),
            8 => p.g_z += Fr::ONE,
            9 => p.g_inv_z += Fr::ONE,
            10 => p.h_z += Fr::ONE,
            11 => p.h_inv_z += Fr::ONE,
            12 => p.s_z += Fr::ONE,
            13 => p.s_inv_z += Fr::ONE,
            _ => unreachable!(),
        }
        assert_ne!(p, it.proof, "field {which} must actually have moved");
        assert_eq!(
            it.check(&it.cm, &it.u, it.v, &p),
            Err(PcsError::VerificationFailed),
            "field {which}"
        );
        count += 1;
    }
    assert_eq!(count, 14, "the sweep must cover every field of the proof");
}

/// Must-be-exact 8: a proof point off the curve or outside the subgroup is
/// refused before it reaches the pairing, and the error names the field.
#[test]
fn an_invalid_proof_point_is_refused_by_name() {
    let it = honest(0x5008_0403);
    // `(1, 1)` is off the curve: `1 != 1 + 3`.
    let off_curve = G1Affine {
        x: curve::Fq::ONE,
        y: curve::Fq::ONE,
        infinity: false,
    };
    assert!(!off_curve.is_on_curve());

    let names = ["h", "q", "g", "s", "d", "pi_z", "w", "w_prime"];
    for (which, name) in names.iter().enumerate() {
        let mut p = it.proof;
        match which {
            0 => p.h = off_curve,
            1 => p.q = off_curve,
            2 => p.g = off_curve,
            3 => p.s = off_curve,
            4 => p.d = off_curve,
            5 => p.pi_z = off_curve,
            6 => p.w = off_curve,
            7 => p.w_prime = off_curve,
            _ => unreachable!(),
        }
        assert_eq!(
            it.check(&it.cm, &it.u, it.v, &p),
            Err(PcsError::InvalidPoint { field: name })
        );
    }

    // The commitment the statement names is validated too.
    assert_eq!(
        it.check(&MercuryCommitment(off_curve), &it.u, it.v, &it.proof),
        Err(PcsError::InvalidPoint { field: "cm" })
    );
}

/// Acceptance 6: `v + 1`, a point differing in one coordinate, and the two
/// halves of `u` swapped.
///
/// The last is the order-convention negative control. `u1` is the **first**
/// `t` coordinates; a reader who takes it for the last `t` writes a verifier
/// that accepts this twin.
#[test]
fn a_tampered_statement_fails() {
    let it = honest(0x5008_0404);

    assert_eq!(
        it.check(&it.cm, &it.u, it.v + Fr::ONE, &it.proof),
        Err(PcsError::VerificationFailed),
        "v + 1"
    );

    for coordinate in 0..NUM_VARS {
        let mut u = it.u.clone();
        u[coordinate] += Fr::ONE;
        assert_eq!(
            it.check(&it.cm, &u, it.v, &it.proof),
            Err(PcsError::VerificationFailed),
            "coordinate {coordinate}"
        );
    }

    let t = NUM_VARS / 2;
    let mut swapped = it.u[t..].to_vec();
    swapped.extend_from_slice(&it.u[..t]);
    assert_ne!(swapped, it.u, "the two halves must actually differ");
    assert_eq!(
        it.check(&it.cm, &swapped, it.v, &it.proof),
        Err(PcsError::VerificationFailed),
        "u1 and u2 swapped"
    );

    // A commitment to a different polynomial, for completeness.
    let mut rng = Rng::new(0x5008_0405);
    let other = commit(&it.srs, &common::random_poly(&mut rng, NUM_VARS)).expect("commit");
    assert_ne!(other, it.cm);
    assert_eq!(
        it.check(&other, &it.u, it.v, &it.proof),
        Err(PcsError::VerificationFailed),
        "a different commitment"
    );
}

/// A proof byte string that does not decode is rejected by `from_bytes`, so a
/// tampered wire form never reaches `verify` at all.
#[test]
fn a_tampered_encoding_does_not_decode() {
    let it = honest(0x5008_0406);
    let honest_bytes = it.proof.to_bytes();
    assert_eq!(
        MercuryProof::from_bytes(&honest_bytes).expect("the honest proof decodes"),
        it.proof
    );

    // A coordinate at or above the base modulus, in the first point.
    let mut bad = honest_bytes;
    bad[..32].copy_from_slice(&[0xff; 32]);
    assert_eq!(MercuryProof::from_bytes(&bad), None);

    // An on-curve-looking but off-curve point: flip one bit of a coordinate.
    let mut bad = honest_bytes;
    bad[0] ^= 1;
    assert_eq!(MercuryProof::from_bytes(&bad), None);

    // A value at or above the scalar modulus, in the first `Fr`.
    let mut bad = honest_bytes;
    bad[8 * 64..8 * 64 + 32].copy_from_slice(&[0xff; 32]);
    assert_eq!(MercuryProof::from_bytes(&bad), None);
}
