//! Acceptance 3 and the rest of the instance validation: every rejection is an
//! error, and none of them is a panic.
//!
//! Mercury is defined for `n = 2^(2t)`. This crate never pads to reach it and
//! never truncates to fit, so an instance that is not one is refused at the
//! door on all three entry points.

mod common;

use field::Fr;
use pcs::{commit, open, verify, PcsError};
use poly::{MultilinearPoly, PolyBacking};
use test_support::Rng;
use transcript::Transcript;

/// Acceptance 3: a `2^15` polynomial and a 15-coordinate point are both
/// rejected, on every entry point that sees them.
#[test]
fn an_odd_variable_count_is_an_error() {
    let srs = common::toy_srs(16);
    let mut rng = Rng::new(0x5008_0300);
    let f = common::random_poly(&mut rng, 15);
    let u = common::random_point(&mut rng, 15);

    assert_eq!(
        commit(&srs, &f),
        Err(PcsError::UnsupportedNumVars { num_vars: 15 })
    );

    // `open` needs a commitment to absorb; a valid one for a different
    // polynomial is enough, because the size check comes first.
    let even = common::random_poly(&mut rng, 16);
    let cm = commit(&srs, &even).expect("commit");
    let mut tr = Transcript::new();
    assert_eq!(
        open(&srs, &f, &cm, &u, &mut tr),
        Err(PcsError::UnsupportedNumVars { num_vars: 15 })
    );

    // And the verifier, which sees only `u`.
    let honest_u = common::random_point(&mut rng, 16);
    let mut prover = Transcript::new();
    let (v, proof) = open(&srs, &even, &cm, &honest_u, &mut prover).expect("open");
    let mut tr = Transcript::new();
    assert_eq!(
        verify(&srs.verifier(), &cm, &u, v, &proof, &mut tr),
        Err(PcsError::UnsupportedNumVars { num_vars: 15 })
    );

    // Nothing was absorbed on the way out: the size check runs before the
    // transcript does, so a rejected instance leaves the sponge untouched.
    assert_eq!(tr.snapshot(), Transcript::new().snapshot());
}

/// Every odd count up to 9, and the single-evaluation polynomial, whose `b = 1`
/// leaves `S` and the degree check with no room to exist.
#[test]
fn every_unsupported_size_is_refused() {
    let srs = common::toy_srs(10);
    let mut rng = Rng::new(0x5008_0301);
    for num_vars in [0usize, 1, 3, 5, 7, 9] {
        let f = common::random_poly(&mut rng, num_vars);
        assert_eq!(
            commit(&srs, &f),
            Err(PcsError::UnsupportedNumVars { num_vars }),
            "num_vars {num_vars}"
        );
        let u = common::random_point(&mut rng, num_vars);
        let mut tr = Transcript::new();
        let cm = pcs::MercuryCommitment(curve::G1Affine::GENERATOR);
        assert_eq!(
            open(&srs, &f, &cm, &u, &mut tr),
            Err(PcsError::UnsupportedNumVars { num_vars })
        );
        let mut tr = Transcript::new();
        assert_eq!(
            verify(
                &srs.verifier(),
                &cm,
                &u,
                Fr::ZERO,
                &any_proof(&srs, &mut rng),
                &mut tr
            ),
            Err(PcsError::UnsupportedNumVars { num_vars })
        );
    }
}

/// `verify` takes `u` straight from a caller, so its length is the one input
/// whose size nothing else bounds. An oversized point is an error, and in
/// particular not a shift that runs off the end of a `usize` — which is a panic
/// out of a verifier with `overflow-checks` on and a silently wrong `n`
/// without them.
#[test]
fn an_oversized_point_is_an_error_and_not_a_panic() {
    let srs = common::toy_srs(4);
    let mut rng = Rng::new(0x5008_0307);
    let f = common::random_poly(&mut rng, 4);
    let cm = commit(&srs, &f).expect("commit");
    let u = common::random_point(&mut rng, 4);
    let mut tr = Transcript::new();
    let (v, proof) = open(&srs, &f, &cm, &u, &mut tr).expect("open");

    // 54 is the ceiling: the opening transform needs a 2b-th root of unity, and
    // Fr's two-adic subgroup has order 2^28.
    for num_vars in [54usize, 56, 64, 66, 128, 200, 1000] {
        let long = vec![Fr::ONE; num_vars];
        let mut tr = Transcript::new();
        let got = verify(&srs.verifier(), &cm, &long, v, &proof, &mut tr);
        if num_vars <= 54 {
            // Legal shape, wrong instance: it must reach the pairing check and
            // fail there, not be refused for its size.
            assert_eq!(
                got,
                Err(PcsError::VerificationFailed),
                "num_vars {num_vars}"
            );
        } else {
            assert_eq!(
                got,
                Err(PcsError::UnsupportedNumVars { num_vars }),
                "num_vars {num_vars}"
            );
            assert_eq!(
                tr.snapshot(),
                Transcript::new().snapshot(),
                "a refused instance must not touch the transcript"
            );
        }
    }
}

/// The even sizes really are accepted, so the rejection above cannot be passing
/// by refusing everything.
#[test]
fn the_supported_sizes_are_accepted() {
    let srs = common::toy_srs(10);
    let mut rng = Rng::new(0x5008_0302);
    for num_vars in [2usize, 4, 6, 8, 10] {
        let f = common::random_poly(&mut rng, num_vars);
        assert!(commit(&srs, &f).is_ok(), "num_vars {num_vars}");
    }
}

/// `open` refuses a point whose length is not the polynomial's variable count,
/// even when both are legal sizes on their own.
#[test]
fn a_mismatched_point_length_is_an_error() {
    let srs = common::toy_srs(10);
    let mut rng = Rng::new(0x5008_0303);
    let f = common::random_poly(&mut rng, 4);
    let cm = commit(&srs, &f).expect("commit");
    let u = common::random_point(&mut rng, 6);
    let mut tr = Transcript::new();
    assert_eq!(
        open(&srs, &f, &cm, &u, &mut tr),
        Err(PcsError::PointLengthMismatch {
            point: 6,
            num_vars: 4
        })
    );
}

/// An SRS with fewer than `n` powers is an error, never a silent truncation.
#[test]
fn too_few_powers_is_an_error() {
    let srs = common::toy_srs(6);
    let mut rng = Rng::new(0x5008_0304);
    let f = common::random_poly(&mut rng, 8);
    let expected = PcsError::SrsTooSmall {
        needed: 256,
        available: 64,
    };
    assert_eq!(commit(&srs, &f), Err(expected));

    let small = common::random_poly(&mut rng, 6);
    let cm = commit(&srs, &small).expect("commit");
    let u = common::random_point(&mut rng, 8);
    let mut tr = Transcript::new();
    assert_eq!(open(&srs, &f, &cm, &u, &mut tr), Err(expected));
}

/// The `U1` backing's bitset commits to the same point as the `Fr` lift of the
/// same bits, and the four narrow backings agree with `Fr` on a common table.
///
/// Must-be-exact 10 routes `U1`/`U8`/`U16`/`U32` through the small-scalar MSM
/// and only `Fr` through the general one; that they agree is what makes the
/// dispatch invisible.
#[test]
fn every_backing_commits_to_the_same_point() {
    let srs = common::toy_srs(8);
    let mut rng = Rng::new(0x5008_0305);
    let n = 1usize << 8;

    let bits: Vec<u32> = (0..n).map(|_| (rng.next_u64() & 1) as u32).collect();
    let mut limbs = vec![0u64; n / 64];
    for (i, b) in bits.iter().enumerate() {
        limbs[i / 64] |= (*b as u64) << (i % 64);
    }
    let expected = commit(
        &srs,
        &MultilinearPoly::new(PolyBacking::Fr(
            bits.iter().map(|b| Fr::from_u64(*b as u64)).collect(),
        )),
    )
    .expect("commit");
    for backing in [
        PolyBacking::U1(limbs, n),
        PolyBacking::U8(bits.iter().map(|b| *b as u8).collect()),
        PolyBacking::U16(bits.iter().map(|b| *b as u16).collect()),
        PolyBacking::U32(bits.clone()),
    ] {
        let got = commit(&srs, &MultilinearPoly::new(backing)).expect("commit");
        assert_eq!(got, expected, "narrow backings must agree with Fr");
    }

    // And on tables that need the full width of each narrow type, not just zero
    // and one. Zero and one is where every plausible widening slip — a sign
    // extension, a byte swap, a truncation — coincides with the right answer,
    // so a dispatch checked only there is not checked.
    let words: Vec<u32> = (0..n).map(|_| rng.next_u64() as u32).collect();
    let lift = |values: &[u32]| {
        commit(
            &srs,
            &MultilinearPoly::new(PolyBacking::Fr(
                values.iter().map(|w| Fr::from_u64(*w as u64)).collect(),
            )),
        )
        .expect("commit")
    };

    let bytes: Vec<u8> = words.iter().map(|w| *w as u8).collect();
    let halves: Vec<u16> = words.iter().map(|w| *w as u16).collect();
    assert!(
        bytes.iter().any(|b| *b >= 0x80) && halves.iter().any(|h| *h >= 0x8000),
        "the sample must reach the top bit of each width, where a sign extension shows"
    );
    assert_eq!(
        commit(&srs, &MultilinearPoly::new(PolyBacking::U8(bytes.clone()))).expect("commit"),
        lift(&bytes.iter().map(|b| *b as u32).collect::<Vec<_>>())
    );
    assert_eq!(
        commit(
            &srs,
            &MultilinearPoly::new(PolyBacking::U16(halves.clone()))
        )
        .expect("commit"),
        lift(&halves.iter().map(|h| *h as u32).collect::<Vec<_>>())
    );
    assert_eq!(
        commit(&srs, &MultilinearPoly::new(PolyBacking::U32(words.clone()))).expect("commit"),
        lift(&words)
    );

    // The extremes of each width, which a random sample does not produce.
    for (max, index) in [(u8::MAX as u32, 0usize), (u16::MAX as u32, 1)] {
        let mut edge = vec![0u32; n];
        edge[index] = max;
        edge[index + 1] = 1;
        let expected = lift(&edge);
        let got = if max == u8::MAX as u32 {
            commit(
                &srs,
                &MultilinearPoly::new(PolyBacking::U8(edge.iter().map(|w| *w as u8).collect())),
            )
        } else {
            commit(
                &srs,
                &MultilinearPoly::new(PolyBacking::U16(edge.iter().map(|w| *w as u16).collect())),
            )
        };
        assert_eq!(got.expect("commit"), expected, "the maximum of a width");
    }
}

/// Must-be-exact 4: `open` absorbs the commitment it is **passed** and never
/// recommits `f`.
///
/// The discriminator is that two different commitments must give two different
/// proofs *for the same witness*. A recommitting `open` would absorb
/// `commit(f)` both times and produce the same proof twice, which is also the
/// silent way to lose a size-`n` MSM's worth of prover time.
#[test]
fn open_absorbs_the_commitment_it_is_given() {
    let srs = common::toy_srs(6);
    let mut rng = Rng::new(0x5008_0306);
    let f = common::random_poly(&mut rng, 6);
    let u = common::random_point(&mut rng, 6);

    let honest = commit(&srs, &f).expect("commit");
    let other = commit(&srs, &common::random_poly(&mut rng, 6)).expect("commit");
    let third = commit(&srs, &common::random_poly(&mut rng, 6)).expect("commit");
    assert_ne!(honest, other);
    assert_ne!(other, third);

    let proof_of = |cm: &pcs::MercuryCommitment| {
        let mut tr = Transcript::new();
        open(&srs, &f, cm, &u, &mut tr).expect("open").1.to_bytes()
    };
    assert_ne!(
        proof_of(&other),
        proof_of(&third),
        "the passed commitment must reach the transcript"
    );
    assert_ne!(proof_of(&honest), proof_of(&other));

    // And the same commitment twice is the same proof, so the difference above
    // is the commitment and not nondeterminism.
    assert_eq!(proof_of(&honest), proof_of(&honest));
}

/// Any structurally valid proof, for the tests above that need one to hand.
fn any_proof(srs: &srs::Srs, rng: &mut Rng) -> pcs::MercuryProof {
    let f = common::random_poly(rng, 4);
    let u = common::random_point(rng, 4);
    let cm = commit(srs, &f).expect("commit");
    let mut tr = Transcript::new();
    open(srs, &f, &cm, &u, &mut tr).expect("open").1
}
