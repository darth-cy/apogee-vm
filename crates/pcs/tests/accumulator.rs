//! Acceptance 8, 9 and 10: deferral, the accumulator, and discharge.
//!
//! Three claims, checked three ways.
//!
//! * **The twelve entries are the two pairing relations.** Their scalars are
//!   rebuilt here from `docs/spec/mercury.md` §6 and §8, out of a second
//!   transcription of the transcript schedule and a second, naive univariate
//!   arithmetic — no crate internals. Since S09 this is what pins the merge
//!   challenge's *use*: `rho` is literally the scalar of entry 11, so an
//!   implementation that squeezed it and then merged with a constant is now
//!   visible to a black-box test, which it was not in S08.
//! * **Deferral changes no verdict.** Over honest and tampered proofs alike,
//!   `verify` and `verify_deferred` + `discharge` agree, and so do the batch
//!   variants.
//! * **Concatenation works.** Two independent verifications' lists join into
//!   one accumulator that discharges in one MSM per side and one two-pairing
//!   check, and every way of damaging it is rejected.

mod common;

use constants::transcript_tags as tags;
use curve::{G1Affine, G1Projective};
use field::Fr;
use pcs::{
    accumulator_digest, accumulator_from_words, accumulator_words, append_g1_list, batch_open,
    batch_verify, batch_verify_deferred, commit, discharge, open, verify, verify_deferred,
    AccumulatorEntry, MercuryCommitment, MercuryProof, PairingSide, PcsError, ENTRIES_PER_CHECK,
    ENTRY_WORDS,
};
use poly::{MultilinearPoly, PolyBacking};
use srs::Srs;
use test_support::Rng;
use transcript::Transcript;

// ---------------------------------------------------------------------------
// Instances
// ---------------------------------------------------------------------------

const NUM_VARS: usize = 8;

struct Single {
    srs: Srs,
    values: Vec<Fr>,
    cm: MercuryCommitment,
    u: Vec<Fr>,
    v: Fr,
    proof: MercuryProof,
}

fn single(seed: u64) -> Single {
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
    Single {
        srs,
        values,
        cm,
        u,
        v,
        proof,
    }
}

/// `verify` and `verify_deferred` + `discharge`, on the same instance.
fn both_ways(
    it: &Single,
    cm: &MercuryCommitment,
    u: &[Fr],
    v: Fr,
    proof: &MercuryProof,
) -> (Result<(), PcsError>, Result<(), PcsError>) {
    let vsrs = it.srs.verifier();
    let mut tr = Transcript::new();
    let native = verify(&vsrs, cm, u, v, proof, &mut tr);

    let mut tr = Transcript::new();
    let deferred = verify_deferred(&vsrs, cm, u, v, proof, &mut tr)
        .and_then(|entries| discharge(&vsrs, &entries, &[entries.len()]));
    (native, deferred)
}

// ---------------------------------------------------------------------------
// The entry table
// ---------------------------------------------------------------------------

/// The twelve entries a verification emits are exactly the terms of the two
/// pairing relations, recomputed from the specification.
#[test]
fn the_entries_are_the_two_relations() {
    let it = single(0x5009_0100);
    let vsrs = it.srs.verifier();
    let mut tr = Transcript::new();
    let entries =
        verify_deferred(&vsrs, &it.cm, &it.u, it.v, &it.proof, &mut tr).expect("verify_deferred");

    assert_eq!(entries.len(), ENTRIES_PER_CHECK);
    assert_eq!(
        entries,
        common::deferred_entries(
            &vsrs.g1_gen,
            &it.cm,
            &it.u,
            it.v,
            &it.proof,
            &common::replay_schedule(&it.cm, &it.u, it.v, &it.proof, &|_| {}),
        ),
        "the deferred terms must be the relations of docs/spec/mercury.md section 8"
    );

    // Ten `G2One` terms then two `G2X` terms, and the points are the statement's
    // commitment, the eight proof points in field order, and the generator.
    let sides: Vec<PairingSide> = entries.iter().map(|e| e.side).collect();
    assert_eq!(
        sides,
        [vec![PairingSide::G2One; 10], vec![PairingSide::G2X; 2]].concat()
    );
    let expected_points = [
        vec![it.cm.0],
        vec![
            it.proof.h,
            it.proof.q,
            it.proof.g,
            it.proof.s,
            it.proof.d,
            it.proof.pi_z,
            it.proof.w,
            it.proof.w_prime,
        ],
        vec![vsrs.g1_gen, it.proof.pi_z, it.proof.w_prime],
    ]
    .concat();
    assert_eq!(
        entries.iter().map(|e| e.point).collect::<Vec<_>>(),
        expected_points
    );

    // And the two relations really are the pairing check: recomputing them by
    // hand and pairing gives the same verdict.
    let mut a = G1Projective::IDENTITY;
    let mut b = G1Projective::IDENTITY;
    for e in &entries {
        let term = G1Projective::from(e.point).mul(&e.scalar);
        match e.side {
            PairingSide::G2One => a = a.add(&term),
            PairingSide::G2X => b = b.add(&term),
        }
    }
    assert!(curve::pairing::pairing_check(&[
        (a.to_affine(), vsrs.g2_gen),
        (-b.to_affine(), vsrs.g2_tau)
    ]));
}

/// A batched verification emits the same twelve entries, over `cm*`.
#[test]
fn a_batch_defers_the_same_twelve_entries() {
    let num_vars = 6;
    let srs = common::toy_srs(num_vars as u32);
    let mut rng = Rng::new(0x5009_0101);
    let cols: Vec<MultilinearPoly> = (0..4)
        .map(|_| common::random_poly(&mut rng, num_vars))
        .collect();
    let cms: Vec<MercuryCommitment> = cols
        .iter()
        .map(|f| commit(&srs, f).expect("commit"))
        .collect();
    let u = common::random_point(&mut rng, num_vars);
    let mut tr = Transcript::new();
    let (vs, proof) = batch_open(&srs, &cols, &cms, &u, &mut tr).expect("batch_open");

    let vsrs = srs.verifier();
    let mut tr = Transcript::new();
    let entries = batch_verify_deferred(&vsrs, &cms, &u, &vs, &proof, &mut tr)
        .expect("batch_verify_deferred");
    assert_eq!(
        entries.len(),
        ENTRIES_PER_CHECK,
        "k does not change the count"
    );

    // `cm*` and `v*`, rebuilt from section 11's preamble.
    let points: Vec<G1Affine> = cms.iter().map(|c| c.0).collect();
    let mut probe = Transcript::new();
    append_g1_list(&mut probe, tags::COMMITMENT, &points);
    let mut claim = u.clone();
    claim.extend_from_slice(&vs);
    probe.append_scalars(tags::EVALUATION_CLAIM, &claim);
    let rho = probe.challenge_scalar(tags::MERCURY_BATCH);

    let mut cm_star = G1Projective::IDENTITY;
    let mut v_star = Fr::ZERO;
    let mut weight = Fr::ONE;
    for (cm, v) in cms.iter().zip(&vs) {
        cm_star = cm_star.add(&G1Projective::from(cm.0).mul(&weight));
        v_star += weight * *v;
        weight *= rho;
    }
    let cm_star = MercuryCommitment(cm_star.to_affine());
    assert_eq!(entries[0].point, cm_star.0, "entry 0 is cm*");

    let prefix = |tr: &mut Transcript| {
        append_g1_list(tr, tags::COMMITMENT, &points);
        let mut claim = u.clone();
        claim.extend_from_slice(&vs);
        tr.append_scalars(tags::EVALUATION_CLAIM, &claim);
        let _ = tr.challenge_scalar(tags::MERCURY_BATCH);
    };
    assert_eq!(
        entries,
        common::deferred_entries(
            &vsrs.g1_gen,
            &cm_star,
            &u,
            v_star,
            &proof,
            &common::replay_schedule(&cm_star, &u, v_star, &proof, &prefix),
        )
    );
}

// ---------------------------------------------------------------------------
// Acceptance 8 — deferred equivalence
// ---------------------------------------------------------------------------

/// The S08 tamper sweep, run through both paths: honest, all fourteen proof
/// fields, the statement twins, the witness twin and the invalid points. Every
/// one of them must land in the same class either way.
#[test]
fn deferral_changes_no_verdict() {
    let it = single(0x5009_0102);

    let mut cases: Vec<(String, MercuryCommitment, Vec<Fr>, Fr, MercuryProof)> =
        vec![("honest".to_string(), it.cm, it.u.clone(), it.v, it.proof)];

    // All fourteen proof fields.
    let shift = |p: G1Affine| {
        G1Projective::from(p)
            .add(&G1Projective::GENERATOR)
            .to_affine()
    };
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
        cases.push((format!("proof field {which}"), it.cm, it.u.clone(), it.v, p));
    }

    // The statement twins: v + 1, each coordinate, the swapped halves.
    cases.push((
        "v + 1".to_string(),
        it.cm,
        it.u.clone(),
        it.v + Fr::ONE,
        it.proof,
    ));
    for coordinate in 0..NUM_VARS {
        let mut u = it.u.clone();
        u[coordinate] += Fr::ONE;
        cases.push((format!("coordinate {coordinate}"), it.cm, u, it.v, it.proof));
    }
    let t = NUM_VARS / 2;
    let mut swapped = it.u[t..].to_vec();
    swapped.extend_from_slice(&it.u[..t]);
    cases.push(("u1/u2 swapped".to_string(), it.cm, swapped, it.v, it.proof));

    // The witness twin: an honest opening of a different polynomial.
    let mut flipped = it.values.clone();
    flipped[17] += Fr::ONE;
    let f = MultilinearPoly::new(PolyBacking::Fr(flipped));
    let mut tr = Transcript::new();
    let (v, proof) = open(&it.srs, &f, &it.cm, &it.u, &mut tr).expect("open");
    cases.push(("witness twin".to_string(), it.cm, it.u.clone(), v, proof));

    // Invalid points, which both paths must refuse before any pairing.
    let off_curve = G1Affine {
        x: curve::Fq::ONE,
        y: curve::Fq::ONE,
        infinity: false,
    };
    let mut p = it.proof;
    p.w = off_curve;
    cases.push(("off-curve w".to_string(), it.cm, it.u.clone(), it.v, p));
    cases.push((
        "off-curve cm".to_string(),
        MercuryCommitment(off_curve),
        it.u.clone(),
        it.v,
        it.proof,
    ));

    // An unsupported instance, which is refused before anything is absorbed.
    cases.push((
        "odd point".to_string(),
        it.cm,
        it.u[..7].to_vec(),
        it.v,
        it.proof,
    ));

    let mut honest = 0;
    for (name, cm, u, v, proof) in &cases {
        let (native, deferred) = both_ways(&it, cm, u, *v, proof);
        assert_eq!(native, deferred, "case `{name}` must agree");
        if native.is_ok() {
            honest += 1;
        }
    }
    assert_eq!(honest, 1, "exactly the honest case verifies");
    assert_eq!(cases.len(), 1 + 14 + 1 + NUM_VARS + 1 + 1 + 2 + 1);
}

/// The same, for the batch variants.
#[test]
fn batch_deferral_changes_no_verdict() {
    let num_vars = 6;
    let srs = common::toy_srs(num_vars as u32);
    let vsrs = srs.verifier();
    let mut rng = Rng::new(0x5009_0103);
    let cols: Vec<MultilinearPoly> = (0..3)
        .map(|_| common::random_poly(&mut rng, num_vars))
        .collect();
    let cms: Vec<MercuryCommitment> = cols
        .iter()
        .map(|f| commit(&srs, f).expect("commit"))
        .collect();
    let u = common::random_point(&mut rng, num_vars);
    let mut tr = Transcript::new();
    let (vs, proof) = batch_open(&srs, &cols, &cms, &u, &mut tr).expect("batch_open");

    let mut swapped_cms = cms.clone();
    swapped_cms.swap(0, 1);
    let mut moved_vs = vs.clone();
    moved_vs[1] += Fr::ONE;
    let mut damaged = proof;
    damaged.g_z += Fr::ONE;

    let cases: Vec<(&str, Vec<MercuryCommitment>, Vec<Fr>, MercuryProof)> = vec![
        ("honest", cms.clone(), vs.clone(), proof),
        ("swapped commitments", swapped_cms, vs.clone(), proof),
        ("moved value", cms.clone(), moved_vs, proof),
        ("damaged proof", cms.clone(), vs.clone(), damaged),
        (
            "dropped commitment",
            cms[..2].to_vec(),
            vs[..2].to_vec(),
            proof,
        ),
        ("empty", Vec::new(), Vec::new(), proof),
        ("length mismatch", cms.clone(), vs[..2].to_vec(), proof),
    ];

    let mut honest = 0;
    for (name, cs, values, p) in &cases {
        let mut tr = Transcript::new();
        let native = batch_verify(&vsrs, cs, &u, values, p, &mut tr);
        let mut tr = Transcript::new();
        let deferred = batch_verify_deferred(&vsrs, cs, &u, values, p, &mut tr)
            .and_then(|entries| discharge(&vsrs, &entries, &[entries.len()]));
        assert_eq!(native, deferred, "case `{name}` must agree");
        if native.is_ok() {
            honest += 1;
        }
    }
    assert_eq!(honest, 1);
}

// ---------------------------------------------------------------------------
// Acceptance 9 — concatenation and discharge
// ---------------------------------------------------------------------------

/// Two independent verifications concatenate into one accumulator, and it
/// discharges. Damaging either half, or the grouping, is rejected.
#[test]
fn two_verifications_concatenate_and_discharge() {
    let a = single(0x5009_0104);
    let b = single(0x5009_0105);
    let vsrs = a.srs.verifier();
    assert_eq!(vsrs, b.srs.verifier(), "the same SRS on both sides");

    let mut tr = Transcript::new();
    let first = verify_deferred(&vsrs, &a.cm, &a.u, a.v, &a.proof, &mut tr).expect("deferred");
    let mut tr = Transcript::new();
    let second = verify_deferred(&vsrs, &b.cm, &b.u, b.v, &b.proof, &mut tr).expect("deferred");
    assert_ne!(first, second, "two instances, two term sets");

    let joined: Vec<AccumulatorEntry> = [first.clone(), second.clone()].concat();
    let checks = [ENTRIES_PER_CHECK, ENTRIES_PER_CHECK];
    discharge(&vsrs, &joined, &checks).expect("the concatenation discharges");

    // Each half discharges on its own too, and the halves are independent.
    discharge(&vsrs, &first, &[ENTRIES_PER_CHECK]).expect("the first half");
    discharge(&vsrs, &second, &[ENTRIES_PER_CHECK]).expect("the second half");

    // Damage in either half fails the whole thing.
    for index in [0usize, 9, 11, 12, 21, 23] {
        let mut damaged = joined.clone();
        damaged[index].scalar += Fr::ONE;
        assert_eq!(
            discharge(&vsrs, &damaged, &checks),
            Err(PcsError::VerificationFailed),
            "entry {index}'s scalar"
        );

        let mut damaged = joined.clone();
        damaged[index].point = G1Projective::from(damaged[index].point)
            .add(&G1Projective::GENERATOR)
            .to_affine();
        assert_eq!(
            discharge(&vsrs, &damaged, &checks),
            Err(PcsError::VerificationFailed),
            "entry {index}'s point"
        );

        let mut damaged = joined.clone();
        damaged[index].side = match damaged[index].side {
            PairingSide::G2One => PairingSide::G2X,
            PairingSide::G2X => PairingSide::G2One,
        };
        assert_eq!(
            discharge(&vsrs, &damaged, &checks),
            Err(PcsError::VerificationFailed),
            "entry {index}'s side"
        );
    }

    // Either order is a valid accumulator. Both are true relations, so both
    // discharge whatever weights they get — a weight only ever matters to a
    // FALSE relation, which is what `the_per_check_weight_separates_the_checks`
    // is for. What IS observable here is that the two orders are different
    // accumulators, and the digest is what says so.
    let reversed: Vec<AccumulatorEntry> = [second.clone(), first.clone()].concat();
    discharge(&vsrs, &reversed, &checks).expect("either order is a valid accumulator");
    assert_ne!(
        accumulator_digest(&accumulator_words(&reversed, &checks).expect("words")),
        accumulator_digest(&accumulator_words(&joined, &checks).expect("words")),
        "the order of the checks is part of the accumulator"
    );

    // Two true relations still sum to a true one, so collapsing them into one
    // group is accepted here. That it would also be accepted for a FALSE pair
    // is the whole of the per-check weight's job, and has its own test.
    discharge(&vsrs, &joined, &[2 * ENTRIES_PER_CHECK])
        .expect("two true relations sum to a true one");

    // A grouping that does not partition the entries is an error, not a panic.
    for checks in [
        vec![ENTRIES_PER_CHECK],
        vec![ENTRIES_PER_CHECK, ENTRIES_PER_CHECK, 1],
        vec![usize::MAX],
        vec![],
    ] {
        assert!(
            matches!(
                discharge(&vsrs, &joined, &checks),
                Err(PcsError::MalformedAccumulator { .. })
            ),
            "checks {checks:?}"
        );
    }

    // An off-curve point in an entry is refused before any group operation.
    let mut invalid = joined.clone();
    invalid[3].point = G1Affine {
        x: curve::Fq::ONE,
        y: curve::Fq::ONE,
        infinity: false,
    };
    assert_eq!(
        discharge(&vsrs, &invalid, &checks),
        Err(PcsError::InvalidPoint {
            field: "accumulator entry"
        })
    );
}

/// The per-check weight is load-bearing: two relations whose errors cancel pass
/// an unweighted sum and fail a weighted one.
#[test]
fn the_per_check_weight_separates_the_checks() {
    let it = single(0x5009_0106);
    let vsrs = it.srs.verifier();
    let mut tr = Transcript::new();
    let honest = verify_deferred(&vsrs, &it.cm, &it.u, it.v, &it.proof, &mut tr).expect("deferred");

    // Two broken checks, equal and opposite: one has `+G` added to an `A` term,
    // the other `-G`. Their unweighted sum is the honest sum twice over.
    let mut plus = honest.clone();
    let mut minus = honest.clone();
    plus.push(AccumulatorEntry {
        side: PairingSide::G2One,
        scalar: Fr::ONE,
        point: G1Affine::GENERATOR,
    });
    minus.push(AccumulatorEntry {
        side: PairingSide::G2One,
        scalar: -Fr::ONE,
        point: G1Affine::GENERATOR,
    });

    // Each on its own is false.
    assert_eq!(
        discharge(&vsrs, &plus, &[plus.len()]),
        Err(PcsError::VerificationFailed)
    );
    assert_eq!(
        discharge(&vsrs, &minus, &[minus.len()]),
        Err(PcsError::VerificationFailed)
    );

    // Concatenated into ONE group they cancel and the sum passes — which is
    // exactly the attack.
    let joined: Vec<AccumulatorEntry> = [plus.clone(), minus.clone()].concat();
    discharge(&vsrs, &joined, &[joined.len()]).expect("the errors cancel in one group");

    // Grouped per check, the weights are `1` and `nu`, and they do not.
    assert_eq!(
        discharge(&vsrs, &joined, &[plus.len(), minus.len()]),
        Err(PcsError::VerificationFailed),
        "the per-check weight must break the cancellation"
    );
}

/// A predictable merge challenge would be forgeable, and the real one is not.
///
/// `nu` cannot be pinned by building a list that balances only under it: the
/// balancing scalar is `-1/nu`, that scalar is one of the words the digest
/// covers, and `nu` comes from the digest — so the construction chases its own
/// tail. What *can* be pinned is the consequence. A `discharge` whose `nu` an
/// adversary can guess is forgeable, so this test builds the forgery for one
/// guessable value and asserts the real `discharge` rejects it.
///
/// Where `nu` comes from is a source-level fact, and
/// `tests/structure.rs::the_merge_challenge_is_derived_from_the_digest` is
/// where it is held — the same instrument, and for the same reason, S08 used on
/// the pairing-merge challenge.
#[test]
fn a_predictable_merge_challenge_would_be_forgeable() {
    let it = single(0x5009_0108);
    let vsrs = it.srs.verifier();
    let mut tr = Transcript::new();
    let honest = verify_deferred(&vsrs, &it.cm, &it.u, it.v, &it.proof, &mut tr).expect("deferred");

    // Two false checks whose errors are `G` and `-G/7`: they cancel exactly
    // when the weights are `1` and `7`, and for no other second weight.
    let guess = Fr::from_u64(7);
    let mut first = honest.clone();
    first.push(AccumulatorEntry {
        side: PairingSide::G2One,
        scalar: Fr::ONE,
        point: G1Affine::GENERATOR,
    });
    let mut second = honest.clone();
    second.push(AccumulatorEntry {
        side: PairingSide::G2One,
        scalar: -guess.inverse().expect("7 is invertible"),
        point: G1Affine::GENERATOR,
    });
    let forged: Vec<AccumulatorEntry> = [first.clone(), second.clone()].concat();
    let checks = [first.len(), second.len()];

    // The forgery works against the guessed weights: run the discharge
    // arithmetic by hand with `[1, 7]` and watch the pairing pass.
    let weigh = |weights: [Fr; 2]| {
        let mut a = G1Projective::IDENTITY;
        let mut b = G1Projective::IDENTITY;
        for (group, weight) in [&first, &second].iter().zip(weights) {
            for e in group.iter() {
                let term = G1Projective::from(e.point).mul(&(weight * e.scalar));
                match e.side {
                    PairingSide::G2One => a = a.add(&term),
                    PairingSide::G2X => b = b.add(&term),
                }
            }
        }
        curve::pairing::pairing_check(&[
            (a.to_affine(), vsrs.g2_gen),
            (-b.to_affine(), vsrs.g2_tau),
        ])
    };
    assert!(
        weigh([Fr::ONE, guess]),
        "the forgery must really pass against the guessed weights"
    );
    assert!(!weigh([Fr::ONE, Fr::ONE]), "and fail against weight 1");

    // And the real discharge, whose `nu` is not 7, rejects it.
    assert_eq!(
        discharge(&vsrs, &forged, &checks),
        Err(PcsError::VerificationFailed),
        "a discharge with a guessable merge challenge would accept this"
    );
}

/// An empty accumulator discharges successfully — `docs/spec/accumulator.md`
/// §6 states it, so it is asserted rather than left to `msm`'s empty case and
/// `pairing_check`'s vacuous truth to keep agreeing by accident.
#[test]
fn an_empty_accumulator_discharges() {
    let it = single(0x5009_0109);
    let vsrs = it.srs.verifier();
    discharge(&vsrs, &[], &[]).expect("no relations is a true conjunction of relations");
    discharge(&vsrs, &[], &[0, 0]).expect("and so is two empty groups of them");
}

// ---------------------------------------------------------------------------
// Acceptance 10 — the wire form
// ---------------------------------------------------------------------------

/// Every entry is six words and 192 bytes, whatever it holds, and the words
/// round trip through the decoder.
#[test]
fn the_entry_length_is_constant() {
    assert_eq!(ENTRY_WORDS, 6);
    assert_eq!(ENTRIES_PER_CHECK, 12);

    let it = single(0x5009_0107);
    let vsrs = it.srs.verifier();
    let mut tr = Transcript::new();
    let entries =
        verify_deferred(&vsrs, &it.cm, &it.u, it.v, &it.proof, &mut tr).expect("deferred");

    let words = accumulator_words(&entries, &[ENTRIES_PER_CHECK]).expect("words");
    assert_eq!(words.len(), 1 + ENTRIES_PER_CHECK * ENTRY_WORDS);
    assert_eq!(
        accumulator_from_words(&words).expect("decode"),
        (entries.clone(), vec![ENTRIES_PER_CHECK])
    );

    // An infinity point costs the same six words as any other.
    let mut with_infinity = entries.clone();
    with_infinity[0].point = G1Affine::IDENTITY;
    let infinite = accumulator_words(&with_infinity, &[ENTRIES_PER_CHECK]).expect("words");
    assert_eq!(infinite.len(), words.len());
    assert_eq!(
        accumulator_from_words(&infinite).expect("decode"),
        (with_infinity, vec![ENTRIES_PER_CHECK])
    );

    // The digest binds the GROUPING, not just the entries: the same twelve
    // entries split two ways are two different accumulators.
    let one_group = accumulator_words(&entries, &[ENTRIES_PER_CHECK]).expect("words");
    let two_groups = accumulator_words(&entries, &[5, ENTRIES_PER_CHECK - 5]).expect("words");
    assert_ne!(one_group, two_groups);
    assert_ne!(
        accumulator_digest(&one_group),
        accumulator_digest(&two_groups),
        "a regrouping must move the digest"
    );

    // The digest moves with every word, and a concatenation is not a half.
    let joined: Vec<Fr> = [words.clone(), words.clone()].concat();
    assert_ne!(accumulator_digest(&joined), accumulator_digest(&words));
    for index in [0usize, 1, 2, 3, words.len() - 1] {
        let mut moved = words.clone();
        moved[index] += Fr::ONE;
        assert_ne!(
            accumulator_digest(&moved),
            accumulator_digest(&words),
            "word {index} binds the digest"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance 9 — the committed accumulator
// ---------------------------------------------------------------------------

const KAT: &str = include_str!("vectors/accumulator.txt");

/// The fixture's single-opening instance.
struct SingleKat {
    values: Vec<Fr>,
    point: Vec<Fr>,
    claim: Fr,
    cm: MercuryCommitment,
    proof: MercuryProof,
}

/// The fixture's batched instance.
struct BatchKat {
    columns: Vec<Vec<Fr>>,
    point: Vec<Fr>,
    claims: Vec<Fr>,
    cms: Vec<MercuryCommitment>,
    proof: MercuryProof,
}

/// The fixture's two instances, parsed.
struct AccumulatorKat {
    tau: Fr,
    single: SingleKat,
    batch: BatchKat,
    words: Vec<Fr>,
    digest: Fr,
}

fn parse_kat(text: &str) -> Result<AccumulatorKat, String> {
    let mut tau = None;
    let mut num_vars = None;
    let (mut sv, mut sp) = (Vec::new(), Vec::new());
    let (mut sc, mut scm, mut sproof) = (None, None, None);
    let mut bv: Vec<Vec<Fr>> = Vec::new();
    let (mut bp, mut bc, mut bcm) = (Vec::new(), Vec::new(), Vec::new());
    let mut bproof = None;
    let mut words: Vec<Fr> = Vec::new();
    let mut digest = None;

    for fields in common::records(text) {
        match (fields[0].as_str(), fields.len()) {
            ("tau", 2) => tau = Some(common::parse_fr(&fields[1])?),
            ("numvars", 2) => {
                num_vars = Some(fields[1].parse::<usize>().map_err(|e| e.to_string())?)
            }
            ("single_value", 3) => {
                if fields[1].parse::<usize>() != Ok(sv.len()) {
                    return Err("single_value must be in index order".to_string());
                }
                sv.push(common::parse_fr(&fields[2])?);
            }
            ("single_point", 3) => {
                if fields[1].parse::<usize>() != Ok(sp.len()) {
                    return Err("single_point must be in variable order".to_string());
                }
                sp.push(common::parse_fr(&fields[2])?);
            }
            ("single_claim", 2) => sc = Some(common::parse_fr(&fields[1])?),
            ("single_cm", 2) => scm = Some(MercuryCommitment(common::parse_g1(&fields[1])?)),
            ("single_proof", 2) => sproof = Some(common::parse_proof(&fields[1])?),
            ("batch_value", 4) => {
                let column = fields[1].parse::<usize>().map_err(|e| e.to_string())?;
                if column > bv.len() {
                    return Err("batch_value must be in column order".to_string());
                }
                if column == bv.len() {
                    bv.push(Vec::new());
                }
                if fields[2].parse::<usize>() != Ok(bv[column].len()) {
                    return Err("batch_value must be in index order".to_string());
                }
                bv[column].push(common::parse_fr(&fields[3])?);
            }
            ("batch_point", 3) => {
                if fields[1].parse::<usize>() != Ok(bp.len()) {
                    return Err("batch_point must be in variable order".to_string());
                }
                bp.push(common::parse_fr(&fields[2])?);
            }
            ("batch_claim", 3) => {
                if fields[1].parse::<usize>() != Ok(bc.len()) {
                    return Err("batch_claim must be in column order".to_string());
                }
                bc.push(common::parse_fr(&fields[2])?);
            }
            ("batch_cm", 3) => {
                if fields[1].parse::<usize>() != Ok(bcm.len()) {
                    return Err("batch_cm must be in column order".to_string());
                }
                bcm.push(MercuryCommitment(common::parse_g1(&fields[2])?));
            }
            ("batch_proof", 2) => bproof = Some(common::parse_proof(&fields[1])?),
            ("word", 3) => {
                if fields[1].parse::<usize>() != Ok(words.len()) {
                    return Err("words must be in order".to_string());
                }
                words.push(common::parse_fr(&fields[2])?);
            }
            ("digest", 2) => digest = Some(common::parse_fr(&fields[1])?),
            (other, n) => return Err(format!("unknown record `{other}` with {n} fields")),
        }
    }

    let num_vars = num_vars.ok_or("no numvars record")?;
    if sv.len() != 1usize << num_vars || sp.len() != num_vars || bp.len() != num_vars {
        return Err("an instance does not match numvars".to_string());
    }
    if bv.len() != bc.len() || bv.len() != bcm.len() || bv.is_empty() {
        return Err("the batch's three lists must agree in length".to_string());
    }
    if bv.iter().any(|c| c.len() != 1usize << num_vars) {
        return Err("a batch column does not match numvars".to_string());
    }
    Ok(AccumulatorKat {
        tau: tau.ok_or("no tau record")?,
        single: SingleKat {
            values: sv,
            point: sp,
            claim: sc.ok_or("no single_claim record")?,
            cm: scm.ok_or("no single_cm record")?,
            proof: sproof.ok_or("no single_proof record")?,
        },
        batch: BatchKat {
            columns: bv,
            point: bp,
            claims: bc,
            cms: bcm,
            proof: bproof.ok_or("no batch_proof record")?,
        },
        words,
        digest: digest.ok_or("no digest record")?,
    })
}

/// The whole replay, as one fallible routine so a corrupted fixture has
/// something to fail (master rule 8).
fn replay_kat(text: &str) -> Result<(), String> {
    let kat = parse_kat(text)?;
    if kat.tau != Fr::from_hex(common::TOY_TAU).expect("the toy tau is canonical") {
        return Err("the fixture's tau is not the toy tau".to_string());
    }
    let single = kat.single;
    let batch = kat.batch;
    let srs = common::toy_srs(single.point.len() as u32);
    let vsrs = srs.verifier();

    // The commitments really commit to the witnesses the fixture carries.
    let f = MultilinearPoly::new(PolyBacking::Fr(single.values));
    if commit(&srs, &f).map_err(|e| format!("{e:?}"))? != single.cm {
        return Err("the single commitment does not match its witness".to_string());
    }
    for (i, column) in batch.columns.iter().enumerate() {
        let f = MultilinearPoly::new(PolyBacking::Fr(column.clone()));
        if commit(&srs, &f).map_err(|e| format!("{e:?}"))? != batch.cms[i] {
            return Err(format!("batch commitment {i} does not match its column"));
        }
    }

    // Two independent deferred verifications, concatenated in fixture order.
    let mut tr = Transcript::new();
    let first = verify_deferred(
        &vsrs,
        &single.cm,
        &single.point,
        single.claim,
        &single.proof,
        &mut tr,
    )
    .map_err(|e| format!("{e:?}"))?;
    let mut tr = Transcript::new();
    let second = batch_verify_deferred(
        &vsrs,
        &batch.cms,
        &batch.point,
        &batch.claims,
        &batch.proof,
        &mut tr,
    )
    .map_err(|e| format!("{e:?}"))?;
    if first.len() != ENTRIES_PER_CHECK || second.len() != ENTRIES_PER_CHECK {
        return Err("a deferred check must be twelve entries".to_string());
    }

    let entries: Vec<AccumulatorEntry> = [first, second].concat();
    let checks = [ENTRIES_PER_CHECK, ENTRIES_PER_CHECK];
    let words = accumulator_words(&entries, &checks).map_err(|e| format!("{e:?}"))?;
    if words != kat.words {
        return Err("the accumulator words do not match the committed layout".to_string());
    }
    if accumulator_digest(&words) != kat.digest {
        return Err("the accumulator digest does not match".to_string());
    }
    // The words decode back to exactly these entries and this grouping.
    if accumulator_from_words(&words).map_err(|e| format!("{e:?}"))?
        != (entries.clone(), checks.to_vec())
    {
        return Err("the committed words do not decode to their entries".to_string());
    }
    discharge(&vsrs, &entries, &checks).map_err(|e| format!("{e:?}"))?;
    Ok(())
}

/// Acceptance 9: the committed accumulator replays word for word, and its
/// concatenation discharges.
#[test]
fn the_committed_accumulator_replays() {
    replay_kat(KAT).expect("the committed accumulator replays");

    // And the file really holds what the layout says it does: two groups, each
    // a count word followed by twelve six-word entries.
    let kat = parse_kat(KAT).expect("parse");
    assert_eq!(kat.words.len(), 2 * (1 + ENTRIES_PER_CHECK * ENTRY_WORDS));
    assert_eq!(kat.words[0], Fr::from_u64(ENTRIES_PER_CHECK as u64));
    assert_eq!(
        kat.words[1 + ENTRIES_PER_CHECK * ENTRY_WORDS],
        Fr::from_u64(ENTRIES_PER_CHECK as u64)
    );
    assert_eq!(kat.words.len() * 32, 2 * (32 + ENTRIES_PER_CHECK * 192));
}

/// Master rule 8: the replayer must be able to fail.
#[test]
fn a_corrupted_accumulator_fixture_is_rejected() {
    let body: String = KAT
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(replay_kat(&body).is_ok(), "the control");

    let damaged = |from: &str, to: &str| {
        let text = body.replacen(from, to, 1);
        assert_ne!(text, body, "the edit must land");
        assert!(replay_kat(&text).is_err(), "{from} -> {to}");
    };

    for record in [
        "single_value 0 ",
        "single_point 0 ",
        "single_claim ",
        "single_cm ",
        "single_proof ",
        "batch_value 0 0 ",
        "batch_point 0 ",
        "batch_claim 0 ",
        "batch_cm 0 ",
        "batch_proof ",
        "word 0 ",
        "word 1 ",
        "word 73 ",
        "digest ",
    ] {
        let line = body
            .lines()
            .find(|l| l.starts_with(record))
            .unwrap_or_else(|| panic!("the {record} record"))
            .to_string();
        let token = line.split_whitespace().last().expect("a token");
        damaged(token, &flip_first_digit(token));
    }

    damaged("numvars 4", "numvars 6");
    damaged("word 5 ", "# word 5 ");
    damaged("batch_cm 2 ", "# batch_cm 2 ");
    damaged("tau ", "tao ");
}

fn flip_first_digit(token: &str) -> String {
    let mut bytes = token.to_string().into_bytes();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).expect("hex is ASCII")
}

/// The fixture is the committed one.
#[test]
fn the_committed_accumulator_file_is_the_pinned_one() {
    assert_eq!(
        test_support::to_hex(&test_support::sha256(KAT.as_bytes())),
        "3ecd609ae0b032641f4db650b33113981a883ec6801aedf7793a8534a019c4c2"
    );
}
