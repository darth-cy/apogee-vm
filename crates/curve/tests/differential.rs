//! In-process differential test against ark-bn254, from a fixed seed so a
//! failure reproduces exactly.
//!
//! The committed fixtures freeze arkworks' answers as of the day they were
//! generated. This file asks the arkworks in the current dependency graph the
//! same questions live, which is the check that notices if the two ever part
//! ways. Acceptance 8 asks for at least 500 random group operations in one
//! run: [`G1_ROUNDS`] and [`G2_ROUNDS`] contribute 5 each, for 1,500.

mod common;

use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::Field as _;
use common::{
    ark_fq2_bytes, ark_fq_bytes, ark_g1_bytes, ark_g2_bytes, next_fq, next_fq2, next_fr, to_ark_fq,
    to_ark_fq2, to_ark_fr, to_ark_g1, to_ark_g2,
};
use curve::{Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use test_support::Rng;

const FIELD_ROUNDS: usize = 1_000;
/// Five group operations per round: add, mixed add, double, scalar mul, neg.
const G1_ROUNDS: usize = 200;
const G2_ROUNDS: usize = 100;
const SEED: u64 = 0x0500_d1ff_0000_0001;

fn same_fq(ours: &Fq, theirs: &ark_bn254::Fq, what: &str, round: usize) {
    assert_eq!(
        ours.to_bytes(),
        ark_fq_bytes(theirs),
        "{what} mismatch at round {round} (seed {SEED:#x})"
    );
}

fn same_fq2(ours: &Fq2, theirs: &ark_bn254::Fq2, what: &str, round: usize) {
    assert_eq!(
        ours.to_bytes(),
        ark_fq2_bytes(theirs),
        "{what} mismatch at round {round} (seed {SEED:#x})"
    );
}

fn same_g1(ours: &G1Affine, theirs: &ark_bn254::G1Affine, what: &str, round: usize) {
    assert_eq!(
        ours.to_bytes(),
        ark_g1_bytes(theirs),
        "{what} mismatch at round {round} (seed {SEED:#x})"
    );
}

fn same_g2(ours: &G2Affine, theirs: &ark_bn254::G2Affine, what: &str, round: usize) {
    assert_eq!(
        ours.to_bytes(),
        ark_g2_bytes(theirs),
        "{what} mismatch at round {round} (seed {SEED:#x})"
    );
}

// ---------------------------------------------------------------------------
// Fq and Fq2
// ---------------------------------------------------------------------------

#[test]
fn fq_arithmetic_matches_arkworks() {
    let mut rng = Rng::new(SEED);
    for round in 0..FIELD_ROUNDS {
        let (a, b) = (next_fq(&mut rng), next_fq(&mut rng));
        let (x, y) = (to_ark_fq(&a), to_ark_fq(&b));
        same_fq(&(a + b), &(x + y), "add", round);
        same_fq(&(a - b), &(x - y), "sub", round);
        same_fq(&(a * b), &(x * y), "mul", round);
        same_fq(&(-a), &(-x), "neg", round);
        same_fq(&a.square(), &x.square(), "square", round);
        same_fq(
            &a.inverse().expect("a random Fq is nonzero"),
            &x.inverse().expect("likewise"),
            "inverse",
            round,
        );

        let exp = rng.next_exp();
        same_fq(&a.pow(&exp), &ark_ff::Field::pow(&x, exp), "pow", round);

        // Both sides compute a^((q+1)/4) for q = 3 mod 4, so the roots agree
        // exactly, not merely up to sign.
        match (a.sqrt(), x.sqrt()) {
            (Some(ours), Some(theirs)) => same_fq(&ours, &theirs, "sqrt", round),
            (None, None) => {}
            (ours, theirs) => panic!(
                "sqrt existence disagrees at round {round}: {:?} vs {}",
                ours,
                theirs.is_some()
            ),
        }
    }
}

#[test]
fn fq2_arithmetic_matches_arkworks() {
    let xi = <ark_bn254::Fq6Config as ark_ff::fields::Fp6Config>::NONRESIDUE;
    let mut rng = Rng::new(SEED ^ 1);
    for round in 0..FIELD_ROUNDS {
        let (a, b) = (next_fq2(&mut rng), next_fq2(&mut rng));
        let (x, y) = (to_ark_fq2(&a), to_ark_fq2(&b));
        same_fq2(&(a + b), &(x + y), "add", round);
        same_fq2(&(a - b), &(x - y), "sub", round);
        same_fq2(&(a * b), &(x * y), "mul", round);
        same_fq2(&(-a), &(-x), "neg", round);
        same_fq2(&a.square(), &x.square(), "square", round);
        same_fq2(
            &a.inverse().expect("a random Fq2 is nonzero"),
            &x.inverse().expect("likewise"),
            "inverse",
            round,
        );
        let mut conjugated = x;
        conjugated.conjugate_in_place();
        same_fq2(&a.conjugate(), &conjugated, "conjugate", round);
        same_fq2(
            &a.mul_by_nonresidue(),
            &(x * xi),
            "mul_by_nonresidue",
            round,
        );
        same_fq(&a.norm(), &x.norm(), "norm", round);

        // arkworks uses the Adj–Rodriguez-Henriquez algorithm here and this
        // crate uses the closed form, so the two can pick opposite roots.
        match (a.sqrt(), x.sqrt()) {
            (Some(ours), Some(theirs)) => {
                assert_eq!(ours.square(), a, "our root does not square back");
                assert!(
                    ours.to_bytes() == ark_fq2_bytes(&theirs)
                        || (-ours).to_bytes() == ark_fq2_bytes(&theirs),
                    "sqrt disagrees beyond a sign at round {round}"
                );
            }
            (None, None) => {}
            (ours, theirs) => panic!(
                "sqrt existence disagrees at round {round}: {:?} vs {}",
                ours,
                theirs.is_some()
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// The groups
// ---------------------------------------------------------------------------

#[test]
fn g1_group_ops_match_arkworks() {
    let mut rng = Rng::new(SEED ^ 2);
    for round in 0..G1_ROUNDS {
        let k = next_fr(&mut rng);
        let p = G1Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine();
        let q = G1Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine();
        let (x, y) = (to_ark_g1(&p), to_ark_g1(&q));
        let (pp, qp) = (G1Projective::from(p), G1Projective::from(q));

        same_g1(
            &pp.add(&qp).to_affine(),
            &(x + y).into_affine(),
            "add",
            round,
        );
        same_g1(
            &pp.add_affine(&q).to_affine(),
            &(x + y).into_affine(),
            "mixed add",
            round,
        );
        same_g1(
            &pp.double().to_affine(),
            &x.into_group().double().into_affine(),
            "double",
            round,
        );
        same_g1(
            &pp.mul(&k).to_affine(),
            &(x.into_group() * to_ark_fr(&k)).into_affine(),
            "scalar mul",
            round,
        );
        same_g1(&(-p), &(-x), "neg", round);

        assert_eq!(
            p.is_on_curve(),
            x.is_on_curve(),
            "is_on_curve disagrees at round {round}"
        );
        assert_eq!(
            p.is_in_subgroup(),
            x.is_in_correct_subgroup_assuming_on_curve(),
            "is_in_subgroup disagrees at round {round}"
        );
    }

    // `batch_to_affine` against arkworks' own batch normalization, identities
    // included. Both sides are built from the same scalars rather than from
    // each other, so nothing of ours is on both sides of the comparison.
    let scalars: Vec<Option<_>> = (0..64)
        .map(|i| {
            if i % 9 == 0 {
                None
            } else {
                Some(next_fr(&mut rng))
            }
        })
        .collect();
    let ours = G1Projective::batch_to_affine(
        &scalars
            .iter()
            .map(|k| match k {
                None => G1Projective::IDENTITY,
                Some(k) => G1Projective::GENERATOR.mul(k),
            })
            .collect::<Vec<_>>(),
    );
    let theirs = ark_bn254::G1Projective::normalize_batch(
        &scalars
            .iter()
            .map(|k| match k {
                None => ark_bn254::G1Projective::default(),
                Some(k) => ark_bn254::G1Projective::generator() * to_ark_fr(k),
            })
            .collect::<Vec<_>>(),
    );
    assert_eq!(ours.len(), theirs.len());
    for (i, (o, t)) in ours.iter().zip(theirs.iter()).enumerate() {
        same_g1(o, t, "batch_to_affine", i);
    }
}

#[test]
fn g2_group_ops_match_arkworks() {
    let mut rng = Rng::new(SEED ^ 3);
    for round in 0..G2_ROUNDS {
        let k = next_fr(&mut rng);
        let p = G2Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine();
        let q = G2Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine();
        let (x, y) = (to_ark_g2(&p), to_ark_g2(&q));
        let (pp, qp) = (G2Projective::from(p), G2Projective::from(q));

        same_g2(
            &pp.add(&qp).to_affine(),
            &(x + y).into_affine(),
            "add",
            round,
        );
        same_g2(
            &pp.add_affine(&q).to_affine(),
            &(x + y).into_affine(),
            "mixed add",
            round,
        );
        same_g2(
            &pp.double().to_affine(),
            &x.into_group().double().into_affine(),
            "double",
            round,
        );
        same_g2(
            &pp.mul(&k).to_affine(),
            &(x.into_group() * to_ark_fr(&k)).into_affine(),
            "scalar mul",
            round,
        );
        same_g2(&(-p), &(-x), "neg", round);

        assert_eq!(
            p.is_on_curve(),
            x.is_on_curve(),
            "is_on_curve disagrees at round {round}"
        );
        assert_eq!(
            p.is_in_subgroup(),
            x.is_in_correct_subgroup_assuming_on_curve(),
            "is_in_subgroup disagrees at round {round}"
        );
    }
}

/// The subgroup check is only interesting on points that fail it, and those
/// are the ones arkworks and this crate have to agree about.
#[test]
fn g2_subgroup_check_matches_arkworks_off_the_subgroup() {
    let mut rng = Rng::new(SEED ^ 4);
    let b2 = <ark_bn254::g2::Config as ark_ec::short_weierstrass::SWCurveConfig>::COEFF_B;
    let mut found = 0;
    while found < 16 {
        let x = next_fq2(&mut rng);
        let ark_x = to_ark_fq2(&x);
        let Some(ark_y) = (ark_x * ark_x * ark_x + b2).sqrt() else {
            continue;
        };
        let theirs = ark_bn254::G2Affine::new_unchecked(ark_x, ark_y);
        let ours = G2Affine {
            x,
            y: Fq2::from_bytes(&ark_fq2_bytes(&ark_y)).expect("canonical"),
            infinity: false,
        };
        assert!(ours.is_on_curve() && theirs.is_on_curve());
        assert_eq!(
            ours.is_in_subgroup(),
            theirs.is_in_correct_subgroup_assuming_on_curve(),
            "subgroup verdict disagrees on an un-cleared point"
        );
        assert!(!ours.is_in_subgroup(), "un-cleared points are not in G2");
        found += 1;
    }
}
