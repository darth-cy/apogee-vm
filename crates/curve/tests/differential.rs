//! In-process differential test against ark-bn254, from a fixed seed so a
//! failure reproduces exactly.
//!
//! The committed fixtures freeze arkworks' answers as of the day they were
//! generated. This file asks the arkworks in the current dependency graph the
//! same questions live, which is the check that notices if the two ever part
//! ways. Acceptance 8 asks for at least 500 random group operations in one
//! run: [`G1_ROUNDS`] and [`G2_ROUNDS`] contribute 5 each, for 1,500.

mod common;

use ark_ec::pairing::Pairing as _;
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::Field as _;
use common::{
    ark_fq2_bytes, ark_fq_bytes, ark_g1_bytes, ark_g2_bytes, next_fq, next_fq2, next_fr, to_ark_fq,
    to_ark_fq12, to_ark_fq2, to_ark_fq6, to_ark_fr, to_ark_g1, to_ark_g2,
};
use constants::{BN_PARAMETER_X, FQ_MODULUS, FR_MODULUS};
use curve::pairing::{final_exponentiation, miller_loop, pairing};
use curve::{Fq, Fq12, Fq2, Fq6, G1Affine, G1Projective, G2Affine, G2Projective};
use num_bigint::BigUint;
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

// ---------------------------------------------------------------------------
// The tower and the pairing (S06)
// ---------------------------------------------------------------------------

/// Five Fq6 and six Fq12 operations per round, plus every Frobenius power.
const TOWER_ROUNDS: usize = 50;
/// Two independent comparisons per round, each a full pairing.
const PAIRING_ROUNDS: usize = 20;

fn next_fq6(rng: &mut Rng) -> Fq6 {
    Fq6::new(next_fq2(rng), next_fq2(rng), next_fq2(rng))
}

fn next_fq12(rng: &mut Rng) -> Fq12 {
    Fq12::new(next_fq6(rng), next_fq6(rng))
}

fn same_fq6(ours: &Fq6, theirs: &ark_bn254::Fq6, what: &str, round: usize) {
    same_fq2(&ours.c0, &theirs.c0, what, round);
    same_fq2(&ours.c1, &theirs.c1, what, round);
    same_fq2(&ours.c2, &theirs.c2, what, round);
}

fn same_fq12(ours: &Fq12, theirs: &ark_bn254::Fq12, what: &str, round: usize) {
    same_fq6(&ours.c0, &theirs.c0, what, round);
    same_fq6(&ours.c1, &theirs.c1, what, round);
}

fn big_from_limbs(limbs: &[u64; 4]) -> BigUint {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

fn limbs_of(value: &BigUint) -> [u64; 4] {
    let digits = value.to_u64_digits();
    assert!(digits.len() <= 4, "the value must fit in four limbs");
    let mut out = [0u64; 4];
    out[..digits.len()].copy_from_slice(&digits);
    out
}

/// `(q^12 - 1)/r`, the exact final exponent.
fn full_final_exponent() -> BigUint {
    let (q, r) = (big_from_limbs(&FQ_MODULUS), big_from_limbs(&FR_MODULUS));
    let numerator = q.pow(12) - BigUint::from(1u32);
    let exponent = &numerator / &r;
    assert_eq!(&exponent * &r, numerator, "r divides q^12 - 1");
    exponent
}

/// `m = 2x(6x^2 + 3x + 1) mod r`, the fixed multiplier arkworks' own final
/// exponentiation introduces.
fn fuentes_castaneda_multiplier() -> BigUint {
    let x = BigUint::from(BN_PARAMETER_X);
    let m = BigUint::from(2u32)
        * &x
        * (BigUint::from(6u32) * &x * &x + BigUint::from(3u32) * &x + BigUint::from(1u32));
    m % big_from_limbs(&FR_MODULUS)
}

/// Random Fq6 and Fq12 rounds on top of the committed corpus, on a different
/// seed and against whatever arkworks is in the graph today.
#[test]
fn tower_arithmetic_matches_arkworks() {
    let mut rng = Rng::new(SEED ^ 0x0600);
    for round in 0..TOWER_ROUNDS {
        let (a, b) = (next_fq6(&mut rng), next_fq6(&mut rng));
        let (ark_a, ark_b) = (to_ark_fq6(&a), to_ark_fq6(&b));
        same_fq6(&(a + b), &(ark_a + ark_b), "fq6 add", round);
        same_fq6(&(a - b), &(ark_a - ark_b), "fq6 sub", round);
        same_fq6(&(a * b), &(ark_a * ark_b), "fq6 mul", round);
        same_fq6(&a.square(), &ark_a.square(), "fq6 square", round);
        same_fq6(
            &a.inverse().expect("nonzero"),
            &ark_a.inverse().expect("nonzero"),
            "fq6 inverse",
            round,
        );
        for power in 0..6 {
            let mut theirs = ark_a;
            theirs.frobenius_map_in_place(power);
            same_fq6(&a.frobenius_map(power), &theirs, "fq6 frobenius", round);
        }

        let (a, b) = (next_fq12(&mut rng), next_fq12(&mut rng));
        let (ark_a, ark_b) = (to_ark_fq12(&a), to_ark_fq12(&b));
        same_fq12(&(a + b), &(ark_a + ark_b), "fq12 add", round);
        same_fq12(&(a - b), &(ark_a - ark_b), "fq12 sub", round);
        same_fq12(&(a * b), &(ark_a * ark_b), "fq12 mul", round);
        same_fq12(&a.square(), &ark_a.square(), "fq12 square", round);
        same_fq12(
            &a.inverse().expect("nonzero"),
            &ark_a.inverse().expect("nonzero"),
            "fq12 inverse",
            round,
        );
        let mut conj = ark_a;
        conj.conjugate_in_place();
        same_fq12(&a.conjugate(), &conj, "fq12 conjugate", round);
        for power in 0..12 {
            let mut theirs = ark_a;
            theirs.frobenius_map_in_place(power);
            same_fq12(&a.frobenius_map(power), &theirs, "fq12 frobenius", round);
        }
    }
}

/// The whole pairing against arkworks, twice over, on fresh inputs.
///
/// 1. Against the **definition**: arkworks' Miller loop raised to the literal
///    integer `(q^12 - 1)/r`. That is what the committed fixtures carry, and
///    it depends on no library's choice of decomposition.
/// 2. Against arkworks' **own complete pipeline** — precomputed G2 line
///    coefficients, sparse `mul_by_034`, cyclotomic squarings and the
///    Fuentes-Castaneda hard part, none of which this crate has. That routine
///    returns `f^(m d)` rather than `f^d`, so the comparison raises our value
///    to `m` first. `r` is prime and `m` is nonzero mod `r`, so `f -> f^m` is
///    a bijection of the order-`r` subgroup and the comparison is an equality
///    test rather than a weaker one.
#[test]
fn pairing_matches_arkworks() {
    let mut rng = Rng::new(SEED ^ 0x0601);
    let exponent = full_final_exponent();
    let m = fuentes_castaneda_multiplier();
    assert_ne!(
        m,
        BigUint::from(0u32),
        "m must be invertible mod the prime r for the m-power comparison to be exact"
    );

    for round in 0..PAIRING_ROUNDS {
        let p = G1Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine();
        let q = G2Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine();
        let ours = pairing(&p, &q);

        let ark_miller = ark_bn254::Bn254::multi_miller_loop([to_ark_g1(&p)], [to_ark_g2(&q)]).0;
        same_fq12(
            &ours,
            &ark_miller.pow(exponent.to_u64_digits()),
            "pairing vs the literal exponent",
            round,
        );
        same_fq12(
            &ours.pow(&limbs_of(&m)),
            &ark_bn254::Bn254::pairing(to_ark_g1(&p), to_ark_g2(&q)).0,
            "pairing^m vs arkworks' own pairing",
            round,
        );
    }

    // ...and the shared-iteration multi-pair loop against arkworks' own.
    for k in [2usize, 3, 5] {
        let pairs: Vec<(G1Affine, G2Affine)> = (0..k)
            .map(|_| {
                (
                    G1Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine(),
                    G2Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine(),
                )
            })
            .collect();
        let ours = final_exponentiation(&miller_loop(&pairs));
        let ark_miller = ark_bn254::Bn254::multi_miller_loop(
            pairs.iter().map(|(p, _)| to_ark_g1(p)).collect::<Vec<_>>(),
            pairs.iter().map(|(_, q)| to_ark_g2(q)).collect::<Vec<_>>(),
        )
        .0;
        same_fq12(
            &ours,
            &ark_miller.pow(exponent.to_u64_digits()),
            "multi-pair vs the literal exponent",
            k,
        );
    }
}
