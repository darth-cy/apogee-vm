//! In-process differential test against ark-bn254: 1,000 randomized inputs per
//! operator, from a fixed seed, so a failure reproduces exactly.

mod common;

use common::{ark_to_bytes, next_canonical, next_fr, to_ark};
use field::{batch_inverse, Fr};
use test_support::Rng;

const ROUNDS: usize = 1_000;
const SEED: u64 = 0x5001_f1e1_d000_0001;

/// Every comparison goes through the canonical wire form, which also exercises
/// `to_bytes` on every single result.
fn assert_same(ours: &Fr, theirs: &ark_bn254::Fr, what: &str, round: usize) {
    assert_eq!(
        ours.to_bytes(),
        ark_to_bytes(theirs),
        "{what} mismatch at round {round} (seed {SEED:#x})"
    );
}

#[test]
fn add_matches_arkworks() {
    let mut rng = Rng::new(SEED);
    for round in 0..ROUNDS {
        let (a, b) = (next_fr(&mut rng), next_fr(&mut rng));
        assert_same(&(a + b), &(to_ark(&a) + to_ark(&b)), "add", round);
    }
}

#[test]
fn sub_matches_arkworks() {
    let mut rng = Rng::new(SEED ^ 1);
    for round in 0..ROUNDS {
        let (a, b) = (next_fr(&mut rng), next_fr(&mut rng));
        assert_same(&(a - b), &(to_ark(&a) - to_ark(&b)), "sub", round);
    }
}

#[test]
fn mul_matches_arkworks() {
    let mut rng = Rng::new(SEED ^ 2);
    for round in 0..ROUNDS {
        let (a, b) = (next_fr(&mut rng), next_fr(&mut rng));
        assert_same(&(a * b), &(to_ark(&a) * to_ark(&b)), "mul", round);
    }
}

#[test]
fn neg_matches_arkworks() {
    let mut rng = Rng::new(SEED ^ 3);
    for round in 0..ROUNDS {
        let a = next_fr(&mut rng);
        assert_same(&(-a), &(-to_ark(&a)), "neg", round);
    }
}

#[test]
fn square_matches_arkworks() {
    let mut rng = Rng::new(SEED ^ 4);
    for round in 0..ROUNDS {
        let a = next_fr(&mut rng);
        let theirs = to_ark(&a) * to_ark(&a);
        assert_same(&a.square(), &theirs, "square", round);
    }
}

#[test]
fn inverse_matches_arkworks() {
    let mut rng = Rng::new(SEED ^ 5);
    for round in 0..ROUNDS {
        let a = next_fr(&mut rng);
        let theirs = ark_ff::Field::inverse(&to_ark(&a)).expect("random element is nonzero");
        assert_same(&a.inverse().expect("nonzero"), &theirs, "inverse", round);
        assert_eq!(
            a * a.inverse().unwrap(),
            Fr::ONE,
            "a * a^-1 at round {round}"
        );
    }
}

#[test]
fn pow_matches_arkworks() {
    let mut rng = Rng::new(SEED ^ 6);
    for round in 0..ROUNDS {
        let a = next_fr(&mut rng);
        let e = rng.next_exp();
        let theirs = ark_ff::Field::pow(&to_ark(&a), e);
        assert_same(&a.pow(&e), &theirs, "pow", round);
    }
}

/// The by-reference operator impls are the thing under test here, so `op_ref`
/// is exactly the pattern we want.
#[test]
#[allow(clippy::op_ref)]
fn assign_operators_match_owned_operators() {
    let mut rng = Rng::new(SEED ^ 7);
    for _ in 0..ROUNDS {
        let (a, b) = (next_fr(&mut rng), next_fr(&mut rng));

        let mut t = a;
        t += b;
        assert_eq!(t, a + b);
        let mut t = a;
        t += &b;
        assert_eq!(t, a + b);

        let mut t = a;
        t -= b;
        assert_eq!(t, a - b);
        let mut t = a;
        t -= &b;
        assert_eq!(t, a - b);

        let mut t = a;
        t *= b;
        assert_eq!(t, a * b);
        let mut t = a;
        t *= &b;
        assert_eq!(t, a * b);

        // Reference forms must agree with the owned forms.
        assert_eq!(&a + &b, a + b);
        assert_eq!(&a + b, a + b);
        assert_eq!(a + &b, a + b);
        assert_eq!(&a - &b, a - b);
        assert_eq!(&a - b, a - b);
        assert_eq!(a - &b, a - b);
        assert_eq!(&a * &b, a * b);
        assert_eq!(&a * b, a * b);
        assert_eq!(a * &b, a * b);
        assert_eq!(-&a, -a);
    }
}

#[test]
fn batch_inverse_matches_arkworks() {
    let mut rng = Rng::new(SEED ^ 8);
    let mut ours: Vec<Fr> = (0..ROUNDS).map(|_| next_fr(&mut rng)).collect();
    let mut theirs: Vec<ark_bn254::Fr> = ours.iter().map(to_ark).collect();

    batch_inverse(&mut ours);
    ark_ff::fields::batch_inversion(&mut theirs);

    for (round, (o, t)) in ours.iter().zip(theirs.iter()).enumerate() {
        assert_same(o, t, "batch_inverse", round);
    }
}

#[test]
fn from_u64_matches_arkworks() {
    let mut rng = Rng::new(SEED ^ 9);
    for round in 0..ROUNDS {
        let x = rng.next_u64();
        assert_same(&Fr::from_u64(x), &ark_bn254::Fr::from(x), "from_u64", round);
    }
}

#[test]
fn wire_roundtrip_matches_arkworks() {
    let mut rng = Rng::new(SEED ^ 10);
    for round in 0..ROUNDS {
        let bytes = next_canonical(&mut rng);
        let ours = Fr::from_bytes(&bytes).expect("canonical by construction");
        let theirs: ark_bn254::Fr = ark_ff::PrimeField::from_le_bytes_mod_order(&bytes);
        assert_same(&ours, &theirs, "from_bytes", round);
        assert_eq!(ours.to_bytes(), bytes, "to_bytes is the inverse at {round}");
    }
}
