//! The pairing's algebraic properties: bilinearity, non-degeneracy, the
//! final-exponentiation identities, infinity handling, and the multi-pair
//! product relations `pairing_check` exists for.
//!
//! The committed fixtures in `tests/kats.rs` pin the *values*. This file pins
//! the *laws*, which is the half a corrupted oracle could not fake: a wrong
//! but bilinear map would pass the laws, and a right one that disagreed with
//! arkworks would pass nothing.

mod common;

use common::next_fr;
use constants::{FQ_MODULUS, FR_MODULUS};
use curve::pairing::{final_exponentiation, miller_loop, pairing, pairing_check};
use curve::{Fq12, G1Affine, G1Projective, G2Affine, G2Projective};
use field::Fr;
use num_bigint::BigUint;
use test_support::Rng;

const SEED: u64 = 20260916;

/// An `Fr` as the plain 256-bit little-endian integer `Fq12::pow` takes.
fn fr_limbs(x: &Fr) -> [u64; 4] {
    let bytes = x.to_bytes();
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[8 * i..8 * i + 8]);
        *limb = u64::from_le_bytes(word);
    }
    limbs
}

fn g1(k: &Fr) -> G1Affine {
    G1Projective::GENERATOR.mul(k).to_affine()
}

fn g2(k: &Fr) -> G2Affine {
    G2Projective::GENERATOR.mul(k).to_affine()
}

// ---------------------------------------------------------------------------
// Acceptance 3: bilinearity
// ---------------------------------------------------------------------------

#[test]
fn pairing_is_bilinear() {
    let mut rng = Rng::new(SEED);
    let e = pairing(&G1Affine::GENERATOR, &G2Affine::GENERATOR);

    for _ in 0..6 {
        let (a, b) = (next_fr(&mut rng), next_fr(&mut rng));
        let (p, q) = (g1(&a), g2(&b));

        // e(aP, Q) = e(P, aQ) = e(P, Q)^a, with P and Q the generators.
        let left = pairing(&p, &G2Affine::GENERATOR);
        let right = pairing(&G1Affine::GENERATOR, &g2(&a));
        assert_eq!(left, right, "e(aG1, G2) != e(G1, aG2)");
        assert_eq!(left, e.pow(&fr_limbs(&a)), "e(aG1, G2) != e(G1, G2)^a");

        // e(aP, bQ) = e(P, Q)^(ab). The exponent is `ab` reduced mod r, which
        // is exact because the pairing value has order dividing r.
        assert_eq!(
            pairing(&p, &q),
            e.pow(&fr_limbs(&(a * b))),
            "e(aG1, bG2) != e(G1, G2)^(ab)"
        );
    }
}

#[test]
fn pairing_is_additive_in_the_first_argument() {
    let mut rng = Rng::new(SEED + 1);
    for _ in 0..4 {
        let (a, b, c) = (next_fr(&mut rng), next_fr(&mut rng), next_fr(&mut rng));
        let (p, p_prime, q) = (g1(&a), g1(&b), g2(&c));
        let sum = (G1Projective::from(p).add_affine(&p_prime)).to_affine();

        assert_eq!(
            pairing(&sum, &q),
            pairing(&p, &q) * pairing(&p_prime, &q),
            "e(P + P', Q) != e(P, Q) e(P', Q)"
        );

        // and the same in the second argument, which is the other half of the
        // bilinearity the protocol leans on.
        let q_prime = g2(&b);
        let q_sum = G2Projective::from(q).add_affine(&q_prime).to_affine();
        assert_eq!(
            pairing(&p, &q_sum),
            pairing(&p, &q) * pairing(&p, &q_prime),
            "e(P, Q + Q') != e(P, Q) e(P, Q')"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance 4: the final-exponentiation identities
// ---------------------------------------------------------------------------

#[test]
fn pairing_values_have_order_r_and_are_unitary() {
    let mut rng = Rng::new(SEED + 2);
    let e = pairing(&G1Affine::GENERATOR, &G2Affine::GENERATOR);

    // Non-degeneracy. Without this every other identity here is satisfied by
    // the constant map to one.
    assert_ne!(e, Fq12::ONE, "e(G1, G2) must not be one");
    assert_eq!(e.pow(&FR_MODULUS), Fq12::ONE, "e(G1, G2)^r != 1");

    for _ in 0..4 {
        let f = pairing(&g1(&next_fr(&mut rng)), &g2(&next_fr(&mut rng)));
        assert_eq!(f.pow(&FR_MODULUS), Fq12::ONE, "e(P, Q)^r != 1");
        // Unitarity: the final exponentiation lands in the cyclotomic
        // subgroup, where the q^6 Frobenius is inversion. This is exactly the
        // fact the hard part's negative lambda exponents rely on.
        assert_eq!(
            f.conjugate(),
            f.inverse().expect("a pairing value is nonzero"),
            "conj(f) != f^-1: the value is not unitary"
        );
        assert_eq!(
            f.conjugate(),
            f.frobenius_map(6),
            "conj != frobenius_map(6)"
        );
        assert_eq!(f * f.conjugate(), Fq12::ONE, "f * conj(f) != 1");
    }

    assert_eq!(
        final_exponentiation(&Fq12::ONE),
        Fq12::ONE,
        "final_exponentiation(ONE) != ONE"
    );
}

/// The final exponentiation of a value the Miller loop never produces is still
/// a well-defined power, and it still lands in the order-`r` subgroup: the
/// exponent is a multiple of `(q^12 - 1)/(q^4 - q^2 + 1) * r`-worth of
/// structure for *any* nonzero input, not only for a Miller output.
#[test]
fn final_exponentiation_maps_anything_nonzero_into_the_subgroup() {
    let mut rng = Rng::new(SEED + 3);
    for _ in 0..4 {
        let a = Fq12::new(
            curve::Fq6::new(
                common::next_fq2(&mut rng),
                common::next_fq2(&mut rng),
                common::next_fq2(&mut rng),
            ),
            curve::Fq6::new(
                common::next_fq2(&mut rng),
                common::next_fq2(&mut rng),
                common::next_fq2(&mut rng),
            ),
        );
        let f = final_exponentiation(&a);
        assert_eq!(f.pow(&FR_MODULUS), Fq12::ONE);
        assert_eq!(f.conjugate(), f.inverse().expect("nonzero"));
    }
}

// ---------------------------------------------------------------------------
// Acceptance 5: infinity
// ---------------------------------------------------------------------------

#[test]
fn infinity_pairs_contribute_the_identity() {
    let mut rng = Rng::new(SEED + 4);
    let p = g1(&next_fr(&mut rng));
    let q = g2(&next_fr(&mut rng));

    assert_eq!(pairing(&G1Affine::IDENTITY, &q), Fq12::ONE);
    assert_eq!(pairing(&p, &G2Affine::IDENTITY), Fq12::ONE);
    assert_eq!(pairing(&G1Affine::IDENTITY, &G2Affine::IDENTITY), Fq12::ONE);
    assert_eq!(miller_loop(&[]), Fq12::ONE, "an empty Miller loop is one");
    assert!(pairing_check(&[]), "an empty check passes");

    // An affine identity may carry stale coordinates -- the fields are public.
    // The infinity flag alone decides, so this must behave as the identity.
    let stale = G1Affine {
        x: p.x,
        y: p.y,
        infinity: true,
    };
    assert_eq!(
        pairing(&stale, &q),
        Fq12::ONE,
        "a stale infinity still skips"
    );

    // A list with infinity pairs matches the same list with them removed.
    let live: Vec<(G1Affine, G2Affine)> = (0..3)
        .map(|_| (g1(&next_fr(&mut rng)), g2(&next_fr(&mut rng))))
        .collect();
    let mut padded = live.clone();
    padded.insert(0, (G1Affine::IDENTITY, q));
    padded.push((p, G2Affine::IDENTITY));
    padded.push((G1Affine::IDENTITY, G2Affine::IDENTITY));
    assert_eq!(miller_loop(&padded), miller_loop(&live));
    assert_eq!(pairing_check(&padded), pairing_check(&live));

    // ...including when removing them leaves nothing at all.
    let all_infinite = [
        (G1Affine::IDENTITY, q),
        (p, G2Affine::IDENTITY),
        (G1Affine::IDENTITY, G2Affine::IDENTITY),
    ];
    assert_eq!(miller_loop(&all_infinite), Fq12::ONE);
    assert!(pairing_check(&all_infinite));
}

// ---------------------------------------------------------------------------
// Acceptance 6: the product relations, each with its negative twin
// ---------------------------------------------------------------------------

#[test]
fn pairing_check_accepts_the_scalar_shuffle_and_rejects_a_perturbed_one() {
    let mut rng = Rng::new(SEED + 5);
    for _ in 0..3 {
        let a = next_fr(&mut rng);
        let p = g1(&next_fr(&mut rng));
        let q = g2(&next_fr(&mut rng));

        // e(aP, Q) e(-P, aQ) = e(P, Q)^a e(P, Q)^-a = 1.
        let ap = G1Projective::from(p).mul(&a).to_affine();
        let aq = G2Projective::from(q).mul(&a).to_affine();
        assert!(
            pairing_check(&[(ap, q), (-p, aq)]),
            "[(aP, Q), (-P, aQ)] must hold"
        );

        // The negative twin: one scalar off by one.
        let b = a + Fr::ONE;
        let bp = G1Projective::from(p).mul(&b).to_affine();
        assert!(
            !pairing_check(&[(bp, q), (-p, aq)]),
            "perturbing a scalar must break the relation"
        );
    }
}

/// The KZG opening shape, on a hand-built toy instance.
///
/// With `tau` a secret scalar, `G` and `H` the generators, a degree-two
/// `f(X) = f0 + f1 X + f2 X^2`, a point `z` and the value `v = f(z)`:
///
/// ```text
///   C = f(tau) G          the commitment
///   q(X) = (f(X) - v)/(X - z) = f1 + f2 z + f2 X
///   W = q(tau) G          the opening proof
///
///   e(C - v G, H) * e(-W, tau H - z H) == 1
/// ```
///
/// which is the two-pairing shape every Mercury opening will reduce to. Only
/// the pairing check is exercised here; nothing about a real SRS is claimed,
/// and `tau` is in the clear precisely because this is a toy.
#[test]
fn pairing_check_verifies_a_toy_kzg_opening() {
    let mut rng = Rng::new(SEED + 6);
    let g = G1Projective::GENERATOR;
    let h = G2Projective::GENERATOR;

    for _ in 0..3 {
        let tau = next_fr(&mut rng);
        let (f0, f1, f2) = (next_fr(&mut rng), next_fr(&mut rng), next_fr(&mut rng));
        let z = next_fr(&mut rng);

        let eval = |x: Fr| f0 + f1 * x + f2 * x * x;
        let v = eval(z);
        let commitment = g.mul(&eval(tau)).to_affine();
        let witness = g.mul(&(f1 + f2 * z + f2 * tau)).to_affine();

        // C - v G, and the G2 term tau H - z H.
        let shifted = G1Projective::from(commitment).add(&g.mul(&-v)).to_affine();
        let tau_term = h.mul(&tau).add(&h.mul(&-z)).to_affine();

        assert!(
            pairing_check(&[(shifted, G2Affine::GENERATOR), (-witness, tau_term)]),
            "a correct opening must verify"
        );

        // Negative twin: claim a different value at the same point.
        let bad = G1Projective::from(commitment)
            .add(&g.mul(&-(v + Fr::ONE)))
            .to_affine();
        assert!(
            !pairing_check(&[(bad, G2Affine::GENERATOR), (-witness, tau_term)]),
            "a wrong claimed value must not verify"
        );

        // ...and a witness for a different point.
        let wrong_witness = g.mul(&(f1 + f2 * z + f2 * tau + Fr::ONE)).to_affine();
        assert!(
            !pairing_check(&[(shifted, G2Affine::GENERATOR), (-wrong_witness, tau_term)]),
            "a wrong witness must not verify"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance 7, and Must-be-exact 3
// ---------------------------------------------------------------------------

#[test]
fn multi_pair_matches_the_product_of_single_pairs() {
    let mut rng = Rng::new(SEED + 7);
    for k in [2usize, 3, 5] {
        let pairs: Vec<(G1Affine, G2Affine)> = (0..k)
            .map(|_| (g1(&next_fr(&mut rng)), g2(&next_fr(&mut rng))))
            .collect();

        let batched = final_exponentiation(&miller_loop(&pairs));
        let product = pairs
            .iter()
            .fold(Fq12::ONE, |acc, (p, q)| acc * pairing(p, q));
        assert_eq!(batched, product, "k = {k}: batched != product");
    }
}

/// Must-be-exact 3, pinned behaviourally on top of the code inspection in the
/// handoff note: `pairing_check` is exactly one `miller_loop` followed by one
/// `final_exponentiation` compared against `ONE`, whatever the pair count.
///
/// A second final exponentiation anywhere in `pairing_check` would be a second
/// application of the `(q^12 - 1)/r` power, and `f^((q^12-1)/r)` is not
/// idempotent off the order-`r` subgroup — so this equality would break for
/// the failing lists below, which are the ones that carry a value other than
/// one into the comparison.
#[test]
fn pairing_check_is_one_miller_loop_and_one_final_exponentiation() {
    let mut rng = Rng::new(SEED + 8);
    for k in 0..6usize {
        let mut pairs: Vec<(G1Affine, G2Affine)> = (0..k)
            .map(|_| (g1(&next_fr(&mut rng)), g2(&next_fr(&mut rng))))
            .collect();
        assert_eq!(
            pairing_check(&pairs),
            final_exponentiation(&miller_loop(&pairs)) == Fq12::ONE,
            "k = {k}: a failing check must be the same expression"
        );

        // and again on a list that passes, built by appending the inverse pair.
        if let Some((p, q)) = pairs.first().copied() {
            pairs.push((-p, q));
            let balanced: Vec<(G1Affine, G2Affine)> = vec![(p, q), (-p, q)];
            assert!(pairing_check(&balanced), "e(P, Q) e(-P, Q) = 1");
            assert_eq!(
                pairing_check(&balanced),
                final_exponentiation(&miller_loop(&balanced)) == Fq12::ONE
            );
        }
    }
}

/// `pairing` is the single-pair spelling of the same two calls, so the two
/// entry points can never drift apart.
#[test]
fn pairing_is_the_single_pair_case_of_the_loop() {
    let mut rng = Rng::new(SEED + 9);
    for _ in 0..3 {
        let (p, q) = (g1(&next_fr(&mut rng)), g2(&next_fr(&mut rng)));
        assert_eq!(
            pairing(&p, &q),
            final_exponentiation(&miller_loop(&[(p, q)]))
        );
        assert_eq!(pairing_check(&[(p, q)]), pairing(&p, &q) == Fq12::ONE);
    }
}

// ---------------------------------------------------------------------------
// Must-be-exact 6, against the definition rather than against an oracle
// ---------------------------------------------------------------------------

fn to_biguint(limbs: &[u64; 4]) -> BigUint {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

/// `(q^12 - 1)/r`, 2,790 bits, built from `constants`' own moduli.
fn full_final_exponent() -> BigUint {
    let q = to_biguint(&FQ_MODULUS);
    let r = to_biguint(&FR_MODULUS);
    let numerator = q.pow(12) - BigUint::from(1u32);
    let exponent = &numerator / &r;
    assert_eq!(&exponent * &r, numerator, "r must divide q^12 - 1");
    exponent
}

/// Square-and-multiply over an exponent too wide for `Fq12::pow`'s four limbs.
fn pow_big(a: &Fq12, e: &BigUint) -> Fq12 {
    let mut acc = Fq12::ONE;
    for bit in (0..e.bits()).rev() {
        acc = acc.square();
        if e.bit(bit) {
            acc *= *a;
        }
    }
    acc
}

/// `final_exponentiation` really is the `(q^12 - 1)/r` power.
///
/// The committed `fq12_final_exp` fixtures pin the same claim against
/// arkworks. This pins it against the *definition*: the exponent is built from
/// `constants::FQ_MODULUS` and `constants::FR_MODULUS` as an integer and
/// applied one bit at a time, with no library and no decomposition involved.
/// Any error in the lambda constants, in the easy part, or in the sign
/// convention that turns the negative lambdas into conjugations fails here.
///
/// Deliberately not a fixed power of the right answer: a Fuentes-Castañeda
/// style shortcut would fail this test, which is the point of Must-be-exact 6.
#[test]
fn final_exponentiation_is_the_literal_exponent() {
    let exponent = full_final_exponent();
    assert_eq!(exponent.bits(), 2790, "the exponent is 2,790 bits wide");

    let mut rng = Rng::new(SEED + 10);
    let mut cases = vec![
        Fq12::ONE,
        pairing(&G1Affine::GENERATOR, &G2Affine::GENERATOR),
        miller_loop(&[(G1Affine::GENERATOR, G2Affine::GENERATOR)]),
    ];
    for _ in 0..2 {
        cases.push(miller_loop(&[(
            g1(&next_fr(&mut rng)),
            g2(&next_fr(&mut rng)),
        )]));
    }
    for _ in 0..2 {
        cases.push(Fq12::new(
            curve::Fq6::new(
                common::next_fq2(&mut rng),
                common::next_fq2(&mut rng),
                common::next_fq2(&mut rng),
            ),
            curve::Fq6::new(
                common::next_fq2(&mut rng),
                common::next_fq2(&mut rng),
                common::next_fq2(&mut rng),
            ),
        ));
    }

    for (i, f) in cases.iter().enumerate() {
        assert_eq!(
            final_exponentiation(f),
            pow_big(f, &exponent),
            "case {i}: final_exponentiation is not the (q^12 - 1)/r power"
        );
    }
}
