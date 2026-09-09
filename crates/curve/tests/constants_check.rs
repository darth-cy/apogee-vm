//! Every frozen constant this crate depends on is re-derived here rather than
//! trusted, and so is every arithmetic *fact* the implementation leans on.
//!
//! Two kinds of silence motivate this. A wrong Montgomery constant leaves
//! every operation self-consistent while the field is the wrong one. And the
//! `Fq2::sqrt` branches, the G1 subgroup shortcut and the missing `y = 0`
//! cases are only correct because `-1` is a nonresidue, the cofactor is 1 and
//! both group orders are odd — none of which is visible in the code that
//! relies on it.

mod common;

use std::str::FromStr;

use ark_ec::{AffineRepr, CurveConfig};
use common::{ark_fq2_bytes, ark_fq_bytes, ark_g1_bytes, ark_g2_bytes, next_fq2, to_ark_fq2};
use constants::{
    FQ2_NONRESIDUE, FQ6_NONRESIDUE_C0, FQ6_NONRESIDUE_C1, FQ_INV, FQ_MODULUS, FQ_MODULUS_MINUS_TWO,
    FQ_MODULUS_PLUS_ONE_DIV_FOUR, FQ_R, FQ_R2, FR_MODULUS, G1_B, G1_GENERATOR_X, G1_GENERATOR_Y,
    G2_B_C0, G2_B_C1, G2_GENERATOR_X_C0, G2_GENERATOR_X_C1, G2_GENERATOR_Y_C0, G2_GENERATOR_Y_C1,
};
use curve::{Fq, Fq2, G1Affine, G2Affine};
use test_support::{to_hex, Rng};

/// The master prompt's frozen Fq modulus, in decimal.
const FQ_MODULUS_DECIMAL: &str =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";

fn limbs_to_bytes(limbs: &[u64; 4]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        b[8 * i..8 * i + 8].copy_from_slice(&limbs[i].to_le_bytes());
    }
    b
}

/// `limbs * k`, widened to five limbs. Plain integer arithmetic, independent
/// of anything Montgomery.
fn times(limbs: &[u64; 4], k: u64) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry = 0u128;
    for i in 0..4 {
        let t = (limbs[i] as u128) * (k as u128) + carry;
        out[i] = t as u64;
        carry = t >> 64;
    }
    out[4] = carry as u64;
    out
}

/// `a - b` over five limbs, panicking on borrow-out.
fn sub5(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut borrow = 0i128;
    for i in 0..5 {
        let t = (a[i] as i128) - (b[i] as i128) - borrow;
        out[i] = t as u64;
        borrow = if t < 0 { 1 } else { 0 };
    }
    assert_eq!(borrow, 0, "sub5 underflowed");
    out
}

fn widen(limbs: &[u64; 4]) -> [u64; 5] {
    [limbs[0], limbs[1], limbs[2], limbs[3], 0]
}

// ---------------------------------------------------------------------------
// The Fq modulus and its derived exponents
// ---------------------------------------------------------------------------

#[test]
fn modulus_is_the_bn254_base_field() {
    assert_eq!(
        FQ_MODULUS,
        <ark_bn254::Fq as ark_ff::PrimeField>::MODULUS.0,
        "FQ_MODULUS must be Fq, not Fr"
    );
    assert_ne!(FQ_MODULUS, FR_MODULUS, "Fq and Fr are different moduli");
    // ...and exactly how they differ, because every doc comment in the
    // workspace that warns about confusing them says this: identical above the
    // 128th bit, different below it.
    assert_eq!(
        FQ_MODULUS[2..],
        FR_MODULUS[2..],
        "q and p agree in their top 128 bits"
    );
    assert_ne!(
        FQ_MODULUS[..2],
        FR_MODULUS[..2],
        "q and p differ below the 128th bit"
    );

    // The decimal in the doc comment is pinned from both sides: q - 1 is the
    // largest element, and q itself is not an element at all.
    let q_minus_one_decimal =
        "21888242871839275222246405745257275088696311157297823662689037894645226208582";
    let q_minus_one = ark_bn254::Fq::from_str(q_minus_one_decimal).expect("q-1 is an element");
    assert_eq!(q_minus_one, -ark_bn254::Fq::from(1u64));
    assert_eq!(Fq::MINUS_ONE.to_bytes(), ark_fq_bytes(&q_minus_one));
    assert_eq!(
        ark_bn254::Fq::from_str(FQ_MODULUS_DECIMAL).map(|x| x == ark_bn254::Fq::from(0u64)),
        Ok(true),
        "the decimal modulus must reduce to zero"
    );

    // ...and the hex form of the limbs is the hex form in the doc comment,
    // byte-reversed.
    assert_eq!(
        to_hex(&limbs_to_bytes(&FQ_MODULUS)),
        "47fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e6430",
        "FQ_MODULUS limbs, little-endian bytes"
    );
}

#[test]
fn modulus_minus_two_is_q_minus_two() {
    let mut want = FQ_MODULUS;
    // q ends in ...fd47, so subtracting 2 only touches the low limb.
    assert!(FQ_MODULUS[0] >= 2, "no borrow out of the low limb");
    want[0] = want[0].wrapping_sub(2);
    assert_eq!(FQ_MODULUS_MINUS_TWO, want);
}

#[test]
fn sqrt_exponent_is_q_plus_one_over_four() {
    // q = 3 mod 4 is what makes (q+1)/4 an integer and the square root one
    // exponentiation.
    assert_eq!(FQ_MODULUS[0] & 3, 3, "q must be 3 mod 4");

    let four_x = times(&FQ_MODULUS_PLUS_ONE_DIV_FOUR, 4);
    let mut q_plus_one = widen(&FQ_MODULUS);
    q_plus_one[0] += 1; // q ends in ...47, so no carry
    assert_eq!(four_x, q_plus_one, "4 * (q+1)/4 must be q + 1");
}

#[test]
fn montgomery_radix_constants_are_right() {
    // R = 2^256 mod q and R^2 = 2^512 mod q, as canonical little-endian limbs.
    let two = ark_bn254::Fq::from(2u64);
    let r = ark_ff::Field::pow(&two, [256u64, 0, 0, 0]);
    let r2 = ark_ff::Field::pow(&two, [512u64, 0, 0, 0]);
    assert_eq!(limbs_to_bytes(&FQ_R), ark_fq_bytes(&r), "FQ_R");
    assert_eq!(limbs_to_bytes(&FQ_R2), ark_fq_bytes(&r2), "FQ_R2");
    assert_eq!(r * r, r2, "R^2 is the square of R");

    // R is simultaneously the Montgomery representation of ONE.
    assert_eq!(Fq::ONE.to_bytes()[0], 1);
    assert_eq!(Fq::ONE.to_bytes()[1..], [0u8; 31]);
}

#[test]
fn montgomery_inverse_constant_is_right() {
    // FQ_INV = -q^{-1} mod 2^64, so q * FQ_INV == -1 mod 2^64.
    assert_eq!(FQ_MODULUS[0].wrapping_mul(FQ_INV), u64::MAX);
    assert_eq!(FQ_MODULUS[0] & 1, 1, "Montgomery needs an odd modulus");
}

#[test]
fn minus_one_montgomery_literal_is_right() {
    // The literal in `fq.rs` is opaque Montgomery limbs, so it is pinned three
    // ways against arithmetic that cannot share its mistake.
    assert_eq!(Fq::MINUS_ONE, Fq::ZERO - Fq::ONE);
    assert_eq!(Fq::MINUS_ONE + Fq::ONE, Fq::ZERO);
    assert_eq!(Fq::MINUS_ONE, -Fq::ONE);

    // Its canonical value is q - 1, i.e. (q - 2) + 1.
    let mut q_minus_one = FQ_MODULUS_MINUS_TWO;
    q_minus_one[0] += 1;
    assert_eq!(Fq::MINUS_ONE.to_bytes(), limbs_to_bytes(&q_minus_one));
}

// ---------------------------------------------------------------------------
// The tower: the Fq2 nonresidue, and xi
// ---------------------------------------------------------------------------

#[test]
fn fq2_nonresidue_is_minus_one_and_really_a_nonresidue() {
    let nonresidue = Fq::from_hex(FQ2_NONRESIDUE).expect("FQ2_NONRESIDUE parses");
    assert_eq!(nonresidue, Fq::MINUS_ONE);
    assert_eq!(nonresidue, -Fq::ONE);

    // The load-bearing fact: -1 has no square root mod q. Every branch of
    // `Fq2::sqrt` is exhaustive only because of this — so it is established
    // with arkworks as well as with our own `sqrt`, which is the thing that
    // depends on it.
    assert_eq!(nonresidue.sqrt(), None, "-1 must be a nonresidue mod q");
    assert!(
        ark_ff::Field::sqrt(&(-ark_bn254::Fq::from(1u64))).is_none(),
        "arkworks agrees that -1 is a nonresidue mod q"
    );
    assert_eq!(
        <ark_bn254::Fq2Config as ark_ff::Fp2Config>::NONRESIDUE,
        -ark_bn254::Fq::from(1u64),
        "arkworks builds Fq2 with the same nonresidue"
    );

    // ...and u^2 == -1 in our Fq2.
    let u = Fq2::new(Fq::ZERO, Fq::ONE);
    assert_eq!(u.square(), Fq2::from_fq(Fq::MINUS_ONE));
}

#[test]
fn xi_is_nine_plus_u_and_mul_by_nonresidue_multiplies_by_it() {
    let xi = Fq2::new(
        Fq::from_hex(FQ6_NONRESIDUE_C0).expect("FQ6_NONRESIDUE_C0 parses"),
        Fq::from_hex(FQ6_NONRESIDUE_C1).expect("FQ6_NONRESIDUE_C1 parses"),
    );
    assert_eq!(xi, Fq2::new(Fq::from_u64(9), Fq::ONE), "xi = 9 + u");

    // arkworks' Fq6 is built over Fq2 with exactly this nonresidue.
    assert_eq!(
        ark_fq2_bytes(&<ark_bn254::Fq6Config as ark_ff::fields::Fp6Config>::NONRESIDUE),
        xi.to_bytes(),
        "xi must be arkworks' Fq6 nonresidue"
    );

    // `mul_by_nonresidue` is multiplication by xi, on both the identity and
    // random inputs, cross-checked against arkworks' Fq2 arithmetic.
    assert_eq!(Fq2::ONE.mul_by_nonresidue(), xi);
    assert_eq!(Fq2::ZERO.mul_by_nonresidue(), Fq2::ZERO);
    let mut rng = Rng::new(0x0500_c07e_0000_0001);
    for _ in 0..100 {
        let a = next_fq2(&mut rng);
        assert_eq!(a.mul_by_nonresidue(), a * xi);
        assert_eq!(
            a.mul_by_nonresidue().to_bytes(),
            ark_fq2_bytes(&(to_ark_fq2(&a) * to_ark_fq2(&xi)))
        );
    }

    // xi is a genuine nonresidue in Fq2, which is what makes it a legal
    // extension constant for the tower above. Again from both sides.
    assert_eq!(xi.sqrt(), None, "xi must be a nonresidue in Fq2");
    assert!(
        ark_ff::Field::sqrt(&to_ark_fq2(&xi)).is_none(),
        "arkworks agrees that xi is a nonresidue in Fq2"
    );
}

// ---------------------------------------------------------------------------
// The curves
// ---------------------------------------------------------------------------

#[test]
fn g1_curve_constant_and_generator() {
    let b = Fq::from_hex(G1_B).expect("G1_B parses");
    assert_eq!(b, Fq::from_u64(3));
    assert_eq!(
        ark_fq_bytes(&<ark_bn254::g1::Config as ark_ec::short_weierstrass::SWCurveConfig>::COEFF_B),
        b.to_bytes(),
        "arkworks' G1 b"
    );
    assert_eq!(
        <ark_bn254::g1::Config as ark_ec::short_weierstrass::SWCurveConfig>::COEFF_A,
        ark_bn254::Fq::from(0u64),
        "the a = 0 formulas require a = 0"
    );

    let gen = G1Affine::GENERATOR;
    assert_eq!(gen.x, Fq::from_hex(G1_GENERATOR_X).expect("x parses"));
    assert_eq!(gen.y, Fq::from_hex(G1_GENERATOR_Y).expect("y parses"));
    assert_eq!(gen.x, Fq::from_u64(1));
    assert_eq!(gen.y, Fq::from_u64(2));
    assert!(gen.is_on_curve());
    assert!(gen.is_in_subgroup());
    assert_eq!(
        gen.to_bytes(),
        ark_g1_bytes(&ark_bn254::G1Affine::generator()),
        "our generator is arkworks' generator"
    );

    // 3 is a nonresidue mod q, so `y^2 = 0^3 + 3` has no solution: x = 0 has no
    // on-curve y at all. That is half of why the all-zero infinity encoding is
    // unambiguous, and it is the reason a G1 rejection fixture can be an
    // otherwise-zero encoding with one byte set.
    assert_eq!(b.sqrt(), None, "3 must be a nonresidue mod q");
    assert!(
        ark_ff::Field::sqrt(&ark_bn254::Fq::from(3u64)).is_none(),
        "arkworks agrees that 3 is a nonresidue mod q"
    );

    // G1's cofactor is 1: that is the whole content of `is_in_subgroup`.
    assert_eq!(
        <ark_bn254::g1::Config as CurveConfig>::COFACTOR,
        &[1u64],
        "G1 cofactor must be 1"
    );
    // ...and #E(Fq) = r is odd, so no on-curve point has y = 0, which is why
    // `double` never has to treat 2-torsion as a case.
    assert_eq!(FR_MODULUS[0] & 1, 1, "r is odd");
}

#[test]
fn g2_curve_constant_and_generator() {
    let b = Fq2::new(
        Fq::from_hex(G2_B_C0).expect("G2_B_C0 parses"),
        Fq::from_hex(G2_B_C1).expect("G2_B_C1 parses"),
    );

    // b' = 3/xi, derived here rather than copied.
    let xi = Fq2::new(Fq::from_u64(9), Fq::ONE);
    let three = Fq2::from_fq(Fq::from_u64(3));
    assert_eq!(
        b,
        three * xi.inverse().expect("xi is nonzero"),
        "G2's b must be 3/(9+u)"
    );
    assert_eq!(
        ark_fq2_bytes(
            &<ark_bn254::g2::Config as ark_ec::short_weierstrass::SWCurveConfig>::COEFF_B
        ),
        b.to_bytes(),
        "arkworks' G2 b"
    );

    let gen = G2Affine::GENERATOR;
    assert_eq!(
        gen.x,
        Fq2::new(
            Fq::from_hex(G2_GENERATOR_X_C0).expect("x.c0 parses"),
            Fq::from_hex(G2_GENERATOR_X_C1).expect("x.c1 parses")
        )
    );
    assert_eq!(
        gen.y,
        Fq2::new(
            Fq::from_hex(G2_GENERATOR_Y_C0).expect("y.c0 parses"),
            Fq::from_hex(G2_GENERATOR_Y_C1).expect("y.c1 parses")
        )
    );
    assert!(gen.is_on_curve());
    assert!(
        gen.is_in_subgroup(),
        "the generator must pass the real check"
    );
    assert_eq!(
        gen.to_bytes(),
        ark_g2_bytes(&ark_bn254::G2Affine::generator()),
        "our generator is arkworks' generator"
    );
}

#[test]
fn g2_cofactor_is_two_q_minus_r_and_odd() {
    // #E'(Fq2) = r * (2q - r). The cofactor is not 1, which is why G2's
    // subgroup check is real arithmetic, and it is odd, which is why the twist
    // has no 2-torsion and `double` never sees y = 0.
    let two_q_minus_r = sub5(&times(&FQ_MODULUS, 2), &widen(&FR_MODULUS));
    assert_eq!(two_q_minus_r[4], 0, "2q - r fits in four limbs");
    assert_eq!(two_q_minus_r[0] & 1, 1, "2q - r is odd");

    let ark_cofactor = <ark_bn254::g2::Config as CurveConfig>::COFACTOR;
    assert_eq!(
        &two_q_minus_r[..ark_cofactor.len()],
        ark_cofactor,
        "arkworks' G2 cofactor must be 2q - r"
    );
    assert!(
        two_q_minus_r[ark_cofactor.len()..].iter().all(|&l| l == 0),
        "no limbs beyond arkworks' cofactor"
    );
}
