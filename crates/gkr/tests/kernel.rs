//! The gate kernel, one variant at a time, against arithmetic written out by
//! hand.
//!
//! Every coefficient in the toy is 1, −1 or its one challenge, and every
//! constant 0 or 3. A kernel that dropped a `Product`'s coefficient, or mixed
//! up an `AffineProduct`'s constants, would compute every toy value correctly,
//! and the prover and verifier would agree with it, because both read gates
//! through this one function. So here every variant carries literal
//! coefficients other than 0 and ±1, a challenge coefficient, and a nonzero
//! constant on every side that has one.

use constants::challenge_slot::TOY;
use constraints::{Coeff, GateDef, PolyAddress};
use field::Fr;
use gkr::{eval_gate, ExternalChallenges};

fn fr(v: u64) -> Fr {
    Fr::from_u64(v)
}

fn lit(v: u64) -> Coeff {
    Coeff::Literal(fr(v))
}

fn x(i: u32) -> PolyAddress {
    PolyAddress::Witness(i)
}

/// Slot `TOY` set to a value far from any small integer.
fn gamma() -> (ExternalChallenges, Fr) {
    let gamma = fr(0x9e37_79b9_7f4a_7c15) * fr(0x0123_4567_89ab_cdef);
    let mut challenges = ExternalChallenges::new();
    challenges.insert(TOY, gamma);
    (challenges, gamma)
}

/// `Σ c_i·x_i + c_0`: literal coefficients 2 and 5, a challenge coefficient and
/// constant 7; then a challenge as the constant.
#[test]
fn linear() {
    let (ch, g) = gamma();
    let gate = GateDef::Linear {
        terms: vec![
            (lit(2), x(0)),
            (lit(5), x(1)),
            (Coeff::Challenge(TOY), x(2)),
        ],
        constant: lit(7),
    };
    assert_eq!(
        eval_gate(&gate, &[fr(11), fr(13), fr(17)], &ch),
        fr(2 * 11 + 5 * 13 + 7) + g * fr(17)
    );
    let gate = GateDef::Linear {
        terms: vec![(lit(3), x(0))],
        constant: Coeff::Challenge(TOY),
    };
    assert_eq!(eval_gate(&gate, &[fr(11)], &ch), fr(33) + g);
}

/// `c·x·y` with `c = 3`, and with `c = γ`. Kills M19, the kernel that drops
/// the coefficient and returns `x·y`.
#[test]
fn product() {
    let (ch, g) = gamma();
    let gate = GateDef::Product {
        coeff: lit(3),
        left: x(0),
        right: x(1),
    };
    let value = eval_gate(&gate, &[fr(11), fr(13)], &ch);
    assert_eq!(value, fr(3 * 11 * 13));
    assert_ne!(value, fr(11 * 13), "the coefficient is not dropped");
    let gate = GateDef::Product {
        coeff: Coeff::Challenge(TOY),
        left: x(0),
        right: x(1),
    };
    assert_eq!(eval_gate(&gate, &[fr(11), fr(13)], &ch), g * fr(143));
}

/// `x·m + (1 − m)`: `x` under mask 1, the identity under mask 0, and the
/// polynomial itself off the bits — the kernel does not assume `m` is a bit.
#[test]
fn mask_into_identity() {
    let (ch, _) = gamma();
    let gate = GateDef::MaskIntoIdentity {
        input: x(0),
        mask: x(1),
    };
    assert_eq!(eval_gate(&gate, &[fr(11), fr(1)], &ch), fr(11));
    assert_eq!(eval_gate(&gate, &[fr(11), fr(0)], &ch), fr(1));
    assert_eq!(
        eval_gate(&gate, &[fr(11), fr(5)], &ch),
        fr(11 * 5 + 1) - fr(5)
    );
}

/// `(Σ a_i·x_i + a_0)·(Σ b_j·y_j + b_0)` with `a_0 = 3` and `b_0 = 7`, a
/// challenge among the left coefficients, then a challenge as `b_0`. Kills
/// M20, the right factor taking the left constant, and M20b, the left factor
/// losing its constant: each is written out below and differs.
#[test]
fn affine_product() {
    let (ch, g) = gamma();
    let gate = GateDef::AffineProduct {
        left: vec![(lit(2), x(0)), (Coeff::Challenge(TOY), x(1))],
        left_constant: lit(3),
        right: vec![(lit(5), x(2))],
        right_constant: lit(7),
    };
    let value = eval_gate(&gate, &[fr(11), fr(13), fr(17)], &ch);
    let left = fr(2 * 11 + 3) + g * fr(13);
    assert_eq!(value, left * fr(5 * 17 + 7));
    assert_ne!(
        value,
        left * fr(5 * 17 + 3),
        "the right constant is its own"
    );
    assert_ne!(
        value,
        (fr(2 * 11) + g * fr(13)) * fr(5 * 17 + 7),
        "the left constant is kept"
    );
    let gate = GateDef::AffineProduct {
        left: vec![(lit(2), x(0))],
        left_constant: lit(3),
        right: vec![(lit(5), x(1))],
        right_constant: Coeff::Challenge(TOY),
    };
    assert_eq!(
        eval_gate(&gate, &[fr(11), fr(17)], &ch),
        fr(2 * 11 + 3) * (fr(5 * 17) + g)
    );
}

/// `x(·,0)·x(·,1)`: two values for one operand, its two children.
#[test]
fn tree_product() {
    let (ch, _) = gamma();
    let gate = GateDef::TreeProduct {
        input: PolyAddress::Inner {
            layer: 1,
            offset: 0,
        },
    };
    assert_eq!(eval_gate(&gate, &[fr(11), fr(13)], &ch), fr(11 * 13));
}

/// `c_0 + Σ a_i·x_i + Σ b_j·y_j·z_j` with `c_0 = 7`, linear coefficients 2 and
/// `γ`, product coefficients 3, `γ` and 5, and one operand read twice; then an
/// empty linear list under a challenge constant, an empty products list, and
/// both empty. Kills a kernel that drops the constant, and one that drops a
/// product's coefficient: each is written out below and differs.
#[test]
fn quadratic() {
    let (ch, g) = gamma();
    let gate = GateDef::Quadratic {
        constant: lit(7),
        linear: vec![(lit(2), x(0)), (Coeff::Challenge(TOY), x(1))],
        products: vec![
            (lit(3), x(2), x(3)),
            (Coeff::Challenge(TOY), x(4), x(5)),
            (lit(5), x(0), x(2)),
        ],
    };
    let values = [11, 13, 17, 19, 23, 29, 11, 17].map(fr);
    let value = eval_gate(&gate, &values, &ch);
    let products = fr(3 * 17 * 19 + 5 * 11 * 17) + g * fr(23 * 29);
    assert_eq!(value, fr(7 + 2 * 11) + g * fr(13) + products);
    assert_ne!(
        value,
        fr(2 * 11) + g * fr(13) + products,
        "the constant is kept"
    );
    assert_ne!(
        value,
        fr(7 + 2 * 11 + 17 * 19 + 5 * 11 * 17) + g * fr(13) + g * fr(23 * 29),
        "a product's coefficient is its own"
    );

    let no_linear = GateDef::Quadratic {
        constant: Coeff::Challenge(TOY),
        linear: vec![],
        products: vec![(lit(3), x(0), x(1))],
    };
    assert_eq!(eval_gate(&no_linear, &[fr(11), fr(13)], &ch), g + fr(429));

    let no_products = GateDef::Quadratic {
        constant: lit(7),
        linear: vec![(lit(2), x(0))],
        products: vec![],
    };
    assert_eq!(eval_gate(&no_products, &[fr(11)], &ch), fr(29));

    let constant_only = GateDef::Quadratic {
        constant: lit(7),
        linear: vec![],
        products: vec![],
    };
    assert_eq!(eval_gate(&constant_only, &[], &ch), fr(7));
}
