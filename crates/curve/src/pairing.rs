//! The optimal ate pairing on BN254.
//!
//! ```text
//!   e : G1 x G2 -> Fq12,   e(P, Q) = f_{6x+2, Q}(P) ^ ((q^12 - 1)/r)
//! ```
//!
//! with `x = 4965661367192848881`, the Miller loop running over the
//! non-adjacent form of `6x + 2` and closing with two Frobenius correction
//! steps. [`miller_loop`] is Algorithm 1 of Beuchat, González-Díaz, Mitsunari,
//! Okamoto, Rodríguez-Henríquez and Teruya, *High-Speed Software
//! Implementation of the Optimal Ate Pairing over Barreto–Naehrig Curves*,
//! ePrint 2010/354, line for line; the paper is in `docs/publication`.
//!
//! **This is verification-side code and is written for audit, not for speed.**
//! Nothing in the prover computes a pairing. So the line functions here are
//! materialised as full `Fq12` elements and multiplied in with the generic
//! [`Fq12`] multiplication rather than a sparse `mul_by_034`, the squarings
//! are generic rather than cyclotomic, no G2 line coefficients are
//! precomputed, and the final exponentiation's hard part is written as the
//! `lambda` decomposition itself rather than as an addition chain that
//! evaluates it. Every one of those is a deliberate simplification, and each
//! costs a constant factor on a routine that runs a handful of times per
//! proof.
//!
//! # G2 in homogeneous projective coordinates
//!
//! The Miller accumulator is `(X : Y : Z)` on `E'/Fq2: Y^2 Z = X^3 + b' Z^3`,
//! which is the representation the published doubling and addition line
//! formulas are written in. It is a different chart from
//! [`crate::G2Projective`]'s Jacobian one, so it is a private type here rather
//! than a second constructor on a frozen struct.
//!
//! # What this module does *not* check
//!
//! Nothing here validates that a `G1Affine` is on the curve or that a
//! `G2Affine` is in the order-`r` subgroup. That is the caller's job, at the
//! point where a point is decoded — [`crate::G1Affine::from_bytes`] and
//! [`crate::G2Affine::from_bytes`] do it — as the master prompt's frozen
//! invariant says. Feeding this module a point off the curve produces a
//! meaningless `Fq12`, not an error.

use constants::{
    ATE_LOOP_NAF, FINAL_EXP_LAMBDA_0, FINAL_EXP_LAMBDA_1, FINAL_EXP_LAMBDA_2, G2_B_C0, G2_B_C1,
    TWIST_FROBENIUS_X, TWIST_FROBENIUS_Y,
};

use crate::fq::Fq;
use crate::fq12::Fq12;
use crate::fq2::{fq2_from_hex, Fq2};
use crate::fq6::Fq6;
use crate::g1::G1Affine;
use crate::g2::G2Affine;

/// The Miller accumulator: a point of `E'/Fq2` in homogeneous projective
/// coordinates, `Y^2 Z = X^3 + b' Z^3`.
#[derive(Clone, Copy)]
struct G2Homogeneous {
    x: Fq2,
    y: Fq2,
    z: Fq2,
}

/// The product of the Miller functions `f_{6x+2, Q_i}(P_i)`, over one shared
/// iteration of the loop.
///
/// Pairs with either point at infinity contribute the identity and are
/// skipped rather than rejected; an empty slice gives [`Fq12::ONE`]. This is
/// the only Miller implementation in the crate: [`pairing`] and
/// [`pairing_check`] both go through it.
pub fn miller_loop(pairs: &[(G1Affine, G2Affine)]) -> Fq12 {
    let live: Vec<(G1Affine, G2Affine)> = pairs
        .iter()
        .filter(|(p, q)| !p.infinity && !q.infinity)
        .copied()
        .collect();
    if live.is_empty() {
        return Fq12::ONE;
    }

    let two_inv = Fq::from_u64(2)
        .inverse()
        .expect("2 is nonzero in a field of odd characteristic");
    let b_twist = fq2_from_hex([G2_B_C0, G2_B_C1]);

    // One accumulator per pair, all stepped together so the Fq12 squarings
    // are shared. Each starts at Q, which is the loop's leading NAF digit.
    let mut t: Vec<G2Homogeneous> = live
        .iter()
        .map(|(_, q)| G2Homogeneous {
            x: q.x,
            y: q.y,
            z: Fq2::ONE,
        })
        .collect();

    let mut f = Fq12::ONE;
    // The leading digit at index `len - 1` is the initial `T = Q`, so the
    // loop starts one below it. `f` is ONE on the first pass, so squaring it
    // there is a no-op kept for a uniform body.
    for i in (0..ATE_LOOP_NAF.len() - 1).rev() {
        f = f.square();
        for (k, (p, _)) in live.iter().enumerate() {
            f *= line(doubling_step(&mut t[k], &b_twist, two_inv), p);
        }
        match ATE_LOOP_NAF[i] {
            0 => {}
            digit => {
                for (k, (p, q)) in live.iter().enumerate() {
                    let addend = if digit > 0 { *q } else { -*q };
                    f *= line(addition_step(&mut t[k], &addend), p);
                }
            }
        }
    }

    // The two Frobenius correction steps: `6x + 2` is the ate loop parameter,
    // and `psi(Q)` and `-psi(psi(Q))` finish the optimal ate relation. `x` is
    // positive for BN254, so `f` needs no conjugation before them.
    for (k, (p, q)) in live.iter().enumerate() {
        f *= line(addition_step(&mut t[k], &psi(q)), p);
    }
    for (k, (p, q)) in live.iter().enumerate() {
        f *= line(addition_step(&mut t[k], &-psi(&psi(q))), p);
    }
    f
}

/// `f^((q^12 - 1)/r)`, the exact power and no fixed multiple of it.
///
/// Two halves, as usual:
///
/// ```text
///   (q^12 - 1)/r = (q^6 - 1) (q^2 + 1) * (q^4 - q^2 + 1)/r
///                  \___________________/  \______________/
///                        easy part            hard part
/// ```
///
/// The easy part is `(conj(f) / f)^(q^2 + 1)`, one inversion, one conjugation
/// and one Frobenius. Its output lies in the cyclotomic subgroup — the
/// elements of order dividing `q^4 - q^2 + 1` — where conjugation *is*
/// inversion, which is what lets the hard part take negative exponents for
/// free.
///
/// The hard part is the classic decomposition of `d = (q^4 - q^2 + 1)/r` in
/// base `q`, written out rather than compiled into an addition chain:
///
/// ```text
///   d = lambda_0 + lambda_1 q + lambda_2 q^2 + q^3
///
///   lambda_0 = -(36x^3 + 30x^2 + 18x + 2)
///   lambda_1 = -(36x^3 + 18x^2 + 12x - 1)
///   lambda_2 =    6x^2 + 1
/// ```
///
/// This is the decomposition S06 calls the Devegili-style one. The reference
/// for it is Scott, Benger, Charlemagne, Dominguez Perez and Kachisa, *On the
/// final exponentiation for calculating pairings on ordinary elliptic curves*,
/// ePrint 2008/490 — the procedure Beuchat et al. 2010/354 section 4.2 states
/// it follows. What that paper then builds on top is a vectorial addition
/// chain that evaluates the same exponent in 13 multiplications and 4
/// squarings; this function deliberately evaluates the decomposition itself
/// instead, because three explicit `pow` calls with the exponents written
/// above are auditable by reading and an addition chain is not.
///
/// The magnitudes are [`constants::FINAL_EXP_LAMBDA_0`] and friends.
/// `tests/constants_check.rs` re-derives each from `x` and checks
/// `(lambda_0 + lambda_1 q + lambda_2 q^2 + q^3) * r == q^4 - q^2 + 1` as
/// integers, and `tests/pairing.rs` checks this whole function against
/// `f^((q^12 - 1)/r)` applied one bit at a time.
///
/// The Fuentes-Castañeda variant is deliberately **not** used: it returns
/// `f^(2x(6x^2+3x+1) d)`, a fixed power of the true value rather than the
/// value, and this function's contract is the exact one. It is also what
/// arkworks-bn254's own `final_exponentiation` computes, which is why the
/// committed fixtures raise a Miller output to the literal exponent instead of
/// reading arkworks' pairing back.
///
/// Panics if `f` is zero, which no Miller output ever is.
pub fn final_exponentiation(f: &Fq12) -> Fq12 {
    // Easy part. conj(f) is f^(q^6), so conj(f) * f^-1 is f^(q^6 - 1).
    let inv = f
        .inverse()
        .expect("final_exponentiation: a Miller loop output is never zero");
    let e = f.conjugate() * inv;
    let e = e.frobenius_map(2) * e;

    // Hard part. `e` is unitary from here on, so conjugate() is inverse().
    let a0 = e.pow(&FINAL_EXP_LAMBDA_0).conjugate();
    let a1 = e.frobenius_map(1).pow(&FINAL_EXP_LAMBDA_1).conjugate();
    let a2 = e.frobenius_map(2).pow(&FINAL_EXP_LAMBDA_2);
    let a3 = e.frobenius_map(3);
    a0 * a1 * a2 * a3
}

/// `e(p, q)`. The convenience wrapper: one pair through [`miller_loop`] and
/// [`final_exponentiation`].
///
/// Returns [`Fq12::ONE`] if either point is the identity.
pub fn pairing(p: &G1Affine, q: &G2Affine) -> Fq12 {
    final_exponentiation(&miller_loop(&[(*p, *q)]))
}

/// Whether `prod_i e(P_i, Q_i) == 1`.
///
/// This is the shape every pairing check in the protocol takes: one shared
/// [`miller_loop`] over all the pairs, then **exactly one**
/// [`final_exponentiation`], whatever the pair count — the expression below is
/// the whole implementation. An empty slice, or one whose every pair contains
/// an infinity, is `true`.
pub fn pairing_check(pairs: &[(G1Affine, G2Affine)]) -> bool {
    final_exponentiation(&miller_loop(pairs)) == Fq12::ONE
}

// ---------------------------------------------------------------------------
// The Miller loop's steps
// ---------------------------------------------------------------------------

/// One doubling: `t <- 2t`, returning the tangent line's three nonzero `Fq2`
/// coefficients.
///
/// The standard homogeneous projective doubling-and-line formulas for an
/// `a = 0` short Weierstrass curve, on `Y^2 Z = X^3 + b' Z^3`:
///
/// ```text
///   A = XY/2   B = Y^2   C = Z^2   E = 3 b' C   F = 3E   G = (B + F)/2
///   H = (Y + Z)^2 - (B + C)        I = E - B    J = X^2
///
///   X3 = A(B - F)   Y3 = G^2 - 3E^2   Z3 = B H   line = (-H, 3J, I)
/// ```
///
/// Beuchat et al. 2010/354 write the same lines in *Jacobian* coordinates in
/// their section 4.1; S06 asks for the homogeneous projective chart, which is
/// also the one ark-bn254 implements — so `tests/differential.rs` compares two
/// independent codes over the same formulas rather than one code against
/// itself.
///
/// `two_inv` is `1/2` in `Fq`, computed once per [`miller_loop`] rather than
/// per step, which is why it is a parameter.
fn doubling_step(t: &mut G2Homogeneous, b_twist: &Fq2, two_inv: Fq) -> (Fq2, Fq2, Fq2) {
    let half = Fq2::from_fq(two_inv);
    let a = (t.x * t.y) * half;
    let b = t.y.square();
    let c = t.z.square();
    let e = *b_twist * (c + c + c);
    let f = e + e + e;
    let g = (b + f) * half;
    let h = (t.y + t.z).square() - (b + c);
    let i = e - b;
    let j = t.x.square();
    let e_squared = e.square();

    t.x = a * (b - f);
    t.y = g.square() - (e_squared + e_squared + e_squared);
    t.z = b * h;

    (-h, j + j + j, i)
}

/// One addition: `t <- t + q`, returning the chord line's three nonzero `Fq2`
/// coefficients.
///
/// `q` is affine — it is always the fixed `Q`, `-Q`, or a Frobenius image of
/// `Q` — so this is the mixed-addition form of the same homogeneous
/// projective formulas:
///
/// ```text
///   theta = Y - y_q Z    lambda = X - x_q Z
///   C = theta^2   D = lambda^2   E = lambda D   F = Z C   G = X D
///   H = E + F - 2G
///
///   X3 = lambda H   Y3 = theta(G - H) - E Y   Z3 = Z E
///   J = theta x_q - lambda y_q     line = (lambda, -theta, J)
/// ```
///
/// **No step this loop takes is a degenerate one**, which is why there is no
/// branch here for `lambda == 0`. Writing `T = [m]Q`, the accumulator's
/// multiplier starts at `1` and each iteration sends `m` to `2m + d` with
/// `d` in `{-1, 0, 1}`, so `m` is strictly increasing and stays in
/// `[1, 6x + 2]` — far below `r`. An addition would degenerate only if
/// `T == +-Q`, that is `m == +-1 mod r`, and `m >= 2` at every addition. The
/// two closing steps add `[q]Q` and `[-q^2]Q`, and `6x + 2`, `6x + 2 + q` are
/// congruent to neither `+-q` nor `+-q^2` mod `r`. `T` is never `O` either,
/// since `m >= 1`, and doublings are safe because both group orders are odd
/// so no point has order two. All of this was checked directly, over 40
/// random `Q`, before it was written down.
fn addition_step(t: &mut G2Homogeneous, q: &G2Affine) -> (Fq2, Fq2, Fq2) {
    let theta = t.y - q.y * t.z;
    let lambda = t.x - q.x * t.z;
    let c = theta.square();
    let d = lambda.square();
    let e = lambda * d;
    let f = t.z * c;
    let g = t.x * d;
    let h = e + f - (g + g);

    t.x = lambda * h;
    t.y = theta * (g - h) - e * t.y;
    t.z *= e;

    let j = theta * q.x - lambda * q.y;
    (lambda, -theta, j)
}

/// A line's three coefficients, evaluated at `p`, as a full `Fq12`.
///
/// BN254's twist is the D type, which places the three nonzero coefficients in
/// the `1`, `w` and `v w` slots — flat positions 0, 3 and 4 of
/// `(c0.c0, c0.c1, c0.c2, c1.c0, c1.c1, c1.c2)`. The `Fq` coordinates of `p`
/// scale two of them.
///
/// Building the whole `Fq12` and multiplying it in generically is the point:
/// the sparse `mul_by_034` that libraries use here is an optimisation with its
/// own coefficient identities to get right, and this stage has no need of it.
fn line(coefficients: (Fq2, Fq2, Fq2), p: &G1Affine) -> Fq12 {
    let (c0, c1, c2) = coefficients;
    Fq12 {
        c0: Fq6 {
            c0: c0 * Fq2::from_fq(p.y),
            c1: Fq2::ZERO,
            c2: Fq2::ZERO,
        },
        c1: Fq6 {
            c0: c1 * Fq2::from_fq(p.x),
            c1: c2,
            c2: Fq2::ZERO,
        },
    }
}

/// The untwist-Frobenius-twist endomorphism `psi` on G2.
///
/// `psi(x, y) = (x^q * gamma_x, y^q * gamma_y)` with `gamma_x = xi^((q-1)/3)`
/// and `gamma_y = xi^((q-1)/2)`, and `^q` on an `Fq2` is conjugation. It acts
/// on the order-`r` subgroup as multiplication by `q`, which is what makes the
/// loop's two closing steps compute the optimal ate relation.
///
/// The identity maps to itself; nothing in [`miller_loop`] reaches this with
/// one, since infinite pairs are dropped before the loop.
fn psi(q: &G2Affine) -> G2Affine {
    if q.infinity {
        return G2Affine::IDENTITY;
    }
    G2Affine {
        x: q.x.conjugate() * fq2_from_hex(TWIST_FROBENIUS_X),
        y: q.y.conjugate() * fq2_from_hex(TWIST_FROBENIUS_Y),
        infinity: false,
    }
}
