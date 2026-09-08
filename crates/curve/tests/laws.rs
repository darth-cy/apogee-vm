//! The algebraic laws, and totality on every degenerate input.
//!
//! The fixtures pin values; this file pins *identities* — associativity,
//! bilinearity of the scalar action, `batch_to_affine` against the per-point
//! path — and walks the identity and the inverse through every public method
//! that can see them, since S05's Must-be-exact 5 requires a correct answer
//! rather than a panic for each.

mod common;

use common::{next_fq, next_fq2, next_fr};
use curve::{batch_inverse, Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use field::Fr;
use test_support::Rng;

const ROUNDS: usize = 200;
const SEED: u64 = 0x0500_1a5c_0000_0001;

fn g1(rng: &mut Rng) -> G1Projective {
    G1Projective::GENERATOR.mul(&next_fr(rng))
}

fn g2(rng: &mut Rng) -> G2Projective {
    G2Projective::GENERATOR.mul(&next_fr(rng))
}

// ---------------------------------------------------------------------------
// Group laws
// ---------------------------------------------------------------------------

#[test]
fn g1_addition_is_associative_and_commutative() {
    let mut rng = Rng::new(SEED);
    for round in 0..ROUNDS {
        let (p, q, s) = (g1(&mut rng), g1(&mut rng), g1(&mut rng));
        assert_eq!(p.add(&q), q.add(&p), "commutativity, round {round}");
        assert_eq!(
            p.add(&q).add(&s),
            p.add(&q.add(&s)),
            "associativity, round {round}"
        );
        // ...including when one operand is the identity or the inverse of
        // another, which is where the special-cased branches live.
        let inf = G1Projective::IDENTITY;
        assert_eq!(p.add(&inf).add(&q), p.add(&q), "associativity through O");
        assert_eq!(p.add(&(-p)).add(&q), q, "P + (-P) + Q == Q");
        assert_eq!(p.add(&q.add(&(-q))), p, "Q + (-Q) folded into P");
    }
}

#[test]
fn g2_addition_is_associative_and_commutative() {
    let mut rng = Rng::new(SEED ^ 1);
    for round in 0..ROUNDS {
        let (p, q, s) = (g2(&mut rng), g2(&mut rng), g2(&mut rng));
        assert_eq!(p.add(&q), q.add(&p), "commutativity, round {round}");
        assert_eq!(
            p.add(&q).add(&s),
            p.add(&q.add(&s)),
            "associativity, round {round}"
        );
        let inf = G2Projective::IDENTITY;
        assert_eq!(p.add(&inf).add(&q), p.add(&q), "associativity through O");
        assert_eq!(p.add(&(-p)).add(&q), q, "P + (-P) + Q == Q");
    }
}

#[test]
fn g1_scalar_action_is_bilinear() {
    let mut rng = Rng::new(SEED ^ 2);
    for round in 0..ROUNDS {
        let p = g1(&mut rng);
        let (a, b) = (next_fr(&mut rng), next_fr(&mut rng));
        assert_eq!(
            p.mul(&(a + b)),
            p.mul(&a).add(&p.mul(&b)),
            "(a+b)P == aP + bP, round {round}"
        );
        assert_eq!(
            p.mul(&a).mul(&b),
            p.mul(&(a * b)),
            "a(bP) == (ab mod r)P, round {round}"
        );
        // Doubling is the scalar action at 2, and repeated addition is too.
        assert_eq!(p.double(), p.mul(&Fr::from_u64(2)));
        assert_eq!(p.double(), p.add(&p));
        assert_eq!(p.mul(&Fr::MINUS_ONE), -p, "(r-1)P == -P");
        assert_eq!(p.mul(&Fr::ZERO), G1Projective::IDENTITY);
        assert_eq!(p.mul(&Fr::ONE), p);
    }
}

#[test]
fn g2_scalar_action_is_bilinear() {
    let mut rng = Rng::new(SEED ^ 3);
    for round in 0..ROUNDS {
        let p = g2(&mut rng);
        let (a, b) = (next_fr(&mut rng), next_fr(&mut rng));
        assert_eq!(
            p.mul(&(a + b)),
            p.mul(&a).add(&p.mul(&b)),
            "(a+b)P == aP + bP, round {round}"
        );
        assert_eq!(p.mul(&a).mul(&b), p.mul(&(a * b)), "a(bP) == (ab mod r)P");
        assert_eq!(p.double(), p.add(&p));
        assert_eq!(p.mul(&Fr::MINUS_ONE), -p, "(r-1)P == -P");
        assert_eq!(p.mul(&Fr::ZERO), G2Projective::IDENTITY);
        assert_eq!(p.mul(&Fr::ONE), p);
    }
}

/// Every point the crate can produce has to survive the subgroup check, in
/// both groups: G1's by cofactor 1, G2's by a full ladder.
#[test]
fn produced_points_are_in_the_subgroup() {
    let mut rng = Rng::new(SEED ^ 4);
    for _ in 0..20 {
        let p = g1(&mut rng).to_affine();
        assert!(p.is_on_curve() && p.is_in_subgroup());
        assert!((-p).is_in_subgroup());
        let q = g2(&mut rng).to_affine();
        assert!(q.is_on_curve() && q.is_in_subgroup());
        assert!((-q).is_in_subgroup());
        assert!(q.double().is_in_subgroup());
    }
    assert!(G1Affine::IDENTITY.is_in_subgroup(), "O is in the subgroup");
    assert!(G2Affine::IDENTITY.is_in_subgroup(), "O is in the subgroup");
}

// ---------------------------------------------------------------------------
// Equality itself
// ---------------------------------------------------------------------------

/// All four point equalities are hand-written, and nearly every `assert_eq!`
/// in this crate's tests routes through one of them — so an `eq` that always
/// returned true would quietly empty the whole suite rather than fail it. This
/// is the test that pins the *disequality* direction, one case per conjunct of
/// each impl:
///
/// - the affine impls compare `x` and `y` separately, and the flag mismatch
///   arms decide finite-versus-infinity;
/// - the projective impls cross-multiply, `X1 Z2^2 == X2 Z1^2` and
///   `Y1 Z2^3 == Y2 Z1^3`, so each conjunct needs its own witness. `P` and
///   `-P` share an `x` and differ in `y`, which is exactly the `Y` conjunct.
///
/// The `x`-only witnesses are deliberately off-curve points: equality does not
/// consult the curve equation, and two on-curve points sharing a `y` would need
/// a cube root to construct.
#[test]
fn point_equality_distinguishes_points() {
    let mut rng = Rng::new(SEED ^ 10);

    // --- G1 ---
    let p = g1(&mut rng);
    let q = g1(&mut rng);
    let (pa, qa) = (p.to_affine(), q.to_affine());
    assert!(pa != qa, "distinct points, affine");
    assert!(p != q, "distinct points, projective");
    assert!(pa != -pa, "P != -P, affine: the y comparison");
    assert!(p != -p, "P != -P, projective: the Y conjunct");

    let acc = p.double();
    assert!(acc != -acc, "P != -P at Z != 1");
    assert!(acc != p, "2P != P at Z != 1");
    // ...and the positive direction of the cross-multiplication, which every
    // other comparison in the suite avoids by sharing a Z or normalizing first.
    assert!(
        G1Projective::from(acc.to_affine()) == acc,
        "the same point at Z == 1 and Z != 1 must compare equal"
    );

    assert!(pa != G1Affine::IDENTITY, "finite != infinity, affine");
    assert!(G1Affine::IDENTITY != pa, "infinity != finite, affine");
    assert!(
        p != G1Projective::IDENTITY,
        "finite != infinity, projective"
    );
    assert!(
        G1Projective::IDENTITY != p,
        "infinity != finite, projective"
    );

    // Same y, different x: the x comparison and the X conjunct.
    let (x1, x2, y) = (next_fq(&mut rng), next_fq(&mut rng), next_fq(&mut rng));
    let same_y_1 = G1Affine {
        x: x1,
        y,
        infinity: false,
    };
    let same_y_2 = G1Affine {
        x: x2,
        y,
        infinity: false,
    };
    assert!(x1 != x2, "the sampler must give two different x");
    assert!(
        same_y_1 != same_y_2,
        "same y, different x: the x comparison"
    );
    assert!(
        G1Projective::from(same_y_1) != G1Projective::from(same_y_2),
        "same y, different x: the X conjunct"
    );

    // --- G2 ---
    let p = g2(&mut rng);
    let q = g2(&mut rng);
    let (pa, qa) = (p.to_affine(), q.to_affine());
    assert!(pa != qa, "distinct points, affine");
    assert!(p != q, "distinct points, projective");
    assert!(pa != -pa, "P != -P, affine: the y comparison");
    assert!(p != -p, "P != -P, projective: the Y conjunct");

    let acc = p.double();
    assert!(acc != -acc, "P != -P at Z != 1");
    assert!(acc != p, "2P != P at Z != 1");
    assert!(
        G2Projective::from(acc.to_affine()) == acc,
        "the same point at Z == 1 and Z != 1 must compare equal"
    );

    assert!(pa != G2Affine::IDENTITY, "finite != infinity, affine");
    assert!(G2Affine::IDENTITY != pa, "infinity != finite, affine");
    assert!(
        p != G2Projective::IDENTITY,
        "finite != infinity, projective"
    );
    assert!(
        G2Projective::IDENTITY != p,
        "infinity != finite, projective"
    );

    let (x1, x2, y) = (next_fq2(&mut rng), next_fq2(&mut rng), next_fq2(&mut rng));
    let same_y_1 = G2Affine {
        x: x1,
        y,
        infinity: false,
    };
    let same_y_2 = G2Affine {
        x: x2,
        y,
        infinity: false,
    };
    assert!(x1 != x2, "the sampler must give two different x");
    assert!(
        same_y_1 != same_y_2,
        "same y, different x: the x comparison"
    );
    assert!(
        G2Projective::from(same_y_1) != G2Projective::from(same_y_2),
        "same y, different x: the X conjunct"
    );

    // Two infinities are equal however their dead coordinates differ, which is
    // the arm that lets `IDENTITY` be compared against a computed result.
    assert!(
        G1Affine {
            x: x1.c0,
            y: y.c0,
            infinity: true
        } == G1Affine::IDENTITY,
        "any infinity equals any other, affine"
    );
    assert!(
        G2Affine {
            x: x1,
            y,
            infinity: true
        } == G2Affine::IDENTITY,
        "any infinity equals any other, affine"
    );
}

// ---------------------------------------------------------------------------
// batch_to_affine
// ---------------------------------------------------------------------------

#[test]
fn batch_to_affine_matches_the_per_point_path() {
    let mut rng = Rng::new(SEED ^ 5);

    // Shapes that matter: empty, a lone identity, identities at both ends and
    // in the middle, and a long mixed run.
    let mut shapes: Vec<Vec<G1Projective>> = vec![
        Vec::new(),
        vec![G1Projective::IDENTITY],
        vec![g1(&mut rng)],
        vec![G1Projective::IDENTITY, G1Projective::IDENTITY],
    ];
    let p = g1(&mut rng);
    shapes.push(vec![G1Projective::IDENTITY, p, G1Projective::IDENTITY]);
    shapes.push(vec![p, G1Projective::IDENTITY, p.double()]);
    shapes.push(
        (0..200)
            .map(|i| {
                if i % 7 == 0 {
                    G1Projective::IDENTITY
                } else {
                    g1(&mut rng)
                }
            })
            .collect(),
    );

    for (case, points) in shapes.iter().enumerate() {
        let batched = G1Projective::batch_to_affine(points);
        let one_at_a_time: Vec<G1Affine> = points.iter().map(|p| p.to_affine()).collect();
        assert_eq!(batched, one_at_a_time, "batch_to_affine, case {case}");
    }
}

// ---------------------------------------------------------------------------
// Totality: the identity and the inverse through every public method
// ---------------------------------------------------------------------------

#[test]
fn g1_operations_are_total() {
    let mut rng = Rng::new(SEED ^ 6);
    let p = g1(&mut rng);
    let pa = p.to_affine();
    let inf = G1Projective::IDENTITY;

    assert_eq!(inf.add(&inf), inf, "O + O");
    assert_eq!(inf.add(&p), p, "O + P");
    assert_eq!(p.add(&inf), p, "P + O");
    assert_eq!(p.add(&(-p)), inf, "P + (-P)");
    assert_eq!(p.add(&p), p.double(), "P + P via the generic path");
    assert_eq!(inf.double(), inf, "2O");
    assert_eq!(inf.mul(&next_fr(&mut rng)), inf, "k * O");
    assert_eq!(inf.to_affine(), G1Affine::IDENTITY);
    assert_eq!(G1Projective::from(G1Affine::IDENTITY), inf);

    assert_eq!(inf.add_affine(&G1Affine::IDENTITY), inf, "O + O, mixed");
    assert_eq!(inf.add_affine(&pa), p, "O + P, mixed");
    assert_eq!(p.add_affine(&G1Affine::IDENTITY), p, "P + O, mixed");
    assert_eq!(p.add_affine(&(-pa)), inf, "P + (-P), mixed");
    assert_eq!(p.add_affine(&pa), p.double(), "P + P, mixed");

    // ...and all of it again with an accumulator whose Z is not 1.
    let acc = p.double();
    assert_eq!(acc.add(&inf), acc);
    assert_eq!(acc.add(&(-acc)), inf);
    assert_eq!(acc.add(&acc), acc.double());
    assert_eq!(acc.add_affine(&G1Affine::IDENTITY), acc);
    assert_eq!(acc.add_affine(&acc.to_affine()), acc.double());
    assert_eq!(acc.add_affine(&(-acc.to_affine())), inf);

    // The identity's affine form: on the curve, in the subgroup, all-zero on
    // the wire, and its own negation.
    let o = G1Affine::IDENTITY;
    assert!(o.is_on_curve() && o.is_in_subgroup());
    assert_eq!(o.to_bytes(), [0u8; 64]);
    assert_eq!(G1Affine::from_bytes(&[0u8; 64]), Some(o));
    assert_eq!(-o, o);
    assert_eq!(-inf, inf);

    // An `infinity` flag with stale coordinates still behaves as the identity:
    // the field is public, so a caller can build one.
    let stale = G1Affine {
        x: pa.x,
        y: pa.y,
        infinity: true,
    };
    assert_eq!(stale, o, "any infinity equals any other");
    assert_eq!(stale.to_bytes(), [0u8; 64]);
    assert!(stale.is_on_curve());
    assert_eq!(G1Projective::from(stale), inf);
    assert_eq!(p.add_affine(&stale), p);
}

#[test]
fn g2_operations_are_total() {
    let mut rng = Rng::new(SEED ^ 7);
    let p = g2(&mut rng);
    let pa = p.to_affine();
    let inf = G2Projective::IDENTITY;

    assert_eq!(inf.add(&inf), inf, "O + O");
    assert_eq!(inf.add(&p), p, "O + P");
    assert_eq!(p.add(&inf), p, "P + O");
    assert_eq!(p.add(&(-p)), inf, "P + (-P)");
    assert_eq!(p.add(&p), p.double(), "P + P via the generic path");
    assert_eq!(inf.double(), inf, "2O");
    assert_eq!(inf.mul(&next_fr(&mut rng)), inf, "k * O");
    assert_eq!(inf.to_affine(), G2Affine::IDENTITY);
    assert_eq!(G2Projective::from(G2Affine::IDENTITY), inf);

    assert_eq!(inf.add_affine(&G2Affine::IDENTITY), inf, "O + O, mixed");
    assert_eq!(inf.add_affine(&pa), p, "O + P, mixed");
    assert_eq!(p.add_affine(&G2Affine::IDENTITY), p, "P + O, mixed");
    assert_eq!(p.add_affine(&(-pa)), inf, "P + (-P), mixed");
    assert_eq!(p.add_affine(&pa), p.double(), "P + P, mixed");

    let acc = p.double();
    assert_eq!(acc.add(&inf), acc);
    assert_eq!(acc.add(&(-acc)), inf);
    assert_eq!(acc.add(&acc), acc.double());
    assert_eq!(acc.add_affine(&acc.to_affine()), acc.double());
    assert_eq!(acc.add_affine(&(-acc.to_affine())), inf);

    // The affine convenience methods take the same edges.
    let o = G2Affine::IDENTITY;
    assert_eq!(o.add(&o), o);
    assert_eq!(o.add(&pa), pa);
    assert_eq!(pa.add(&o), pa);
    assert_eq!(pa.add(&(-pa)), o);
    assert_eq!(pa.add(&pa), pa.double());
    assert_eq!(o.double(), o);
    assert_eq!(o.mul(&next_fr(&mut rng)), o);
    assert_eq!(pa.mul(&Fr::ZERO), o);

    assert!(o.is_on_curve() && o.is_in_subgroup());
    assert_eq!(o.to_bytes(), [0u8; 128]);
    assert_eq!(G2Affine::from_bytes(&[0u8; 128]), Some(o));
    assert_eq!(-o, o);
    assert_eq!(-inf, inf);
}

// ---------------------------------------------------------------------------
// Field-level edges
// ---------------------------------------------------------------------------

#[test]
fn fq_operations_are_total() {
    assert_eq!(Fq::ZERO.inverse(), None);
    assert_eq!(Fq::ZERO.sqrt(), Some(Fq::ZERO));
    assert_eq!(Fq::ONE.sqrt(), Some(Fq::ONE));
    assert_eq!(Fq::ZERO.pow(&[0, 0, 0, 0]), Fq::ONE, "0^0 == 1");
    assert_eq!(Fq::ZERO.square(), Fq::ZERO);
    assert_eq!(-Fq::ZERO, Fq::ZERO, "negating zero must not produce q");
    assert_eq!(Fq::ZERO - Fq::ZERO, Fq::ZERO);
    assert_eq!(Fq::from_u64(0), Fq::ZERO);
    assert_eq!(Fq::from_u64(1), Fq::ONE);
    assert_eq!(Fq::ONE.inverse(), Some(Fq::ONE));
    assert_eq!(Fq::MINUS_ONE.inverse(), Some(Fq::MINUS_ONE));
}

#[test]
fn fq2_operations_are_total() {
    assert_eq!(Fq2::ZERO.inverse(), None);
    assert_eq!(Fq2::ZERO.sqrt(), Some(Fq2::ZERO));
    assert_eq!(Fq2::ONE.sqrt(), Some(Fq2::ONE));
    assert_eq!(Fq2::ZERO.square(), Fq2::ZERO);
    assert_eq!(Fq2::ZERO.conjugate(), Fq2::ZERO);
    assert_eq!(Fq2::ZERO.mul_by_nonresidue(), Fq2::ZERO);
    assert_eq!(-Fq2::ZERO, Fq2::ZERO);
    assert_eq!(Fq2::ONE.inverse(), Some(Fq2::ONE));
    assert_eq!(Fq2::ZERO.norm(), Fq::ZERO);
    assert_eq!(Fq2::ONE.norm(), Fq::ONE);

    // `-1` is not a square in Fq but is one in Fq2, because it is `u^2`. That
    // is the purely-imaginary half of `sqrt`'s `c1 == 0` branch, and the reason
    // the branch has two cases at all.
    assert_eq!(Fq::MINUS_ONE.sqrt(), None, "-1 is a nonresidue in Fq");
    let minus_one = Fq2::from_fq(Fq::MINUS_ONE);
    let root = minus_one.sqrt().expect("-1 is a square in Fq2: it is u^2");
    assert_eq!(root.square(), minus_one);
    assert_eq!(root.c0, Fq::ZERO, "the root of -1 is purely imaginary");
}

/// Every square in Fq2 has a root, on both branches of the closed form, and
/// every root squares back. This is the property the fixtures only sample.
#[test]
fn fq2_sqrt_finds_every_root() {
    let mut rng = Rng::new(SEED ^ 8);
    for round in 0..500 {
        // A random square, so a root must exist.
        let x = next_fq2(&mut rng);
        let square = x.square();
        let root = square
            .sqrt()
            .unwrap_or_else(|| panic!("a square has a root, round {round}"));
        assert_eq!(root.square(), square);
        assert!(root == x || root == -x, "a root is x or -x, round {round}");

        // The `c1 == 0` branch, both ways round: a real square, and a real
        // nonresidue whose root is purely imaginary.
        let real = Fq2::from_fq(next_fq(&mut rng));
        let real_square = real.square();
        assert_eq!(
            real_square.sqrt().map(|r| r.square()),
            Some(real_square),
            "a real square has a real root"
        );
        let negated = -real_square;
        let root = negated.sqrt().expect("-(a^2) is a square in Fq2");
        assert_eq!(root.square(), negated);
        assert_eq!(root.c0, Fq::ZERO);
    }
}

#[test]
fn fq_batch_inverse_matches_one_at_a_time() {
    let mut rng = Rng::new(SEED ^ 9);
    for len in [0usize, 1, 2, 3, 17, 1_000] {
        for shape in 0..3 {
            let mut xs: Vec<Fq> = (0..len)
                .map(|i| match shape {
                    0 => Fq::ZERO,
                    1 => next_fq(&mut rng),
                    _ if i % 3 == 0 => Fq::ZERO,
                    _ => next_fq(&mut rng),
                })
                .collect();
            let expected: Vec<Fq> = xs.iter().map(|x| x.inverse().unwrap_or(Fq::ZERO)).collect();
            batch_inverse(&mut xs);
            assert_eq!(xs, expected, "batch_inverse, len {len}, shape {shape}");
        }
    }
}
