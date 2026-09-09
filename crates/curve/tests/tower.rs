//! Fq6 and Fq12 as fields: the axioms, the tower relations that define them,
//! and the Frobenius checked against its own definition rather than against a
//! table.
//!
//! `tests/kats.rs` pins every value against arkworks. This file pins the
//! structure, and one test here — [`frobenius_is_the_q_power_map`] — re-derives
//! every entry of every Frobenius table from `a^(q^i)` with no oracle at all,
//! which is the independent half of "never trusted from derivation alone".

mod common;

use common::next_fq2;
use constants::{FQ6_NONRESIDUE_C0, FQ6_NONRESIDUE_C1, FQ_MODULUS};
use curve::{Fq, Fq12, Fq2, Fq6};
use test_support::Rng;

const SEED: u64 = 20260917;

fn next_fq6(rng: &mut Rng) -> Fq6 {
    Fq6::new(next_fq2(rng), next_fq2(rng), next_fq2(rng))
}

fn next_fq12(rng: &mut Rng) -> Fq12 {
    Fq12::new(next_fq6(rng), next_fq6(rng))
}

/// `xi = 9 + u`, read from `constants` rather than written here.
fn xi() -> Fq2 {
    Fq2::new(
        Fq::from_hex(FQ6_NONRESIDUE_C0).expect("xi's real part is canonical"),
        Fq::from_hex(FQ6_NONRESIDUE_C1).expect("xi's u part is canonical"),
    )
}

/// `v`, the generator of Fq6 over Fq2.
fn v() -> Fq6 {
    Fq6::new(Fq2::ZERO, Fq2::ONE, Fq2::ZERO)
}

/// `w`, the generator of Fq12 over Fq6.
fn w() -> Fq12 {
    Fq12::new(Fq6::ZERO, Fq6::ONE)
}

// ---------------------------------------------------------------------------
// The relations that define the tower
// ---------------------------------------------------------------------------

#[test]
fn the_tower_is_the_one_the_constants_describe() {
    // Fq6 = Fq2[v]/(v^3 - xi)
    assert_eq!(
        v() * v() * v(),
        Fq6::from_fq2(xi()),
        "v^3 must be xi = 9 + u"
    );
    // Fq12 = Fq6[w]/(w^2 - v), so w^2 = v, w^6 = xi and w^12 = xi^2.
    assert_eq!(w() * w(), Fq12::new(v(), Fq6::ZERO), "w^2 must be v");
    assert_eq!(
        w().pow(&[6, 0, 0, 0]),
        Fq12::new(Fq6::from_fq2(xi()), Fq6::ZERO),
        "w^6 must be xi"
    );
    assert_eq!(
        w().pow(&[12, 0, 0, 0]),
        Fq12::new(Fq6::from_fq2(xi() * xi()), Fq6::ZERO),
        "w^12 must be xi^2"
    );

    // `mul_by_nonresidue` is multiplication by the generator one level up.
    let mut rng = Rng::new(SEED);
    for _ in 0..8 {
        let a = next_fq6(&mut rng);
        assert_eq!(
            a.mul_by_nonresidue(),
            a * v(),
            "Fq6 mul_by_nonresidue != *v"
        );
        let x = next_fq2(&mut rng);
        assert_eq!(
            x.mul_by_nonresidue(),
            x * xi(),
            "Fq2 mul_by_nonresidue != *xi"
        );
    }
}

// ---------------------------------------------------------------------------
// The field axioms
// ---------------------------------------------------------------------------

#[test]
fn fq6_is_a_field() {
    let mut rng = Rng::new(SEED + 1);
    for _ in 0..32 {
        let (a, b, c) = (next_fq6(&mut rng), next_fq6(&mut rng), next_fq6(&mut rng));

        assert_eq!(a + b, b + a);
        assert_eq!((a + b) + c, a + (b + c));
        assert_eq!(a * b, b * a);
        assert_eq!((a * b) * c, a * (b * c));
        assert_eq!(a * (b + c), a * b + a * c);
        assert_eq!(a - b, a + (-b));
        assert_eq!(a + Fq6::ZERO, a);
        assert_eq!(a * Fq6::ONE, a);
        assert_eq!(a * Fq6::ZERO, Fq6::ZERO);
        assert_eq!(a + (-a), Fq6::ZERO);
        assert_eq!(-(-a), a);
        assert_eq!(a.square(), a * a);

        let inv = a.inverse().expect("a random Fq6 is nonzero");
        assert_eq!(a * inv, Fq6::ONE);
        assert_eq!(inv.inverse().expect("an inverse is nonzero"), a);

        assert_eq!(a.pow(&[0, 0, 0, 0]), Fq6::ONE);
        assert_eq!(a.pow(&[1, 0, 0, 0]), a);
        assert_eq!(a.pow(&[3, 0, 0, 0]), a * a * a);

        // The Fq2 embedding is a ring homomorphism.
        let (x, y) = (next_fq2(&mut rng), next_fq2(&mut rng));
        assert_eq!(
            Fq6::from_fq2(x) * Fq6::from_fq2(y),
            Fq6::from_fq2(x * y),
            "the Fq2 embedding must be multiplicative"
        );
    }
    assert_eq!(Fq6::ZERO.inverse(), None, "zero has no inverse");
    assert_eq!(Fq6::ONE.inverse(), Some(Fq6::ONE));
}

#[test]
fn fq12_is_a_field() {
    let mut rng = Rng::new(SEED + 2);
    for _ in 0..24 {
        let (a, b, c) = (
            next_fq12(&mut rng),
            next_fq12(&mut rng),
            next_fq12(&mut rng),
        );

        assert_eq!(a + b, b + a);
        assert_eq!((a + b) + c, a + (b + c));
        assert_eq!(a * b, b * a);
        assert_eq!((a * b) * c, a * (b * c));
        assert_eq!(a * (b + c), a * b + a * c);
        assert_eq!(a - b, a + (-b));
        assert_eq!(a + Fq12::ZERO, a);
        assert_eq!(a * Fq12::ONE, a);
        assert_eq!(a * Fq12::ZERO, Fq12::ZERO);
        assert_eq!(a + (-a), Fq12::ZERO);
        assert_eq!(a.square(), a * a);

        let inv = a.inverse().expect("a random Fq12 is nonzero");
        assert_eq!(a * inv, Fq12::ONE);
        assert_eq!(inv.inverse().expect("an inverse is nonzero"), a);

        assert_eq!(a.pow(&[0, 0, 0, 0]), Fq12::ONE);
        assert_eq!(a.pow(&[1, 0, 0, 0]), a);
        assert_eq!(a.pow(&[3, 0, 0, 0]), a * a * a);

        // Conjugation is an involution and a ring homomorphism.
        assert_eq!(a.conjugate().conjugate(), a);
        assert_eq!((a * b).conjugate(), a.conjugate() * b.conjugate());
        assert_eq!((a + b).conjugate(), a.conjugate() + b.conjugate());
    }
    assert_eq!(Fq12::ZERO.inverse(), None, "zero has no inverse");
    assert_eq!(Fq12::ONE.inverse(), Some(Fq12::ONE));
}

/// The cofactor identity `Fq6::inverse`'s doc comment claims: the triple it
/// divides by the norm really is the adjugate.
#[test]
fn fq6_inverse_uses_the_adjugate_it_claims() {
    let mut rng = Rng::new(SEED + 3);
    for _ in 0..16 {
        let a = next_fq6(&mut rng);
        let t0 = a.c0.square() - (a.c1 * a.c2).mul_by_nonresidue();
        let t1 = a.c2.square().mul_by_nonresidue() - a.c0 * a.c1;
        let t2 = a.c1.square() - a.c0 * a.c2;
        let d = a.c0 * t0 + (a.c2 * t1 + a.c1 * t2).mul_by_nonresidue();

        assert_ne!(d, Fq2::ZERO, "the norm of a nonzero element is nonzero");
        assert_eq!(
            a * Fq6::new(t0, t1, t2),
            Fq6::from_fq2(d),
            "a * adj(a) must be the norm"
        );
        let d_inv = d.inverse().expect("a nonzero norm inverts");
        assert_eq!(
            a.inverse().expect("nonzero"),
            Fq6::new(t0 * d_inv, t1 * d_inv, t2 * d_inv)
        );
    }
}

// ---------------------------------------------------------------------------
// The Frobenius, from its definition
// ---------------------------------------------------------------------------

/// `frobenius_map(i)` is `a^(q^i)`, checked by actually raising to `q` that
/// many times.
///
/// This is the test that makes the Frobenius coefficient tables in `constants`
/// independently verified rather than merely copied: nothing here reads a
/// table, and an error in any of the 6 + 6 + 12 entries fails it. `FQ_MODULUS`
/// is `q` as a plain 256-bit integer, which is exactly what `pow` takes.
#[test]
fn frobenius_is_the_q_power_map() {
    let mut rng = Rng::new(SEED + 4);

    for _ in 0..3 {
        let a = next_fq6(&mut rng);
        let mut expected = a;
        for power in 0..6 {
            assert_eq!(
                a.frobenius_map(power),
                expected,
                "Fq6 frobenius_map({power}) != a^(q^{power})"
            );
            expected = expected.pow(&FQ_MODULUS);
        }
        // The map has order 6 on Fq6: a^(q^6) = a.
        assert_eq!(expected, a, "Fq6 has q^6 elements, so a^(q^6) = a");
        assert_eq!(a.frobenius_map(6), a, "power 6 must reduce to 0");
        assert_eq!(
            a.frobenius_map(7),
            a.frobenius_map(1),
            "power reduces mod 6"
        );
    }

    for _ in 0..2 {
        let a = next_fq12(&mut rng);
        let mut expected = a;
        for power in 0..12 {
            assert_eq!(
                a.frobenius_map(power),
                expected,
                "Fq12 frobenius_map({power}) != a^(q^{power})"
            );
            expected = expected.pow(&FQ_MODULUS);
        }
        assert_eq!(expected, a, "Fq12 has q^12 elements, so a^(q^12) = a");
        assert_eq!(a.frobenius_map(12), a, "power 12 must reduce to 0");
        assert_eq!(
            a.frobenius_map(13),
            a.frobenius_map(1),
            "power reduces mod 12"
        );
        // Conjugation is the q^6 Frobenius, which is what the final
        // exponentiation's easy part treats it as.
        assert_eq!(
            a.frobenius_map(6),
            a.conjugate(),
            "conj != frobenius_map(6)"
        );
    }
}

#[test]
fn frobenius_is_a_ring_homomorphism() {
    let mut rng = Rng::new(SEED + 5);
    for power in 0..12 {
        let (a, b) = (next_fq12(&mut rng), next_fq12(&mut rng));
        assert_eq!(
            (a * b).frobenius_map(power),
            a.frobenius_map(power) * b.frobenius_map(power)
        );
        assert_eq!(
            (a + b).frobenius_map(power),
            a.frobenius_map(power) + b.frobenius_map(power)
        );
        assert_eq!(Fq12::ONE.frobenius_map(power), Fq12::ONE);

        let (x, y) = (next_fq6(&mut rng), next_fq6(&mut rng));
        assert_eq!(
            (x * y).frobenius_map(power),
            x.frobenius_map(power) * y.frobenius_map(power)
        );
        assert_eq!(Fq6::ONE.frobenius_map(power), Fq6::ONE);
        // Fq2 elements are fixed by even powers and conjugated by odd ones.
        let e = next_fq2(&mut rng);
        assert_eq!(
            Fq6::from_fq2(e).frobenius_map(power),
            Fq6::from_fq2(if power % 2 == 0 { e } else { e.conjugate() })
        );
    }
}

// ---------------------------------------------------------------------------
// Equality is not vacuous
// ---------------------------------------------------------------------------

/// S05 found that a suite can be silently emptied by an equality that always
/// says yes. `Fq6` and `Fq12` derive `PartialEq`, but nothing else here ever
/// asserts two of them are *different*, so this does.
#[test]
fn equality_distinguishes_every_coefficient() {
    let mut rng = Rng::new(SEED + 6);
    let a = next_fq6(&mut rng);
    assert_ne!(Fq6::ZERO, Fq6::ONE);
    for k in 0..3 {
        let mut b = a;
        let bump = |x: Fq2| x + Fq2::ONE;
        match k {
            0 => b.c0 = bump(b.c0),
            1 => b.c1 = bump(b.c1),
            _ => b.c2 = bump(b.c2),
        }
        assert_ne!(a, b, "Fq6 equality ignores coefficient {k}");
    }

    let a = next_fq12(&mut rng);
    assert_ne!(Fq12::ZERO, Fq12::ONE);
    for k in 0..2 {
        let mut b = a;
        if k == 0 {
            b.c0 += Fq6::ONE;
        } else {
            b.c1 += Fq6::ONE;
        }
        assert_ne!(a, b, "Fq12 equality ignores half {k}");
    }

    // ...and down to a single Fq coefficient, which is what a wrong Frobenius
    // constant would move.
    let mut b = a;
    b.c1.c2.c1 += Fq::ONE;
    assert_ne!(a, b, "Fq12 equality ignores its last Fq coefficient");
}
