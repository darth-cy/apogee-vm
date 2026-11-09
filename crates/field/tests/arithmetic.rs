//! The field against Rust's own `u128` remainder, which shares nothing with
//! this crate.

use field::{Fp, Fp2, Fp2Sum, A64_C5};
use test_support::Rng;

/// The values a `2^64 − 59` reduction gets wrong first, then a seeded random
/// set.
fn values(seed: u64) -> Vec<u64> {
    let edges = [
        0,
        1,
        2,
        58,
        59,
        60,
        1 << 32,
        (1 << 63) - 1,
        1 << 63,
        A64_C5 - 59,
        A64_C5 - 2,
        A64_C5 - 1,
    ];
    let mut rng = Rng::new(seed);
    edges
        .into_iter()
        .chain((0..100).map(|_| rng.next_u64() % A64_C5))
        .collect()
}

/// `+`, `−` and `×` in every pairing of [`values`], negation and the inverse
/// of each, and `from_u128` at every `u128` whose two halves are among those
/// values or the words at and above `p`.
#[test]
fn the_field_is_integer_arithmetic_mod_p() {
    let p = A64_C5 as u128;
    let values = values(0xa64c5);
    for &a in &values {
        let x = Fp::from_u64(a);
        assert_eq!(Fp::from_canonical(a), Some(x));
        assert_eq!(Fp::from_bytes(&x.to_bytes()), Some(x));
        assert_eq!(x.to_u64(), a);
        assert_eq!(x + Fp::ZERO, x);
        assert_eq!(x * Fp::ONE, x);
        assert_eq!((-x).to_u64() as u128, (p - a as u128) % p);
        match x.inverse() {
            Some(inv) => assert_eq!(x * inv, Fp::ONE),
            None => assert_eq!(a, 0),
        }
        for &b in &values {
            let y = Fp::from_u64(b);
            assert_eq!((x + y).to_u64() as u128, (a as u128 + b as u128) % p);
            assert_eq!((x - y).to_u64() as u128, (a as u128 + p - b as u128) % p);
            assert_eq!((x * y).to_u64() as u128, a as u128 * b as u128 % p);
        }
    }
    assert_eq!(Fp::MINUS_ONE + Fp::ONE, Fp::ZERO);

    // The 59 words at and above `p` are not canonical; `from_u64` reduces them.
    let high = [A64_C5, A64_C5 + 1, u64::MAX];
    for w in high {
        assert_eq!(Fp::from_canonical(w), None);
        assert_eq!(Fp::from_bytes(&w.to_le_bytes()), None);
        assert_eq!(Fp::from_u64(w).to_u64() as u128, w as u128 % p);
    }

    let words: Vec<u64> = values.iter().copied().chain(high).collect();
    for &hi in &words {
        for &lo in &words {
            let x = ((hi as u128) << 64) | lo as u128;
            assert_eq!(Fp::from_u128(x).to_u64() as u128, x % p);
        }
    }
}

/// `F_{p^2}` against its definition over the integers: `x^2 = 2`, product and
/// inverse by the schoolbook rule mod `p`, a sum of products reduced once
/// against the same products reduced each, and 2 a non-square by Euler's
/// criterion, `2^((p−1)/2) = −1`, which is what makes it a field.
#[test]
fn the_extension_is_the_field_mod_x2_minus_2() {
    let p = A64_C5 as u128;
    let pow = |x: Fp, mut e: u64| {
        let (mut base, mut acc) = (x, Fp::ONE);
        while e > 0 {
            if e & 1 == 1 {
                acc *= base;
            }
            base *= base;
            e >>= 1;
        }
        acc
    };
    assert_eq!(pow(Fp::from_u64(2), (A64_C5 - 1) / 2), Fp::MINUS_ONE);

    let x = Fp2 {
        c0: Fp::ZERO,
        c1: Fp::ONE,
    };
    assert_eq!(x * x, Fp2::from(Fp::from_u64(2)));

    let (lo, hi) = (values(1), values(2));
    let elements: Vec<(u64, u64)> = lo.iter().copied().zip(hi.iter().copied()).collect();
    let fp2 = |(a0, a1): (u64, u64)| Fp2 {
        c0: Fp::from_u64(a0),
        c1: Fp::from_u64(a1),
    };
    let (mut sum, mut each) = (Fp2Sum::default(), Fp2::ZERO);
    for &a in &elements {
        let x = fp2(a);
        assert_eq!(Fp2::from_bytes(&x.to_bytes()), Some(x));
        match x.inverse() {
            Some(inv) => assert_eq!(x * inv, Fp2::ONE),
            None => assert_eq!(a, (0, 0)),
        }
        for &b in &elements {
            let y = fp2(b);
            let (a0, a1, b0, b1) = (a.0 as u128, a.1 as u128, b.0 as u128, b.1 as u128);
            let c0 = (a0 * b0 % p + 2 * (a1 * b1 % p)) % p;
            let c1 = (a0 * b1 % p + a1 * b0 % p) % p;
            assert_eq!(x * y, fp2((c0 as u64, c1 as u64)));
            sum.add_product(x, y);
            each += x * y;
            assert_eq!(x * y.c0, x * Fp2::from(y.c0));
            assert_eq!(y.c0 * x, x * y.c0);
            assert_eq!(x + y - y, x);
            assert_eq!(x + y.c0, x + Fp2::from(y.c0));
            assert_eq!(y.c0 + x, x + y.c0);
            assert_eq!(x - y.c0, x - Fp2::from(y.c0));
            assert_eq!(y.c0 - x, Fp2::from(y.c0) - x);
        }
    }
    assert_eq!(sum.reduce(), each);
}
