//! The field against Rust's own `u128` remainder, which shares nothing with
//! this crate.

use field_a64_c5::{Fp, A64_C5};
use test_support::Rng;

/// `+` and `×` in every pairing of the values a `2^64 − 59` reduction gets
/// wrong first and a seeded random set, and `from_u128` at every `u128` whose
/// two halves are among those values or the words at and above `p`.
#[test]
fn the_field_is_integer_arithmetic_mod_p() {
    let p = A64_C5 as u128;
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
    let mut rng = Rng::new(0xa64c5);
    let values: Vec<u64> = edges
        .into_iter()
        .chain((0..100).map(|_| rng.next_u64() % A64_C5))
        .collect();
    for &a in &values {
        let x = Fp::from_u64(a);
        assert_eq!(Fp::from_canonical(a), Some(x));
        assert_eq!(x.to_u64(), a);
        assert_eq!(x + Fp::ZERO, x);
        assert_eq!(x * Fp::ONE, x);
        for &b in &values {
            let y = Fp::from_u64(b);
            assert_eq!((x + y).to_u64() as u128, (a as u128 + b as u128) % p);
            assert_eq!((x * y).to_u64() as u128, a as u128 * b as u128 % p);
        }
    }

    // The 59 words at and above `p` are not canonical; `from_u64` reduces them.
    let high = [A64_C5, A64_C5 + 1, u64::MAX];
    for w in high {
        assert_eq!(Fp::from_canonical(w), None);
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
