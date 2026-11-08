//! The permutation and its field, each against an implementation that shares
//! nothing with this crate.

use test_support::Rng;
use transcript_a64_c5::{poseidon2_permute, Fp, A64_C5, WIDTH};

/// The generator's own Poseidon2 at `[0, 1, …, 15]`: `poseidon2()` in
/// `poseidon2_rust_params.sage`, explicit matrices over Sage's `GF(p)`, printed
/// by the run that printed the constants (`docs/tools.md` §8). Every round
/// constant and diagonal entry reaches every output lane, so this one vector
/// holds the whole table as well as the round structure.
#[rustfmt::skip]
const GENERATOR_KAT: [u64; WIDTH] = [
    0x59bb4dfebd9c36af, 0x04ef6d6db08fe0c3, 0x58712eed1ea7dab3, 0x6fdcdfd2cac82706,
    0xc28b6eb60e8cc108, 0x2dceea61d9b39cdc, 0x38a3f5e89590b70b, 0x8eaf1d087cb5fd81,
    0x461e234d53d95651, 0x3b06fe7980170f39, 0x3f92a9c75ed65822, 0x652f6a10605b537d,
    0x11f277067885fa72, 0x744edcd6a289fcb0, 0xde10fc99342e7e2b, 0x189b9d1e6db72de6,
];

#[test]
fn the_permutation_is_the_generators() {
    let mut state: [Fp; WIDTH] = core::array::from_fn(|i| Fp::from_u64(i as u64));
    poseidon2_permute(&mut state);
    assert_eq!(state.map(Fp::to_u64), GENERATOR_KAT);
}

/// `+` and `×` against Rust's own `u128` remainder, in every pairing of the
/// values a `2^64 − 59` reduction gets wrong first and a seeded random set.
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
        for &b in &values {
            let (x, y) = (Fp::from_u64(a), Fp::from_u64(b));
            assert_eq!((x + y).to_u64() as u128, (a as u128 + b as u128) % p);
            assert_eq!((x * y).to_u64() as u128, a as u128 * b as u128 % p);
        }
    }

    // The 59 words at and above `p` are not canonical; `from_u64` reduces them.
    for w in [A64_C5, A64_C5 + 1, u64::MAX] {
        assert_eq!(Fp::from_canonical(w), None);
        assert_eq!(Fp::from_u64(w).to_u64() as u128, w as u128 % p);
    }
}
