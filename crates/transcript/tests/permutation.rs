//! The permutation, against an implementation that shares nothing with this
//! crate.

use field::Fp;
use transcript::{poseidon2_permute, WIDTH};

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
