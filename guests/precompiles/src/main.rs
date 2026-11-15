#![no_std]
#![no_main]
//! Both precompiles and the SDK's `U256`, each at the edges a test knows the
//! answer to without either: the Poseidon2 permutation of the generator's own
//! input and of sixteen lanes at `2^64 − 1`, a Merkle root over the leaves the
//! public input carries, and `mul_div` where its answer is hand-derived or a
//! `u128`'s, overflowing, by zero, and at `U256::MAX`.
//!
//! # The public input
//!
//! ```text
//!           0..4     n               u32 LE, a power of two, at most 16
//!           4..      n leaves        8 lanes of u64 LE each
//! ```
//!
//! # The journal
//!
//! ```text
//!   permute [0, 1, …, 15]           16 u64
//!   permute [2^64 − 1; 16]          16 u64, every lane read mod p
//!   the Merkle root                 8 u64, `poseidon2_compress` pairwise
//!   a chain                         16 u64: [root, 0^8] permuted CHAIN times
//!   for each mul_div case below     a status byte (1 answered, 0 refused),
//!                                   then q and r, 32 bytes LE each, zero if refused
//! ```

use guest_sdk::{poseidon2_compress, poseidon2_permute, U256};

guest_sdk::entry!(main);

/// The chain's permutations: more than a `2^12`-row shard of the rounds holds,
/// 256 calls, so a streaming run fills that buffer mid-execution.
const CHAIN: usize = 300;

/// `2^k`.
fn pow2(k: u32) -> U256 {
    U256::ONE << k
}

fn main() {
    let input = guest_sdk::public_input();
    let mut out = [0u8; 2048];
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        out[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };

    let mut state: [u64; 16] = core::array::from_fn(|i| i as u64);
    poseidon2_permute(&mut state);
    state.iter().for_each(|l| put(&l.to_le_bytes()));
    let mut state = [u64::MAX; 16];
    poseidon2_permute(&mut state);
    state.iter().for_each(|l| put(&l.to_le_bytes()));

    let n = u32::from_le_bytes(input[..4].try_into().expect("a leaf count")) as usize;
    assert!(
        n.is_power_of_two() && n <= 16,
        "precompiles: n is a power of two to 16"
    );
    let mut level = [[0u64; 8]; 16];
    for (i, leaf) in level.iter_mut().take(n).enumerate() {
        for (j, lane) in leaf.iter_mut().enumerate() {
            let at = 4 + 64 * i + 8 * j;
            *lane = u64::from_le_bytes(input[at..at + 8].try_into().expect("a lane"));
        }
    }
    let mut width = n;
    while width > 1 {
        for i in 0..width / 2 {
            level[i] = poseidon2_compress(&level[2 * i], &level[2 * i + 1]);
        }
        width /= 2;
    }
    level[0].iter().for_each(|l| put(&l.to_le_bytes()));
    let mut state = [0u64; 16];
    state[..8].copy_from_slice(&level[0]);
    for _ in 0..CHAIN {
        poseidon2_permute(&mut state);
    }
    state.iter().for_each(|l| put(&l.to_le_bytes()));

    let p = 0xffff_ffff_ffff_ffc5u64;
    let cases = [
        (pow2(200), pow2(100), pow2(60)),
        (U256::MAX, U256::MAX, U256::MAX),
        (
            U256::from(p),
            U256::from(0x1234_5678_9abc_def0u64),
            U256::from(1_000_000_007u64),
        ),
        (U256::MAX, U256::ONE, U256::from(3u64)),
        (U256::MAX - U256::ONE, U256::MAX, U256::MAX),
        (pow2(200), pow2(200), pow2(100)),
        (U256::ONE, U256::ONE, U256::ZERO),
    ];
    for (a, b, d) in cases {
        match a.mul_div_rem(b, d) {
            Some((q, r)) => {
                put(&[1]);
                put(&q.to_le_bytes());
                put(&r.to_le_bytes());
            }
            None => {
                put(&[0]);
                put(&[0; 64]);
            }
        }
    }
    guest_sdk::commit(&out[..at]);
}
