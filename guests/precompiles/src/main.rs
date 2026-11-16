#![no_std]
#![no_main]
//! The precompiles and the SDK's `U256`, each at the edges a test knows the
//! answer to without them: the Poseidon2 permutation of the generator's own
//! input and of sixteen lanes at `2^64 − 1`, a Merkle root over the leaves the
//! public input carries, `mul_div` where its answer is hand-derived or a
//! `u128`'s, overflowing, by zero, and at `U256::MAX`, and Merkle paths by
//! `merkle_root`, the first two each checked against the fold
//! `poseidon2_compress` gives, then a run of them long enough that a path's
//! levels straddle a shard.
//!
//! # The public input
//!
//! ```text
//!           0..4     n               u32 LE, a power of two, at most 16
//!           4..      n leaves        8 lanes of u64 LE each, each below p
//!   then    slot     u32 LE          below 2^depth
//!           depth    u32 LE          16..=32
//!           path     depth siblings  64 bytes each, each lane below p
//!   then    runs     u32 LE          depth-32 paths before the last, depth-20 one
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
//!   merkle_root                     8 u64: leaf 0 at slot up the input's path,
//!                                   its siblings read in place from the input
//!   merkle_root                     8 u64: leaf 0 at slot 2^32 − 1, depth 32, up
//!                                   the leaves in turn, from the guest's memory
//!   merkle_root                     8 u64: path i < runs from the root before it,
//!                                   at slot i, up the same 32 siblings; then a
//!                                   depth-20 one from the last, at slot 0x5a5a5,
//!                                   up their first 20
//! ```
//!
//! With 126 runs the depth-20 path is levels 4,080 to 4,099: it straddles
//! level 4,096, where a `MERKLE_ROUNDS` shard ends at `2^12` rows and at
//! `2^16`.

use guest_sdk::{merkle_root, poseidon2_compress, poseidon2_permute, Digest, U256};

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
    let mut leaves = [Digest::default(); 16];
    for (i, leaf) in leaves.iter_mut().take(n).enumerate() {
        *leaf = digest(&input[4 + 64 * i..]);
    }
    let mut level = leaves;
    let mut width = n;
    while width > 1 {
        for i in 0..width / 2 {
            level[i] = poseidon2_compress(&level[2 * i], &level[2 * i + 1]);
        }
        width /= 2;
    }
    level[0].lanes().iter().for_each(|l| put(&l.to_le_bytes()));
    let mut state = [0u64; 16];
    state[..8].copy_from_slice(level[0].lanes());
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

    let at_path = 4 + 64 * n;
    let word = |at: usize| u32::from_le_bytes(input[at..at + 4].try_into().expect("a word"));
    let (slot, depth) = (word(at_path), word(at_path + 4) as usize);
    let path = &input[at_path + 8..at_path + 8 + 64 * depth];
    let root = merkle_root(slot, &leaves[0], path);
    let mut node = leaves[0];
    for (level, sibling) in path.chunks(64).enumerate() {
        node = fold(slot, level, &node, &digest(sibling));
    }
    assert!(root == node, "precompiles: merkle_root is not the fold");
    root.lanes().iter().for_each(|l| put(&l.to_le_bytes()));

    let ram: [Digest; 32] = core::array::from_fn(|l| leaves[l % n]);
    let root = merkle_root(u32::MAX, &leaves[0], Digest::bytes(&ram));
    let node = ram
        .iter()
        .enumerate()
        .fold(leaves[0], |node, (level, sibling)| {
            fold(u32::MAX, level, &node, sibling)
        });
    assert!(root == node, "precompiles: merkle_root is not the fold");
    root.lanes().iter().for_each(|l| put(&l.to_le_bytes()));

    let runs = word(at_path + 8 + 64 * depth);
    let mut node = leaves[0];
    for i in 0..runs {
        node = merkle_root(i, &node, Digest::bytes(&ram));
    }
    let root = merkle_root(0x5a5a5, &node, &Digest::bytes(&ram)[..64 * 20]);
    root.lanes().iter().for_each(|l| put(&l.to_le_bytes()));
    guest_sdk::commit(&out[..at]);
}

/// The digest at the start of `b`, 8 lanes of u64 LE, each below `p`.
fn digest(b: &[u8]) -> Digest {
    let lanes = core::array::from_fn(|j| {
        u64::from_le_bytes(b[8 * j..8 * j + 8].try_into().expect("a lane"))
    });
    Digest::new(lanes).expect("precompiles: a lane is not below p")
}

/// Level `level` of a path from `slot`: the node on the left where its bit is 0.
fn fold(slot: u32, level: usize, node: &Digest, sibling: &Digest) -> Digest {
    match slot >> level & 1 {
        0 => poseidon2_compress(node, sibling),
        _ => poseidon2_compress(sibling, node),
    }
}
