#![no_std]
#![no_main]
//! The precompiles and the SDK's `U256`, each at the edges a test knows the
//! answer to without them: the Poseidon2 permutation of the generator's own
//! input and of sixteen lanes at `2^64 − 1`, a Merkle root over the leaves the
//! public input carries, `mul_div` where its answer is hand-derived or a
//! `u128`'s, overflowing, by zero, and at `U256::MAX`, and Merkle paths by
//! `merkle_root`, the first two each checked against the fold
//! `poseidon2_compress` gives, then a run of them long enough that a path's
//! levels straddle a shard; Keccak-f[1600] of the state the public input
//! carries, once and then a chain of it, and SHAKE256 of its message, absorbed
//! and squeezed in halves; and Falcon-512's lattice check of the three arrays
//! the public input carries, once and then their rotations in turn.
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
//!   then    state    25 lanes        u64 LE each, Keccak-f[1600]'s input
//!           chain    u32 LE          permutations after the first
//!   then    len      u32 LE          SHAKE256's message length
//!           message  len bytes
//!           squeeze  u32 LE          bytes of SHAKE256 output, at most 2,048
//!   then    h        512 u16 LE      Falcon-512's arrays, any halfwords, each
//!           s2       512 u16 LE      read mod q
//!           c        512 u16 LE
//!           more     u32 LE          s1_norm calls after the first
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
//!   keccak_f1600                    25 u64: the input's state permuted
//!   keccak_f1600                    25 u64: that state permuted chain times more
//!   SHAKE256                        squeeze bytes of the message's output, the
//!                                   message absorbed and the output squeezed
//!                                   in two halves
//!   falcon512::s1_norm              u64: ‖s1‖² of the input's h, s2 and c
//!   falcon512::s1_norm              u64: the sum of more calls', call k's
//!                                   arrays the input's rotated k times: (s2,
//!                                   c, h), (c, h, s2), (h, s2, c), …
//! ```
//!
//! With 126 runs the depth-20 path is levels 4,080 to 4,099: it straddles
//! level 4,096, where a `MERKLE_ROUNDS` shard ends at `2^12` rows and at
//! `2^16`. With a chain of 520 the Keccak calls are more than the 512 a
//! `KECCAK_RHO` or `KECCAK_CHI` shard holds at `2^16`, so a streaming run hands
//! one over mid-execution, and with 1,024 more `s1_norm` calls the Falcon calls
//! are more than the 1,024 a `FALCON_SPLIT` shard holds.

use guest_sdk::falcon512::{self, Poly};
use guest_sdk::{
    keccak_f1600, merkle_root, poseidon2_compress, poseidon2_permute, Digest, Shake256, U256,
};

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
    let mut out = [0u8; 4096];
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

    let at_state = at_path + 12 + 64 * depth;
    let lane = |at: usize| u64::from_le_bytes(input[at..at + 8].try_into().expect("a lane"));
    let mut state: [u64; 25] = core::array::from_fn(|i| lane(at_state + 8 * i));
    keccak_f1600(&mut state);
    state.iter().for_each(|l| put(&l.to_le_bytes()));
    for _ in 0..word(at_state + 200) {
        keccak_f1600(&mut state);
    }
    state.iter().for_each(|l| put(&l.to_le_bytes()));

    let at_message = at_state + 208;
    let len = word(at_state + 204) as usize;
    let message = &input[at_message..at_message + len];
    let squeeze = word(at_message + len) as usize;
    let mut bytes = [0u8; 2048];
    assert!(
        squeeze <= bytes.len(),
        "precompiles: SHAKE256 squeezes at most 2,048 bytes"
    );
    let mut sponge = Shake256::new();
    sponge.absorb(&message[..len / 2]);
    sponge.absorb(&message[len / 2..]);
    sponge.finalize();
    sponge.squeeze(&mut bytes[..squeeze / 2]);
    sponge.squeeze(&mut bytes[squeeze / 2..squeeze]);
    put(&bytes[..squeeze]);

    let at_falcon = at_message + len + 4;
    let poly = |i: usize| {
        let at = at_falcon + 1024 * i;
        Poly(core::array::from_fn(|t| {
            u16::from_le_bytes([input[at + 2 * t], input[at + 2 * t + 1]])
        }))
    };
    let polys = [poly(0), poly(1), poly(2)];
    put(&falcon512::s1_norm(&polys[0], &polys[1], &polys[2]).to_le_bytes());
    let mut sum = 0u64;
    for k in 1..=word(at_falcon + 3 * 1024) as usize {
        let p = |i: usize| &polys[(i + k) % 3];
        sum += falcon512::s1_norm(p(0), p(1), p(2));
    }
    put(&sum.to_le_bytes());
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
