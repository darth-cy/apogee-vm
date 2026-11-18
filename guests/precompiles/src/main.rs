#![no_std]
#![no_main]
//! The precompiles and the SDK's `U256`, each at the edges a test knows the
//! answer to without them: the Poseidon2 permutation of the generator's own
//! input and of sixteen lanes at `2^64 − 1`, the root of the leaves the public
//! input carries, compressed pairwise, and `mul_div` where its answer is
//! hand-derived or a `u128`'s, overflowing, by zero, and at `U256::MAX`;
//! Falcon-512's lattice check of the three arrays the public input carries,
//! once and then their rotations in turn; HashToPoint's sampler over lanes at
//! its edges; trie roots by `mpt_eval` over op programs written by hand, each
//! checked against the trie's hashes by `poseidon2_compress`, some of the
//! blocks advised, then a program long enough that its ops straddle a shard,
//! checked against the permutation; tables by the SDK's trie, each opened from
//! the proof the advice carries, held to its root, edited by a batch and its
//! root journaled; and Falcon-512 verification of the keys, signatures,
//! messages and contexts it carries, the keys and the signatures in the SDK's
//! advised forms.
//!
//! # The public input
//!
//! ```text
//!           0..4     n               u32 LE, a power of two, at most 16
//!           4..      n leaves        8 lanes of u64 LE each, each below p
//!   then    h        512 u16 LE      Falcon-512's arrays, any halfwords, each
//!           s2       512 u16 LE      read mod q
//!           c        512 u16 LE
//!           more     u32 LE          s1_norm calls after the first
//!   then    cases    u32 LE          Falcon-512 verifications
//!           keys     per case        its key, 896 bytes, then its signature, a
//!                                    u32 LE length and its bytes, a whole
//!                                    number of words
//!           strings  per case        its message, then its context, each a
//!                                    u32 LE length and its bytes
//! ```
//!
//! Every key and signature starts on a word, as the SDK reads them in place,
//! and no byte of the input is padding: the messages and contexts, of any
//! length, follow every case's key and signature.
//!
//! # The advice
//!
//! ```text
//!           0..4     steps           u32 LE, the long program's hash ops, at
//!                                    least 1
//!           4..      steps + 1       blocks, 64 bytes each: 16 u32 LE words,
//!                                    8 lanes, each read mod p
//!   then    count    u32 LE          trie scenarios
//!           per one  K, V            u32 LE each: its keys' bytes and its
//!                                    values', each a multiple of 4
//!                    m, then m       u32 LE, then the keys the batch opens,
//!                    entries         ascending, each its key and its value
//!                    proof           the batch's proof, opening them
//!                    root            8 u64 LE, each below p: the table's
//!                                    before the batch
//!                    a, then a       u32 LE, then (key, value)s to insert
//!                    b, then b       u32 LE, then (key, value)s to set
//!                    c, then c       u32 LE, then keys to remove
//! ```
//!
//! With K and V multiples of 4 every proof starts on a word, as the SDK reads
//! it in place.
//!
//! The long program loads block 0, then at step `s` from 1 hashes the value
//! with block `s` on its right at depth `d = s mod 512`: by a SIB at an odd
//! step, at an even one by a LOAD of the block parking the value and a JOIN
//! of that park on the left. Its value is a duplex of the permutation: from
//! the 16 lanes of blocks 0 and 1, each step permutes and adds `d + 1` to lane
//! 0. So each block past 1 is the last 8 lanes of the step before its own,
//! and the guest reads none of them: one that is not is a root that is not
//! the duplex's.
//!
//! # The journal
//!
//! ```text
//!   permute [0, 1, …, 15]           16 u64
//!   permute [2^64 − 1; 16]          16 u64, every lane read mod p
//!   the leaves' root                8 u64, `poseidon2_compress` pairwise
//!   a chain                         16 u64: [root, 0^8] permuted CHAIN times
//!   for each mul_div case below     a status byte (1 answered, 0 refused),
//!                                   then q and r, 32 bytes LE each, zero if refused
//!   falcon512::s1_norm              u64: ‖s1‖² of the input's h, s2 and c
//!   falcon512::s1_norm              u64: the sum of more calls', call k's
//!                                   arrays the input's rotated k times: (s2,
//!                                   c, h), (c, h, s2), (h, s2, c), …
//!   falcon512::sample               8 u64: the lanes 0, 1, q^4 − 1, q^4,
//!                                   T − 1, ⌊T/3⌋, T − q^4 and
//!                                   0x0123456789abcdef, T = ⌊p/q^4⌋·q^4, each
//!                                   its four base-q digits, u16 LE
//!   mpt_eval                        8 u64 each: a, branch(5, a, b),
//!                                   branch(5, b, a), branch(511, a, b) of two
//!                                   leaves joined, branch(1, branch(9, a, b),
//!                                   branch(3, d, c)), block 0 mod p, and
//!                                   branch(7, block 1 mod p, a), where a to d
//!                                   are the leaves 0 to 3 mod n and
//!                                   branch(c, l, r) is poseidon2_compress(l, r)
//!                                   with c + 1 added to lane 0 mod p
//!   mpt_eval                        8 u64: the long program's value
//!   Trie::root                      8 u64 a scenario: its table's after the
//!                                   batch, the inserts first, then the sets
//!                                   and the removes, each leaf by mpt::leaf
//!   PublicKey::verify               a byte a case, 1: the key decodes, the
//!                                   signature verifies under the context, and
//!                                   its length is the one the input gives; any
//!                                   other case ends the execution, a panic or
//!                                   the decode call's refusal
//! ```
//!
//! With 1,024 more `s1_norm` calls the Falcon calls are more than the 1,024 a
//! `FALCON_SPLIT` shard holds, so a streaming run hands one over
//! mid-execution. The programs before the long one are 16 ops, 7 of them
//! hashing, so with 4,100 steps the long program's 6,151 ops straddle the
//! 4,096th, where an `MPT_NODES` shard ends at `2^12` rows, and its hash ops
//! the 4,096th, where an `MPT_ROUNDS` shard ends at `2^16`. Every call is
//! after the Falcon arrays are read, past cycle `2^14`.

extern crate alloc;

use alloc::vec;

use guest_sdk::falcon512::{self, Poly, PublicKey, KEY_BYTES};
use guest_sdk::{mpt, mpt_eval, poseidon2_compress, poseidon2_permute, Digest, U256};

guest_sdk::entry!(main);

/// The chain's permutations: more than a `2^12`-row shard of the rounds holds,
/// 256 calls, so a streaming run fills that buffer mid-execution.
const CHAIN: usize = 300;

/// `p`, the field's modulus: `2^64 − 59`.
const P: u64 = 0xffff_ffff_ffff_ffc5;

/// An op's kinds and bits (`constants::delegation::mpt`): a LOAD, a SIB and a
/// JOIN; the park and left bits.
const LOAD: u32 = 0;
const SIB: u32 = 1;
const JOIN: u32 = 2;
const PARK: u32 = 4;
const LEFT: u32 = 8;

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

    let word = |at: usize| u32::from_le_bytes(input[at..at + 4].try_into().expect("a word"));
    let at_falcon = 4 + 64 * n;
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

    let q4 = (falcon512::Q as u64).pow(4);
    let t = p / q4 * q4;
    let mut lanes = [
        0,
        1,
        q4 - 1,
        q4,
        t - 1,
        t / 3,
        t - q4,
        0x0123_4567_89ab_cdef,
    ];
    falcon512::sample(&mut lanes);
    lanes.iter().for_each(|l| put(&l.to_le_bytes()));

    // The trie precompile over programs written by hand, each root checked
    // against `branch`: a leaf, a branch with its block on the right and on
    // the left, two leaves joined, two branches joined, the parked one a
    // branch whose `pending` it carries; then the advice's block 0 loaded and
    // its block 1 a sibling.
    let address = |d: &Digest| d as *const Digest as u32;
    let ram: [Digest; 4] = core::array::from_fn(|l| leaves[l % n]);
    let (a, b, c, d) = (&ram[0], &ram[1], &ram[2], &ram[3]);
    let advice = guest_sdk::advice();
    let advised = |at: usize| u32::from_le_bytes(advice[at..at + 4].try_into().expect("a word"));
    let steps = advised(0);
    assert!(
        steps >= 1 && advice.len() >= 4 + 64 * (steps as usize + 1),
        "precompiles: the advice is a long program's steps and its blocks"
    );
    let block = |s: u32| advice.as_ptr() as u32 + 4 + 64 * s;
    let mut state: [u64; 16] = core::array::from_fn(|k| {
        u64::from_le_bytes(advice[4 + 8 * k..12 + 8 * k].try_into().expect("a lane"))
    });
    let reduced = |at: usize| {
        let lanes = core::array::from_fn(|k| state[at + k] % P);
        Digest::new(lanes).expect("a lane mod p")
    };
    let tries: [(&[u32], Digest); 7] = [
        (&[LOAD, address(a)], *a),
        (
            &[LOAD, address(a), op(SIB, 0, 5), address(b)],
            branch(5, a, b),
        ),
        (
            &[LOAD, address(a), op(SIB, LEFT, 5), address(b)],
            branch(5, b, a),
        ),
        (
            &[
                LOAD,
                address(a),
                op(LOAD, PARK, 0),
                address(b),
                op(JOIN, LEFT, 511),
                1,
            ],
            branch(511, a, b),
        ),
        (
            &[
                LOAD,
                address(a),
                op(SIB, 0, 9),
                address(b),
                op(LOAD, PARK, 0),
                address(c),
                op(SIB, LEFT, 3),
                address(d),
                op(JOIN, LEFT, 1),
                2,
            ],
            branch(1, &branch(9, a, b), &branch(3, d, c)),
        ),
        (&[LOAD, block(0)], reduced(0)),
        (
            &[LOAD, address(a), op(SIB, LEFT, 7), block(1)],
            branch(7, &reduced(8), a),
        ),
    ];
    for (ops, want) in tries {
        let root = mpt_eval(ops);
        assert!(root == want, "precompiles: mpt_eval is not the trie's hash");
        root.lanes().iter().for_each(|l| put(&l.to_le_bytes()));
    }

    // The long program, its value a duplex of the permutation: from blocks 0
    // and 1, each step permutes and adds `d + 1` to lane 0. Its words are
    // written in a `while`: a debug build pays for every iterator call.
    let mut ops = vec![0u32; 2 * (1 + steps + steps / 2) as usize];
    let words = ops.as_mut_slice();
    words[1] = block(0);
    let (mut s, mut addr, mut w) = (1, block(1), 2);
    while s <= steps {
        let d = s % 512;
        if s % 2 == 1 {
            words[w] = SIB | d << 4;
            words[w + 1] = addr;
            w += 2;
        } else {
            words[w] = LOAD | PARK;
            words[w + 1] = addr;
            words[w + 2] = JOIN | LEFT | d << 4;
            words[w + 3] = w as u32 / 2;
            w += 4;
        }
        poseidon2_permute(&mut state);
        state[0] = plus(state[0], d as u64 + 1);
        (s, addr) = (s + 1, addr + 64);
    }
    let root = mpt_eval(&ops);
    assert!(
        root.lanes()[..] == state[..8],
        "precompiles: mpt_eval is not the duplex"
    );
    root.lanes().iter().for_each(|l| put(&l.to_le_bytes()));

    // The SDK's trie over each scenario after the long program's blocks: the
    // table opened and held to its root before, then the batch.
    let mut scan = 4 + 64 * (steps as usize + 1);
    for _ in 0..number(advice, &mut scan) {
        let (k, v) = (number(advice, &mut scan), number(advice, &mut scan));
        let m = number(advice, &mut scan);
        let entries = take(advice, &mut scan, m * (k + v))
            .chunks_exact(k + v)
            .map(|e| (&e[..k], mpt::leaf(&e[..k], &e[k..])));
        let mut trie = mpt::Trie::open(k, entries, advice, &mut scan);
        let before = digest(take(advice, &mut scan, 64));
        assert!(
            trie.root() == before,
            "precompiles: the trie opens to another root"
        );
        for _ in 0..number(advice, &mut scan) {
            let (key, value) = (take(advice, &mut scan, k), take(advice, &mut scan, v));
            trie.insert(key, mpt::leaf(key, value));
        }
        for _ in 0..number(advice, &mut scan) {
            let (key, value) = (take(advice, &mut scan, k), take(advice, &mut scan, v));
            trie.set(key, mpt::leaf(key, value));
        }
        for _ in 0..number(advice, &mut scan) {
            trie.remove(take(advice, &mut scan, k));
        }
        let after = trie.root();
        after.lanes().iter().for_each(|l| put(&l.to_le_bytes()));
    }

    let at_cases = at_falcon + 3 * 1024 + 4;
    let cases = word(at_cases);
    let mut signed = at_cases + 4;
    let next = |at: usize| at + KEY_BYTES + 4 + word(at + KEY_BYTES) as usize;
    let mut said = (0..cases).fold(signed, |at, _| next(at));
    for _ in 0..cases {
        let key = &input[signed..signed + KEY_BYTES];
        let signature = &input[signed + KEY_BYTES + 4..next(signed)];
        signed = next(signed);
        let mut string = || {
            let len = word(said) as usize;
            said += 4 + len;
            &input[said - len..said]
        };
        let (message, context) = (string(), string());
        let length = PublicKey::decode(key).verify(message, signature, context);
        assert!(
            length == signature.len(),
            "precompiles: verify's length is not the signature's"
        );
        put(&[1]);
    }
    guest_sdk::commit(&out[..at]);
}

/// The `len` bytes of `bytes` at `at`, which moves past them.
fn take<'a>(bytes: &'a [u8], at: &mut usize, len: usize) -> &'a [u8] {
    *at += len;
    &bytes[*at - len..*at]
}

/// The u32 LE of `bytes` at `at`, which moves past it.
fn number(bytes: &[u8], at: &mut usize) -> usize {
    u32::from_le_bytes(take(bytes, at, 4).try_into().expect("a word")) as usize
}

/// The digest at the start of `b`, 8 lanes of u64 LE, each below `p`.
fn digest(b: &[u8]) -> Digest {
    let lanes = core::array::from_fn(|j| {
        u64::from_le_bytes(b[8 * j..8 * j + 8].try_into().expect("a lane"))
    });
    Digest::new(lanes).expect("precompiles: a lane is not below p")
}

/// An op's info word: its kind, its park and left bits, and its depth `d`.
fn op(kind: u32, bits: u32, d: u32) -> u32 {
    kind | bits | d << 4
}

/// `x + t` mod `p`, `x` below it and `t` small.
fn plus(x: u64, t: u64) -> u64 {
    match x.overflowing_add(t) {
        (s, false) if s < P => s,
        (s, _) => s.wrapping_sub(P),
    }
}

/// A trie's branch at crit bit `d`: [`poseidon2_compress`] of `l` and `r`,
/// `d + 1` added to lane 0 mod `p`.
fn branch(d: u32, l: &Digest, r: &Digest) -> Digest {
    let mut lanes = *poseidon2_compress(l, r).lanes();
    lanes[0] = plus(lanes[0], d as u64 + 1);
    Digest::new(lanes).expect("precompiles: a lane is not below p")
}
