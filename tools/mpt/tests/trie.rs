//! The trie against `docs/spec/precompiles.md`'s MPT section by hand: a leaf is
//! `F` of its key and value packed seven bytes to a lane plus the first 8 of
//! those lanes, a branch is `F` of its children with its crit bit plus one
//! added to lane 0, and the root is the trie the definition gives the key set,
//! whatever order the table was built in. The walk an insert is witnessed by,
//! and what the tool refuses.

use std::array;
use std::panic::{catch_unwind, AssertUnwindSafe};

use apogee_mpt::{branch, leaf, Digest, Trie};
use field::{Fp, A64_C5};
use test_support::Rng;
use transcript::poseidon2_permute;

/// `F` by hand: the first 8 lanes of the permutation.
fn f(mut state: [Fp; 16]) -> Digest {
    poseidon2_permute(&mut state);
    array::from_fn(|i| state[i].to_u64())
}

/// A leaf by hand: byte `i` of `key ‖ value` is itself times `256^(i mod 7)` in
/// lane `⌊i / 7⌋`, and lane `j < 8` of the permutation takes lane `j` back.
fn hand_leaf(key: &[u8], value: &[u8]) -> Digest {
    let mut state = [Fp::ZERO; 16];
    for (i, &b) in key.iter().chain(value).enumerate() {
        state[i / 7] += Fp::from_u64((b as u64) << (8 * (i % 7)));
    }
    let out = f(state);
    array::from_fn(|j| (Fp::from_u64(out[j]) + state[j]).to_u64())
}

/// A branch by hand: `F(l ‖ r)`, then lane 0 plus `c + 1` mod `p`.
fn hand_branch(c: usize, l: &Digest, r: &Digest) -> Digest {
    let mut out = f(array::from_fn(|i| {
        Fp::from_u64(if i < 8 { l[i] } else { r[i - 8] })
    }));
    out[0] = ((out[0] as u128 + c as u128 + 1) % A64_C5 as u128) as u64;
    out
}

/// Bit `d` of `key`, as the spec writes it.
fn bit(key: &[u8], d: usize) -> bool {
    (key[d >> 3] >> (7 - (d & 7))) & 1 == 1
}

/// The least bit where `a` and `b` differ, bit by bit.
fn crit(a: &[u8], b: &[u8]) -> usize {
    (0..8 * a.len())
        .find(|&d| bit(a, d) != bit(b, d))
        .expect("distinct keys")
}

/// The definition's trie of `set`, ascending: nothing's is zero, one key's is
/// its leaf, and more keys' a branch at the crit bit of the least and greatest
/// over the keys with that bit clear and those with it set.
fn definition(set: &[(Vec<u8>, Digest)]) -> Digest {
    match set {
        [] => [0; 8],
        [(_, leaf)] => *leaf,
        [(first, _), .., (last, _)] => {
            let c = crit(first, last);
            let (l, r): (Vec<_>, Vec<_>) = set.iter().cloned().partition(|(k, _)| !bit(k, c));
            hand_branch(c, &definition(&l), &definition(&r))
        }
    }
}

/// Run `f`, which must panic, and return its message.
fn panic_message<R>(f: impl FnOnce() -> R) -> String {
    let payload = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => panic!("the call returned; it should have panicked"),
        Err(payload) => payload,
    };
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .expect("a panic carries a message")
}

/// Keys and values from a byte to the full 112, across lane boundaries: a leaf
/// is the bytes seven to a lane, little-endian, zero-extended, permuted once and
/// fed forward.
#[test]
fn a_leaf_is_its_bytes_seven_to_a_lane() {
    let mut rng = Rng::new(0x1eaf);
    for (key_len, value_len) in [
        (1, 0),
        (4, 3),
        (7, 0),
        (8, 6),
        (32, 40),
        (4, 80),
        (52, 60),
        (64, 48),
    ] {
        let (key, value) = (rng.next_bytes(key_len), rng.next_bytes(value_len));
        assert_eq!(
            leaf(&key, &value),
            hand_leaf(&key, &value),
            "{key_len} + {value_len}"
        );
    }
}

/// The empty table's root is zero, and one key's is its leaf.
#[test]
fn the_empty_root_is_zero_and_one_key_is_its_leaf() {
    for key_len in [1, 32, 64] {
        let mut trie = Trie::new(key_len);
        assert_eq!(trie.root(), [0; 8]);
        let (key, value) = (vec![0xa5; key_len], b"a value".to_vec());
        trie.insert(&key, leaf(&key, &value));
        assert_eq!(trie.root(), hand_leaf(&key, &value));
    }
}

/// Two keys are a branch at their crit bit, the key with that bit clear on the
/// left, inserted in either order: crit bits in the first byte, mid-key, and
/// the last bit of a 64-byte key, 511.
#[test]
fn two_keys_are_a_branch_at_their_crit_bit() {
    let mut deep = vec![0x3c; 64];
    deep[63] = 0x3d;
    let cases: [(Vec<u8>, Vec<u8>, usize); 4] = [
        (vec![0x00], vec![0x80], 0),
        (vec![0xa0, 0xff], vec![0xb0, 0x00], 3),
        (vec![1, 2, 3, 4], vec![1, 2, 3, 5], 31),
        (vec![0x3c; 64], deep, 511),
    ];
    for (lo, hi, c) in cases {
        let expected = hand_branch(c, &hand_leaf(&lo, b"lo"), &hand_leaf(&hi, b"hi"));
        for order in [[&lo, &hi], [&hi, &lo]] {
            let mut trie = Trie::new(lo.len());
            for key in order {
                let value: &[u8] = if key == &lo { b"lo" } else { b"hi" };
                trie.insert(key, leaf(key, value));
            }
            assert_eq!(trie.root(), expected, "crit bit {c}");
        }
    }
}

/// Three keys, two sharing a longer prefix: the root is a branch at the crit
/// bit of all three over the pair's branch and the third's leaf, the pair on
/// the left or on the right.
#[test]
fn three_keys_are_a_branch_over_the_pair_with_the_longer_prefix() {
    let l = |key: &[u8]| hand_leaf(key, &[key[2]; 5]);
    // 0x34 and 0xb4 differ in bit 8, 0x00 and 0x80 in bit 16.
    let (x, y, z) = ([0x12, 0x34, 0x00], [0x12, 0x34, 0x80], [0x12, 0xb4, 0x00]);
    let left_pair = hand_branch(8, &hand_branch(16, &l(&x), &l(&y)), &l(&z));
    // 0x00 and 0x80 differ in bit 8, 0x00 and 0x01 in bit 23.
    let (u, v, w) = ([0x12, 0x00, 0x00], [0x12, 0x80, 0x00], [0x12, 0x80, 0x01]);
    let right_pair = hand_branch(8, &l(&u), &hand_branch(23, &l(&v), &l(&w)));
    for (keys, expected) in [([x, y, z], left_pair), ([u, v, w], right_pair)] {
        for order in [[0, 1, 2], [2, 0, 1], [1, 2, 0]] {
            let mut trie = Trie::new(3);
            for i in order {
                trie.insert(&keys[i], leaf(&keys[i], &[keys[i][2]; 5]));
            }
            assert_eq!(trie.root(), expected);
        }
    }
}

/// Random tables of 1- to 64-byte keys, 52-byte ones under three shared 32-byte
/// prefixes among them, are built sorted, reversed, and shuffled with other
/// keys inserted and removed and leaves replaced and put back: each order gives
/// the definition's root of the final set.
#[test]
fn the_root_is_the_sets_whatever_the_order() {
    let mut rng = Rng::new(0xca7);
    for (key_len, n) in [
        (1, 2),
        (1, 5),
        (1, 200),
        (2, 300),
        (4, 64),
        (32, 200),
        (52, 200),
        (64, 100),
    ] {
        let prefixes: Vec<Vec<u8>> = (0..3).map(|_| rng.next_bytes(32)).collect();
        let draw = |rng: &mut Rng| match key_len {
            52 => [
                &prefixes[rng.next_u64() as usize % 3][..],
                &rng.next_bytes(20),
            ]
            .concat(),
            _ => rng.next_bytes(key_len),
        };
        let mut set = std::collections::BTreeMap::new();
        while set.len() < n {
            let key = draw(&mut rng);
            let len = rng.next_u64() as usize % (113 - key_len);
            set.insert(key.clone(), leaf(&key, &rng.next_bytes(len)));
        }
        let set: Vec<(Vec<u8>, Digest)> = set.into_iter().collect();
        let expected = definition(&set);

        let mut sorted = Trie::new(key_len);
        let mut reversed = Trie::new(key_len);
        for (key, digest) in &set {
            sorted.insert(key, *digest);
        }
        for (key, digest) in set.iter().rev() {
            reversed.insert(key, *digest);
        }
        // Every third key first under a stand-in leaf, and a key outside the
        // set drawn at each step, all put right once every key is in.
        let mut shuffled = Trie::new(key_len);
        let mut order: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            order.swap(i, rng.next_u64() as usize % (i + 1));
        }
        let mut others = Vec::new();
        for (step, &i) in order.iter().enumerate() {
            let (key, digest) = &set[i];
            shuffled.insert(
                key,
                if step % 3 == 0 {
                    [step as u64; 8]
                } else {
                    *digest
                },
            );
            let other = draw(&mut rng);
            let outside = set.binary_search_by(|(k, _)| k.cmp(&other)).is_err();
            if outside && shuffled.get(&other).is_none() {
                shuffled.insert(&other, leaf(&other, b""));
                others.push(other);
            }
        }
        for (step, &i) in order.iter().enumerate().step_by(3) {
            assert_eq!(shuffled.get(&set[i].0), Some([step as u64; 8]));
            shuffled.insert(&set[i].0, set[i].1);
        }
        for other in &others {
            shuffled.remove(other);
        }
        assert_eq!(shuffled.len(), n);
        for trie in [&sorted, &reversed, &shuffled] {
            assert_eq!(trie.root(), expected, "{key_len}-byte keys, {n} of them");
        }
    }
}

/// The witness is the leaf the walk on the key's bits reaches, not a neighbour
/// in key order: under 0x40, 0x50 and 0x70 the walk on 0x10 takes bit 2 clear,
/// then bit 3 set, to 0x50, though 0x40 is 0x10's successor.
#[test]
fn the_witness_is_the_leaf_the_walk_reaches() {
    let mut trie = Trie::new(1);
    trie.insert(&[0x40], leaf(&[0x40], b""));
    assert_eq!(trie.witness(&[0xff]), [0x40], "one key witnesses every key");
    for key in [0x50, 0x70] {
        trie.insert(&[key], leaf(&[key], b""));
    }
    for (key, witness) in [
        (0x10, 0x50),
        (0x00, 0x40),
        (0x60, 0x70),
        (0xff, 0x70),
        (0x50, 0x50),
    ] {
        assert_eq!(trie.witness(&[key]), [witness], "witness of {key:#04x}");
    }
}

/// A key length outside 1 to 64, a key of another length, a leaf over 112
/// bytes, a crit bit of 512, removing an absent key, a witness in an empty
/// table, and a proof of an absent key or of one key twice: each panics.
#[test]
fn malformed_input_panics() {
    let mut trie = Trie::new(4);
    trie.insert(b"abcd", leaf(b"abcd", b""));
    let messages = [
        panic_message(|| Trie::new(0)),
        panic_message(|| Trie::new(65)),
        panic_message(|| trie.clone().insert(b"abc", [0; 8])),
        panic_message(|| trie.get(b"abcde")),
        panic_message(|| trie.proof(&[b"abc".as_slice()])),
        panic_message(|| leaf(&[0; 64], &[0; 49])),
        panic_message(|| branch(512, &[0; 8], &[0; 8])),
        panic_message(|| trie.clone().remove(b"abce")),
        panic_message(|| Trie::new(4).witness(b"abcd")),
        panic_message(|| trie.proof(&[b"abce"])),
        panic_message(|| trie.proof(&[b"abcd", b"abcd"])),
    ];
    let expected = [
        "a key is 1 to 64 bytes",
        "a key is 1 to 64 bytes",
        "a key is the table's 4 bytes",
        "a key is the table's 4 bytes",
        "a key is the table's 4 bytes",
        "at most 112 bytes",
        "a crit bit is below 512",
        "the key is in the table",
        "a nonempty table",
        "a touched key is in the table",
        "the touched keys are distinct",
    ];
    for (message, expected) in messages.iter().zip(expected) {
        assert!(
            message.contains(expected),
            "{message:?} is not {expected:?}"
        );
    }
}
