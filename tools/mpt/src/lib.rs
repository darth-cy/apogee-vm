//! The MPT precompile's crit-bit trie, the host's half: a table's canonical
//! trie, its root, and the batched proof a guest opens it by, as
//! `docs/spec/precompiles.md`'s MPT section specifies them and
//! `guest_sdk::mpt` reads them. Test infrastructure, for the suites and the
//! batch drivers that build tables, roots and proofs; never linked by the
//! prover, the verifier or a guest.
//!
//! A table maps keys of one length `K`, 1 to 64 bytes, to leaves. Bit `d` of a
//! key is `(key[d >> 3] >> (7 − (d & 7))) & 1`, most significant first, so the
//! trie's leaf order is the keys' byte order, and `crit(a, b)` is the least bit
//! where `a` and `b` differ. The trie of one key is its leaf, and of more a
//! branch at `c = crit(min, max)` whose left child is the trie of the keys with
//! bit `c` clear and whose right is the trie of those with it set: a function
//! of the key set, whatever order the table was built in. A leaf is [`leaf`] of
//! its key and value, a branch is [`branch`] of its crit bit and children, and
//! the empty table's root is the zero digest. Both are [`node`]'s one
//! compression in a domain, 0 for a leaf and `c + 1` for a branch at `c`.

use std::array;
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Included, Unbounded};

use field::Fp;
use transcript::poseidon2_permute;

/// Eight lanes, each below `p`: a leaf, a node or a root.
pub type Digest = [u64; 8];

/// A key's most bytes: every crit bit is below `8·64 = 512`, the precompile's
/// depth bound.
const MAX_KEY: usize = 64;

/// A leaf's most bytes, its key's and its value's: 16 lanes of seven.
const MAX_LEAF: usize = 112;

/// A leaf: [`node`] of `x` in domain 0, `x` being `key ‖ value` packed seven
/// bytes to a lane, little-endian, each lane below `2^56`, and zero-extended
/// to 16 lanes. Panics if the two are more than 112 bytes.
pub fn leaf(key: &[u8], value: &[u8]) -> Digest {
    let bytes = [key, value].concat();
    assert!(
        bytes.len() <= MAX_LEAF,
        "leaf: a key and its value are at most 112 bytes"
    );
    let mut lanes = [0; 16];
    for (lane, seven) in lanes.iter_mut().zip(bytes.chunks(7)) {
        *lane = seven.iter().rev().fold(0, |x, &b| (x << 8) | b as u64);
    }
    node(lanes, 0)
}

/// A branch at crit bit `c` over `left` and `right`: [`node`] of `left ‖
/// right` in domain `c + 1`. Panics unless `c` is below 512.
pub fn branch(c: usize, left: &Digest, right: &Digest) -> Digest {
    assert!(c < 8 * MAX_KEY, "branch: a crit bit is below 512");
    let mut lanes = [0; 16];
    lanes[..8].copy_from_slice(left);
    lanes[8..].copy_from_slice(right);
    node(lanes, c as u64 + 1)
}

/// Every node's hash, `F(z) + z[0..8]` lane by lane mod `p` with the domain
/// `t` added to lane 0: `F` is the SDK's `poseidon2_compress`, the first 8
/// lanes of the Poseidon2-A64-C5 permutation of `z`, each read mod `p`, and
/// the feed-forward keeps its inverse from opening a digest. On one `z` two
/// domains differ by their difference in lane 0.
fn node(z: [u64; 16], t: u64) -> Digest {
    let mut state = z.map(Fp::from_u64);
    poseidon2_permute(&mut state);
    state[0] += Fp::from_u64(t);
    array::from_fn(|i| (state[i] + Fp::from_u64(z[i])).to_u64())
}

/// A table: its key length and its leaves by key. The trie is never held but
/// walked over the sorted keys, a node being the run of keys under it, from
/// its first to its last.
#[derive(Clone, Debug)]
pub struct Trie {
    key_len: usize,
    leaves: BTreeMap<Vec<u8>, Digest>,
}

impl Trie {
    /// An empty table of `key_len`-byte keys. Panics unless `key_len` is 1 to
    /// 64. Every method taking a key panics unless it is `key_len` bytes.
    pub fn new(key_len: usize) -> Trie {
        assert!(
            (1..=MAX_KEY).contains(&key_len),
            "Trie::new: a key is 1 to 64 bytes"
        );
        Trie {
            key_len,
            leaves: BTreeMap::new(),
        }
    }

    /// The number of keys.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// `key`'s leaf, if `key` is in the table.
    pub fn get(&self, key: &[u8]) -> Option<Digest> {
        self.check(key);
        self.leaves.get(key).copied()
    }

    /// Sets `key`'s leaf, inserting `key` if it is absent.
    pub fn insert(&mut self, key: &[u8], leaf: Digest) {
        self.check(key);
        self.leaves.insert(key.to_vec(), leaf);
    }

    /// Removes `key`. Panics if it is absent.
    pub fn remove(&mut self, key: &[u8]) {
        self.check(key);
        assert!(
            self.leaves.remove(key).is_some(),
            "Trie::remove: the key is in the table"
        );
    }

    /// The root: the zero digest for the empty table, the leaf for one key.
    pub fn root(&self) -> Digest {
        self.ends().map_or([0; 8], |(first, last)| {
            self.node(first, last, &[], 0, &mut Vec::new())
        })
    }

    /// The key of the leaf a walk on `key`'s bits reaches, taking at each
    /// branch the child `key`'s bit at its crit bit names: `key` itself if it
    /// is in the table, and otherwise the leaf an insert of `key` is spliced
    /// beside, which a batch inserting `key` touches. Panics on an empty table.
    pub fn witness(&self, key: &[u8]) -> Vec<u8> {
        self.check(key);
        let (mut first, mut last) = self.ends().expect("Trie::witness: a nonempty table");
        while first != last {
            let (c, left, right) = self.split(first, last);
            if bit(key, c) {
                first = right;
            } else {
                last = left;
            }
        }
        first.to_vec()
    }

    /// The batched proof of `touched`, the bytes a guest opens the table by:
    /// `u32 s`; `s` words, each a sibling's depth, its parent's crit bit, plus
    /// 512 times its owner, the index among the sorted touched keys of the
    /// last one under its parent, owners ascending and each owner's deepest
    /// first; then the `s` siblings' digests in the words' order, 8 lanes u64
    /// little-endian each. A sibling is a child holding no touched key of a
    /// node holding one. With nothing touched the proof is `s = 0` for the
    /// empty table, and otherwise `s = 1`, the word 0 and the root.
    ///
    /// Panics unless the touched keys are distinct and in the table; their
    /// order is free.
    pub fn proof<K: AsRef<[u8]>>(&self, touched: &[K]) -> Vec<u8> {
        let mut keys: Vec<&[u8]> = touched.iter().map(AsRef::as_ref).collect();
        keys.sort_unstable();
        for key in &keys {
            assert!(
                self.get(key).is_some(),
                "Trie::proof: a touched key is in the table"
            );
        }
        assert!(
            keys.windows(2).all(|pair| pair[0] < pair[1]),
            "Trie::proof: the touched keys are distinct"
        );
        let mut siblings = Vec::new();
        match self.ends() {
            Some((first, last)) if !keys.is_empty() => {
                self.node(first, last, &keys, 0, &mut siblings);
            }
            Some(_) => siblings.push((0, self.root())),
            None => {}
        }
        let s = u32::try_from(siblings.len()).expect("fewer than 2^32 siblings");
        let words = siblings.iter().flat_map(|(word, _)| word.to_le_bytes());
        let digests = siblings
            .iter()
            .flat_map(|(_, digest)| digest.iter().flat_map(|lane| lane.to_le_bytes()));
        s.to_le_bytes()
            .into_iter()
            .chain(words)
            .chain(digests)
            .collect()
    }

    /// The digest of the run `first..=last`. When `touched`, the touched keys
    /// in the run, the first of them touched key `index`, is not empty, the
    /// siblings of their pruned trie within the run are pushed to `siblings`,
    /// `(word, digest)`, in post-order: by owner, and an owner's deepest first.
    fn node(
        &self,
        first: &[u8],
        last: &[u8],
        touched: &[&[u8]],
        index: usize,
        siblings: &mut Vec<(u32, Digest)>,
    ) -> Digest {
        if first == last {
            return self.leaves[first];
        }
        let (c, left_last, right_first) = self.split(first, last);
        let t = touched.partition_point(|key| !bit(key, c));
        let left = self.node(first, left_last, &touched[..t], index, siblings);
        let right = self.node(right_first, last, &touched[t..], index + t, siblings);
        if !touched.is_empty() && (t == 0 || t == touched.len()) {
            let owner = index + touched.len() - 1;
            let word = u32::try_from(c + 512 * owner).expect("an owner below 2^23");
            siblings.push((word, if t == 0 { left } else { right }));
        }
        branch(c, &left, &right)
    }

    /// The branch over the run `first..=last`, `first < last`: its crit bit
    /// `c`, its left child's last key and its right child's first. The run's
    /// keys share their bits before `c`, so the right child's run begins at the
    /// least key with those bits and bit `c` set.
    fn split(&self, first: &[u8], last: &[u8]) -> (usize, &[u8], &[u8]) {
        let c = crit(first, last);
        let (byte, shift) = (c / 8, 7 - c % 8);
        let mut bound = first.to_vec();
        bound[byte] = ((bound[byte] >> shift) | 1) << shift;
        bound[byte + 1..].fill(0);
        let bound: &[u8] = &bound;
        let mut left = self.leaves.range::<[u8], _>((Unbounded, Excluded(bound)));
        let mut right = self.leaves.range::<[u8], _>((Included(bound), Unbounded));
        match (left.next_back(), right.next()) {
            (Some((left, _)), Some((right, _))) => (c, left, right),
            _ => unreachable!("a branch has two children"),
        }
    }

    /// The first and last keys, the root's run, unless the table is empty.
    fn ends(&self) -> Option<(&[u8], &[u8])> {
        let (first, _) = self.leaves.first_key_value()?;
        let (last, _) = self.leaves.last_key_value()?;
        Some((first, last))
    }

    fn check(&self, key: &[u8]) {
        assert!(
            key.len() == self.key_len,
            "a key is the table's {} bytes",
            self.key_len
        );
    }
}

/// Bit `d` of `key`, most significant first.
fn bit(key: &[u8], d: usize) -> bool {
    (key[d / 8] >> (7 - d % 8)) & 1 == 1
}

/// The least bit where `a` and `b`, distinct keys of one length, differ.
fn crit(a: &[u8], b: &[u8]) -> usize {
    let i = a
        .iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .expect("distinct keys");
    8 * i + (a[i] ^ b[i]).leading_zeros() as usize
}
