//! The batched proof against an opener written here from
//! `docs/spec/precompiles.md`'s MPT section, the guest's validation: for any
//! touched set the proof opens a pruned trie whose root is the table's; and a
//! batch's proof, of the keys it reads, sets and removes and of its inserts'
//! witnesses, opens a pruned trie that the batch's edits, by the guest's rules,
//! take to the table's root after the batch.

use std::array;
use std::collections::{BTreeMap, BTreeSet};
use std::mem;
use std::panic::{catch_unwind, AssertUnwindSafe};

use apogee_mpt::{branch, leaf, Digest, Trie};
use test_support::Rng;

/// A node of an opened trie: a touched key and its leaf, a sibling's digest,
/// or a branch at its crit bit.
enum Node {
    Leaf(Vec<u8>, Digest),
    Opaque(Digest),
    Branch(usize, Box<Node>, Box<Node>),
}

impl Node {
    fn digest(&self) -> Digest {
        match self {
            Node::Leaf(_, digest) | Node::Opaque(digest) => *digest,
            Node::Branch(c, left, right) => branch(*c, &left.digest(), &right.digest()),
        }
    }
}

/// An opened table: its pruned trie, none when the table is empty.
struct Opened(Option<Node>);

/// The validation: `entries`, `key_len`-byte keys strictly ascending with
/// their leaves, and `proof` give the pruned trie. Each chain `i` climbs from
/// `k_i`'s leaf, taking the deeper of its next sibling and the parked subtree
/// on top of the stack while either is below where the chain parks, `c_i`, or
/// to the root for the last chain. Panics on anything else.
fn open(key_len: usize, entries: &[(Vec<u8>, Digest)], proof: &[u8]) -> Opened {
    assert!(entries.iter().all(|(key, _)| key.len() == key_len));
    assert!(
        entries.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "keys ascending"
    );
    let (s, rest) = proof.split_first_chunk().expect("u32 s");
    let s = u32::from_le_bytes(*s) as usize;
    assert_eq!(rest.len(), 68 * s, "s words, s digests, nothing after");
    let (words, digests) = rest.split_at(4 * s);
    let words: Vec<usize> = words
        .chunks(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()) as usize)
        .collect();
    let digests: Vec<Digest> = digests
        .chunks(64)
        .map(|d| array::from_fn(|l| u64::from_le_bytes(d[8 * l..8 * l + 8].try_into().unwrap())))
        .collect();
    if entries.is_empty() {
        return match words[..] {
            [] => Opened(None),
            [0] => Opened(Some(Node::Opaque(digests[0]))),
            _ => panic!("untouched, the proof is nothing or the root"),
        };
    }
    let mut stack: Vec<(usize, Node)> = Vec::new();
    let mut next = 0;
    let mut root = None;
    for (i, (key, digest)) in entries.iter().enumerate() {
        let mut cur = 8 * key_len;
        let mut node = Node::Leaf(key.clone(), *digest);
        let park = entries.get(i + 1).map(|(after, _)| crit(key, after));
        let below_park = |d: usize| park.is_none_or(|p| d > p);
        loop {
            let sibling = match words.get(next) {
                Some(&word) if word / 512 == i => Some(word % 512),
                Some(&word) => {
                    assert!(word / 512 > i, "a stale sibling");
                    None
                }
                None => None,
            };
            let join = stack.last().map(|&(c, _)| c).filter(|&c| below_park(c));
            let taken = match (sibling, join) {
                (Some(d), Some(c)) => {
                    assert_ne!(d, c, "a sibling at a join");
                    d.max(c)
                }
                (Some(d), None) => d,
                (None, Some(c)) => c,
                (None, None) => break,
            };
            assert!(
                sibling.is_none_or(below_park),
                "a sibling at or above the park"
            );
            assert!(taken < cur, "each depth above the last");
            cur = taken;
            node = if sibling == Some(taken) {
                let other = Box::new(Node::Opaque(digests[next]));
                next += 1;
                if bit(key, taken) {
                    Node::Branch(taken, other, Box::new(node))
                } else {
                    Node::Branch(taken, Box::new(node), other)
                }
            } else {
                let (_, parked) = stack.pop().unwrap();
                Node::Branch(taken, Box::new(parked), Box::new(node))
            };
        }
        match park {
            Some(c) => stack.push((c, node)),
            None => root = Some(node),
        }
    }
    assert!(
        stack.is_empty() && next == s,
        "every subtree joined, every sibling taken"
    );
    Opened(root)
}

/// The guest's edits on an opened trie.
impl Opened {
    fn root(&self) -> Digest {
        self.0.as_ref().map_or([0; 8], Node::digest)
    }

    /// An opened key's leaf replaced.
    fn set(&mut self, key: &[u8], leaf: Digest) {
        fn at(node: &mut Node, key: &[u8], leaf: Digest) {
            match node {
                Node::Branch(c, left, right) => {
                    at(if bit(key, *c) { right } else { left }, key, leaf)
                }
                Node::Leaf(k, digest) if *k == key => *digest = leaf,
                _ => panic!("set: an opened key"),
            }
        }
        at(self.0.as_mut().expect("set: an opened key"), key, leaf);
    }

    /// An absent key: the walk on its bits reaches an opened leaf, and a branch
    /// at their crit bit `c*` is spliced in above the first node on the path
    /// deeper than `c*`. An empty trie's root becomes the leaf.
    fn insert(&mut self, key: &[u8], leaf: Digest) {
        let Some(root) = self.0.as_mut() else {
            self.0 = Some(Node::Leaf(key.to_vec(), leaf));
            return;
        };
        let reached = reach(root, key);
        assert_ne!(reached, key, "insert: an absent key");
        let c = crit(key, reached);
        splice(root, key, leaf, c);
    }

    /// An opened key: its parent's other child takes the parent's place, and
    /// the last key leaves the trie empty.
    fn remove(&mut self, key: &[u8]) {
        let root = self.0.as_mut().expect("remove: an opened key");
        if matches!(&*root, Node::Leaf(k, _) if k == key) {
            self.0 = None;
        } else {
            cut(root, key);
        }
    }
}

/// The key of the leaf the walk on `key`'s bits reaches, which is opened.
fn reach<'a>(node: &'a Node, key: &[u8]) -> &'a [u8] {
    match node {
        Node::Branch(c, left, right) => reach(if bit(key, *c) { right } else { left }, key),
        Node::Leaf(k, _) => k,
        Node::Opaque(_) => panic!("insert: the walk reaches an opaque node"),
    }
}

/// `key`'s leaf under a branch at `c`, above the first node on its walk deeper
/// than `c`.
fn splice(node: &mut Node, key: &[u8], leaf: Digest, c: usize) {
    match node {
        Node::Branch(d, left, right) if *d < c => {
            splice(if bit(key, *d) { right } else { left }, key, leaf, c)
        }
        _ => {
            let below = Box::new(mem::replace(node, Node::Opaque([0; 8])));
            let new = Box::new(Node::Leaf(key.to_vec(), leaf));
            *node = if bit(key, c) {
                Node::Branch(c, below, new)
            } else {
                Node::Branch(c, new, below)
            };
        }
    }
}

/// `key`'s leaf cut from below `node`, its sibling taking its parent's place.
fn cut(node: &mut Node, key: &[u8]) {
    let Node::Branch(c, left, right) = node else {
        panic!("remove: an opened key");
    };
    let (child, other) = if bit(key, *c) {
        (right, left)
    } else {
        (left, right)
    };
    if matches!(&**child, Node::Leaf(k, _) if k == key) {
        *node = mem::replace(&mut **other, Node::Opaque([0; 8]));
    } else {
        cut(child, key);
    }
}

/// Bit `d` of `key`, most significant first.
fn bit(key: &[u8], d: usize) -> bool {
    (key[d >> 3] >> (7 - (d & 7))) & 1 == 1
}

/// The least bit where `a` and `b` differ.
fn crit(a: &[u8], b: &[u8]) -> usize {
    (0..8 * a.len())
        .find(|&d| bit(a, d) != bit(b, d))
        .expect("distinct keys")
}

/// A key a bit away from one of `near` one time in four, and otherwise a
/// random key, under one of `prefixes` when there are any.
fn draw(rng: &mut Rng, key_len: usize, prefixes: &[Vec<u8>], near: &[Vec<u8>]) -> Vec<u8> {
    if !near.is_empty() && rng.next_u64().is_multiple_of(4) {
        let mut key = near[rng.next_u64() as usize % near.len()].clone();
        let d = rng.next_u64() as usize % (8 * key_len);
        key[d / 8] ^= 0x80 >> (d % 8);
        return key;
    }
    match prefixes {
        [] => rng.next_bytes(key_len),
        _ => {
            let prefix = &prefixes[rng.next_u64() as usize % prefixes.len()];
            [&prefix[..], &rng.next_bytes(key_len - prefix.len())].concat()
        }
    }
}

/// A leaf of a random value for `key`.
fn random_leaf(rng: &mut Rng, key: &[u8]) -> Digest {
    let len = rng.next_u64() as usize % (113 - key.len());
    leaf(key, &rng.next_bytes(len))
}

/// A table of `n` distinct keys from [`draw`]: the trie and its leaves by key.
fn table(
    rng: &mut Rng,
    key_len: usize,
    n: usize,
    prefixes: &[Vec<u8>],
) -> (Trie, BTreeMap<Vec<u8>, Digest>) {
    let (mut trie, mut leaves, mut keys) = (Trie::new(key_len), BTreeMap::new(), Vec::new());
    while leaves.len() < n {
        let key = draw(rng, key_len, prefixes, &keys);
        if !leaves.contains_key(&key) {
            let digest = random_leaf(rng, &key);
            trie.insert(&key, digest);
            leaves.insert(key.clone(), digest);
            keys.push(key);
        }
    }
    (trie, leaves)
}

/// `keys` in a random order.
fn shuffled(rng: &mut Rng, mut keys: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    for i in (1..keys.len()).rev() {
        keys.swap(i, rng.next_u64() as usize % (i + 1));
    }
    keys
}

/// `touched` opened from `trie`'s proof of it, given shuffled: the touched keys
/// ascending with their leaves, and the proof.
fn open_touched(rng: &mut Rng, key_len: usize, trie: &Trie, touched: &BTreeSet<Vec<u8>>) -> Opened {
    let proof = trie.proof(&shuffled(rng, touched.iter().cloned().collect()));
    let entries: Vec<(Vec<u8>, Digest)> = touched
        .iter()
        .map(|key| (key.clone(), trie.get(key).unwrap()))
        .collect();
    open(key_len, &entries, &proof)
}

/// Random subsets of `keys`: nothing, everything, the least and the greatest,
/// four single keys, and keys kept one time in ten, two, five and nine.
fn subsets(rng: &mut Rng, keys: &[Vec<u8>]) -> Vec<BTreeSet<Vec<u8>>> {
    let n = keys.len();
    let mut subsets = vec![BTreeSet::new(), keys.iter().cloned().collect()];
    let mut singles = vec![0, n - 1];
    singles.extend((0..4).map(|_| rng.next_u64() as usize % n));
    for i in singles {
        subsets.push(BTreeSet::from([keys[i].clone()]));
    }
    for tenths in [1, 2, 5, 9] {
        subsets.push(
            keys.iter()
                .filter(|_| rng.next_u64() % 10 < tenths)
                .cloned()
                .collect(),
        );
    }
    subsets
}

/// Tables of 1 to 300 keys of 1, 4, 32 and 64 bytes, and the empty table: a
/// proof of nothing, of single keys, of every key and of random subsets, given
/// in any order, opens to the table's root. Untouched, the proof is nothing
/// for the empty table and otherwise the root under the word 0; with every key
/// touched it has no sibling.
#[test]
fn a_proof_opens_to_the_root() {
    let mut rng = Rng::new(0x9f00f);
    for key_len in [1, 32, 64] {
        let proof = Trie::new(key_len).proof::<&[u8]>(&[]);
        assert_eq!(proof, 0u32.to_le_bytes());
        assert_eq!(open(key_len, &[], &proof).root(), [0; 8]);
    }
    for (key_len, n) in [
        (1, 1),
        (1, 2),
        (1, 3),
        (1, 200),
        (4, 2),
        (4, 17),
        (4, 300),
        (32, 300),
        (64, 120),
    ] {
        let (trie, leaves) = table(&mut rng, key_len, n, &[]);
        let keys: Vec<Vec<u8>> = leaves.keys().cloned().collect();
        let mut untouched = vec![1, 0, 0, 0, 0, 0, 0, 0];
        untouched.extend(trie.root().iter().flat_map(|lane| lane.to_le_bytes()));
        assert_eq!(trie.proof::<&[u8]>(&[]), untouched);
        assert_eq!(trie.proof(&keys), 0u32.to_le_bytes());
        for touched in subsets(&mut rng, &keys) {
            let opened = open_touched(&mut rng, key_len, &trie, &touched);
            assert_eq!(
                opened.root(),
                trie.root(),
                "{key_len}-byte keys, {} of {n} touched",
                touched.len()
            );
        }
    }
}

/// 52-byte keys, a 32-byte user address and a 20-byte token, under three
/// addresses, many a bit apart; and 64-byte keys under one 63-byte prefix,
/// pairs of them apart only in bit 511. Single keys, one address's keys and
/// random subsets open to the root.
#[test]
fn keys_sharing_long_prefixes_open_to_the_root() {
    let mut rng = Rng::new(0xadd7);
    let addresses: Vec<Vec<u8>> = (0..3).map(|_| rng.next_bytes(32)).collect();
    let deep = [rng.next_bytes(63)];
    for (key_len, n, prefixes) in [(52, 300, &addresses[..]), (64, 200, &deep[..])] {
        let (trie, leaves) = table(&mut rng, key_len, n, prefixes);
        let keys: Vec<Vec<u8>> = leaves.keys().cloned().collect();
        let deepest = keys.windows(2).map(|pair| crit(&pair[0], &pair[1])).max();
        assert!(
            key_len == 52 || deepest == Some(511),
            "a pair apart in bit 511"
        );
        let mut all = subsets(&mut rng, &keys);
        all.push(
            keys.iter()
                .filter(|key| key[..32] == prefixes[0][..32])
                .cloned()
                .collect(),
        );
        for touched in all {
            let opened = open_touched(&mut rng, key_len, &trie, &touched);
            assert_eq!(
                opened.root(),
                trie.root(),
                "{key_len}-byte keys, {} touched",
                touched.len()
            );
        }
    }
}

/// Batches of reads, sets, inserts and removes, over 4-, 32- and 52-byte keys,
/// from the empty table through one batch removing every key and on: each
/// batch's proof, of the keys it reads, sets and removes and of each insert's
/// witness on the table before it, opens to the root before; the batch's sets,
/// then its inserts, then its removes, on the opened trie, give the root after.
#[test]
fn a_batch_edits_its_opened_trie_to_the_root_after() {
    let mut rng = Rng::new(0xba7c4);
    let addresses: Vec<Vec<u8>> = (0..2).map(|_| rng.next_bytes(32)).collect();
    for (key_len, prefixes) in [(4, &[][..]), (32, &[][..]), (52, &addresses[..])] {
        let (mut trie, mut leaves) = (Trie::new(key_len), BTreeMap::new());
        for round in 0..40 {
            let keys = shuffled(&mut rng, leaves.keys().cloned().collect());
            let [r, s, t] = match round {
                25 => [keys.len(), 0, 0],
                _ => [15, 15, 8].map(|most| (rng.next_u64() % (most + 1)) as usize),
            };
            let (removes, rest) = keys.split_at(r.min(keys.len()));
            let (sets, rest) = rest.split_at(s.min(rest.len()));
            let reads = &rest[..t.min(rest.len())];
            let mut inserts = BTreeMap::new();
            for _ in 0..rng.next_u64() % 31 {
                let key = draw(&mut rng, key_len, prefixes, &keys);
                if !leaves.contains_key(&key) {
                    inserts.insert(key.clone(), random_leaf(&mut rng, &key));
                }
            }
            let sets: BTreeMap<Vec<u8>, Digest> = sets
                .iter()
                .map(|key| (key.clone(), random_leaf(&mut rng, key)))
                .collect();

            let mut touched: BTreeSet<Vec<u8>> = reads.iter().chain(removes).cloned().collect();
            touched.extend(sets.keys().cloned());
            if !trie.is_empty() {
                touched.extend(inserts.keys().map(|key| trie.witness(key)));
            }
            let mut opened = open_touched(&mut rng, key_len, &trie, &touched);
            assert_eq!(
                opened.root(),
                trie.root(),
                "{key_len}-byte keys, round {round}, before"
            );

            for (key, digest) in sets.iter().chain(&inserts) {
                trie.insert(key, *digest);
                leaves.insert(key.clone(), *digest);
            }
            for (key, digest) in &sets {
                opened.set(key, *digest);
            }
            for (key, digest) in &inserts {
                opened.insert(key, *digest);
            }
            for key in removes {
                opened.remove(key);
                trie.remove(key);
                leaves.remove(key);
            }
            assert_eq!(
                opened.root(),
                trie.root(),
                "{key_len}-byte keys, round {round}, after"
            );
            assert_eq!(trie.len(), leaves.len());
        }
    }
}

/// The opener refuses, by panicking or by opening to another root, a proof a
/// sibling short, two siblings swapped, a sibling of a chain past the last, a
/// digest changed, a byte more or less, or the proof of another touched set.
#[test]
fn a_malformed_proof_is_refused() {
    let mut rng = Rng::new(0xbad);
    let (trie, leaves) = table(&mut rng, 4, 200, &[]);
    let keys: Vec<Vec<u8>> = leaves.keys().cloned().collect();
    let touched: Vec<Vec<u8>> = keys.iter().step_by(7).cloned().collect();
    let entries: Vec<(Vec<u8>, Digest)> = touched
        .iter()
        .map(|key| (key.clone(), leaves[key]))
        .collect();
    let proof = trie.proof(&touched);
    let s = u32::from_le_bytes(proof[..4].try_into().unwrap()) as usize;
    let (word, digest) = (|j: usize| 4 + 4 * j, |j: usize| 4 + 4 * s + 64 * j);
    assert!(s > 10);
    assert_eq!(open(4, &entries, &proof).root(), trie.root());

    let mut tampered = Vec::new();
    let mut short = proof.clone();
    short.drain(digest(s - 1)..);
    short.drain(word(s - 1)..word(s));
    short[..4].copy_from_slice(&(s as u32 - 1).to_le_bytes());
    tampered.push(short);
    for j in [0, s / 2, s - 2] {
        let mut swapped = proof.clone();
        for (at, len) in [(word(j), 4), (digest(j), 64)] {
            let (a, b) = swapped[at..at + 2 * len].split_at_mut(len);
            a.swap_with_slice(b);
        }
        tampered.push(swapped);
    }
    let mut past = proof.clone();
    past[word(s - 1)..word(s)].copy_from_slice(&(512 * touched.len() as u32).to_le_bytes());
    tampered.push(past);
    let mut changed = proof.clone();
    changed[digest(s / 2)] ^= 1;
    tampered.push(changed);
    tampered.push([&proof[..], &[0]].concat());
    tampered.push(proof[..proof.len() - 1].to_vec());
    tampered.push(trie.proof(&keys[1..].iter().step_by(7).collect::<Vec<_>>()));

    for (i, bytes) in tampered.iter().enumerate() {
        let root = catch_unwind(AssertUnwindSafe(|| open(4, &entries, bytes).root()));
        assert!(
            root.is_err() || root.unwrap() != trie.root(),
            "tamper {i} opens to the root"
        );
    }
}
