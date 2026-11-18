//! A table's crit-bit trie, the guest's half: opened from the proof a batch
//! is advised with, edited, and hashed by the trie precompile, [`mpt_eval`],
//! in one call. `docs/spec/precompiles.md`'s MPT section defines the trie,
//! its hashes and the proof; `tools/mpt` is the host's half.
//!
//! A table's keys are one length, 1 to 64 bytes, and **its values are one
//! width**: [`leaf`] packs a key and its value and binds neither length, so a
//! value and the same value with zero bytes appended would be one leaf.
//!
//! [`Trie::open`] reads a batch's touched keys, their leaves and the proof of
//! their pruned trie, and panics on any proof that is not one. [`Trie::root`]
//! is that trie's root, which the caller holds to the root it trusts: equal,
//! each touched key's leaf is the one a walk on its bits reaches from that
//! root. [`Trie::set`], [`Trie::insert`] and [`Trie::remove`] then edit the
//! trie as the table is edited, each walking from the root on the key's bits:
//! the trie is its own index. [`Trie::root`] after them is the table's root
//! after the batch.
//!
//! **A batch that inserts and removes inserts first.** An insert's walk must
//! reach an opened leaf, which the proof opens as the walk reaches it on the
//! table before the batch. An insert leaves every opened leaf where a walk
//! reaches it, but a remove lifts the removed leaf's sibling, which may be a
//! node not opened, into its parent's place, where a later insert's walk would
//! meet it and panic.

use alloc::vec::Vec;

use constants::delegation::mpt::{DEPTH_SHIFT, JOIN, LEFT, LOAD, MAX_KEY, MAX_LEAF, PARK, SIB};

use crate::{mpt_eval, poseidon2_permute, Digest};

/// A leaf: the first 8 lanes of the permutation of `key ‖ value` packed seven
/// bytes to a lane, little-endian, and zero-extended to 16 lanes, one
/// [`poseidon2_permute`] call. Panics if the two are over 112 bytes.
pub fn leaf(key: &[u8], value: &[u8]) -> Digest {
    assert!(
        key.len() + value.len() <= MAX_LEAF,
        "mpt::leaf: a key and its value are at most 112 bytes"
    );
    let mut state = [0u64; 16];
    let (mut lane, mut shift) = (0, 0);
    for bytes in [key, value] {
        for &byte in bytes {
            state[lane] |= (byte as u64) << shift;
            shift += 8;
            if shift == 56 {
                (lane, shift) = (lane + 1, 0);
            }
        }
    }
    poseidon2_permute(&mut state);
    let mut lanes = [0; 8];
    lanes.copy_from_slice(&state[..8]);
    Digest(lanes)
}

/// An opened table: the pruned trie of the keys a batch touches, its nodes in
/// an arena, and its root, none for the empty table. The keys are borrowed,
/// and a sibling's digest stays where the proof holds it.
pub struct Trie<'a> {
    key_len: usize,
    nodes: Vec<Node<'a>>,
    root: Option<usize>,
}

/// A node of the pruned trie.
enum Node<'a> {
    /// A touched key and its leaf.
    Leaf(&'a [u8], Digest),
    /// A sibling: the address of its digest, 16 words the call reads mod `p`.
    Opaque(u32),
    /// A branch at a crit bit over its children, left then right.
    Branch(usize, [usize; 2]),
}

/// A child's place: its branch, and its side, 0 on the left and 1 on the
/// right.
type Slot = (usize, usize);

impl<'a> Trie<'a> {
    /// The pruned trie of a batch's touched keys, from `entries`, each a key
    /// of `key_len` bytes and its leaf, keys strictly ascending, and the proof
    /// at `advice[at..]`, word-aligned, which `at` is moved past. Each chain
    /// climbs from its key's leaf, taking the deeper of its next sibling and
    /// the subtree parked on top of the stack while either is deeper than the
    /// crit bit of its key and the next, where it parks, or to the root for
    /// the last chain; anything else panics. The siblings' digests are not
    /// read here: they are [`Trie::root`]'s blocks, in place, and nothing is
    /// held to a root until the caller holds [`Trie::root`] to one.
    pub fn open<E>(key_len: usize, entries: E, advice: &'a [u8], at: &mut usize) -> Trie<'a>
    where
        E: IntoIterator<Item = (&'a [u8], Digest)>,
    {
        assert!(
            (1..=MAX_KEY).contains(&key_len),
            "mpt::Trie::open: a key is 1 to 64 bytes"
        );
        let proof = *at;
        assert!(
            (advice.as_ptr().addr() + proof).is_multiple_of(4),
            "mpt::Trie::open: a proof is word-aligned"
        );
        let word = |i: usize| {
            let at = proof + 4 * i;
            u32::from_le_bytes(advice[at..at + 4].try_into().expect("a word")) as usize
        };
        let s = word(0);
        let digests = proof + 4 + 4 * s;
        *at = digests + 64 * s;
        assert!(
            *at <= advice.len(),
            "mpt::Trie::open: the proof is in the advice"
        );

        // Touched key `i`'s leaf is node `i`, and sibling `j` node `m + j`.
        let entries = entries.into_iter();
        let mut nodes = Vec::with_capacity(2 * (entries.size_hint().0 + s));
        for (key, leaf) in entries {
            assert!(
                key.len() == key_len,
                "mpt::Trie::open: a key is the table's length"
            );
            nodes.push(Node::Leaf(key, leaf));
        }
        let m = nodes.len();
        let base = advice.as_ptr().addr() + digests;
        nodes.extend((0..s).map(|j| Node::Opaque((base + 64 * j) as u32)));
        let mut trie = Trie {
            key_len,
            nodes,
            root: None,
        };
        if m == 0 {
            assert!(
                s == 0 || (s == 1 && word(1) == 0),
                "mpt::Trie::open: an untouched table's proof is nothing or its root"
            );
            trie.root = (s == 1).then_some(0);
            return trie;
        }

        // The parked subtrees, `(crit bit, node)`, the deepest on top.
        let mut stack: Vec<(usize, usize)> = Vec::with_capacity(m);
        let mut next = 0;
        for i in 0..m {
            let key = trie.key(i);
            let park = (i + 1 < m).then(|| ascending(key, trie.key(i + 1)));
            let deeper = |d: usize| park.is_none_or(|c| d > c);
            let (mut node, mut cur) = (i, 8 * key_len);
            loop {
                let sibling = match next < s {
                    true => {
                        let w = word(1 + next);
                        assert!(w / 512 >= i, "mpt::Trie::open: a sibling is its chain's");
                        (w / 512 == i).then_some(w % 512)
                    }
                    false => None,
                };
                assert!(
                    sibling.is_none_or(deeper),
                    "mpt::Trie::open: a sibling is deeper than its chain's park"
                );
                let join = stack.last().map(|&(c, _)| c).filter(|&c| deeper(c));
                let d = match (sibling, join) {
                    (Some(d), Some(c)) => {
                        assert!(d != c, "mpt::Trie::open: a sibling is not at a join");
                        d.max(c)
                    }
                    (Some(d), None) | (None, Some(d)) => d,
                    (None, None) => break,
                };
                assert!(d < cur, "mpt::Trie::open: a branch is above its child");
                cur = d;
                let children = if sibling == Some(d) {
                    let mut children = [m + next; 2];
                    children[bit(key, d)] = node;
                    next += 1;
                    children
                } else {
                    let (_, parked) = stack.pop().expect("a parked subtree");
                    [parked, node]
                };
                node = trie.nodes.len();
                trie.nodes.push(Node::Branch(d, children));
            }
            match park {
                Some(c) => stack.push((c, node)),
                None => trie.root = Some(node),
            }
        }
        assert!(
            stack.is_empty() && next == s,
            "mpt::Trie::open: every subtree is joined and every sibling taken"
        );
        trie
    }

    /// The root: the zero digest for the empty table, and otherwise the value
    /// of the pruned trie's program by one [`mpt_eval`] call, canonical even
    /// where the root is a sibling, one LOAD. The program is post-order, in a
    /// buffer of its own, and names each digest once: a leaf's in the arena,
    /// a sibling's in the proof.
    pub fn root(&self) -> Digest {
        let Some(root) = self.root else {
            return Digest::default();
        };
        let mut ops = Vec::with_capacity(2 * self.nodes.len());
        self.emit(root, 0, &mut ops);
        mpt_eval(&ops)
    }

    /// Replaces an opened key's leaf. Panics unless the walk on `key` reaches
    /// it.
    pub fn set(&mut self, key: &[u8], leaf: Digest) {
        let (at, reached, ..) = self.walk(key);
        assert!(reached == key, "mpt::Trie::set: an opened key");
        self.nodes[at] = Node::Leaf(reached, leaf);
    }

    /// Inserts a key the table does not hold, with its leaf: under a branch at
    /// `c`, the crit bit of `key` and the opened key its walk reaches, spliced
    /// above the first node on that walk deeper than `c`. The empty table's
    /// root becomes the leaf. Panics where the walk reaches a node not opened
    /// or `key`'s own leaf.
    pub fn insert(&mut self, key: &'a [u8], leaf: Digest) {
        let new = self.nodes.len();
        let Some(mut at) = self.root else {
            assert!(
                key.len() == self.key_len,
                "mpt::Trie: a key is the table's length"
            );
            self.nodes.push(Node::Leaf(key, leaf));
            self.root = Some(new);
            return;
        };
        let (_, reached, ..) = self.walk(key);
        let c = crit(key, reached);
        let mut slot = None;
        while let Node::Branch(d, children) = self.nodes[at] {
            if d > c {
                break;
            }
            slot = Some((at, bit(key, d)));
            at = children[bit(key, d)];
        }
        let mut children = [at; 2];
        children[bit(key, c)] = new;
        self.nodes.push(Node::Leaf(key, leaf));
        self.nodes.push(Node::Branch(c, children));
        self.link(slot, new + 1);
    }

    /// Removes an opened key: its parent's other child takes the parent's
    /// place, and the last key leaves the table empty. Panics unless the walk
    /// on `key` reaches it.
    pub fn remove(&mut self, key: &[u8]) {
        let (_, reached, slot, above) = self.walk(key);
        assert!(reached == key, "mpt::Trie::remove: an opened key");
        match slot {
            Some((parent, side)) => {
                let other = self.children(parent)[1 - side];
                self.link(above, other);
            }
            None => self.root = None,
        }
    }

    /// The walk on `key`'s bits from the root: the leaf it reaches, that
    /// leaf's key, and the slots of the leaf and of its parent, none above the
    /// root. Panics on the empty table, on a key not the table's length, and
    /// where the walk reaches a node not opened.
    fn walk(&self, key: &[u8]) -> (usize, &'a [u8], Option<Slot>, Option<Slot>) {
        assert!(
            key.len() == self.key_len,
            "mpt::Trie: a key is the table's length"
        );
        let mut at = self
            .root
            .expect("mpt::Trie: a walk in a table that is not empty");
        let (mut slot, mut above) = (None, None);
        loop {
            match self.nodes[at] {
                Node::Branch(c, children) => {
                    let side = bit(key, c);
                    (above, slot) = (slot, Some((at, side)));
                    at = children[side];
                }
                Node::Leaf(reached, _) => return (at, reached, slot, above),
                Node::Opaque(_) => panic!("mpt::Trie: a walk reaches a node not opened"),
            }
        }
    }

    /// Emits `node`'s ops, its first parking where `park` is [`PARK`], and
    /// returns that first op's index.
    fn emit(&self, node: usize, park: u32, ops: &mut Vec<u32>) -> u32 {
        let first = (ops.len() / 2) as u32;
        match self.nodes[node] {
            Node::Leaf(_, ref leaf) => op(ops, LOAD | park, (leaf as *const Digest).addr() as u32),
            Node::Opaque(at) => op(ops, LOAD | park, at),
            Node::Branch(c, [left, right]) => {
                let d = (c as u32) << DEPTH_SHIFT;
                match (self.opaque(left), self.opaque(right)) {
                    (Some(l), Some(r)) => {
                        op(ops, LOAD | park, l);
                        op(ops, SIB | d, r);
                    }
                    (Some(l), None) => {
                        self.emit(right, park, ops);
                        op(ops, SIB | LEFT | d, l);
                    }
                    (None, Some(r)) => {
                        self.emit(left, park, ops);
                        op(ops, SIB | d, r);
                    }
                    (None, None) => {
                        self.emit(left, park, ops);
                        let i = self.emit(right, PARK, ops);
                        op(ops, JOIN | LEFT | d, i);
                    }
                }
            }
        }
        first
    }

    /// The address of `node`'s digest, if it is a sibling.
    fn opaque(&self, node: usize) -> Option<u32> {
        match self.nodes[node] {
            Node::Opaque(at) => Some(at),
            _ => None,
        }
    }

    /// Touched key `i` while the trie is opened: node `i` is its leaf.
    fn key(&self, i: usize) -> &'a [u8] {
        match self.nodes[i] {
            Node::Leaf(key, _) => key,
            _ => unreachable!("node i is touched key i's leaf"),
        }
    }

    /// The children of the branch `branch`.
    fn children(&mut self, branch: usize) -> &mut [usize; 2] {
        match &mut self.nodes[branch] {
            Node::Branch(_, children) => children,
            _ => unreachable!("a slot is a branch's"),
        }
    }

    /// Makes `node` the child at `slot`, or the root where there is none.
    fn link(&mut self, slot: Option<Slot>, node: usize) {
        match slot {
            Some((branch, side)) => self.children(branch)[side] = node,
            None => self.root = Some(node),
        }
    }
}

/// Appends the op `(info, arg)`.
fn op(ops: &mut Vec<u32>, info: u32, arg: u32) {
    ops.push(info);
    ops.push(arg);
}

/// Bit `d` of `key`, most significant first: the side a walk takes.
fn bit(key: &[u8], d: usize) -> usize {
    ((key[d >> 3] >> (7 - (d & 7))) & 1) as usize
}

/// The least bit where `a` and `b`, of one length, differ. Panics if they do
/// not.
fn crit(a: &[u8], b: &[u8]) -> usize {
    let i = a
        .iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .expect("mpt: two keys are distinct");
    8 * i + (a[i] ^ b[i]).leading_zeros() as usize
}

/// The crit bit of `a` and `b`, where `b`'s bit is set: panics unless
/// `a < b`.
fn ascending(a: &[u8], b: &[u8]) -> usize {
    let c = crit(a, b);
    assert!(
        bit(b, c) == 1,
        "mpt::Trie::open: keys are strictly ascending"
    );
    c
}
