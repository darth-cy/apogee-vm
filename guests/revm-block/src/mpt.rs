//! Ethereum's Merkle-Patricia trie, and the RLP codec under it — written here
//! rather than taken from a crate, because S25's core algorithm says so:
//! *"Own the in-guest MPT verification, which is guest workload rather than
//! proving stack. An RLP decode and node-hash trie walk hashes through S21's
//! keccak256 shim, and one code path serves both pre-state authentication and
//! post-state root recomputation."*
//!
//! It is one code path, and that is the design rather than a coincidence.
//! Authentication and recomputation are the same operation seen twice: a node
//! is authentic exactly when the parent that names it hashes to what *its*
//! parent names, so **resolving a reference through the node map is the
//! verification** — there is no separate check-the-hash step to forget. Build
//! the sparse trie from the witness's nodes, assert its root re-hashes to the
//! parent state root once, and every read below that point is authenticated by
//! construction. Apply the block's writes to the same structure and re-hash,
//! and that is the post-state root.
//!
//! # What must not be got wrong
//!
//! Four rules carry the whole thing, and each has a way of failing that looks
//! almost right:
//!
//! - **A missing node is an invalid witness, never an absence.** If the walk
//!   needs a node the witness does not carry, this module errors. Returning
//!   "absent" instead would let anyone prove any key absent by truncating the
//!   witness. It is one `?` away from being wrong and it is the single most
//!   important line here.
//! - **A storage value is doubly RLP-wrapped.** The trie value is
//!   `rlp(minimal_big_endian(v))`, and the leaf then encodes *that byte string*
//!   as its second item. Slot value `0x80` appears in the leaf as `82 81 80`.
//!   Encoding the 32-byte word, or wrapping once, is a wrong root that looks
//!   almost right.
//! - **A zero storage value is a deletion.** There is no stored zero in a
//!   storage trie, which is correct: the EVM reads an unwritten slot and a
//!   zeroed one identically.
//! - **An extension's path is never empty.** When a split leaves the old
//!   child's remaining path empty, the original child is attached to the new
//!   branch *directly*. `Ext([], child)` is illegal and silently gives a
//!   different root.
//!
//! # Inlining
//!
//! A node whose RLP is under 32 bytes is embedded in its parent verbatim
//! instead of being referenced by hash, and the test is the RLP **type** — a
//! list item is an inlined node, a 32-byte string is a hash, the empty string
//! is an absent child. In a keccak-keyed trie it essentially never fires: a
//! branch is at least 83 bytes and an extension at least 36, so only a leaf
//! near the bottom of a 64-nibble path goes under 32, which needs a 160-bit
//! keccak collision. It is implemented anyway, because if it ever fired and
//! were missing the result would be a silently wrong root, and because the
//! rule is load-bearing for the *small* tries this module's own tests use.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::{keccak, Word32};

/// `keccak256(rlp(""))` — the root of an empty trie, and what an account with
/// no storage carries in its `storage_root` field.
///
/// Not the empty code hash (`keccak256("")`), and not the empty uncle-list hash
/// (`keccak256(rlp([]))`). The three are confused often enough to be worth
/// naming together.
pub const EMPTY_TRIE_ROOT: Word32 = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// Everything this module refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MptError {
    /// A node's bytes are not a well-formed, canonically encoded trie node.
    Malformed,
    /// The walk needs a node the witness does not carry. **Never an absence**
    /// — the hash names what is missing so that a witness can be completed.
    MissingNode { hash: Word32 },
    /// A deletion left a branch with one child that the witness has only as a
    /// hash, so the collapse cannot be performed.
    ///
    /// This is the case `eth_getProof` cannot supply on its own: the surviving
    /// child is a *sibling* of the deleted key, so it is not on that key's
    /// path and not in its proof. The witness builder has to add it; the guest
    /// names it and stops.
    BlindedCollapse { hash: Word32 },
    /// The trie's root does not hash to the root the witness claims.
    RootMismatch,
}

// ---------------------------------------------------------------------------
// RLP
// ---------------------------------------------------------------------------

/// Append the RLP of a byte string.
pub fn encode_bytes(out: &mut Vec<u8>, payload: &[u8]) {
    if payload.len() == 1 && payload[0] < 0x80 {
        out.push(payload[0]);
        return;
    }
    encode_header(out, payload.len(), 0x80);
    out.extend_from_slice(payload);
}

/// Append the RLP of a list whose payload — the concatenation of its items'
/// complete encodings — is already built.
fn encode_list(out: &mut Vec<u8>, payload: &[u8]) {
    encode_header(out, payload.len(), 0xc0);
    out.extend_from_slice(payload);
}

/// Append the RLP of a non-negative integer given big-endian: **minimal**, with
/// zero as the empty string.
fn encode_uint(out: &mut Vec<u8>, be: &[u8]) {
    let start = be.iter().position(|b| *b != 0).unwrap_or(be.len());
    encode_bytes(out, &be[start..]);
}

fn encode_header(out: &mut Vec<u8>, len: usize, short: u8) {
    if len <= 55 {
        out.push(short + len as u8);
        return;
    }
    let be = (len as u64).to_be_bytes();
    let start = be
        .iter()
        .position(|b| *b != 0)
        .expect("len > 55 is nonzero");
    out.push(short + 55 + (8 - start) as u8);
    out.extend_from_slice(&be[start..]);
}

/// One RLP item: where its payload is, and whether it is a list.
struct Item<'a> {
    list: bool,
    payload: &'a [u8],
    /// The item's complete encoding, header included — which is what an
    /// inlined child needs.
    whole: &'a [u8],
}

/// Split one item off the front of `bytes`, strictly.
///
/// Every canonical-form rule is enforced, because each one is a second encoding
/// of one value. They cannot change a *node* — a node is bound by its keccak —
/// but they are the same rules this module's own encoder must follow, and
/// checking them on the way in turns a malformed witness into an error instead
/// of a wrong answer.
fn split(bytes: &[u8]) -> Result<(Item<'_>, &[u8]), MptError> {
    let first = *bytes.first().ok_or(MptError::Malformed)?;
    match first {
        // A single byte below 0x80 is itself, with no header.
        0x00..=0x7f => Ok((
            Item {
                list: false,
                payload: &bytes[..1],
                whole: &bytes[..1],
            },
            &bytes[1..],
        )),
        0x80..=0xb7 => {
            let len = (first - 0x80) as usize;
            let body = bytes.get(1..1 + len).ok_or(MptError::Malformed)?;
            // A one-byte string below 0x80 is never wrapped.
            if len == 1 && body[0] < 0x80 {
                return Err(MptError::Malformed);
            }
            Ok((
                Item {
                    list: false,
                    payload: body,
                    whole: &bytes[..1 + len],
                },
                &bytes[1 + len..],
            ))
        }
        0xb8..=0xbf => long(bytes, (first - 0xb7) as usize, false),
        0xc0..=0xf7 => {
            let len = (first - 0xc0) as usize;
            let body = bytes.get(1..1 + len).ok_or(MptError::Malformed)?;
            Ok((
                Item {
                    list: true,
                    payload: body,
                    whole: &bytes[..1 + len],
                },
                &bytes[1 + len..],
            ))
        }
        0xf8..=0xff => long(bytes, (first - 0xf7) as usize, true),
    }
}

fn long(bytes: &[u8], width: usize, list: bool) -> Result<(Item<'_>, &[u8]), MptError> {
    let size = bytes.get(1..1 + width).ok_or(MptError::Malformed)?;
    // No leading zero in a length, and the length must not have fitted the
    // short form.
    if size[0] == 0 {
        return Err(MptError::Malformed);
    }
    // `usize` is four bytes on the guest, so a wide length is an overflow and
    // never a silent truncation.
    if width > core::mem::size_of::<usize>() {
        return Err(MptError::Malformed);
    }
    let mut len = 0usize;
    for byte in size {
        len = len.checked_mul(256).ok_or(MptError::Malformed)?;
        len = len.checked_add(*byte as usize).ok_or(MptError::Malformed)?;
    }
    if len <= 55 {
        return Err(MptError::Malformed);
    }
    let at = 1 + width;
    let body = bytes.get(at..at + len).ok_or(MptError::Malformed)?;
    Ok((
        Item {
            list,
            payload: body,
            whole: &bytes[..at + len],
        },
        &bytes[at + len..],
    ))
}

/// Every item of a list, with nothing left over.
fn list_items(bytes: &[u8]) -> Result<Vec<Item<'_>>, MptError> {
    let (head, rest) = split(bytes)?;
    if !head.list || !rest.is_empty() {
        return Err(MptError::Malformed);
    }
    let mut items = Vec::new();
    let mut at = head.payload;
    while !at.is_empty() {
        let (item, next) = split(at)?;
        items.push(item);
        at = next;
    }
    Ok(items)
}

// ---------------------------------------------------------------------------
// Nibbles and the hex prefix
// ---------------------------------------------------------------------------

/// A 32-byte trie key as its 64 nibbles, high nibble first.
pub fn nibbles(key: &Word32) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    for byte in key {
        out.push(byte >> 4);
        out.push(byte & 0xf);
    }
    out
}

/// The hex-prefix (compact) encoding of a nibble path.
///
/// One flag nibble carries two bits — leaf-or-extension, and odd-or-even — and
/// on an odd path the low nibble of the first byte carries the first real
/// nibble rather than padding. The four leading nibbles are `0` even
/// extension, `1` odd extension, `2` even leaf, `3` odd leaf.
fn hp_encode(path: &[u8], leaf: bool) -> Vec<u8> {
    let flag = if leaf { 2u8 } else { 0u8 };
    let mut out = Vec::with_capacity(1 + path.len() / 2 + 1);
    let rest = if path.len() % 2 == 1 {
        out.push(((flag | 1) << 4) | path[0]);
        &path[1..]
    } else {
        out.push(flag << 4);
        path
    };
    for pair in rest.chunks(2) {
        out.push((pair[0] << 4) | pair[1]);
    }
    out
}

/// The inverse, strictly: a leading nibble above 3 is refused, and so is a
/// nonzero padding nibble on an even path.
fn hp_decode(bytes: &[u8]) -> Result<(Vec<u8>, bool), MptError> {
    let first = *bytes.first().ok_or(MptError::Malformed)?;
    let flag = first >> 4;
    if flag > 3 {
        return Err(MptError::Malformed);
    }
    let leaf = flag & 2 != 0;
    let odd = flag & 1 != 0;
    let mut path = Vec::with_capacity(2 * bytes.len());
    if odd {
        path.push(first & 0xf);
    } else if first & 0xf != 0 {
        return Err(MptError::Malformed);
    }
    for byte in &bytes[1..] {
        path.push(byte >> 4);
        path.push(byte & 0xf);
    }
    Ok((path, leaf))
}

fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    let mut n = 0;
    while n < a.len() && n < b.len() && a[n] == b[n] {
        n += 1;
    }
    n
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

/// One node of a **sparse** trie: the witness's nodes, parsed, with every
/// subtree the witness did not carry standing in as its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    /// No node. Encodes as the empty string, which is what an absent branch
    /// child is.
    Empty,
    /// A terminus: the rest of the key, and the value.
    Leaf { path: Vec<u8>, value: Vec<u8> },
    /// A shared prefix and the node below it. `path` is never empty.
    Ext { path: Vec<u8>, child: Box<Node> },
    /// Sixteen children by nibble, and the node's own value — which in a
    /// secure trie is always empty, every key being 64 nibbles, but is carried
    /// because the collapse rule reads it.
    Branch {
        children: Box<[Node; 16]>,
        value: Vec<u8>,
    },
    /// A subtree the witness did not carry, known only by its hash.
    Blinded(Word32),
}

impl Node {
    /// The empty branch, for building one child at a time.
    fn branch() -> Node {
        Node::Branch {
            children: Box::new(core::array::from_fn(|_| Node::Empty)),
            value: Vec::new(),
        }
    }

    /// This node's RLP.
    ///
    /// A blinded node has none — it is known only by its hash, and
    /// [`Node::reference`] is what a parent needs. Reaching this on one is a
    /// broken caller, so it panics rather than inventing bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Node::Empty => out.push(0x80),
            Node::Leaf { path, value } => {
                let mut payload = Vec::new();
                encode_bytes(&mut payload, &hp_encode(path, true));
                encode_bytes(&mut payload, value);
                encode_list(&mut out, &payload);
            }
            Node::Ext { path, child } => {
                assert!(!path.is_empty(), "an extension's path is never empty");
                let mut payload = Vec::new();
                encode_bytes(&mut payload, &hp_encode(path, false));
                payload.extend_from_slice(&child.reference());
                encode_list(&mut out, &payload);
            }
            Node::Branch { children, value } => {
                let mut payload = Vec::new();
                for child in children.iter() {
                    payload.extend_from_slice(&child.reference());
                }
                encode_bytes(&mut payload, value);
                encode_list(&mut out, &payload);
            }
            Node::Blinded(_) => panic!("a blinded node has no encoding, only a reference"),
        }
        out
    }

    /// How a parent names this node: its RLP inlined when that is under 32
    /// bytes, otherwise the RLP of its keccak.
    pub fn reference(&self) -> Vec<u8> {
        if let Node::Blinded(hash) = self {
            let mut out = Vec::with_capacity(33);
            encode_bytes(&mut out, hash);
            return out;
        }
        let encoded = self.encode();
        if encoded.len() < 32 {
            return encoded;
        }
        let mut out = Vec::with_capacity(33);
        encode_bytes(&mut out, &keccak(&encoded));
        out
    }

    /// This node as a trie root: `keccak256` of its RLP, whatever its size.
    pub fn root(&self) -> Word32 {
        if let Node::Blinded(hash) = self {
            return *hash;
        }
        keccak(&self.encode())
    }

    /// Whether this node holds nothing.
    pub fn is_empty(&self) -> bool {
        matches!(self, Node::Empty)
    }
}

/// The witness's nodes, keyed by their keccak.
///
/// A plain sorted list rather than a map: the guest builds it once, looks up
/// each node while parsing, and a binary search over a few thousand entries is
/// cheaper than a hash map it would have to allocate. The keys are already
/// keccaks, so they are as well distributed as a hash could make them.
pub struct NodeMap {
    entries: Vec<(Word32, Vec<u8>)>,
}

impl NodeMap {
    /// Hash every node once and sort. A repeated node is kept once; two
    /// different nodes cannot share a hash.
    pub fn new(nodes: &[Vec<u8>]) -> NodeMap {
        let mut entries: Vec<(Word32, Vec<u8>)> =
            nodes.iter().map(|n| (keccak(n), n.clone())).collect();
        entries.sort_unstable_by_key(|e| e.0);
        entries.dedup_by(|a, b| a.0 == b.0);
        NodeMap { entries }
    }

    fn get(&self, hash: &Word32) -> Option<&[u8]> {
        self.entries
            .binary_search_by(|e| e.0.cmp(hash))
            .ok()
            .map(|at| self.entries[at].1.as_slice())
    }
}

/// The sparse trie under `root`, from the nodes the witness carries.
///
/// A hash the witness does not carry becomes [`Node::Blinded`] rather than an
/// error: an untouched subtree is exactly what a sparse trie is for, and it
/// re-encodes to its own hash verbatim so the root round-trips. What *is* an
/// error is needing one of those subtrees later — [`MptError::MissingNode`].
///
/// The root itself must be present, and the caller should follow this with
/// [`check_root`], which is the one assertion that catches every parse and
/// encode bug at the moment it appears rather than as a wrong root at the end.
pub fn build(db: &NodeMap, root: &Word32) -> Result<Node, MptError> {
    if *root == EMPTY_TRIE_ROOT {
        return Ok(Node::Empty);
    }
    let bytes = db.get(root).ok_or(MptError::MissingNode { hash: *root })?;
    parse(db, bytes)
}

/// Parse one node's bytes, resolving its children through the map.
fn parse(db: &NodeMap, bytes: &[u8]) -> Result<Node, MptError> {
    let items = list_items(bytes)?;
    match items.len() {
        2 => {
            let (path, leaf) = hp_decode(items[0].payload)?;
            if leaf {
                Ok(Node::Leaf {
                    path,
                    value: items[1].payload.to_vec(),
                })
            } else {
                if path.is_empty() {
                    return Err(MptError::Malformed);
                }
                Ok(Node::Ext {
                    path,
                    child: Box::new(child_of(db, &items[1])?),
                })
            }
        }
        17 => {
            let mut children: Vec<Node> = Vec::with_capacity(16);
            for item in items.iter().take(16) {
                children.push(child_of(db, item)?);
            }
            let array: [Node; 16] = children.try_into().expect("sixteen children");
            Ok(Node::Branch {
                children: Box::new(array),
                value: items[16].payload.to_vec(),
            })
        }
        _ => Err(MptError::Malformed),
    }
}

/// One child slot: an inlined node, a hash reference, or nothing.
///
/// The test is the RLP **type**, not the length. A list item is an inlined
/// node and its whole encoding is the node; a 32-byte string is a hash; the
/// empty string is an absent child. Any other string width is malformed.
fn child_of(db: &NodeMap, item: &Item<'_>) -> Result<Node, MptError> {
    if item.list {
        return parse(db, item.whole);
    }
    match item.payload.len() {
        0 => Ok(Node::Empty),
        32 => {
            let hash: Word32 = item.payload.try_into().expect("thirty-two bytes");
            match db.get(&hash) {
                Some(bytes) => parse(db, bytes),
                None => Ok(Node::Blinded(hash)),
            }
        }
        _ => Err(MptError::Malformed),
    }
}

/// The parsed trie re-hashes to the root it was built from.
///
/// One line, and it is worth its own function because of when it is called: a
/// blinded subtree re-encodes to its own hash verbatim, so an untouched trie
/// round-trips exactly, and this catches a parse or encode bug at the moment it
/// appears rather than as a wrong root after every update has been applied.
pub fn check_root(node: &Node, root: &Word32) -> Result<(), MptError> {
    if node.root() == *root {
        Ok(())
    } else {
        Err(MptError::RootMismatch)
    }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// The value at `path`, or `None` when the trie proves there is none.
///
/// **A node the witness does not carry is [`MptError::MissingNode`], never
/// `None`.** Treating a missing node as an absence is how a truncated witness
/// proves any key absent, and it is the one line in this module that carries
/// the authentication.
pub fn get(node: &Node, path: &[u8]) -> Result<Option<Vec<u8>>, MptError> {
    match node {
        Node::Empty => Ok(None),
        Node::Blinded(hash) => Err(MptError::MissingNode { hash: *hash }),
        Node::Leaf { path: leaf, value } => Ok((leaf.as_slice() == path).then(|| value.clone())),
        Node::Ext { path: ext, child } => {
            if path.len() < ext.len() || &path[..ext.len()] != ext.as_slice() {
                return Ok(None);
            }
            get(child, &path[ext.len()..])
        }
        Node::Branch { children, value } => match path.split_first() {
            None => Ok((!value.is_empty()).then(|| value.clone())),
            Some((nibble, rest)) => get(&children[*nibble as usize], rest),
        },
    }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Insert or replace `path`'s value.
pub fn insert(node: Node, path: &[u8], value: Vec<u8>) -> Result<Node, MptError> {
    match node {
        Node::Blinded(hash) => Err(MptError::MissingNode { hash }),
        Node::Empty => Ok(Node::Leaf {
            path: path.to_vec(),
            value,
        }),
        Node::Leaf {
            path: leaf,
            value: old,
        } => {
            if leaf.as_slice() == path {
                return Ok(Node::Leaf { path: leaf, value });
            }
            let shared = common_prefix(&leaf, path);
            let mut branch = Node::branch();
            place(
                &mut branch,
                &leaf[shared..],
                Node::Leaf {
                    path: Vec::new(),
                    value: old,
                },
            );
            place(
                &mut branch,
                &path[shared..],
                Node::Leaf {
                    path: Vec::new(),
                    value,
                },
            );
            Ok(wrap(&leaf[..shared], branch))
        }
        Node::Ext { path: ext, child } => {
            let shared = common_prefix(&ext, path);
            if shared == ext.len() {
                let below = insert(*child, &path[shared..], value)?;
                return Ok(Node::Ext {
                    path: ext,
                    child: Box::new(below),
                });
            }
            // The paths diverge inside the extension: a branch is born at
            // `shared`. The old child goes at `ext[shared]` with the rest of
            // the extension above it — and **when that rest is empty the
            // original child is attached directly**, because an extension's
            // path is never empty and `Ext([], child)` silently gives a
            // different root.
            let mut branch = Node::branch();
            let remainder = &ext[shared + 1..];
            let below = if remainder.is_empty() {
                *child
            } else {
                Node::Ext {
                    path: remainder.to_vec(),
                    child,
                }
            };
            set_child(&mut branch, ext[shared], below);
            place(
                &mut branch,
                &path[shared..],
                Node::Leaf {
                    path: Vec::new(),
                    value,
                },
            );
            Ok(wrap(&ext[..shared], branch))
        }
        Node::Branch {
            mut children,
            value: own,
        } => match path.split_first() {
            // The key ends at this branch, so the branch's own value slot is
            // what it names. Unreachable in a secure trie, where every key is
            // 64 nibbles and no key is a prefix of another, but the small
            // tries this module's tests use do reach it.
            None => {
                let _ = own;
                Ok(Node::Branch { children, value })
            }
            Some((nibble, rest)) => {
                let slot = core::mem::replace(&mut children[*nibble as usize], Node::Empty);
                children[*nibble as usize] = insert(slot, rest, value)?;
                Ok(Node::Branch {
                    children,
                    value: own,
                })
            }
        },
    }
}

/// Put `leaf` — which carries an empty path — into `branch` at `rest`.
///
/// An empty `rest` means the key ends here, so the value belongs in the
/// branch's own slot; otherwise the first nibble picks a child and the rest is
/// the leaf's path.
fn place(branch: &mut Node, rest: &[u8], leaf: Node) {
    let Node::Branch { children, value } = branch else {
        panic!("place is called on a branch");
    };
    let Node::Leaf { value: v, .. } = leaf else {
        panic!("place is called with a leaf");
    };
    match rest.split_first() {
        None => *value = v,
        Some((nibble, tail)) => {
            children[*nibble as usize] = Node::Leaf {
                path: tail.to_vec(),
                value: v,
            }
        }
    }
}

fn set_child(branch: &mut Node, nibble: u8, node: Node) {
    let Node::Branch { children, .. } = branch else {
        panic!("set_child is called on a branch");
    };
    children[nibble as usize] = node;
}

/// An extension above `node`, or `node` itself when the prefix is empty.
fn wrap(prefix: &[u8], node: Node) -> Node {
    if prefix.is_empty() {
        node
    } else {
        Node::Ext {
            path: prefix.to_vec(),
            child: Box::new(node),
        }
    }
}

/// Remove `path`, collapsing whatever the removal leaves behind.
pub fn remove(node: Node, path: &[u8]) -> Result<Node, MptError> {
    match node {
        Node::Blinded(hash) => Err(MptError::MissingNode { hash }),
        Node::Empty => Ok(Node::Empty),
        Node::Leaf { path: leaf, value } => {
            if leaf.as_slice() == path {
                Ok(Node::Empty)
            } else {
                Ok(Node::Leaf { path: leaf, value })
            }
        }
        Node::Ext { path: ext, child } => {
            if path.len() < ext.len() || &path[..ext.len()] != ext.as_slice() {
                return Ok(Node::Ext { path: ext, child });
            }
            let below = remove(*child, &path[ext.len()..])?;
            normalize_ext(ext, below)
        }
        Node::Branch {
            mut children,
            value,
        } => match path.split_first() {
            None => normalize_branch(children, Vec::new()),
            Some((nibble, rest)) => {
                let slot = core::mem::replace(&mut children[*nibble as usize], Node::Empty);
                children[*nibble as usize] = remove(slot, rest)?;
                normalize_branch(children, value)
            }
        },
    }
}

/// An extension over whatever its child became.
fn normalize_ext(path: Vec<u8>, child: Node) -> Result<Node, MptError> {
    Ok(match child {
        Node::Empty => Node::Empty,
        Node::Leaf { path: below, value } => Node::Leaf {
            path: [path, below].concat(),
            value,
        },
        Node::Ext {
            path: below,
            child: under,
        } => Node::Ext {
            path: [path, below].concat(),
            child: under,
        },
        other => Node::Ext {
            path,
            child: Box::new(other),
        },
    })
}

/// A branch, after one of its children changed.
///
/// A branch with one live child and no value **must disappear**: the trie has
/// exactly one shape per contents, and leaving it standing gives a different
/// root. Collapsing into a child the witness carries only as a hash is
/// impossible — the child's type and path are what the collapse needs — and
/// that is [`MptError::BlindedCollapse`], named rather than guessed at.
fn normalize_branch(children: Box<[Node; 16]>, value: Vec<u8>) -> Result<Node, MptError> {
    let live: Vec<usize> = (0..16).filter(|i| !children[*i].is_empty()).collect();
    match (live.len(), value.is_empty()) {
        (0, true) => Ok(Node::Empty),
        (0, false) => Ok(Node::Leaf {
            path: Vec::new(),
            value,
        }),
        (1, true) => {
            let at = live[0];
            let mut children = children;
            let only = core::mem::replace(&mut children[at], Node::Empty);
            let nibble = at as u8;
            Ok(match only {
                Node::Leaf { path, value } => Node::Leaf {
                    path: [vec![nibble], path].concat(),
                    value,
                },
                Node::Ext { path, child } => Node::Ext {
                    path: [vec![nibble], path].concat(),
                    child,
                },
                Node::Blinded(hash) => return Err(MptError::BlindedCollapse { hash }),
                other => Node::Ext {
                    path: vec![nibble],
                    child: Box::new(other),
                },
            })
        }
        _ => Ok(Node::Branch { children, value }),
    }
}

// ---------------------------------------------------------------------------
// The two tries Ethereum keeps
// ---------------------------------------------------------------------------

/// An account, as the state trie stores it: `[nonce, balance, storage_root,
/// code_hash]`.
///
/// **Not revm's field order.** `AccountInfo` declares balance before nonce; the
/// trie list is nonce first. Transcribing the struct order gives a leaf that
/// still decodes and a root that is wrong.
pub fn encode_account(
    nonce: u64,
    balance: &Word32,
    storage_root: &Word32,
    code_hash: &Word32,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(80);
    encode_uint(&mut payload, &nonce.to_be_bytes());
    encode_uint(&mut payload, balance);
    encode_bytes(&mut payload, storage_root);
    encode_bytes(&mut payload, code_hash);
    let mut out = Vec::with_capacity(payload.len() + 3);
    encode_list(&mut out, &payload);
    out
}

/// A storage slot's trie value: the RLP of its **minimal big-endian** integer.
///
/// The leaf then encodes this as a byte string, so the bytes in the node are
/// doubly wrapped. A zero never reaches here — it is a deletion.
pub fn encode_slot(value: &Word32) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    encode_uint(&mut out, value);
    out
}

/// The four fields of an account leaf's value.
pub fn decode_account(bytes: &[u8]) -> Result<(u64, Word32, Word32, Word32), MptError> {
    let items = list_items(bytes)?;
    if items.len() != 4 {
        return Err(MptError::Malformed);
    }
    Ok((
        uint_of(&items[0])?,
        word_of(&items[1])?,
        fixed_of(&items[2])?,
        fixed_of(&items[3])?,
    ))
}

fn uint_of(item: &Item<'_>) -> Result<u64, MptError> {
    if item.list || item.payload.len() > 8 {
        return Err(MptError::Malformed);
    }
    if item.payload.first() == Some(&0) {
        return Err(MptError::Malformed);
    }
    let mut value = 0u64;
    for byte in item.payload {
        value = (value << 8) | *byte as u64;
    }
    Ok(value)
}

/// A minimal big-endian integer, left-padded to 32 bytes.
fn word_of(item: &Item<'_>) -> Result<Word32, MptError> {
    if item.list || item.payload.len() > 32 {
        return Err(MptError::Malformed);
    }
    if item.payload.first() == Some(&0) {
        return Err(MptError::Malformed);
    }
    let mut out = [0u8; 32];
    out[32 - item.payload.len()..].copy_from_slice(item.payload);
    Ok(out)
}

/// An exactly-32-byte field.
fn fixed_of(item: &Item<'_>) -> Result<Word32, MptError> {
    if item.list || item.payload.len() != 32 {
        return Err(MptError::Malformed);
    }
    Ok(item.payload.try_into().expect("thirty-two bytes"))
}

/// The value a storage leaf holds, as a 32-byte word.
pub fn decode_slot(bytes: &[u8]) -> Result<Word32, MptError> {
    let (item, rest) = split(bytes)?;
    if !rest.is_empty() {
        return Err(MptError::Malformed);
    }
    word_of(&item)
}
