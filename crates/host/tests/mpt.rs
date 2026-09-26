//! `revm_block::mpt` against Ethereum's own published trie vectors, and
//! against itself.
//!
//! The module is guest code and compiles for the host too, so it can be tested
//! here without a guest build — the `guests/consistency` pattern. What it is
//! held to:
//!
//! - **Three canonical root vectors**, the ones every Ethereum client's test
//!   suite carries. They are the only external oracle available: there is no
//!   trie implementation in this workspace to differential against, and
//!   `alloy-trie` is not a dependency of anything here (nor should it be — S25
//!   says own the MPT).
//! - **Round-trip laws** that need no oracle: a trie built by insertion equals
//!   one built in a different order; deleting a key gives the same root as
//!   never having inserted it; a sparse trie rebuilt from a subset of its own
//!   nodes re-hashes to the same root.
//! - **The refusals**, each one separately: a missing node is not an absence, a
//!   blinded collapse is named rather than guessed, and every canonical-form
//!   rule refuses.
//!
//! The vectors use short ASCII keys rather than 32-byte hashes, which is what
//! makes them worth having: a secure trie's 64-nibble keys never produce a
//! branch with a value, never produce an inlined node, and never produce an
//! extension above a leaf, so a test that only used hashed keys would leave
//! three of the five node shapes unexercised. `dogglesworth` in particular is
//! the vector that exercises inlining.

use revm_block::mpt::{self, MptError, Node, NodeMap, EMPTY_TRIE_ROOT};
use revm_block::Word32;

/// A key's nibbles, for the short ASCII keys the published vectors use.
fn nib(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 * key.len());
    for byte in key {
        out.push(byte >> 4);
        out.push(byte & 0xf);
    }
    out
}

/// A trie built by inserting every pair in order.
fn built(pairs: &[(&[u8], &[u8])]) -> Node {
    let mut node = Node::Empty;
    for (key, value) in pairs {
        node = mpt::insert(node, &nib(key), value.to_vec()).expect("an unblinded insert");
    }
    node
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// The published vectors
// ---------------------------------------------------------------------------

#[test]
fn the_empty_trie_has_the_published_root() {
    assert_eq!(
        hex(&Node::Empty.root()),
        "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    );
    assert_eq!(Node::Empty.root(), EMPTY_TRIE_ROOT);
    // The empty trie's root is keccak of the empty *string*, and an absent
    // branch child is that empty string — two different things that are easy
    // to conflate, so both are pinned.
    assert_eq!(Node::Empty.encode(), vec![0x80]);
}

/// `{doe: reindeer, dog: puppy, dogglesworth: cat}`.
///
/// The vector that exercises **inlining**: `dogglesworth`'s branch carries
/// children whose RLP is under 32 bytes, so they are embedded in their parent
/// rather than referenced by hash.
#[test]
fn the_dogglesworth_vector_matches() {
    let node = built(&[
        (b"doe", b"reindeer"),
        (b"dog", b"puppy"),
        (b"dogglesworth", b"cat"),
    ]);
    assert_eq!(
        hex(&node.root()),
        "8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3"
    );
}

/// `{do: verb, horse: stallion, doge: coin, dog: puppy}`.
///
/// The vector that exercises a **branch with a value**: `do` is a prefix of
/// `dog`, so the branch at the end of `do`'s path holds `verb` in its own slot.
#[test]
fn the_horse_vector_matches() {
    let node = built(&[
        (b"do", b"verb"),
        (b"horse", b"stallion"),
        (b"doge", b"coin"),
        (b"dog", b"puppy"),
    ]);
    assert_eq!(
        hex(&node.root()),
        "5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84"
    );
}

// ---------------------------------------------------------------------------
// Laws that need no oracle
// ---------------------------------------------------------------------------

/// Insertion order does not change the root.
///
/// The trie has one shape per contents, so this is the property every
/// divergence case — a leaf that splits, a key that diverges inside an
/// extension — has to preserve. Every permutation of four keys, which is the
/// cheap exhaustive version of a property test.
#[test]
fn insertion_order_does_not_move_the_root() {
    let pairs: [(&[u8], &[u8]); 4] = [
        (b"do", b"verb"),
        (b"horse", b"stallion"),
        (b"doge", b"coin"),
        (b"dog", b"puppy"),
    ];
    let want = built(&pairs).root();
    let mut checked = 0;
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let order = [a, b, c, d];
                    let mut seen = [false; 4];
                    for i in order {
                        seen[i] = true;
                    }
                    if !seen.iter().all(|s| *s) {
                        continue;
                    }
                    let permuted: Vec<(&[u8], &[u8])> = order.iter().map(|i| pairs[*i]).collect();
                    assert_eq!(built(&permuted).root(), want, "order {order:?}");
                    checked += 1;
                }
            }
        }
    }
    assert_eq!(checked, 24, "every permutation of four keys");
}

/// Deleting a key gives the same root as never having inserted it.
///
/// This is the whole of the collapse logic, checked against a from-scratch
/// rebuild rather than against a hand-written expectation: a branch left with
/// one child must disappear, and an extension above it must merge, or the two
/// roots differ.
#[test]
fn deleting_a_key_equals_never_inserting_it() {
    let pairs: [(&[u8], &[u8]); 6] = [
        (b"do", b"verb"),
        (b"dog", b"puppy"),
        (b"doge", b"coin"),
        (b"dogglesworth", b"cat"),
        (b"horse", b"stallion"),
        (b"house", b"brick"),
    ];
    for drop in 0..pairs.len() {
        let survivors: Vec<(&[u8], &[u8])> = pairs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != drop)
            .map(|(_, p)| *p)
            .collect();
        let rebuilt = built(&survivors).root();
        let deleted = mpt::remove(built(&pairs), &nib(pairs[drop].0))
            .expect("an unblinded delete")
            .root();
        assert_eq!(
            deleted,
            rebuilt,
            "deleting {:?} does not give the rebuilt root",
            core::str::from_utf8(pairs[drop].0).unwrap()
        );
    }
}

/// Deleting every key in turn empties the trie.
#[test]
fn deleting_everything_gives_the_empty_root() {
    let pairs: [(&[u8], &[u8]); 4] = [
        (b"do", b"verb"),
        (b"dog", b"puppy"),
        (b"doge", b"coin"),
        (b"horse", b"stallion"),
    ];
    let mut node = built(&pairs);
    for (key, _) in pairs {
        node = mpt::remove(node, &nib(key)).expect("an unblinded delete");
    }
    assert_eq!(node.root(), EMPTY_TRIE_ROOT);
    assert!(node.is_empty());
}

/// Every key reads back what was written, and nothing else does.
#[test]
fn every_key_reads_back() {
    let pairs: [(&[u8], &[u8]); 4] = [
        (b"do", b"verb"),
        (b"dog", b"puppy"),
        (b"doge", b"coin"),
        (b"horse", b"stallion"),
    ];
    let node = built(&pairs);
    for (key, value) in pairs {
        assert_eq!(
            mpt::get(&node, &nib(key)).expect("an unblinded read"),
            Some(value.to_vec()),
            "{:?}",
            core::str::from_utf8(key).unwrap()
        );
    }
    for absent in [b"d".as_slice(), b"dogs", b"cat", b"hors", b"horses", b""] {
        assert_eq!(
            mpt::get(&node, &nib(absent)).expect("an unblinded read"),
            None,
            "{:?} is not in the trie",
            core::str::from_utf8(absent).unwrap()
        );
    }
}

// ---------------------------------------------------------------------------
// Sparse rebuilding — the half that authenticates
// ---------------------------------------------------------------------------

/// Every node of a trie, by walking it. The stand-in for `eth_getProof`'s
/// arrays in a test that has the whole trie to hand.
fn all_nodes(node: &Node, out: &mut Vec<Vec<u8>>) {
    match node {
        Node::Empty | Node::Blinded(_) => {}
        Node::Leaf { .. } => out.push(node.encode()),
        Node::Ext { child, .. } => {
            out.push(node.encode());
            all_nodes(child, out);
        }
        Node::Branch { children, .. } => {
            out.push(node.encode());
            for child in children.iter() {
                all_nodes(child, out);
            }
        }
    }
}

/// A trie rebuilt from its own nodes is the same trie.
#[test]
fn a_sparse_rebuild_round_trips() {
    let node = built(&[
        (b"do", b"verb"),
        (b"dog", b"puppy"),
        (b"doge", b"coin"),
        (b"dogglesworth", b"cat"),
        (b"horse", b"stallion"),
    ]);
    let root = node.root();
    let mut nodes = Vec::new();
    all_nodes(&node, &mut nodes);
    let db = NodeMap::new(&nodes);
    let rebuilt = mpt::build(&db, &root).expect("the root is present");
    mpt::check_root(&rebuilt, &root).expect("the rebuild re-hashes to its root");
    assert_eq!(rebuilt, node, "the rebuilt trie is not the original");
}

/// A trie rebuilt from **some** of its nodes still re-hashes to its root, with
/// the rest standing in as hashes.
///
/// This is what makes a sparse trie worth having, and the assertion is the one
/// worth making early: a blinded subtree re-encodes to its own hash verbatim,
/// so an untouched part of the trie round-trips for free and any parse or
/// encode bug shows up here rather than as a wrong root after every update.
#[test]
fn a_partial_rebuild_still_hashes_to_the_root() {
    let node = built(&[
        (b"do", b"verb"),
        (b"dog", b"puppy"),
        (b"doge", b"coin"),
        (b"horse", b"stallion"),
        (b"house", b"brick"),
    ]);
    let root = node.root();
    let mut nodes = Vec::new();
    all_nodes(&node, &mut nodes);
    assert!(nodes.len() > 2, "the trie has interior nodes to drop");
    // Every prefix of the node list: the root alone, the root plus one, and so
    // on. Each must re-hash to the same root.
    for keep in 1..=nodes.len() {
        let db = NodeMap::new(&nodes[..keep]);
        let rebuilt = mpt::build(&db, &root).expect("the root is present");
        mpt::check_root(&rebuilt, &root).unwrap_or_else(|e| {
            panic!(
                "a rebuild from {keep} of {} nodes does not re-hash: {e:?}",
                nodes.len()
            )
        });
    }
}

// ---------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------

/// **A missing node is an invalid witness, never an absence.**
///
/// The single most important line in the module: if a truncated witness read as
/// "this key is absent", anyone could prove any key absent by truncating.
#[test]
fn a_missing_node_is_not_an_absence() {
    let node = built(&[
        (b"do", b"verb"),
        (b"dog", b"puppy"),
        (b"doge", b"coin"),
        (b"horse", b"stallion"),
    ]);
    let root = node.root();
    let mut nodes = Vec::new();
    all_nodes(&node, &mut nodes);
    // The root alone: every subtree below it is blinded.
    let db = NodeMap::new(&nodes[..1]);
    let sparse = mpt::build(&db, &root).expect("the root is present");
    let mut blinded = 0;
    for (key, _) in [
        (b"do".as_slice(), ()),
        (b"dog", ()),
        (b"doge", ()),
        (b"horse", ()),
    ] {
        match mpt::get(&sparse, &nib(key)) {
            Err(MptError::MissingNode { .. }) => blinded += 1,
            Ok(Some(_)) => {}
            Ok(None) => panic!(
                "{:?} read as absent from a truncated witness",
                core::str::from_utf8(key).unwrap()
            ),
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert!(blinded > 0, "the truncated witness blinded nothing");
}

/// A root the witness does not carry is named, not guessed.
#[test]
fn a_missing_root_is_named() {
    let db = NodeMap::new(&[]);
    let mut root = [0u8; 32];
    root[0] = 1;
    assert_eq!(
        mpt::build(&db, &root),
        Err(MptError::MissingNode { hash: root })
    );
    // Except the empty root, which needs no node.
    assert_eq!(mpt::build(&db, &EMPTY_TRIE_ROOT), Ok(Node::Empty));
}

/// A deletion that would collapse a branch into a blinded child is refused by
/// name.
///
/// This is the case `eth_getProof` cannot supply: the surviving child is a
/// *sibling* of the deleted key, so it is not on that key's path and not in its
/// proof. The guest cannot derive it and must not guess; the witness builder
/// has to add it. The error carries the hash so that it can.
///
/// **The keys are 32 bytes and the values are too**, which is not decoration.
/// A short key gives leaves whose RLP is under 32 bytes, and those are
/// *inlined* in their parent rather than hash-referenced — so there is no
/// separate sibling node to be missing, and the case cannot arise. That is the
/// inlining rule doing its job, and it is why the first draft of this test
/// passed for the wrong reason. A secure trie's keys are always 32 bytes, so
/// this shape is the realistic one.
#[test]
fn a_blinded_collapse_is_refused_by_name() {
    // Two keys differing in their last nibble: the branch that separates them
    // sits at depth 63, and each child is a leaf with an empty path and a
    // 32-byte value — 35 bytes of RLP, so hash-referenced.
    let mut one = [0x11u8; 32];
    let mut two = [0x11u8; 32];
    one[31] = 0x10;
    two[31] = 0x12;
    let value_one = [0xaau8; 32];
    let value_two = [0xbbu8; 32];

    let mut node = Node::Empty;
    node = mpt::insert(node, &mpt::nibbles(&one), value_one.to_vec()).expect("a leaf");
    node = mpt::insert(node, &mpt::nibbles(&two), value_two.to_vec()).expect("a leaf");
    let root = node.root();

    let mut nodes = Vec::new();
    all_nodes(&node, &mut nodes);
    // The surviving sibling really is its own node, or this test proves nothing.
    let survivor = nodes
        .iter()
        .find(|n| n.ends_with(&value_two))
        .expect("the sibling leaf is a node of its own, not inlined")
        .clone();
    assert!(
        survivor.len() >= 32,
        "a leaf under 32 bytes would be inlined and there would be no sibling to miss"
    );

    // With every node, the delete succeeds and collapses.
    let whole = NodeMap::new(&nodes);
    let full = mpt::build(&whole, &root).expect("the root is present");
    let deleted = mpt::remove(full, &mpt::nibbles(&one)).expect("an unblinded delete");
    let rebuilt = mpt::insert(Node::Empty, &mpt::nibbles(&two), value_two.to_vec())
        .expect("a leaf")
        .root();
    assert_eq!(deleted.root(), rebuilt, "the collapse did not merge");

    // Drop the sibling and the same delete is refused by name.
    let without: Vec<Vec<u8>> = nodes.iter().filter(|n| **n != survivor).cloned().collect();
    assert_eq!(
        without.len(),
        nodes.len() - 1,
        "exactly the sibling was dropped"
    );
    let sparse = mpt::build(&NodeMap::new(&without), &root).expect("the root is present");
    mpt::check_root(&sparse, &root).expect("a blinded sibling still re-hashes");
    match mpt::remove(sparse, &mpt::nibbles(&one)) {
        Err(MptError::BlindedCollapse { hash }) => {
            assert_eq!(
                hash,
                revm_block::keccak(&survivor),
                "the error names a hash that is not the missing sibling's"
            );
        }
        Ok(_) => panic!("a collapse into a blinded sibling was performed rather than refused"),
        Err(e) => panic!("unexpected {e:?}"),
    }
}

/// Every canonical-form rule refuses.
#[test]
fn non_canonical_rlp_is_refused() {
    let leaf = mpt::insert(Node::Empty, &nib(b"dog"), b"puppy".to_vec())
        .expect("a leaf")
        .encode();
    let root = revm_block::keccak(&leaf);
    // The honest node parses.
    assert!(mpt::build(&NodeMap::new(std::slice::from_ref(&leaf)), &root).is_ok());

    // A node whose bytes are anything else does not hash to `root`, so a
    // malformed node cannot be *substituted* — what these check is that the
    // parser refuses rather than accepting something it should not, which is
    // what keeps the guest's own re-encoding canonical.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("trailing bytes", [leaf.clone(), vec![0]].concat()),
        ("a truncated node", leaf[..leaf.len() - 1].to_vec()),
        ("nothing at all", Vec::new()),
        ("a bare string", vec![0x83, b'd', b'o', b'g']),
        ("a one-item list", vec![0xc1, 0x80]),
        ("a three-item list", vec![0xc3, 0x80, 0x80, 0x80]),
        // A 2-item list whose first item has a leading nibble above 3.
        ("a bad hex prefix", vec![0xc4, 0x82, 0x40, 0x12, 0x80]),
        // A 2-item list whose even-length path has a nonzero padding nibble.
        ("a padded even path", vec![0xc4, 0x82, 0x21, 0x12, 0x80]),
    ];
    for (what, bytes) in cases {
        let hash = revm_block::keccak(&bytes);
        assert!(
            mpt::build(&NodeMap::new(std::slice::from_ref(&bytes)), &hash).is_err(),
            "{what} was accepted as a node"
        );
    }
}

// ---------------------------------------------------------------------------
// The two tries Ethereum keeps
// ---------------------------------------------------------------------------

/// An account leaf's value, field by field, against the published shape.
#[test]
fn an_account_encodes_as_the_yellow_paper_says() {
    let empty_code: Word32 = revm_block::keccak(&[]);
    // nonce 0, balance 0, no storage, no code — 70 bytes, and the field order
    // is nonce first, which is NOT revm's struct order.
    let bytes = mpt::encode_account(0, &[0u8; 32], &EMPTY_TRIE_ROOT, &empty_code);
    assert_eq!(bytes.len(), 70);
    assert_eq!(&bytes[..3], &[0xf8, 0x44, 0x80]);
    assert_eq!(
        bytes[3], 0x80,
        "a zero balance is the empty string, not 0x00"
    );
    let (nonce, balance, storage, code) = mpt::decode_account(&bytes).expect("it decodes");
    assert_eq!(
        (nonce, balance, storage, code),
        (0, [0u8; 32], EMPTY_TRIE_ROOT, empty_code)
    );

    // nonce 1, balance 1e18 — 78 bytes.
    let mut balance = [0u8; 32];
    balance[24..].copy_from_slice(&1_000_000_000_000_000_000u64.to_be_bytes());
    let bytes = mpt::encode_account(1, &balance, &EMPTY_TRIE_ROOT, &empty_code);
    assert_eq!(bytes.len(), 78);
    assert_eq!(&bytes[..4], &[0xf8, 0x4c, 0x01, 0x88]);
    let (n, b, s, c) = mpt::decode_account(&bytes).expect("it decodes");
    assert_eq!((n, b, s, c), (1, balance, EMPTY_TRIE_ROOT, empty_code));
}

/// A storage value is a **minimal** big-endian integer, and the leaf wraps it
/// again.
#[test]
fn a_storage_value_is_minimal_and_doubly_wrapped() {
    let word = |low: &[u8]| -> Word32 {
        let mut out = [0u8; 32];
        out[32 - low.len()..].copy_from_slice(low);
        out
    };
    // (value, the trie value, the leaf's second item)
    let cases: Vec<(Word32, Vec<u8>, Vec<u8>)> = vec![
        (word(&[0x01]), vec![0x01], vec![0x01]),
        (word(&[0x7f]), vec![0x7f], vec![0x7f]),
        (word(&[0x80]), vec![0x81, 0x80], vec![0x82, 0x81, 0x80]),
        (word(&[0xff]), vec![0x81, 0xff], vec![0x82, 0x81, 0xff]),
        (
            word(&[0x01, 0x00]),
            vec![0x82, 0x01, 0x00],
            vec![0x83, 0x82, 0x01, 0x00],
        ),
    ];
    for (value, trie_value, wrapped) in cases {
        let encoded = mpt::encode_slot(&value);
        assert_eq!(encoded, trie_value, "the trie value for {}", hex(&value));
        let mut leaf_item = Vec::new();
        mpt::encode_bytes(&mut leaf_item, &encoded);
        assert_eq!(
            leaf_item,
            wrapped,
            "the leaf's second item for {}",
            hex(&value)
        );
        assert_eq!(mpt::decode_slot(&encoded).expect("it decodes"), value);
    }
}

/// One slot in one storage trie, against a computed root.
///
/// The worked example from the specification research: slot 0 holding 1.
#[test]
fn a_single_slot_storage_trie_has_the_computed_root() {
    let key = revm_block::keccak(&[0u8; 32]);
    assert_eq!(
        hex(&key),
        "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
    );
    let mut value = [0u8; 32];
    value[31] = 1;
    let node =
        mpt::insert(Node::Empty, &mpt::nibbles(&key), mpt::encode_slot(&value)).expect("a leaf");
    assert_eq!(node.encode().len(), 36);
    assert_eq!(
        hex(&node.root()),
        "821e2556a290c86405f8160a2d662042a431ba456b9db265c79bb837c04be5f0"
    );
}
