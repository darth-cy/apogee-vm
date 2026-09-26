//! The synthetic **stateless** block: the fixture S25's acceptance 7 runs on.
//!
//! Part of the `revm` group, so a regeneration is itself the differential — the
//! same arrangement `src/revm.rs` has for the mini mode.
//!
//! # Why this block is synthetic, and what that costs
//!
//! Acceptance 7 asks for the *pinned full block*'s recomputed root against its
//! header's. That needs a **complete** stateless witness, and `eth_getProof`
//! cannot produce one: a block that deletes a key — which writing zero to a
//! storage slot is — collapses a branch into a **sibling** that appears in no
//! key's proof, and the endpoint serves neither `debug_executionWitness` nor
//! node-by-hash lookups. `docs/handoff/S25-block.md` §4 is the measurement.
//!
//! So the witness here is built rather than recorded, which makes its node set
//! complete by construction. What that costs is the *external* oracle: a
//! synthetic block's post-state root is not a number Ethereum published. The
//! trie code's external checks are elsewhere and there are two —
//! `crates/host/tests/mpt.rs`'s three published root vectors, and
//! `crates/host/tests/stateless.rs`'s authentication of the pinned mini-block's
//! seventeen real accounts against the **real** parent state root. What this
//! fixture adds is the whole transition end to end, and acceptance 7's two
//! negative controls.

use revm_block::mpt::{self, Node, EMPTY_TRIE_ROOT};
use revm_block::stateless::StatelessError;
use revm_block::{
    AccountWitness, Address20, BlockWitness, StatelessWitness, WithdrawalWitness, Word32,
};

/// The withdrawals this block credits: two, so that ordering is exercised, and
/// one of them to an address the transactions never touch — which is the case
/// that inserts a *new* account into the state trie after the last transaction.
const WITHDRAWALS: [(u64, u64, u8, u64); 2] = [
    // (index, validator, address label, amount in gwei)
    (11, 700, 0x51, 32_000_000_000),
    (12, 701, 0x52, 1_000_000_000),
];

/// EIP-4788's beacon-roots contract, and its **real deployed bytecode**.
///
/// Both system contracts have to be in the witness with their code, and the
/// strict database is what says so: S24's lax one would have let the call hit
/// an empty account, succeed, change nothing and give a wrong state root, which
/// is exactly the failure `docs/spec/revm-block.md` §1.0 exists to prevent. The
/// first run of this generator failed with *"the 4788 system call: the witness
/// carries no such account"*, which is the behaviour that was wanted.
const BEACON_ROOTS: Address20 = [
    0x00, 0x0f, 0x3d, 0xf6, 0xd7, 0x32, 0x80, 0x7e, 0xf1, 0x31, 0x9f, 0xb7, 0xb8, 0xbb, 0x85, 0x22,
    0xd0, 0xbe, 0xac, 0x02,
];
const BEACON_ROOTS_CODE: &str = "3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff015500";

/// EIP-2935's block-hash history contract, and its real deployed bytecode.
const HISTORY_STORAGE: Address20 = [
    0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb, 0x7a, 0x02, 0x33, 0x5b, 0x17, 0x53,
    0x20, 0x00, 0x29, 0x35,
];
const HISTORY_STORAGE_CODE: &str = "3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500";

/// EIP-4788's and EIP-2935's ring-buffer length, which both contracts take the
/// modulus by.
const RING: u64 = 8191;

/// `0x`-less hex as bytes.
fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// An address of this fixture's own, leading with `0xee` for the reason
/// `docs/spec/revm-block.md` §1.3 gives: every precompile's address is nineteen
/// zero bytes and a label, so a "label in the last byte" scheme picks one.
const fn address(label: u8) -> Address20 {
    let mut out = [0u8; 20];
    out[0] = 0xee;
    out[19] = label;
    out
}

/// A 32-byte word from a small integer.
fn word(value: u128) -> Word32 {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

/// The block, its authenticating nodes, and the post-state root it produces.
///
/// The pre-state is `src/revm.rs`'s synthetic one — one funded sender, an empty
/// recipient, a beneficiary and a counter contract holding a slot — plus the
/// **two withdrawal recipients**, one of which does not exist and so is created
/// by its credit. The transactions are the same transfer and counter call.
pub fn synthetic_stateless() -> (BlockWitness, Word32) {
    let mut witness = crate::revm::synthetic_block();

    // The withdrawal recipients. One exists with a balance; one does not, and
    // is recorded as the all-zero "asked about, and not there" shape — which is
    // what makes the credit an *insertion* into the state trie.
    for (i, (_, _, label, _)) in WITHDRAWALS.iter().enumerate() {
        witness.accounts.push(AccountWitness {
            address: address(*label),
            nonce: 0,
            balance: if i == 0 { word(5_000) } else { [0u8; 32] },
            code: Vec::new(),
            slots: Vec::new(),
        });
    }
    // The two system contracts, with their real code and the slots their set
    // paths touch. An `SSTORE` reads the original value first, so every slot
    // written is also a slot read — and the strict database refuses a slot the
    // witness does not carry, which is what makes these explicit rather than
    // discovered at run time.
    //
    // EIP-4788 writes `timestamp % 8191` and `timestamp % 8191 + 8191`;
    // EIP-2935 writes `(number - 1) % 8191`. Both moduli are computed here
    // rather than written down, so the fixture's own header fields decide them.
    let timestamp = u64::from_be_bytes(witness.env.timestamp[24..].try_into().expect("8 bytes"));
    let number = u64::from_be_bytes(witness.env.number[24..].try_into().expect("8 bytes"));
    witness.accounts.push(AccountWitness {
        address: BEACON_ROOTS,
        nonce: 1,
        balance: [0u8; 32],
        code: unhex(BEACON_ROOTS_CODE),
        slots: {
            let mut slots = vec![
                (word((timestamp % RING) as u128), [0u8; 32]),
                (word((timestamp % RING + RING) as u128), [0u8; 32]),
            ];
            slots.sort_by_key(|(k, _)| *k);
            slots
        },
    });
    witness.accounts.push(AccountWitness {
        address: HISTORY_STORAGE,
        nonce: 1,
        balance: [0u8; 32],
        code: unhex(HISTORY_STORAGE_CODE),
        slots: vec![(word(((number - 1) % RING) as u128), [0u8; 32])],
    });
    witness.accounts.sort_by_key(|a| a.address);

    // Build the pre-state tries and collect every node, so the set is complete
    // by construction — §1.5's requirement, which a recorded witness cannot
    // meet from `eth_getProof` alone.
    let (state, nodes) = pre_state(&witness.accounts);
    let parent_state_root = state.root();

    let mut parent_hash = [0u8; 32];
    parent_hash[0] = 0x9a;
    let mut beacon = [0u8; 32];
    beacon[0] = 0x4b;

    witness.stateless = Some(StatelessWitness {
        parent_state_root,
        parent_hash,
        parent_beacon_block_root: Some(beacon),
        withdrawals: WITHDRAWALS
            .iter()
            .map(
                |(index, validator_index, label, amount_gwei)| WithdrawalWitness {
                    index: *index,
                    validator_index: *validator_index,
                    address: address(*label),
                    amount_gwei: *amount_gwei,
                },
            )
            .collect(),
        nodes,
    });

    // What root does it produce? Ask by claiming one it cannot be: the run
    // reports the root it computed, which is the fixture's answer. Asking this
    // way rather than through a second entry point keeps `run_stateless`'s
    // signature the one the guest uses — the root is compared against something
    // outside the witness, always.
    let post = match revm_block::stateless::run_stateless(&witness, &[0xffu8; 32]) {
        Err(StatelessError::RootMismatch { computed, .. }) => computed,
        Ok(_) => panic!("the all-ones root cannot be this block's"),
        Err(e) => panic!("the synthetic stateless block does not run: {e:?}"),
    };
    (witness, post)
}

/// The pre-state trie over these accounts, and every node of it and of every
/// storage trie beneath it.
fn pre_state(accounts: &[AccountWitness]) -> (Node, Vec<Vec<u8>>) {
    let empty_code_hash = revm_block::keccak(&[]);
    let mut nodes = Vec::new();
    let mut state = Node::Empty;
    for account in accounts {
        // An account recorded as all zeros does not exist, and an account that
        // does not exist has no leaf in the trie.
        if account.nonce == 0 && account.balance == [0u8; 32] && account.code.is_empty() {
            continue;
        }
        let mut storage = Node::Empty;
        for (slot, value) in &account.slots {
            if *value == [0u8; 32] {
                continue;
            }
            let key = revm_block::keccak(slot);
            storage = mpt::insert(storage, &mpt::nibbles(&key), mpt::encode_slot(value))
                .expect("an unblinded insert");
        }
        let storage_root = if storage.is_empty() {
            EMPTY_TRIE_ROOT
        } else {
            all_nodes(&storage, &mut nodes);
            storage.root()
        };
        let code_hash = if account.code.is_empty() {
            empty_code_hash
        } else {
            revm_block::keccak(&account.code)
        };
        let key = revm_block::keccak(&account.address);
        let value = mpt::encode_account(account.nonce, &account.balance, &storage_root, &code_hash);
        state = mpt::insert(state, &mpt::nibbles(&key), value).expect("an unblinded insert");
    }
    all_nodes(&state, &mut nodes);
    nodes.sort_unstable_by_key(|n| revm_block::keccak(n));
    nodes.dedup();
    (state, nodes)
}

/// Every node of a trie, by walking it.
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

/// Write the three fixtures.
pub fn generate() {
    let (witness, post) = synthetic_stateless();
    let encoded = witness.encode();
    assert_eq!(
        BlockWitness::decode(&encoded).as_ref(),
        Ok(&witness),
        "the stateless witness this builder writes is one its decoder accepts"
    );
    crate::write_bytes(
        "crates/emulator/tests/vectors/revm_stateless_witness.bin",
        &encoded,
    );
    let stateless = witness.stateless.as_ref().expect("the stateless section");
    println!(
        "  StatelessWitness: {} accounts, {} trie nodes, {} withdrawals, {} bytes",
        witness.accounts.len(),
        stateless.nodes.len(),
        stateless.withdrawals.len(),
        encoded.len()
    );

    crate::write_bytes(
        "crates/emulator/tests/vectors/revm_stateless_root.bin",
        &post,
    );
    let journal = revm_block::stateless::run_stateless(&witness, &post)
        .expect("the stateless block runs against its own root");
    crate::write_bytes(
        "crates/emulator/tests/vectors/revm_stateless_journal.bin",
        &journal,
    );
    println!(
        "  post-state root {} , journal {} bytes",
        hex(&post),
        journal.len()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
