//! S25's **stateless mode**: acceptance 7, and the authentication that carries
//! it.
//!
//! Acceptance 7 is three claims — *"for the pinned full block, the
//! guest-recomputed post-state root equals the header's state root. Corrupting
//! one MPT witness node makes the guest reject, which is the authentication
//! negative control. Corrupting one account balance in the witness flips the
//! recomputed root and the guest asserts out."* — and this file holds all three,
//! over two fixtures rather than one. §4 of `docs/handoff/S25-block.md` says why
//! there are two, and the short version is here:
//!
//! | half | fixture | oracle |
//! | --- | --- | --- |
//! | authentication | the pinned mini-block's real `eth_getProof` nodes | **the real mainnet state root** |
//! | the transition | a synthetic stateless block | its own pinned root, regenerated and diffed in CI |
//!
//! **A recorded witness cannot carry a complete node set.** `eth_getProof`
//! returns the nodes on each key's own path; a block that deletes a key — which
//! writing zero to a storage slot is — collapses a branch into a **sibling**
//! that is on no touched key's path, and the endpoint serves neither
//! `debug_executionWitness` nor lookups by node hash. So the *transition* runs
//! on a block whose nodes are complete by construction, and the *reading* is
//! checked against the chain, where a real state root is the oracle. The two
//! together are what the trie code is held to, beside
//! `crates/host/tests/mpt.rs`'s three published root vectors.

mod common;

use std::path::PathBuf;

use revm_block::mpt::{self, MptError, NodeMap};
use revm_block::stateless::{self, StatelessError};
use revm_block::{BlockWitness, StatelessWitness, Word32};

fn vectors(crate_dir: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(crate_dir)
        .join(name)
}

fn read(crate_dir: &str, name: &str) -> Vec<u8> {
    let path = vectors(crate_dir, name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The mini-block's own fixtures live beside this crate's tests.
fn mine(name: &str) -> Vec<u8> {
    read("tests/vectors", name)
}

/// The synthetic stateless fixtures live with the emulator's, beside the other
/// `revm` group vectors.
fn theirs(name: &str) -> Vec<u8> {
    read("../emulator/tests/vectors", name)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Authentication, against the real chain
// ---------------------------------------------------------------------------

/// The pinned mini-block's real `eth_getProof` nodes, and the real state root
/// they authenticate against.
fn recorded() -> (BlockWitness, StatelessWitness) {
    let witness = BlockWitness::decode(&mine("mini-block-witness.bin")).expect("the witness");
    let nodes: StatelessWitness =
        postcard::from_bytes(&mine("mini-block-nodes.bin")).expect("the node set");
    (witness, nodes)
}

/// **Must-be-exact 3**: every account, slot and code the guest reads is
/// verified against the parent state root before use.
///
/// Real mainnet data and a real state root, which makes this the external check
/// on the trie code that a synthetic fixture cannot be: the nodes came off the
/// chain, the root is block 26,057,508's, and nothing in this repository
/// computed either.
#[test]
fn a7_every_recorded_value_authenticates_against_the_real_state_root() {
    let (witness, nodes) = recorded();
    let db = NodeMap::new(&nodes.nodes);
    let state = mpt::build(&db, &nodes.parent_state_root).expect("the state root is present");
    mpt::check_root(&state, &nodes.parent_state_root)
        .expect("the sparse state trie re-hashes to the real parent state root");

    let empty_code_hash = revm_block::keccak(&[]);
    let mut accounts = 0;
    let mut slots = 0;
    for account in &witness.accounts {
        let key = revm_block::keccak(&account.address);
        let leaf = mpt::get(&state, &mpt::nibbles(&key)).expect("an authenticated walk");
        let code_hash = if account.code.is_empty() {
            empty_code_hash
        } else {
            revm_block::keccak(&account.code)
        };
        let storage_root = match leaf {
            None => {
                // The trie proves it absent, so the witness must record it as
                // the all-zero shape.
                assert_eq!(account.nonce, 0, "{}", hex(&account.address));
                assert_eq!(account.balance, [0u8; 32], "{}", hex(&account.address));
                assert!(account.code.is_empty(), "{}", hex(&account.address));
                continue;
            }
            Some(bytes) => {
                let (nonce, balance, storage_root, trie_code_hash) =
                    mpt::decode_account(&bytes).expect("an account leaf");
                assert_eq!(nonce, account.nonce, "nonce of {}", hex(&account.address));
                assert_eq!(
                    balance,
                    account.balance,
                    "balance of {}",
                    hex(&account.address)
                );
                assert_eq!(
                    trie_code_hash,
                    code_hash,
                    "code hash of {}",
                    hex(&account.address)
                );
                accounts += 1;
                storage_root
            }
        };
        // Only where there is something to authenticate: an account whose
        // slots nobody read has no storage nodes in its proof, and asking for
        // them would be asking for what nothing needs.
        if account.slots.is_empty() {
            continue;
        }
        let trie = mpt::build(&db, &storage_root).expect("the storage root is present");
        mpt::check_root(&trie, &storage_root).expect("the storage trie re-hashes");
        for (slot, value) in &account.slots {
            let key = revm_block::keccak(slot);
            let found = match mpt::get(&trie, &mpt::nibbles(&key)).expect("an authenticated walk") {
                None => [0u8; 32],
                Some(bytes) => mpt::decode_slot(&bytes).expect("a storage leaf"),
            };
            assert_eq!(
                found,
                *value,
                "slot {} of {}",
                hex(slot),
                hex(&account.address)
            );
            slots += 1;
        }
    }
    assert!(accounts >= 3, "only {accounts} accounts authenticated");
    assert!(slots >= 10, "only {slots} slots authenticated");
    println!(
        "a7: {accounts} real accounts and {slots} real slots authenticated against {}",
        hex(&nodes.parent_state_root)
    );
}

/// Corrupting one node makes the authentication fail — **every** node, swept.
///
/// A corrupted node no longer hashes to what its parent names, so the walk that
/// would have reached it finds nothing under that hash. The refusal is
/// `MissingNode`, and that is the point: it is not an absence.
#[test]
fn a7_a_corrupted_node_is_refused() {
    let (witness, nodes) = recorded();
    let mut refused = 0;
    for at in 0..nodes.nodes.len() {
        let mut damaged = nodes.nodes.clone();
        let last = damaged[at].len() - 1;
        damaged[at][last] ^= 1;
        if reads_cleanly(&witness, &damaged, &nodes.parent_state_root).is_err() {
            refused += 1;
        }
    }
    assert_eq!(
        refused,
        nodes.nodes.len(),
        "{} of {} corrupted nodes went unnoticed",
        nodes.nodes.len() - refused,
        nodes.nodes.len()
    );
}

/// Deleting one node is refused too, and **as a missing node rather than as an
/// absence**.
///
/// The single most important line in the trie: if a truncated witness read as
/// "this key is absent", anyone could prove any key absent by truncating. Here
/// it is at the level of a real proof, not a hand-built trie.
#[test]
fn a7_a_deleted_node_is_a_missing_node_and_not_an_absence() {
    let (witness, nodes) = recorded();
    let mut missing = 0;
    for at in 0..nodes.nodes.len() {
        let mut short = nodes.nodes.clone();
        short.remove(at);
        match reads_cleanly(&witness, &short, &nodes.parent_state_root) {
            Err(MptError::MissingNode { .. }) | Err(MptError::RootMismatch) => missing += 1,
            Err(e) => panic!("node {at} was refused as {e:?} rather than as missing"),
            Ok(()) => {
                // A node no walk reaches can be dropped without anything
                // noticing — which is correct, and is why the count is checked
                // rather than every case being required to fail.
            }
        }
    }
    assert!(
        missing > 0,
        "dropping a node the walk needs was not noticed at all"
    );
    println!(
        "a7: {missing} of {} dropped nodes refused",
        nodes.nodes.len()
    );
}

/// Read every recorded value through a node set, reporting the first refusal.
fn reads_cleanly(witness: &BlockWitness, nodes: &[Vec<u8>], root: &Word32) -> Result<(), MptError> {
    let db = NodeMap::new(nodes);
    let state = mpt::build(&db, root)?;
    mpt::check_root(&state, root)?;
    for account in &witness.accounts {
        let key = revm_block::keccak(&account.address);
        let Some(bytes) = mpt::get(&state, &mpt::nibbles(&key))? else {
            continue;
        };
        let (_, _, storage_root, _) = mpt::decode_account(&bytes)?;
        if account.slots.is_empty() {
            continue;
        }
        let trie = mpt::build(&db, &storage_root)?;
        mpt::check_root(&trie, &storage_root)?;
        for (slot, _) in &account.slots {
            let key = revm_block::keccak(slot);
            mpt::get(&trie, &mpt::nibbles(&key))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The transition, over the synthetic stateless block
// ---------------------------------------------------------------------------

fn synthetic() -> (BlockWitness, Word32, Vec<u8>) {
    let witness = BlockWitness::decode(&theirs("revm_stateless_witness.bin")).expect("the witness");
    let root: Word32 = theirs("revm_stateless_root.bin")
        .try_into()
        .expect("a 32-byte root");
    (witness, root, theirs("revm_stateless_journal.bin"))
}

/// The recomputed post-state root is the pinned one, and the journal is the
/// pinned one.
///
/// Acceptance 7's positive claim, on the host. The guest half —
/// `a7_the_guest_recomputes_the_same_root` — is the same claim through the
/// emulator, and is `#[ignore]`d because it builds the guest.
#[test]
fn a7_the_transition_recomputes_the_pinned_root() {
    let (witness, root, journal) = synthetic();
    let produced = stateless::run_stateless(&witness, &root)
        .expect("the synthetic stateless block reaches its pinned root");
    assert_eq!(produced, journal, "the journal is not the pinned one");
    assert_eq!(
        produced.len(),
        stateless::STATELESS_JOURNAL_BYTES,
        "the stateless journal is a fixed size whatever the block"
    );
    // The journal names both roots, which is what makes it worth reading: a
    // verifier learns "from P this block produced Q" rather than just "Q".
    let stateless_section = witness.stateless.as_ref().expect("the stateless section");
    assert_eq!(&produced[..32], &stateless_section.parent_state_root[..]);
    assert_eq!(&produced[32..64], &root[..]);
}

/// A root the block does not produce is refused, naming what it computed.
#[test]
fn a7_a_claimed_root_the_block_does_not_reach_is_refused() {
    let (witness, root, _) = synthetic();
    let mut wrong = root;
    wrong[31] ^= 1;
    match stateless::run_stateless(&witness, &wrong) {
        Err(StatelessError::RootMismatch { computed, claimed }) => {
            assert_eq!(computed, root);
            assert_eq!(claimed, wrong);
        }
        other => panic!("a wrong claimed root was not refused: {other:?}"),
    }
}

/// **Corrupting one account balance in the witness flips the recomputed root
/// and the run asserts out.**
///
/// Acceptance 7's second negative control, swept over every account rather than
/// one. The refusal is `Unauthenticated` and not `RootMismatch`, and that is
/// the stronger answer: the balance is checked against the trie *before* the
/// block runs, so a corrupted one never reaches the EVM at all.
#[test]
fn a7_a_corrupted_balance_is_refused() {
    let (witness, root, _) = synthetic();
    let mut refused = 0;
    for a in 0..witness.accounts.len() {
        let mut damaged = witness.clone();
        for byte in damaged.accounts[a].balance.iter_mut().rev() {
            let (next, carried) = byte.overflowing_add(1);
            *byte = next;
            if !carried {
                break;
            }
        }
        match stateless::run_stateless(&damaged, &root) {
            Err(StatelessError::Unauthenticated { address }) => {
                assert_eq!(address, witness.accounts[a].address);
                refused += 1;
            }
            // An account the trie proves absent is recorded as all zeros, and
            // giving it a balance makes it an account the trie does not have —
            // still unauthenticated, still refused.
            Err(StatelessError::RootMismatch { .. }) | Err(StatelessError::NotExecutable(_)) => {
                refused += 1
            }
            other => panic!(
                "a corrupted balance on {} was not refused: {other:?}",
                hex(&witness.accounts[a].address)
            ),
        }
    }
    assert_eq!(
        refused,
        witness.accounts.len(),
        "a corrupted balance went unnoticed"
    );
}

/// Corrupting one trie node in the stateless witness makes the run reject.
///
/// Acceptance 7's first negative control, on the transition fixture rather than
/// the authentication one, and swept over every node.
#[test]
fn a7_a_corrupted_stateless_node_is_refused() {
    let (witness, root, _) = synthetic();
    let count = witness
        .stateless
        .as_ref()
        .expect("the stateless section")
        .nodes
        .len();
    let mut refused = 0;
    for at in 0..count {
        let mut damaged = witness.clone();
        let nodes = &mut damaged.stateless.as_mut().expect("the section").nodes;
        let last = nodes[at].len() - 1;
        nodes[at][last] ^= 1;
        // The node set is sorted by hash and a corrupted node hashes elsewhere,
        // so re-sort: this test is about the trie refusing, not about the
        // decoder refusing a mis-sorted witness.
        nodes.sort_unstable_by_key(|n| revm_block::keccak(n));
        if stateless::run_stateless(&damaged, &root).is_err() {
            refused += 1;
        }
    }
    assert_eq!(refused, count, "a corrupted node went unnoticed");
}

/// The witness must carry a stateless section, and a mini-block's does not.
#[test]
fn the_mini_mode_s_witness_is_refused_by_the_stateless_mode() {
    let witness = BlockWitness::decode(&mine("mini-block-witness.bin")).expect("the witness");
    assert!(witness.stateless.is_none());
    assert_eq!(
        stateless::run_stateless(&witness, &[0u8; 32]),
        Err(StatelessError::NotStateless),
        "a mini-block witness is not a stateless one and the two binaries differ"
    );
}

/// The two system-contract addresses are the ones their EIPs name.
///
/// They are literals in `guests/revm-block/src/stateless.rs` because revm 42
/// exports none of them — they live in `alloy-eips`, which is in neither
/// lockfile — so a transcription error would be silent: the call would hit an
/// empty account, succeed, change nothing, and give a wrong state root.
#[test]
fn the_system_contracts_are_the_addresses_their_eips_name() {
    let want = [
        (
            "EIP-4788 beacon roots",
            "000f3df6d732807ef1319fb7b8bb8522d0beac02",
        ),
        (
            "EIP-2935 history storage",
            "0000f90827f1c53a10cb7a02335b175320002935",
        ),
        (
            "EIP-7002 withdrawal requests",
            "00000961ef480eb55e80d19ad83579a64c007002",
        ),
        (
            "EIP-7251 consolidation requests",
            "0000bbddc7ce488642fb579f8b00f3a590007251",
        ),
    ];
    assert_eq!(stateless::system_contracts().len(), want.len());
    for ((what, address), (also, expected)) in stateless::system_contracts().iter().zip(want) {
        assert_eq!(*what, also);
        assert_eq!(hex(address), expected, "{what}");
    }
}

// ---------------------------------------------------------------------------
// Acceptance 7, through the guest
// ---------------------------------------------------------------------------

/// The **guest** recomputes the pinned root, and its journal is the pinned one.
///
/// Acceptance 7's positive claim on the binary a proof would be about, rather
/// than on the host library. The header's state root arrives where a proof
/// binds it — the **public input** window — and the journal comes back out of
/// the public output window, which is the arrangement S-IO built.
///
/// `#[ignore]`d because it builds a 2 MB `revm` image from source; CI asks for
/// it by name, as it does for `crates/emulator/tests/revm.rs`.
#[test]
#[ignore = "builds the revm stateless guest from source"]
fn a7_the_guest_recomputes_the_pinned_root() {
    let (_, root, journal) = synthetic();
    let elf = common::build_guest_bin("revm-block-stateless", "a7");
    let image = loader::load_elf(&elf).expect("the stateless guest loads");
    let io = emulator::GuestIo {
        stdin: Vec::new(),
        input: root.to_vec(),
        advice: theirs("revm_stateless_witness.bin"),
        hint: Vec::new(),
    };
    let execution = emulator::run(&image, &io).expect("the guest runs");
    assert_eq!(
        execution.exit_code, 0,
        "the guest exited {}; 67 is a root mismatch, 66 an unauthenticated value, \
         65 a trie failure",
        execution.exit_code
    );
    assert_eq!(
        execution.io.output, journal,
        "the guest's journal is not what the host computed from the same witness"
    );
    println!(
        "a7: the guest recomputed {} in {} cycles",
        hex(&root),
        execution.cycle_count
    );
}

/// The guest **rejects** a corrupted trie node and a corrupted balance, with
/// the exit status naming which.
///
/// Acceptance 7's two negative controls, on the binary rather than the library.
/// One case each rather than a sweep: the sweeps are the host-side tests above,
/// and each guest run is a whole emulated execution.
#[test]
#[ignore = "builds the revm stateless guest from source"]
fn a7_the_guest_rejects_a_corrupted_witness() {
    let (witness, root, _) = synthetic();
    let elf = common::build_guest_bin("revm-block-stateless", "a7-neg");
    let image = loader::load_elf(&elf).expect("the stateless guest loads");
    let run = |advice: Vec<u8>| -> i32 {
        let io = emulator::GuestIo {
            stdin: Vec::new(),
            input: root.to_vec(),
            advice,
            hint: Vec::new(),
        };
        emulator::run(&image, &io)
            .expect("the guest runs")
            .exit_code
    };

    // A corrupted trie node: the walk cannot resolve what its parent names.
    let mut damaged = witness.clone();
    {
        let nodes = &mut damaged.stateless.as_mut().expect("the section").nodes;
        let last = nodes[0].len() - 1;
        nodes[0][last] ^= 1;
        nodes.sort_unstable_by_key(|n| revm_block::keccak(n));
    }
    let status = run(damaged.encode());
    assert!(
        status == 65 || status == 66,
        "a corrupted trie node gave exit {status}, not a trie or authentication failure"
    );

    // A corrupted balance: caught by authentication, before the block runs.
    let mut damaged = witness.clone();
    let at = damaged
        .accounts
        .iter()
        .position(|a| a.balance != [0u8; 32])
        .expect("a funded account");
    damaged.accounts[at].balance[31] ^= 1;
    assert_eq!(
        run(damaged.encode()),
        66,
        "a corrupted balance was not refused as unauthenticated"
    );
}

// ---------------------------------------------------------------------------
// revm's selfdestruct flag, and why `apply` may not read it.
//
// Found by the S25 adversarial review. `execute` keeps ONE journal for the
// whole block and finalizes exactly once, which is what makes the post-state a
// single `EvmState` — but revm's `SelfDestructed` status bit is **block-global**
// under that arrangement. `commit_tx` clears the journal, the logs, the
// transient storage and `selfdestructed_addresses`, and explicitly leaves the
// account's status alone; only a revert clears the local bit. So once any
// transaction destroys an address, every later transaction's finalized view of
// that address still reads as destroyed.
//
// `apply` removed an account on that flag, so a destroyed-then-refunded address
// was deleted from the state trie — an address real Ethereum keeps, a non-zero
// balance not being empty — and deleted before the `is_created()` branch could
// rebuild its storage. The fix is to test emptiness alone. This pins both
// halves: revm's behaviour, so an upstream change is visible, and the predicate.

/// A destroyed-then-refunded account is not empty, so the trie keeps it.
#[test]
fn a_selfdestructed_then_refunded_account_is_not_removed() {
    use revm::context::TxEnv;
    use revm::context_interface::{ContextTr, JournalTr};
    use revm::database::{CacheDB, EmptyDB};
    use revm::primitives::{Address, Bytes, TxKind, U256};
    use revm::state::AccountInfo;
    use revm::{Context, ExecuteEvm, MainBuilder, MainContext};
    use revm_block::SpecId;

    let sender = Address::from([0x11u8; 20]);
    let beneficiary = Address::from([0x22u8; 20]);

    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(
        sender,
        AccountInfo {
            balance: U256::from(10u64).pow(U256::from(18u64)),
            nonce: 0,
            ..Default::default()
        },
    );

    let mut cfg = revm::context::CfgEnv::new_with_spec(SpecId::CANCUN);
    cfg.chain_id = 1;
    cfg.disable_nonce_check = true;
    let mut evm = Context::mainnet().with_db(db).with_cfg(cfg).build_mainnet();

    // Init code: `PUSH20 <beneficiary> SELFDESTRUCT`. The contract is created
    // and destroyed inside one transaction, which is the case EIP-6780 still
    // permits to destroy fully.
    let mut init = vec![0x73];
    init.extend_from_slice(beneficiary.as_slice());
    init.push(0xff);

    let created = sender.create(0);
    let create = TxEnv::builder()
        .caller(sender)
        .kind(TxKind::Create)
        .data(Bytes::from(init))
        .gas_limit(1_000_000)
        .gas_price(0)
        .nonce(0)
        .chain_id(Some(1))
        .build_fill();
    evm.transact_one(create).expect("the create runs");

    // A later transaction credits the destroyed address one wei.
    let refund = TxEnv::builder()
        .caller(sender)
        .kind(TxKind::Call(created))
        .value(U256::from(1u64))
        .gas_limit(1_000_000)
        .gas_price(0)
        .nonce(1)
        .chain_id(Some(1))
        .build_fill();
    evm.transact_one(refund).expect("the refund runs");
    evm.ctx.journal_mut().commit_tx();
    let state = evm.finalize();

    let account = state
        .get(&created)
        .expect("the destroyed-then-refunded address is in the post-state");

    // revm's own behaviour, pinned: the flag is still set two transactions on.
    assert!(
        account.is_selfdestructed(),
        "revm no longer keeps `SelfDestructed` set across `commit_tx`; \
         the reason `apply` must not read it has changed, so re-read the rule"
    );
    // And the account is not empty, so Ethereum keeps it — which is what
    // `apply`'s predicate now says, and what the flag would have overruled.
    assert_eq!(account.info.balance, U256::from(1u64));
    assert!(
        !account.state_clear_aware_is_empty(SpecId::CANCUN),
        "a one-wei balance is not empty, so EIP-161 does not clear it"
    );
}

/// Prague's two **post**-block system calls are made, and the fixture can tell.
///
/// EIP-7002's withdrawal-request predeploy and EIP-7251's consolidation-request
/// predeploy each dequeue their request queue and rewrite the queue head and
/// tail, the excess counter and the per-block count. revm makes neither for you
/// — `revm-handler`'s `SystemCallEvm` says the client must — so without them a
/// Prague-or-later block with either queue non-empty recomputes a root the
/// header does not carry.
///
/// What makes the committed root an actual check of that is the **excess
/// counter starting at 5 rather than 0**. Each call recomputes the excess as
/// `previous + count - target` when positive and 0 otherwise, so from zero with
/// an empty queue the call writes 0 over 0 and a root computed without making
/// the call at all is identical — the fixture would happily accept the code
/// being deleted. From 5 it writes a smaller number, so
/// `a7_the_transition_recomputes_the_pinned_root` moves if the calls go. This
/// test guards that property of the fixture, which is what gives the other one
/// its teeth.
#[test]
fn the_prague_request_calls_move_the_root() {
    let witness = BlockWitness::decode(&theirs("revm_stateless_witness.bin")).expect("the witness");
    for (what, address) in stateless::system_contracts() {
        let account = witness
            .accounts
            .iter()
            .find(|a| a.address == address)
            .unwrap_or_else(|| panic!("{what} is in the witness"));
        assert!(
            !account.code.is_empty(),
            "{what} is in the witness with its real deployed code, or the strict \
             database would refuse the system call"
        );
    }

    // The two request predeploys, and their excess counter. Slot 0 is the
    // excess; it must not start at zero, or the call writes 0 over 0.
    for (what, address) in stateless::system_contracts().into_iter().skip(2) {
        let account = witness
            .accounts
            .iter()
            .find(|a| a.address == address)
            .expect("a request predeploy");
        let (_, excess) = account
            .slots
            .iter()
            .find(|(slot, _)| *slot == [0u8; 32])
            .unwrap_or_else(|| panic!("{what} carries its excess counter"));
        assert_ne!(
            *excess, [0u8; 32],
            "{what}'s excess counter starts at zero, so the system call writes 0 over 0 \
             and the committed root no longer detects the call being removed"
        );
    }
}
